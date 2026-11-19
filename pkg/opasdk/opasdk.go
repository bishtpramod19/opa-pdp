// -
//   ========================LICENSE_START=================================
//   Copyright (C) 2024-2025: Deutsche Telekom
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.
//   SPDX-License-Identifier: Apache-2.0
//   ========================LICENSE_END===================================

// The opasdk package provides functionalities for integrating with the Open Policy Agent
// (OPA) SDK, including reading configurations and managing a singleton OPA instance.
// This package is designed to ensure efficient, thread-safe initialization and configuration
// of the OPA instance.
package opasdk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"policy-opa-pdp/consts"
	"policy-opa-pdp/pkg/log"
	"slices"
	"strings"
	"sync"

	"policy-opa-pdp/pkg/model/oapicodegen"

	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/sdk"
	"github.com/open-policy-agent/opa/v1/storage"
)

// Define the structs
var (
	opaInstance     *sdk.OPA  //A singleton instance of the OPA object
	once            sync.Once //A sync.Once variable used to ensure that the OPA instance is initialized only once,
	memStore        storage.Store
	initErr         error
	UpsertPolicyVar UpsertPolicyFunc = UpsertPolicy
	WriteDataVar    WriteDataFunc    = WriteData

	WriteDataKeepingFoldersVar WriteDataKeepingFoldersFunc = WriteDataKeepingFolders
	CompileWithLiveModulesVar  CompileWithLiveModulesFunc  = CompileWithLiveModules
	RemoveOwnDataVar           RemoveOwnDataFunc           = RemoveOwnData
	DeletePolicyIfExistsVar    DeletePolicyIfExistsFunc    = DeletePolicyIfExists
	patchCompilerVar           patchCompilerFunc           = liveCompiler
)

type (
	UpsertPolicyFunc func(ctx context.Context, policyID string, policyContent []byte) error
	WriteDataFunc    func(ctx context.Context, dataPath string, data interface{}) error

	WriteDataKeepingFoldersFunc func(ctx context.Context, dataPath string, data interface{}, keepFolders [][]string) error
	CompileWithLiveModulesFunc  func(ctx context.Context, candidates map[string]string) error
	RemoveOwnDataFunc           func(ctx context.Context, dataPath string, protectedFolders, neededFolders [][]string) error
	DeletePolicyIfExistsFunc    func(ctx context.Context, policyID string) error
	patchCompilerFunc           func(ctx context.Context, txn storage.Transaction) *ast.Compiler
)

type PatchImpl struct {
	Path  storage.Path
	Op    storage.PatchOp
	Value interface{}
}

// reads JSON configuration from a file and return a jsonReader
func getJSONReader(filePath string, openFunc func(string) (*os.File, error),
	readAllFunc func(io.Reader) ([]byte, error)) (*bytes.Reader, error) {
	file, err := openFunc(filePath)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %w", err)
	}
	defer func() {
		if cerr := file.Close(); cerr != nil {
			log.Warnf("Failed to close config file: %v", cerr)
		}
	}()

	byteValue, err := readAllFunc(file)
	if err != nil {
		return nil, fmt.Errorf("error reading config file: %w", err)
	}

	jsonReader := bytes.NewReader(byteValue)
	return jsonReader, nil
}

type NewSDKFunc func(ctx context.Context, options sdk.Options) (*sdk.OPA, error)

var NewSDK NewSDKFunc = sdk.New

// singletonResult returns the package-level OPA instance and the persisted init error.
// Using a helper ensures the getter's return path is testable in isolation.
func singletonResult() (*sdk.OPA, error) {
	return opaInstance, initErr
}

// Returns a singleton instance of the OPA object. The initialization of the instance is
// thread-safe, and the OPA object is configured using a JSON configuration file.
func GetOPASingletonInstance() (*sdk.OPA, error) {
	once.Do(func() {
		memStore = inmem.New()
		var opaErr error
		opaInstance, opaErr = NewSDK(context.Background(), sdk.Options{
			V1Compatible: true,
			Store:        memStore,
		})
		log.Debugf("Create an instance of OPA Object")
		if opaErr != nil {
			log.Warnf("Error creating OPA instance: %s", opaErr)
			initErr = opaErr
			return
		}
		if cfgErr := configureInstance(opaInstance, consts.OpasdkConfigPath); cfgErr != nil {
			initErr = cfgErr
		}
	})
	return singletonResult()
}

// configureInstance loads the OPA JSON config and applies it. Returns any error
// so callers can fail fast instead of using a mis-configured instance.
func configureInstance(opa *sdk.OPA, configPath string) error {
	jsonReader, jsonErr := getJSONReader(configPath, os.Open, io.ReadAll)
	if jsonErr != nil {
		log.Warnf("Error getting JSON reader: %s", jsonErr)
		return jsonErr
	}
	log.Debugf("Configure an instance of OPA Object")
	if err := opa.Configure(context.Background(), sdk.ConfigOptions{Config: jsonReader}); err != nil {
		log.Warnf("Failed to configure OPA: %v", err)
		return err
	}
	return nil
}

func UpsertPolicy(ctx context.Context, policyID string, policyContent []byte) error {
	txn, err := memStore.NewTransaction(ctx, storage.WriteParams)
	if err != nil {
		log.Warnf("Error creating transaction While Upsert Policy: %s", err)
		memStore.Abort(ctx, txn)
		return err
	}
	err = memStore.UpsertPolicy(ctx, txn, policyID, policyContent)
	if err != nil {
		log.Warnf("Error inserting policy: %s", err)
		memStore.Abort(ctx, txn)
		return err
	}
	err = memStore.Commit(ctx, txn)
	if err != nil {
		log.Warnf("Error commiting the transaction while upsert policy: %s", err)
		memStore.Abort(ctx, txn)
		return err
	}
	return nil
}

func DeletePolicy(ctx context.Context, policyID string) error {
	txn, err := memStore.NewTransaction(ctx, storage.WriteParams)
	if err != nil {
		log.Warnf("Error creating transaction while delete policy: %s", err)
		memStore.Abort(ctx, txn)
		return err
	}
	err = memStore.DeletePolicy(ctx, txn, policyID)
	if err != nil {
		log.Warnf("Error deleting policy: %s", err)
		memStore.Abort(ctx, txn)
		return err
	}
	err = memStore.Commit(ctx, txn)
	if err != nil {
		log.Warnf("Error commiting the transaction while delete policy: %s", err)
		memStore.Abort(ctx, txn)
		return err
	}
	return nil
}

func WriteData(ctx context.Context, dataPath string, data interface{}) error {
	txn, err := memStore.NewTransaction(ctx, storage.WriteParams)
	if err != nil {
		log.Warnf("Error creating transaction while write data: %s", err)
		memStore.Abort(ctx, txn)
		return err
	}

	// Initialize the path if it doesn't exist
	err = initializePath(ctx, txn, dataPath)
	if err != nil {
		log.Warnf("Error initializling Path : %s", dataPath)
		log.Warnf("Error : %s", err)
		memStore.Abort(ctx, txn)
		return err
	}

	parsedPath, ok := storage.ParsePath(dataPath)
	if !ok {
		memStore.Abort(ctx, txn)
		return fmt.Errorf("invalid data path: %s", dataPath)
	}
	err = memStore.Write(ctx, txn, storage.AddOp, parsedPath, data)
	if err != nil {
		log.Warnf("Error Adding data: %s", err)
		memStore.Abort(ctx, txn)
		return err
	}
	err = memStore.Commit(ctx, txn)
	if err != nil {
		log.Warnf("Error commiting the transaction while write data: %s", err)
		memStore.Abort(ctx, txn)
		return err
	}
	return nil

}

func DeleteData(ctx context.Context, dataPath string) error {
	txn, err := memStore.NewTransaction(ctx, storage.WriteParams)
	if err != nil {
		log.Warnf("Error creating transaction while Delete Data: %s", err)
		memStore.Abort(ctx, txn)
		return err
	}
	parsedPath, ok := storage.ParsePath(dataPath)
	if !ok {
		memStore.Abort(ctx, txn)
		return fmt.Errorf("invalid data path: %s", dataPath)
	}
	err = memStore.Write(ctx, txn, storage.RemoveOp, parsedPath, nil)
	if err != nil {
		log.Warnf("Error deleting data: %s", err)
		memStore.Abort(ctx, txn)
		return err
	}
	err = memStore.Commit(ctx, txn)
	if err != nil {
		log.Warnf("Error commiting the transaction while Delete Data: %s", err)
		memStore.Abort(ctx, txn)
		return err
	}
	return nil
}

// Added below method to test get policies (added for testing purpose only)
func ListPolicies(res http.ResponseWriter, req *http.Request) {
	ctx := context.Background()
	rtxn, err := memStore.NewTransaction(ctx, storage.TransactionParams{Write: false})
	if err != nil {
		log.Warnf("Error creating transaction  while listing policies: %s", err)
		memStore.Abort(ctx, rtxn)
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}
	policies, err := memStore.ListPolicies(ctx, rtxn)
	if err != nil {
		log.Warnf("Error ListPolicies %s", err)
		memStore.Abort(ctx, rtxn)
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}

	for _, policyId := range policies {
		log.Debugf("Policy ID: %s", policyId)
		policy, err := memStore.GetPolicy(ctx, rtxn, policyId)
		if err != nil {
			log.Warnf("Error GetPolicy %s", err)
			memStore.Abort(ctx, rtxn)
			http.Error(res, err.Error(), http.StatusInternalServerError)
			return
		}
		log.Debugf("Policy Content: %s\n", string(policy))
	}
	memStore.Abort(ctx, rtxn)
	res.WriteHeader(http.StatusOK)
	if _, err := res.Write([]byte("Check logs")); err != nil {
		log.Warnf("Warning: Failed to write response: %v", err)
	}
}

func initializePath(ctx context.Context, txn storage.Transaction, path string) error {
	segments, ok := storage.ParsePath(path)
	if !ok {
		return fmt.Errorf("invalid data path: %s", path)
	}
	for i := 1; i <= len(segments); i++ {
		subPath := segments[:i]
		_, err := memStore.Read(ctx, txn, subPath)
		if err != nil && storage.IsNotFound(err) {
			// Create the intermediate path
			log.Debugf("storage not found creating : %s", subPath.String())
			err = memStore.Write(ctx, txn, storage.AddOp, subPath, map[string]interface{}{})
			if err != nil {
				log.Debugf("Error initializing path: %s", err)
				return err
			}
		} else if err != nil {
			log.Debugf("Error reading path: %s", err)
			return err
		}
	}
	return nil
}

func PatchData(ctx context.Context, patches []PatchImpl) error {
	txn, err := memStore.NewTransaction(ctx, storage.WriteParams)
	if err != nil {
		log.Warnf("Error in creating transaction while Patch Data: %s", err)
		memStore.Abort(ctx, txn)
		return err
	}

	for _, patch := range patches {
		err = memStore.Write(ctx, txn, patch.Op, patch.Path, patch.Value)
		path := (patch.Path).String()
		if err != nil {
			log.Warnf("Error in writing data under "+path+" in memory: %s", err)
			memStore.Abort(ctx, txn)
			return err
		}
	}

	// Compiler holding the live policies, so that path conflicts with their rules are detected
	compiler := patchCompilerVar(ctx, txn)

	// Check for path conflicts
	errInfo := ast.CheckPathConflicts(compiler, storage.NonEmpty(ctx, memStore, txn))
	if len(errInfo) > 0 {
		memStore.Abort(ctx, txn)
		log.Errorf("Path conflicts detected: %s", errInfo)
		return errInfo
	} else {
		log.Debugf("No path conflicts detected")
	}

	err = memStore.Commit(ctx, txn)
	if err != nil {
		log.Warnf("Error in commiting the transaction: %s", err)
		memStore.Abort(ctx, txn)
		return err
	}
	return nil
}

func GetDataInfo(ctx context.Context, dataPath string) (data *oapicodegen.OPADataResponse_Data, err error) {

	path, ok := storage.ParsePath(dataPath)
	if !ok {
		return nil, fmt.Errorf("invalid data path: %s", dataPath)
	}
	rtxn, err := memStore.NewTransaction(ctx, storage.TransactionParams{Write: false})
	if err != nil {
		log.Warnf("Error creating transaction while getting data: %s", err)
		return nil, err
	}
	defer memStore.Abort(ctx, rtxn) // Ensure transaction is aborted to avoid leaks

	result, err := memStore.Read(ctx, rtxn, path)
	if err != nil {
		log.Warnf("Error in reading data under %s path", dataPath)
		return nil, err
	}

	jsonData, err := json.Marshal(result)
	if err != nil {
		log.Warnf("Error in converting result into json data %s", err)
		return nil, err
	}

	log.Debugf("Json Data at %s: %s\n", path, jsonData)

	var resData oapicodegen.OPADataResponse_Data

	err = json.Unmarshal(jsonData, &resData)
	if err != nil {
		log.Errorf("Error in unmarshalling data: %s", err)
		return nil, err
	}

	return &resData, nil
}

func ParsePatchPathEscaped(str string) (path storage.Path, ok bool) {
	path, ok = storage.ParsePathEscaped(str)
	if !ok {
		return
	}
	for i := range path {
		// RFC 6902 section 4: "[The "path" member's] value is a string containing
		// a JSON-Pointer value [RFC6901] that references a location within the
		// target document (the "target location") where the operation is performed."
		//
		// RFC 6901 section 3: "Because the characters '~' (%x7E) and '/' (%x2F)
		// have special meanings in JSON Pointer, '~' needs to be encoded as '~0'
		// and '/' needs to be encoded as '~1' when these characters appear in a
		// reference token."

		// RFC 6901 section 4: "Evaluation of each reference token begins by
		// decoding any escaped character sequence.  This is performed by first
		// transforming any occurrence of the sequence '~1' to '/', and then
		// transforming any occurrence of the sequence '~0' to '~'.  By performing
		// the substitutions in this order, an implementation avoids the error of
		// turning '~01' first into '~1' and then into '/', which would be
		// incorrect (the string '~01' correctly becomes '~1' after transformation)."
		path[i] = strings.ReplaceAll(path[i], "~1", "/")
		path[i] = strings.ReplaceAll(path[i], "~0", "~")
	}

	return
}

// DeletePolicyIfExists deletes a policy module by its ID.
func DeletePolicyIfExists(ctx context.Context, policyID string) error {
	err := DeletePolicy(ctx, policyID)
	if err != nil && storage.IsNotFound(err) {
		log.Debugf("Policy %s is not in the store, nothing to delete", policyID)
		return nil
	}
	return err
}

// writes the parent’s data at its path, but first remembers the child’s folder and puts it back after.
//
//	All of it is one transaction, so it is all or nothing. A failure halfway leaves the store as it was.
func WriteDataKeepingFolders(ctx context.Context, dataPath string, data interface{}, keepFolders [][]string) error {
	txn, err := memStore.NewTransaction(ctx, storage.WriteParams)
	if err != nil {
		log.Warnf("Error creating transaction while writing data keeping folders: %s", err)
		return err
	}
	if err := replaceDataKeepingNestedFolders(ctx, txn, dataPath, data, keepFolders); err != nil {
		log.Warnf("Error writing data keeping folders under %s: %s", dataPath, err)
		memStore.Abort(ctx, txn)
		return err
	}
	if err := memStore.Commit(ctx, txn); err != nil {
		log.Warnf("Error commiting the transaction while writing data keeping folders: %s", err)
		memStore.Abort(ctx, txn)
		return err
	}
	return nil
}

type keptFolder struct {
	path  storage.Path
	value any
}

func replaceDataKeepingNestedFolders(ctx context.Context, txn storage.Transaction, dataPath string, data any, keepFolders [][]string) error {
	parsedPath, ok := storage.ParsePath(dataPath)
	if !ok {
		return fmt.Errorf("invalid data path: %s", dataPath)
	}
	kept, err := readKeptFolders(ctx, txn, keepFolders)
	if err != nil {
		return err
	}
	if err := initializePath(ctx, txn, dataPath); err != nil {
		return err
	}
	if err := memStore.Write(ctx, txn, storage.AddOp, parsedPath, data); err != nil {
		return err
	}
	return restoreKeptFolders(ctx, txn, kept)
}

// readKeptFolders reads the child folders that has data
func readKeptFolders(ctx context.Context, txn storage.Transaction, keepFolders [][]string) ([]keptFolder, error) {
	kept := make([]keptFolder, 0, len(keepFolders))
	for _, folder := range keepFolders {
		path := storage.Path(slices.Clone(folder))
		value, err := memStore.Read(ctx, txn, path)
		if storage.IsNotFound(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		kept = append(kept, keptFolder{path: path, value: value})
	}
	return kept, nil
}

func restoreKeptFolders(ctx context.Context, txn storage.Transaction, kept []keptFolder) error {
	for _, folder := range kept {
		if err := initializePath(ctx, txn, folder.path.String()); err != nil {
			return err
		}
		if err := memStore.Write(ctx, txn, storage.AddOp, folder.path, folder.value); err != nil {
			return err
		}
	}
	return nil
}

// RemoveOwnData removes the policy’s own data and nothing else, then tidies empty parent folders.
func RemoveOwnData(ctx context.Context, dataPath string, protectedFolders, neededFolders [][]string) error {
	path, ok := storage.ParsePath(dataPath)
	if !ok {
		return fmt.Errorf("invalid data path: %s", dataPath)
	}
	txn, err := memStore.NewTransaction(ctx, storage.WriteParams)
	if err != nil {
		log.Warnf("Error creating transaction while removing own data: %s", err)
		return err
	}
	if err := removeOwnItems(ctx, txn, path, protectedFolders); err != nil {
		memStore.Abort(ctx, txn)
		return err
	}
	if err := pruneEmptyParents(ctx, txn, path, neededFolders); err != nil {
		memStore.Abort(ctx, txn)
		return err
	}
	if err := memStore.Commit(ctx, txn); err != nil {
		log.Warnf("Error commiting the transaction while removing own data: %s", err)
		memStore.Abort(ctx, txn)
		return err
	}
	return nil
}

func removeOwnItems(ctx context.Context, txn storage.Transaction, path storage.Path, protectedFolders [][]string) error {
	value, err := memStore.Read(ctx, txn, path)
	if storage.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	object, isObject := value.(map[string]interface{})
	if !isObject {
		return removeIfPresent(ctx, txn, path)
	}
	keptItems := 0
	for _, name := range slices.Sorted(maps.Keys(object)) {
		itemPath := append(slices.Clone(path), name)
		if isProtected(itemPath, protectedFolders) {
			keptItems++
			continue
		}
		if err := removeIfPresent(ctx, txn, itemPath); err != nil {
			return err
		}
	}
	if keptItems == 0 {
		return removeIfPresent(ctx, txn, path)
	}
	return nil
}

// isProtected reports is this path a child’s folder or not
func isProtected(path storage.Path, protectedFolders [][]string) bool {
	return slices.ContainsFunc(protectedFolders, func(folder []string) bool {
		return hasSegmentPrefix(folder, path)
	})
}

// hasSegmentPrefix reports whether path starts with every segment of prefix.
func hasSegmentPrefix(path, prefix []string) bool {
	return len(prefix) <= len(path) && slices.Equal(path[:len(prefix)], prefix)
}

func removeIfPresent(ctx context.Context, txn storage.Transaction, path storage.Path) error {
	err := memStore.Write(ctx, txn, storage.RemoveOp, slices.Clone(path), nil)
	if err != nil && !storage.IsNotFound(err) {
		return err
	}
	return nil
}

// pruneEmptyParents removes the parent folders of path one by one for as long as they are
// empty and not needed by another policy.
func pruneEmptyParents(ctx context.Context, txn storage.Transaction, path storage.Path, neededFolders [][]string) error {
	for parent := path[:max(len(path)-1, 0)]; len(parent) > 0; parent = parent[:len(parent)-1] {
		gone, err := removeIfEmptyAndUnneeded(ctx, txn, slices.Clone(parent), neededFolders)
		if err != nil || !gone {
			return err
		}
	}
	return nil
}

// removeIfEmptyAndUnneeded returns true when the folder is gone
func removeIfEmptyAndUnneeded(ctx context.Context, txn storage.Transaction, path storage.Path, neededFolders [][]string) (bool, error) {
	value, err := memStore.Read(ctx, txn, path)
	if storage.IsNotFound(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	object, isObject := value.(map[string]any)
	if !isObject || len(object) > 0 || slices.ContainsFunc(neededFolders, func(folder []string) bool { return slices.Equal(folder, path) }) {
		return false, nil
	}
	return true, removeIfPresent(ctx, txn, path)
}

// CompileWithLiveModules compiles the candidate policy modules together with the policies
// that are live,  Nothing is written to the store.
func CompileWithLiveModules(ctx context.Context, candidates map[string]string) error {
	if memStore == nil {
		return nil
	}
	live, err := readLivePolicyTexts(ctx)
	if err != nil {
		return fmt.Errorf("failed to read the deployed policies: %w", err)
	}
	combined := maps.Clone(live)
	maps.Copy(combined, candidates)
	return newCompileErrors(compileMessages(live), compileMessages(combined))
}

func readLivePolicyTexts(ctx context.Context) (map[string]string, error) {
	txn, err := memStore.NewTransaction(ctx)
	if err != nil {
		return nil, err
	}
	defer memStore.Abort(ctx, txn)
	return policyTexts(ctx, txn)
}

// policyTexts returns the text of every policy module in the store, by module ID.
func policyTexts(ctx context.Context, txn storage.Transaction) (map[string]string, error) {
	ids, err := memStore.ListPolicies(ctx, txn)
	if err != nil {
		return nil, err
	}
	texts := make(map[string]string, len(ids))
	for _, id := range ids {
		content, err := memStore.GetPolicy(ctx, txn, id)
		if err != nil {
			return nil, err
		}
		texts[id] = string(content)
	}
	return texts, nil
}

// compileMessages parses and compiles the modules and returns the text of every error found.
func compileMessages(texts map[string]string) []string {
	modules, messages := parseModules(texts)
	compiler := ast.NewCompiler().WithDefaultRegoVersion(ast.RegoV1)
	compiler.Compile(modules)
	for _, compileErr := range compiler.Errors {
		messages = append(messages, compileErr.Error())
	}
	return messages
}

func parseModules(texts map[string]string) (map[string]*ast.Module, []string) {
	modules := make(map[string]*ast.Module, len(texts))
	var messages []string
	for _, id := range slices.Sorted(maps.Keys(texts)) {
		module, err := ast.ParseModuleWithOpts(id, texts[id], ast.ParserOptions{RegoVersion: ast.RegoV1})
		if err != nil {
			messages = append(messages, err.Error())
			continue
		}
		if module != nil {
			modules[id] = module
		}
	}
	return modules, messages
}

// newCompileErrors returns only the errors the candidate causes,
// it is basically to return the full error text
func newCompileErrors(baseline, combined []string) error {
	var fresh []string
	for _, message := range combined {
		if !slices.Contains(baseline, message) {
			fresh = append(fresh, message)
		}
	}
	if len(fresh) == 0 {
		return nil
	}
	return fmt.Errorf("%d error(s) occurred: %s", len(fresh), strings.Join(fresh, "; "))
}

// liveCompiler returns a compiler holding the live policies
func liveCompiler(ctx context.Context, txn storage.Transaction) *ast.Compiler {
	texts, err := policyTexts(ctx, txn)
	if err != nil {
		log.Warnf("Could not read the live policies for the patch conflict check: %s", err)
		return ast.NewCompiler()
	}
	modules, _ := parseModules(texts)
	compiler := ast.NewCompiler().WithDefaultRegoVersion(ast.RegoV1)
	compiler.Compile(modules)
	return compiler
}
