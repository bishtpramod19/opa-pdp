// -
//   ========================LICENSE_START=================================
//   Copyright (C) 2025-2026: Deutsche Telekom
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

// will process the update message from pap and send the pdp status response.
package handler

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"policy-opa-pdp/consts"
	"policy-opa-pdp/pkg/kafkacomm/publisher"
	"policy-opa-pdp/pkg/log"
	"policy-opa-pdp/pkg/metrics"
	"policy-opa-pdp/pkg/model"
	"policy-opa-pdp/pkg/opasdk"
	"policy-opa-pdp/pkg/policymap"
	"policy-opa-pdp/pkg/utils"
	"slices"
	"sort"
	"strings"
	"sync"
)

// Define types for the functions
type (
	UpsertPolicyFunc             func(model.ToscaPolicy) error
	UpsertDataFunc               func(model.ToscaPolicy) error
	HandlePolicyDeploymentFunc   func(pdpUpdate model.PdpUpdate, p publisher.PdpStatusSender) ([]string, map[string]string)
	validatePackageNameFunc      func(key, decodedPolicyContent string) error
	extractAndDecodePoliciesFunc func(policy model.ToscaPolicy) (map[string]string, []string, error)
	createPolicyDirectoriesFunc  func(decodedPolicies map[string]string) error
	extractAndDecodeDatFunc      func(policy model.ToscaPolicy) (map[string]string, []string, error)
	createDataDirectoriesFunc    func(decodedData map[string]string) error
	createAndStorePolicyDataFunc func(policy model.ToscaPolicy) error
	validateParentPolicyFunc     func(policy model.ToscaPolicy) (bool, error)
)

// Declare function variables that will be used during testing
var (
	upsertPolicyFunc            UpsertPolicyFunc             = upsertPolicy
	upsertDataFunc              UpsertDataFunc               = upsertData
	handlePolicyDeploymentVar   HandlePolicyDeploymentFunc   = handlePolicyDeployment
	validatePackageNameVar      validatePackageNameFunc      = validatePackageName
	extractAndDecodePoliciesVar extractAndDecodePoliciesFunc = extractAndDecodePolicies
	createPolicyDirectoriesVar  createPolicyDirectoriesFunc  = createPolicyDirectories
	extractAndDecodeDataVar     extractAndDecodeDatFunc      = extractAndDecodeData
	createDataDirectoriesVar    createDataDirectoriesFunc    = createDataDirectories
	createAndStorePolicyDataVar createAndStorePolicyDataFunc = createAndStorePolicyData
	validateParentPolicyVar     validateParentPolicyFunc     = validateParentPolicy
)

// stores policy and data files to directory.
func createAndStorePolicyData(policy model.ToscaPolicy) error {

	// Remember what is on disk now, so that a failed deployment can put it back
	backupPolicyFiles(policy)

	// Extract and decode policies
	decodedPolicies, key, err := extractAndDecodePoliciesVar(policy)
	if err != nil {
		log.Errorf("Failed to extract and decode policies for key : %v, %v", key, err)
		return err
	}

	err = createPolicyDirectoriesVar(decodedPolicies)
	if err != nil {
		log.Errorf("Failed to create policy directories: %v", err)
		return err
	}

	decodedData, _, err := extractAndDecodeDataVar(policy)
	if err != nil {
		log.Errorf("Failed to extract and decode data: %v", err)
		return err
	}

	err = createDataDirectoriesVar(decodedData)
	if err != nil {
		log.Errorf("Failed to create data directories: %v", err)
		return err
	}

	return nil
}

// Function to create directories and save policies
func createPolicyDirectories(decodedPolicies map[string]string) error {

	for key, decodedPolicy := range decodedPolicies {
		policyDir := filepath.Join(basePolicyDir, filepath.Join(strings.Split(key, ".")...))

		err := utils.CreateDirectoryVar(policyDir)
		if err != nil {
			log.Errorf("Failed to create policy directory %s: %v", policyDir, err)
			return err
		}

		err = os.WriteFile(filepath.Join(policyDir, "policy.rego"), []byte(decodedPolicy), 0600)
		if err != nil {
			log.Errorf("Failed to save policy.rego for %s: %v", key, err)
			return err
		}
		log.Infof("Policy file saved: %s", filepath.Join(policyDir, "policy.rego"))
	}

	return nil
}

// Function to create directories and save data
func createDataDirectories(decodedData map[string]string) error {

	for key, dataContent := range decodedData {
		dataDir := filepath.Join(baseDataDir, filepath.Join(strings.Split(key, ".")...))

		err := utils.CreateDirectoryVar(dataDir)
		if err != nil {
			log.Errorf("Failed to create data directory %s: %v", dataDir, err)
			return err
		}

		err = os.WriteFile(filepath.Join(dataDir, "data.json"), []byte(dataContent), 0600)
		if err != nil {
			log.Errorf("Failed to save data.json for %s: %v", key, err)
			return err
		}
		log.Infof("Data file saved: %s", filepath.Join(dataDir, "data.json"))
	}

	return nil
}

// Extract and decodes Policies from PDP_UPDATE message using Base64Decode
func extractAndDecodePolicies(policy model.ToscaPolicy) (map[string]string, []string, error) {

	decodedPolicies := make(map[string]string)
	var keys []string
	for key, encodedPolicy := range policy.Properties.Policy {
		decodedPolicy, err := base64.StdEncoding.DecodeString(encodedPolicy)
		if err != nil {
			log.Errorf("Failed to decode policy for key: %v, %v", key, err)

			return nil, nil, err
		}

		decodedPolicies[key] = string(decodedPolicy)
		keys = append(keys, key)
		log.Tracef("Decoded policy content: %s", decodedPolicy)

		// Validate package name
		if err := validatePackageNameVar(key, string(decodedPolicy)); err != nil {

			log.Errorf("Validation for Policy: %v failed, %v", key, err)
			return nil, nil, err
		}

		log.Tracef("Decoded policy content for key '%s': %s", key, decodedPolicy)
	}

	return decodedPolicies, keys, nil
}

// Validate the package name extracted from the decoded policy against the key
func validatePackageName(key, decodedPolicyContent string) error {
	// Extract the package name from the first line of the decoded policy content
	lines := strings.Split(decodedPolicyContent, "\n")
	if len(lines) == 0 {
		return fmt.Errorf("no content found in decoded policy for key '%s'", key)
	}

	// Assume the first line contains the package declaration
	packageLine := strings.TrimSpace(lines[0])
	if !strings.HasPrefix(packageLine, "package ") {
		return fmt.Errorf("package declaration not found in policy content for key '%s'", key)
	}

	// Extract the actual package name
	packageName := strings.TrimSpace(strings.TrimPrefix(packageLine, "package "))

	expectedPackageName := key

	// Compare the extracted package name with the expected package name
	if packageName != expectedPackageName {
		return fmt.Errorf("package name mismatch for key '%s': expected '%s' but got '%s'", key, expectedPackageName, packageName)
	}

	return nil
}

// Extract and decodes Data from PDP_UPDATE message using Base64Decode
func extractAndDecodeData(policy model.ToscaPolicy) (map[string]string, []string, error) {

	decodedData := make(map[string]string)
	var keys []string
	for key, encodedData := range policy.Properties.Data {
		decodedContent, err := base64.StdEncoding.DecodeString(encodedData)
		if err != nil {
			log.Errorf("Failed to decode data for key: %v, %v", key, err)
			return nil, nil, err
		}
		decodedData[key] = string(decodedContent)
		keys = append(keys, key)
		log.Tracef("Decoded data content: %s", decodedContent)
	}

	return decodedData, keys, nil
}

// upsert policy to sdk.
func upsertPolicy(policy model.ToscaPolicy) error {
	decodedContent, keys, err := extractAndDecodePoliciesVar(policy)
	if err != nil {
		log.Errorf("Failed to decode policies for %s: %v", policy.Name, err)
		return err
	}
	for _, key := range keys {
		policyContent := decodedContent[key]
		err := opasdk.UpsertPolicyVar(context.Background(), key, []byte(policyContent))
		if err != nil {
			log.Errorf("Failed to Insert Policy %v", err)
			return err
		}
	}

	return nil
}

// handles writing data to sdk.
func upsertData(policy model.ToscaPolicy) error {
	decodedDataContent, dataKeys, err := extractAndDecodeDataVar(policy)
	if err != nil {
		log.Errorf("Failed to decode data for %s: %v", policy.Name, err)
		return err
	}
	sort.Stable(utils.ByDotCount{Keys: dataKeys, Ascend: true})
	otherDataKeys := deployedDataKeysOfOthers(policy.Name)
	for _, dataKey := range dataKeys {
		dataContent := decodedDataContent[dataKey]
		reader := bytes.NewReader([]byte(dataContent))
		decoder := json.NewDecoder(reader)
		decoder.UseNumber()

		var wdata interface{}
		err = decoder.Decode(&wdata)
		if err != nil {
			log.Errorf("Failed to Insert Data: %s: %v", policy.Name, err)
			return err

		}
		keypath := "/" + strings.ReplaceAll(dataKey, ".", "/")
		err = writePolicyData(keypath, dataKey, wdata, otherDataKeys)
		if err != nil {
			log.Errorf("Failed to Write Data: %s: %v", policy.Name, err)
			return err

		}

	}
	return nil
}

// handles policy deployment
func handlePolicyDeployment(pdpUpdate model.PdpUpdate, p publisher.PdpStatusSender) ([]string, map[string]string) {
	var failureMessages []string
	successPolicies := make(map[string]string)

	// Check if policy is deployed previously
	pdpUpdate.PoliciesToBeDeployed = checkIfPolicyAlreadyDeployed(pdpUpdate)

	for _, policy := range pdpUpdate.PoliciesToBeDeployed {
		if err := validateAndPreparePolicy(policy, &failureMessages); err != nil {
			continue
		}
		if err := deployPolicyAndData(policy, successPolicies); err != nil {
			failureMessages = append(failureMessages, err.Error())
			continue
		}

	}

	totalPolicies := policymap.GetTotalDeployedPoliciesCountFromMap()
	metrics.SetTotalPoliciesCount(int64(totalPolicies))

	return failureMessages, successPolicies

}

func validateAndPreparePolicy(policy model.ToscaPolicy, failureMessages *[]string) error {
	// Validate the policy

	policyAllowed, err := validateParentPolicyVar(policy)
	if err != nil {
		log.Warnf("Tosca Policy Id validation failed for policy nameas it is a parent folder:%s, %v", policy.Name, err)
		*failureMessages = append(*failureMessages, fmt.Sprintf("%s, %v", policy.Name, err))
		metrics.IncrementDeployFailureCount()
		metrics.IncrementTotalErrorCount()
		return err
	}
	if policyAllowed {
		log.Debugf("Policy Is Allowed: %s", policy.Name)
	} else {
		return fmt.Errorf("policy not Allowed")
	}

	if err := utils.ValidateToscaPolicyJsonFields(policy); err != nil {
		log.Debugf("Tosca Policy Validation Failed for policy Name: %s, %v", policy.Name, err)
		*failureMessages = append(*failureMessages, fmt.Sprintf("Tosca Policy Validation failed for Policy: %s: %v", policy.Name, err))
		metrics.IncrementDeployFailureCount()
		metrics.IncrementTotalErrorCount()
		return err
	}

	// Create and store policy data
	if err := createAndStorePolicyDataVar(policy); err != nil {
		*failureMessages = append(*failureMessages, fmt.Sprintf("%s: %v", policy.Name, err))
		metrics.IncrementDeployFailureCount()
		metrics.IncrementTotalErrorCount()
		return err
	}
	return nil

}

func deployPolicyAndData(policy model.ToscaPolicy, successPolicies map[string]string) error {
	defer discardFileBackup(policy.Name)

	// Build the bundle
	if err := verifyPolicyByBundleCreation(policy); err != nil {
		metrics.IncrementDeployFailureCount()
		metrics.IncrementTotalErrorCount()
		return fmt.Errorf("failed to build Rego File for %s: %v", policy.Name, err)
	}

	// Compile the policy together with the policies that are live, before anything is stored
	if err := verifyPolicyAgainstLiveModules(policy); err != nil {
		cleanupPolicyFiles(policy)
		metrics.IncrementDeployFailureCount()
		metrics.IncrementTotalErrorCount()
		return fmt.Errorf("failed to compile %s together with the deployed policies: %v", policy.Name, err)
	}

	// Upsert policy and data
	if err := upsertPolicyAndData(policy, successPolicies); err != nil {
		metrics.IncrementDeployFailureCount()
		metrics.IncrementTotalErrorCount()
		return err
	}

	// The deployed-policies map, not the OPA store, is what decision requests are
	// validated against - so a policy missing from the map is undecidable however
	// well the upsert went. Report the deployment as failed and let PAP retry;
	// re-deploying the same name and version is idempotent.
	if _, err := policymap.UpdateDeployedPoliciesinMap(policy); err != nil {
		metrics.IncrementDeployFailureCount()
		metrics.IncrementTotalErrorCount()
		return fmt.Errorf("failed to record deployment of %s in the deployed policies map: %v", policy.Name, err)
	}

	successPolicies[policy.Name] = policy.Version
	metrics.IncrementDeploySuccessCount()
	log.Debugf("Loaded Policy: %s", policy.Name)
	return nil
}

// checks if policy exists in the map.
func checkIfPolicyAlreadyDeployed(pdpUpdate model.PdpUpdate) []model.ToscaPolicy {
	deployedPolicies := policymap.GetLastDeployedPolicies()
	if len(deployedPolicies) > 0 {
		log.Debugf("Check if Policy is Already Deployed: %v", deployedPolicies)
		return policymap.VerifyAndReturnPoliciesToBeDeployed(deployedPolicies, pdpUpdate)
	}
	return pdpUpdate.PoliciesToBeDeployed
}

// verfies policy by creating bundle.
func verifyPolicyByBundleCreation(policy model.ToscaPolicy) error {
	// create bundle
	if err := createBundleFuncVar(); err != nil {
		log.Warnf("Failed to initialize bundle for %s: %v", policy.Name, err)
		cleanupPolicyFiles(policy)
		log.Debugf("Directory cleanup as bundle creation failed")
		return err
	}
	return nil
}

// handles Upsert func for policy and data
func upsertPolicyAndData(policy model.ToscaPolicy, successPolicies map[string]string) error {
	if err := upsertPolicyFunc(policy); err != nil {
		log.Warnf("Failed to upsert policy: %v", err)
		return fmt.Errorf("failed to Insert Policy: %s: %v", policy.Name, err)
	}

	if err := upsertDataFunc(policy); err != nil {
		return fmt.Errorf("failed to Write Data: %s: %v", policy.Name, err)
	}

	return nil
}

// validates whether new policy is parent of the existing policy
func validateParentPolicy(policy model.ToscaPolicy) (bool, error) {
	policiesmap, err := policymap.UnmarshalLastDeployedPolicies(policymap.GetLastDeployedPolicies())
	if err != nil {
		log.Warnf("Failed to extract deployed policies: %v", err)
		return false, err
	}

	policyAllowed, err := utils.IsPolicyNameAllowed(policy, policiesmap)

	if err != nil {
		log.Warnf("Tosca Policy Id validation failed for policy nameas it is a parent folder:%s, %v", policy.Name, err)
		return false, err
	}

	if err := validatePolicyNesting(policy); err != nil {
		log.Warnf("Nested policy validation failed for policy %s: %v", policy.Name, err)
		return false, err
	}
	return policyAllowed, nil

}

// validatePolicyNesting makes sure a deployment cannot replace the rules or the data of a
// policy that is already deployed, whatever order parent and child arrive in.
func validatePolicyNesting(policy model.ToscaPolicy) error {
	deployed, err := policymap.GetDeployedPolicyDetails()
	if err != nil {
		return err
	}
	if err := utils.ValidateKeyOwnership(policy, policymap.PolicyNames(deployed)); err != nil {
		return err
	}
	return validateDataAgainstDeployed(policy, policymap.WithoutPolicy(deployed, policy.Name))
}

// validateDataAgainstDeployed checks the content of the policy's data against the data the
// other deployed policies hold
func validateDataAgainstDeployed(policy model.ToscaPolicy, others []policymap.DeployedPolicy) error {
	otherDataKeys := policymap.DataKeysByPolicy(others)
	occupiedItems := policymap.DataItemsByPolicy(others)
	for _, dataKey := range slices.Sorted(maps.Keys(policy.Properties.Data)) {
		if err := utils.ValidateDataKeyNotOccupied(dataKey, occupiedItems); err != nil {
			return err
		}
		items := dataItemNames(policy.Properties.Data[dataKey])
		if err := utils.ValidateDataItemsAvailable(dataKey, items, otherDataKeys); err != nil {
			return err
		}
	}
	return nil
}

// dataItemNames returns the top-level items of base64 encoded JSON data.
func dataItemNames(encodedData string) []string {
	decoded, err := base64.StdEncoding.DecodeString(encodedData)
	if err != nil {
		return nil
	}
	return utils.TopLevelItemNames(string(decoded))
}

// deployedDataKeysOfOthers returns the data keys of the deployed policies other than the
// named one. If the deployed policies cannot be read, nothing is reported as nested
func deployedDataKeysOfOthers(policyName string) map[string][]string {
	deployed, err := policymap.GetDeployedPolicyDetails()
	if err != nil {
		log.Warnf("Could not read the deployed policies to protect nested data: %v", err)
		return nil
	}
	return policymap.DataKeysByPolicy(policymap.WithoutPolicy(deployed, policyName))
}

func writePolicyData(keyPath, dataKey string, data interface{}, otherDataKeys map[string][]string) error {
	keepFolders := nestedFolders(dataKey, otherDataKeys)
	if len(keepFolders) == 0 {
		return opasdk.WriteDataVar(context.Background(), keyPath, data)
	}
	log.Debugf("Keeping the data of nested policies %v while writing %s", keepFolders, dataKey)
	return opasdk.WriteDataKeepingFoldersVar(context.Background(), keyPath, data, keepFolders)
}

// nestedFolders returns the outermost data folders of other policies that lie below the data key.
func nestedFolders(dataKey string, dataKeysByPolicy map[string][]string) [][]string {
	keyPath := utils.DataKeySegments(dataKey)
	var folders [][]string
	for _, policyName := range slices.Sorted(maps.Keys(dataKeysByPolicy)) {
		for _, otherKey := range dataKeysByPolicy[policyName] {
			otherPath := utils.DataKeySegments(otherKey)
			if len(otherPath) > len(keyPath) && utils.HasSegmentPrefix(otherPath, keyPath) {
				folders = append(folders, otherPath)
			}
		}
	}
	return utils.TopmostPaths(folders)
}

// verifyPolicyAgainstLiveModules compiles the policy's rules together with the policies that
// are live, in memory, so that a rule or package clash is found before anything is stored.
func verifyPolicyAgainstLiveModules(policy model.ToscaPolicy) error {
	decodedPolicies, _, err := extractAndDecodePoliciesVar(policy)
	if err != nil {
		return err
	}
	return opasdk.CompileWithLiveModulesVar(context.Background(), decodedPolicies)
}

type ownFile struct {
	path    string
	stopDir string
}

type previousFile struct {
	content []byte
	existed bool
}

type fileBackup map[string]previousFile

var (
	fileBackupsMu sync.Mutex
	// fileBackups keeps the backup of each policy that is being deployed, by policy name.
	fileBackups = map[string]fileBackup{}
)

func policyFilePath(policyKey string) string {
	return filepath.Join(basePolicyDir, filepath.Join(strings.Split(policyKey, ".")...), "policy.rego")
}

func dataFilePath(dataKey string) string {
	return filepath.Join(baseDataDir, filepath.Join(strings.Split(dataKey, ".")...), "data.json")
}

// ownFiles lists the files of this policy only: one policy.rego per policy key and one
// data.json per data key. Files of nested policies are never in the list.
func ownFiles(policy model.ToscaPolicy) []ownFile {
	files := make([]ownFile, 0, len(policy.Properties.Policy)+len(policy.Properties.Data))
	for _, key := range slices.Sorted(maps.Keys(policy.Properties.Policy)) {
		files = append(files, ownFile{path: policyFilePath(key), stopDir: basePolicyDir})
	}
	dataStopDir := filepath.Join(baseDataDir, filepath.Base(consts.DataNode))
	for _, key := range slices.Sorted(maps.Keys(policy.Properties.Data)) {
		files = append(files, ownFile{path: dataFilePath(key), stopDir: dataStopDir})
	}
	return files
}

// backupPolicyFiles remembers the content of the files this deployment is about to write
func backupPolicyFiles(policy model.ToscaPolicy) {
	backup := make(fileBackup)
	for _, file := range ownFiles(policy) {
		content, err := os.ReadFile(file.path)
		backup[file.path] = previousFile{content: content, existed: err == nil}
	}
	fileBackupsMu.Lock()
	defer fileBackupsMu.Unlock()
	fileBackups[policy.Name] = backup
}

func takeFileBackup(policyName string) fileBackup {
	fileBackupsMu.Lock()
	defer fileBackupsMu.Unlock()
	backup := fileBackups[policyName]
	delete(fileBackups, policyName)
	return backup
}

func discardFileBackup(policyName string) {
	takeFileBackup(policyName)
}

// cleanupPolicyFiles undoes the files of a failed deployment
func cleanupPolicyFiles(policy model.ToscaPolicy) {
	backup := takeFileBackup(policy.Name)
	for _, file := range ownFiles(policy) {
		if err := restoreOrRemoveFile(file, backup); err != nil {
			log.Errorf("Error cleaning up file %s for policy %s: %v", file.path, policy.Name, err)
		}
	}
}

func restoreOrRemoveFile(file ownFile, backup fileBackup) error {
	if previous, ok := backup[file.path]; ok && previous.existed {
		return os.WriteFile(file.path, previous.content, 0600)
	}
	err := utils.RemoveFileAndEmptyParents(file.path, file.stopDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
