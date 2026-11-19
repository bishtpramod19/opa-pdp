// -
//   ========================LICENSE_START=================================
//   Copyright (C) 2024-2026: Deutsche Telekom
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

// Package provides common  functionalities

package utils

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"policy-opa-pdp/consts"
	"policy-opa-pdp/pkg/log"
	"policy-opa-pdp/pkg/model"
	"policy-opa-pdp/pkg/model/oapicodegen"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

type (
	CreateDirectoryFunc       func(dirPath string) error
	ValidateFieldsStructsFunc func(pdpUpdate model.PdpUpdate) error
)

var (
	CreateDirectoryVar       CreateDirectoryFunc       = CreateDirectory
	removeAll                                          = os.RemoveAll
	removeFile                                         = os.Remove
	ValidateFieldsStructsVar ValidateFieldsStructsFunc = ValidateFieldsStructs
)

// validates if the given request is in valid uuid form
func IsValidUUID(u string) bool {
	_, err := uuid.Parse(u)
	return err == nil
}

// Helper function to create a directory if it doesn't exist
func CreateDirectory(dirPath string) error {
	err := os.MkdirAll(dirPath, 0750)
	if err != nil {
		log.Errorf("Failed to create directory %s: %v", dirPath, err)
		return err
	}
	log.Infof("Directory created: %s", dirPath)
	return nil
}

// Helper function to check and remove a directory
func RemoveDirectory(dirPath string) error {

	fileDirPath := filepath.Clean(dirPath)
	err := removeAll(fileDirPath)
	if err != nil {
		return fmt.Errorf("failed to remove file: %s, error: %w", fileDirPath, err)
	}

	// Create a loop to check parent directories.
	// Move to the parent directory
	currentPath := filepath.Clean(filepath.Dir(dirPath))
	for {
		// Check if we have reached the match path
		if currentPath == filepath.Clean(consts.DataNode) || currentPath == filepath.Clean(consts.Policies) {
			return nil // Stop if we reach the match path
		}

		if currentPath == "/" || currentPath == "." {
			log.Infof("Reached root orelative path: %s", currentPath)
			return nil // Stop if we reach the match path
		}
		log.Infof("Processig Parent dir : %s", currentPath)
		// Check if the parent directory exists before proceeding
		if _, err := os.Stat(currentPath); os.IsNotExist(err) {
			log.Debugf("directory does not exist: %s. Stopping iteration.", currentPath)
			return nil // Stop if we can't find the parent path
		}
		// Clean the parent directory
		err = isSubDirEmpty(currentPath)
		if err != nil {
			return err
		}

		// Move to the parent directory
		currentPath = filepath.Dir(currentPath)
	}
}

func isSubDirEmpty(entryPath string) error {

	isEmpty, err := isDirEmpty(entryPath)
	if err != nil {
		return err
	}
	if isEmpty {
		log.Debugf("Removing empty subdirectory: %s", entryPath)
		if err := removeAll(entryPath); err != nil {
			return fmt.Errorf("failed to remove directory: %s, error: %w", entryPath, err)
		}
	}
	return nil
}

// Helper function to check if a directory is empty
func isDirEmpty(dirPath string) (bool, error) {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return false, fmt.Errorf("failed to read directory: %s, error: %w", dirPath, err)
	}
	return len(entries) == 0, nil
}

func ValidateFieldsStructs(pdpUpdate model.PdpUpdate) error {
	//Initialize Validator and validate Struct after unmarshalling
	validate := validator.New()

	err := validate.Struct(pdpUpdate)
	if err != nil {
		if verrs, ok := err.(validator.ValidationErrors); ok {
			for _, fe := range verrs {
				log.Infof("Field %s failed on the %s tag", fe.Field(), fe.Tag())
			}
		}
		return err
	}
	return err
}

// Validate validates the fields based on your requirements.
func ValidateToscaPolicyJsonFields(policy model.ToscaPolicy) error {
	// 1. Validate that Name, Version, and Metadata fields match.
	emphasize := "Validation emphasizes the condition"
	if policy.Name != policy.Metadata.PolicyID {
		return fmt.Errorf("policy name '%s' does not match metadata policy-id '%s', '%s'", policy.Name, policy.Metadata.PolicyID, emphasize)
	}
	if policy.Version != policy.Metadata.PolicyVersion {
		return fmt.Errorf("policy version '%s' does not match metadata policy-version '%s', '%s'", policy.Version, policy.Metadata.PolicyVersion, emphasize)
	}

	if policy.Properties.Data != nil {
		log.Debugf("Validating properties data for policy: %s", policy.Name)
		if err := validateKeys(policy.Properties.Data, "node."+policy.Name, "data", emphasize); err != nil {
			return err
		}
	}

	log.Debugf("Validating properties policy for policy: %s", policy.Name)
	if err := validateKeys(policy.Properties.Policy, policy.Name, "policy", emphasize); err != nil {
		return err
	}

	log.Infof("Validation successful for policy: %s", policy.Name)
	return nil
}

func validateKeys(keys map[string]string, prefix, propertyType, emphasize string) error {
	for key := range keys {
		if !strings.HasPrefix(key, prefix) {
			return fmt.Errorf("%s key '%s' does not have name '%s' as a prefix, '%s'", propertyType, key, prefix, emphasize)
		}
	}
	return nil
}

func IsKeyOwnedByPolicy(key, policyName string) bool {
	if key == "" || policyName == "" {
		return false
	}
	if key == policyName {
		return true
	}
	return strings.HasPrefix(key, policyName+".") && len(key) > len(policyName)+1
}

const DataKeyPrefix = "node."

func HasSegmentPrefix(path, prefix []string) bool {
	if len(prefix) > len(path) {
		return false
	}
	for index := range prefix {
		if path[index] != prefix[index] {
			return false
		}
	}
	return true
}

func DataKeySegments(dataKey string) []string {
	return strings.Split(dataKey, ".")
}

// FindKeyOwner returns the deployed policy a key belongs to
func FindKeyOwner(key, keyPrefix string, policyNames []string) string {
	owner := ""
	for _, name := range policyNames {
		if len(name) > len(owner) && IsKeyOwnedByPolicy(key, keyPrefix+name) {
			owner = name
		}
	}
	return owner
}

func ValidateKeyOwnership(policy model.ToscaPolicy, deployedNames []string) error {
	names := append(append(make([]string, 0, len(deployedNames)+1), deployedNames...), policy.Name)
	if err := checkKeysBelongToPolicy(policy.Properties.Policy, "", "policy", policy.Name, names); err != nil {
		return err
	}
	return checkKeysBelongToPolicy(policy.Properties.Data, DataKeyPrefix, "data", policy.Name, names)
}

func checkKeysBelongToPolicy(keys map[string]string, keyPrefix, propertyType, policyName string, names []string) error {
	for _, key := range slices.Sorted(maps.Keys(keys)) {
		owner := FindKeyOwner(key, keyPrefix, names)
		if owner != "" && owner != policyName {
			return fmt.Errorf("%s key '%s' of policy '%s' belongs to deployed policy '%s'; a policy may only use keys under its own name", propertyType, key, policyName, owner)
		}
	}
	return nil
}

// TopLevelItemNames returns the sorted names of the top-level items of a JSON object
// It returns no items when the content is not a JSON object or has no items.
func TopLevelItemNames(jsonContent string) []string {
	var object map[string]json.RawMessage
	if err := json.Unmarshal([]byte(jsonContent), &object); err != nil {
		return nil
	}
	return slices.Sorted(maps.Keys(object))
}

// ValidateDataItemsAvailable makes sure none of the top-level items of a data key sits
// on, or above, the data of another deployed policy. Such an item would replace that
// policy's data when it is written.
func ValidateDataItemsAvailable(dataKey string, items []string, otherDataKeys map[string][]string) error {
	keyPath := DataKeySegments(dataKey)
	for _, item := range slices.Sorted(slices.Values(items)) {
		itemPath := append(append(make([]string, 0, len(keyPath)+1), keyPath...), item)
		if owner := findPolicyAtOrBelow(itemPath, otherDataKeys); owner != "" {
			return fmt.Errorf("data item '%s' of data key '%s' would replace the data of deployed policy '%s'", item, dataKey, owner)
		}
	}
	return nil
}

// findPolicyAtOrBelow returns a policy that has a data key at, or below, path ("" if none).
func findPolicyAtOrBelow(path []string, dataKeysByPolicy map[string][]string) string {
	for _, policyName := range slices.Sorted(maps.Keys(dataKeysByPolicy)) {
		for _, dataKey := range dataKeysByPolicy[policyName] {
			if HasSegmentPrefix(DataKeySegments(dataKey), path) {
				return policyName
			}
		}
	}
	return ""
}

// ValidateDataKeyNotOccupied makes sure a data key is not already taken by a top-level
// data item of another deployed policy. Writing it would replace that item.
func ValidateDataKeyNotOccupied(dataKey string, occupiedItems map[string]map[string][]string) error {
	policyName, occupiedPath := findOccupier(DataKeySegments(dataKey), occupiedItems)
	if policyName != "" {
		return fmt.Errorf("data key '%s' is already used by data item '%s' of deployed policy '%s'", dataKey, strings.Join(occupiedPath, "."), policyName)
	}
	return nil
}

func findOccupier(keyPath []string, occupiedItems map[string]map[string][]string) (string, []string) {
	for _, policyName := range slices.Sorted(maps.Keys(occupiedItems)) {
		if occupiedPath := findOccupiedPath(keyPath, occupiedItems[policyName]); occupiedPath != nil {
			return policyName, occupiedPath
		}
	}
	return "", nil
}

func findOccupiedPath(keyPath []string, itemsByDataKey map[string][]string) []string {
	for _, deployedKey := range slices.Sorted(maps.Keys(itemsByDataKey)) {
		for _, item := range itemsByDataKey[deployedKey] {
			occupiedPath := append(DataKeySegments(deployedKey), item)
			if HasSegmentPrefix(keyPath, occupiedPath) {
				return occupiedPath
			}
		}
	}
	return nil
}

// OtherPolicyHoldingPath returns another policy whose data holds the path more closely than
// the policy's own data does
func OtherPolicyHoldingPath(path []string, ownDataKeys []string, otherDataKeys map[string][]string) string {
	ownDepth := 0
	for _, dataKey := range ownDataKeys {
		segments := DataKeySegments(dataKey)
		if HasSegmentPrefix(path, segments) {
			ownDepth = max(ownDepth, len(segments))
		}
	}
	for _, policyName := range slices.Sorted(maps.Keys(otherDataKeys)) {
		for _, dataKey := range otherDataKeys[policyName] {
			segments := DataKeySegments(dataKey)
			if len(segments) > ownDepth && HasSegmentPrefix(path, segments) {
				return policyName
			}
		}
	}
	return ""
}

// OtherPolicyUnderPath returns another policy that has data at, or below, the path
func OtherPolicyUnderPath(path []string, otherDataKeys map[string][]string) string {
	return findPolicyAtOrBelow(path, otherDataKeys)
}

// ChildPolicyNames returns the deployed policies nested under parentName, deepest first,
// so that callers can process children before their parent.
func ChildPolicyNames(parentName string, deployedNames []string) []string {
	children := make([]string, 0)
	for _, name := range deployedNames {
		if name != parentName && IsKeyOwnedByPolicy(name, parentName) {
			children = append(children, name)
		}
	}
	sort.Strings(children)
	sort.Stable(ByDotCount{Keys: children, Ascend: false})
	return children
}

// TopmostPaths drops every path that lies inside another path of the list, and repeated
// paths, so that only the outermost folders remain.
func TopmostPaths(paths [][]string) [][]string {
	topmost := make([][]string, 0, len(paths))
	for index, path := range paths {
		if !isCoveredByAnotherPath(index, path, paths) {
			topmost = append(topmost, path)
		}
	}
	return topmost
}

func isCoveredByAnotherPath(index int, path []string, paths [][]string) bool {
	for otherIndex, other := range paths {
		if otherIndex == index || !HasSegmentPrefix(path, other) {
			continue
		}
		if len(other) < len(path) || otherIndex < index {
			return true
		}
	}
	return false
}

// RemoveFileAndEmptyParents removes one file and then every parent folder that became
// empty, the files of other
// policies are never touched.
func RemoveFileAndEmptyParents(filePath, stopDir string) error {
	if err := removeFile(filePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to remove file: %s, error: %w", filePath, err)
	}
	return removeEmptyParents(filepath.Dir(filePath), filepath.Clean(stopDir))
}

func removeEmptyParents(dir, stopDir string) error {
	for current := filepath.Clean(dir); isStrictlyInside(current, stopDir); current = filepath.Dir(current) {
		gone, err := removeDirIfEmpty(current)
		if err != nil {
			return err
		}
		if !gone {
			return nil
		}
	}
	return nil
}

func removeDirIfEmpty(dir string) (bool, error) {
	isEmpty, err := isDirEmpty(dir)
	if errors.Is(err, os.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if !isEmpty {
		return false, nil
	}
	if err := removeFile(dir); err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("failed to remove directory: %s, error: %w", dir, err)
	}
	return true, nil
}

func isStrictlyInside(dir, root string) bool {
	relative, err := filepath.Rel(root, dir)
	if err != nil || relative == "." || relative == ".." {
		return false
	}
	return !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func IsPolicyNameAllowed(policy model.ToscaPolicy, deployedPolicies []map[string]interface{}) (bool, error) {

	policyID := policy.Name

	if policyID == "" {
		return false, fmt.Errorf("policy Name cannot be Empty")
	}

	policyHierarchyLevel := strings.Split(policyID, ".")

	for _, deployedPolicy := range deployedPolicies {
		deployedPolicyID, ok := deployedPolicy["policy-id"].(string)
		if !ok {
			return false, fmt.Errorf("invalid or missing policy-id field")
		}

		deployedPolicyIDHierarchyLevel := strings.Split(deployedPolicyID, ".")

		if isParentOfExistingPolicy(policyHierarchyLevel, deployedPolicyIDHierarchyLevel) {
			log.Debugf("Policy-id: %s is the parent of deployed policy: %s, nested policies are allowed", policyID, deployedPolicyID)
		}

		if isChildOfExistingPolicy(policyHierarchyLevel, deployedPolicyIDHierarchyLevel) {
			log.Debugf("Policy-id: %s is a child of deployed policy: %s, nested policies are allowed", policyID, deployedPolicyID)
		}

	}

	return true, nil
}

func isParentOfExistingPolicy(policyHierarchyLevel, deployedPolicyIDHierarchyLevel []string) bool {

	// new policy should have fewer levels than deployed policy to be a parent
	if len(policyHierarchyLevel) < len(deployedPolicyIDHierarchyLevel) {
		for policyNameIndex := range policyHierarchyLevel {
			if policyHierarchyLevel[policyNameIndex] != deployedPolicyIDHierarchyLevel[policyNameIndex] {
				return false
			}
		}
		return true

	}

	return false
}

func isChildOfExistingPolicy(policyHierarchyLevel, deployedPolicyIDHierarchyLevel []string) bool {

	// new policy should have more levels than deployed policy to be a  child
	if len(policyHierarchyLevel) > len(deployedPolicyIDHierarchyLevel) {
		for policyNameIndex := range deployedPolicyIDHierarchyLevel {
			if deployedPolicyIDHierarchyLevel[policyNameIndex] != policyHierarchyLevel[policyNameIndex] {
				return false
			}
		}
		return true

	}

	return false
}

// Custom validation function for time format
func IsValidTime(t *time.Time) bool {
	if t == nil {
		return false
	}
	// Format the time in RFC3339 and try parsing it
	formattedTime := t.Format(time.RFC3339)
	// Check if the time is a valid date
	_, err := time.Parse(time.RFC3339, formattedTime)
	return err == nil
}

// Custom validation function for time offset format (e.g., '02:00', '-05:00')
func IsValidTimeOffset(offset *string) bool {
	if offset == nil || strings.TrimSpace(*offset) == "" {
		return false
	}
	re := regexp.MustCompile(`^[-+]?(0\d|1\d|2[0-3]):[0-5]\d$`) // Format like 02:00, -05:00
	return re.MatchString(*offset)
}

// Custom validation function for IANA time zone format (e.g., 'America/New_York')
func IsValidTimeZone(zone *string) bool {
	if zone == nil || strings.TrimSpace(*zone) == "" {
		return false
	}
	_, err := time.LoadLocation(*zone) // Check if it's a real timezone
	if err != nil {
		return false
	}
	re := regexp.MustCompile(`^(?:[A-Za-z]+(?:/[A-Za-z_]+)?|UTC([+-]\d{1,2}:?\d{2})?|[A-Za-z]{3,4})$`) //^(?:[A-Za-z]/[A-Za-z_]|UTC)$`) // Simple check for time zone format like 'America/New_York' or UTC etc
	return re.MatchString(*zone)
}

// Custom validation function for data input
func IsValidData(data *[]map[string]interface{}) bool {
	if data == nil || len(*data) == 0 {
		return false
	} else {
		return true
	}
}

// Custom validation function for CurrentDate
func IsValidCurrentDate(currentDate *string) bool {
	if currentDate == nil || strings.TrimSpace(*currentDate) == "" {
		return true
	}
	re := regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`) //  eg: "2025-01-17"
	return re.MatchString(*currentDate)
}

// Custom validation function for CurrentTime
func IsValidCurrentTime(currentTime *string) bool {
	if currentTime == nil || strings.TrimSpace(*currentTime) == "" {
		return false
	}
	re := regexp.MustCompile(`^\d{2}:\d{2}:\d{2}\.\d{3}Z$`) //eg: 08:26:41.857Z
	return re.MatchString(*currentTime)
}

// Custom validation function for *string type eg: OnapComponent, OnapInstance, OnapName, PolicyName
func IsValidString(name interface{}) bool {
	switch v := name.(type) {
	case *string:
		return v != nil && strings.TrimSpace(*v) != ""
	case string:
		return strings.TrimSpace(v) != ""
	default:
		return false // Handles cases where name is neither a string nor a *string
	}
}

type CommonFields struct {
	CurrentDate     *string
	CurrentDateTime *time.Time
	CurrentTime     *string
	TimeOffset      *string
	TimeZone        *string
	OnapComponent   *string
	OnapInstance    *string
	OnapName        *string
	PolicyName      string
}

func ValidateOPADataRequest(request interface{}) []string {
	//	var validationErrors []string

	if request == nil {
		return []string{"Request is nil"}
	}

	// Handle OPADataUpdateRequest validation
	if updateReq, ok := request.(*oapicodegen.OPADataUpdateRequest); ok {
		currentDate := ""
		if updateReq.CurrentDate != nil {
			currentDate = updateReq.CurrentDate.String()
		}

		commonFields := CommonFields{
			CurrentDate:     &currentDate,
			CurrentDateTime: updateReq.CurrentDateTime,
			CurrentTime:     updateReq.CurrentTime,
			TimeOffset:      updateReq.TimeOffset,
			TimeZone:        updateReq.TimeZone,
			OnapComponent:   updateReq.OnapComponent,
			OnapInstance:    updateReq.OnapInstance,
			OnapName:        updateReq.OnapName,
			PolicyName:      updateReq.PolicyName,
		}
		return validateCommonFields(commonFields)

	}

	// Handle OPADecisionRequest validation
	if decisionReq, ok := request.(*oapicodegen.OPADecisionRequest); ok {
		currentDate := ""
		if decisionReq.CurrentDate != nil {
			currentDate = decisionReq.CurrentDate.String()
		}

		commonFields := CommonFields{
			CurrentDate:     &currentDate,
			CurrentDateTime: decisionReq.CurrentDateTime,
			CurrentTime:     decisionReq.CurrentTime,
			TimeOffset:      decisionReq.TimeOffset,
			TimeZone:        decisionReq.TimeZone,
			OnapComponent:   decisionReq.OnapComponent,
			OnapInstance:    decisionReq.OnapInstance,
			OnapName:        decisionReq.OnapName,
			PolicyName:      decisionReq.PolicyName,
		}
		return validateCommonFields(commonFields)

	}
	return []string{"Invalid request type"}
}

func convertPtrToString(stringPtr *string) string {
	if stringPtr != nil {
		return *stringPtr
	}
	return ""

}

// Helper function to validate common fields
func validateCommonFields(fields CommonFields) []string {

	var validationErrors []string

	if fields.CurrentDate != nil && !IsValidCurrentDate(fields.CurrentDate) {
		validationErrors = append(validationErrors, "CurrentDate is invalid")
	}
	if fields.CurrentDateTime != nil && !IsValidTime(fields.CurrentDateTime) {
		validationErrors = append(validationErrors, "CurrentDateTime is invalid")
	}
	if fields.CurrentTime != nil && !IsValidCurrentTime(fields.CurrentTime) {
		validationErrors = append(validationErrors, "CurrentTime is invalid")
	}
	if fields.TimeOffset != nil && !IsValidTimeOffset(fields.TimeOffset) {
		validationErrors = append(validationErrors, "TimeOffset is invalid")
	}
	if fields.TimeZone != nil && !IsValidTimeZone(fields.TimeZone) {
		validationErrors = append(validationErrors, "TimeZone is invalid")
	}
	if !IsValidString(fields.PolicyName) {
		validationErrors = append(validationErrors, "PolicyName is required and cannot be empty")
	}

	return validationErrors
}
