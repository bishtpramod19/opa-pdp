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

package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"policy-opa-pdp/pkg/model"
	"policy-opa-pdp/pkg/model/oapicodegen"
	"testing"
	"time"

	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Positive Test Case: Valid UUIDs
func TestIsValidUUIDPositive(t *testing.T) {
	// Define valid UUID strings
	validUUIDs := []string{
		"123e4567-e89b-12d3-a456-426614174000", // Standard UUID
		uuid.New().String(),                    // Dynamically generated UUID
	}

	for _, u := range validUUIDs {
		t.Run("Valid UUID", func(t *testing.T) {
			if !IsValidUUID(u) {
				t.Errorf("Expected valid UUID, but got invalid for %s", u)
			}
		})
	}
}

// Negative Test Case: Invalid UUIDs
func TestIsValidUUIDNegative(t *testing.T) {
	// Define invalid UUID strings
	invalidUUIDs := []string{
		"123e4567-e89b-12d3-a456-42661417400",  // Invalid: missing character at the end
		"invalid-uuid-format",                  // Invalid: incorrect format
		"123e4567-e89b-12d3-a456-42661417400x", // Invalid: contains extra non-hex character
		" ",                                    // Invalid: empty string
	}

	for _, u := range invalidUUIDs {
		t.Run("Invalid UUID", func(t *testing.T) {
			if IsValidUUID(u) {
				t.Errorf("Expected invalid UUID, but got valid for %s", u)
			}
		})
	}
}

func TestCreateDirectory_Positive(t *testing.T) {
	tempDir := "testdir"
	defer func() { _ = os.RemoveAll(tempDir) }()

	err := CreateDirectory(tempDir)
	assert.NoError(t, err)
	assert.DirExists(t, tempDir)
}

func TestCreateDirectory_Negative(t *testing.T) {
	err := CreateDirectory("")
	assert.Error(t, err)
}

func TestRemoveDirectory_Positive(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "testdir")
	assert.NoError(t, err)

	filePath := filepath.Join(tempDir, "data.json")
	file, err := os.Create(filePath)
	assert.NoError(t, err)
	_ = file.Close()
	assert.FileExists(t, filePath, "File should exist before deletion")

	err = RemoveDirectory(tempDir)
	assert.NoError(t, err)
	_, err = os.Stat(filePath)
	assert.True(t, os.IsNotExist(err), "Fle should be removed")

}

func TestRemoveDirectory_Negative(t *testing.T) {
	nonExistentDirectory := filepath.Join(os.TempDir(), "non_existent_directory")

	err := RemoveDirectory(nonExistentDirectory)
	assert.NoError(t, err)
}

// Test removing a valid empty directory
func TestRemoveDirectory_ValidEmptyDir(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "testdir")
	assert.NoError(t, err)

	subDir := filepath.Join(tempDir, "emptysubDir")
	err = os.Mkdir(subDir, 0777)
	assert.NoError(t, err)
	err = RemoveDirectory(tempDir)
	assert.NoError(t, err, "Expected no error when removing an empty directory")

	_, err = os.Stat(subDir)
	assert.True(t, os.IsNotExist(err), "Expected directory to be deleted")

}

// Test removing a directory that does not exist
func TestRemoveDirectory_NonExistent(t *testing.T) {
	err := RemoveDirectory("/invalid/nonexistent/path")
	assert.NoError(t, err, "Expected no error when removing a non-existent directory")
}

// Test removing a directory containing only data.json and policy.rego
func TestRemoveDirectory_WithSpecificFiles(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "testdir")
	assert.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir) }()

	dataFile := tempDir + "/data.json"
	policyFile := tempDir + "/policy.rego"

	_ = os.WriteFile(dataFile, []byte("test"), 0644)
	_ = os.WriteFile(policyFile, []byte("test"), 0644)

	err = RemoveDirectory(tempDir)
	assert.NoError(t, err, "Expected no error when removing specific files")

	_, err = os.Stat(dataFile)
	assert.True(t, os.IsNotExist(err), "data.json should be deleted")

	_, err = os.Stat(policyFile)
	assert.True(t, os.IsNotExist(err), "policy.rego should be deleted")
}

func TestIsDirEmpty_Positive(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "testdir")
	assert.NoError(t, err)

	defer func() { _ = os.RemoveAll(tempDir) }()
	isEmpty, err := isDirEmpty(tempDir)
	assert.NoError(t, err)
	assert.True(t, isEmpty)
}

func TestIsDirEmpty_Negative(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "testdir")
	assert.NoError(t, err)

	defer func() { _ = os.RemoveAll(tempDir) }()
	filePath := filepath.Join(tempDir, "data.json")
	file, err := os.Create(filePath)
	assert.NoError(t, err)
	_ = file.Close()
	assert.FileExists(t, filePath, "File should exist before deletion")

	isEmpty, err := isDirEmpty(tempDir)
	assert.NoError(t, err)
	assert.False(t, isEmpty)
}

func TestIsDirEmpty_ValidNonEmptyDir(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "testdir")
	assert.NoError(t, err, "Expected temp directory to be created")
	defer func() { _ = os.RemoveAll(tempDir) }() // Cleanup

	_, err = os.CreateTemp(tempDir, "testfile")
	assert.NoError(t, err, "Expected test file to be created")

	isEmpty, err := isDirEmpty(tempDir)
	assert.NoError(t, err, "Expected no error when checking non-empty directory")
	assert.False(t, isEmpty, "Expected directory to be non-empty")
}

func TestIsDirEmpty_NonExistentDir(t *testing.T) {
	fakeDir := "/nonexistent/path"

	isEmpty, err := isDirEmpty(fakeDir)
	assert.Error(t, err, "Expected error when checking non-existent directory")
	assert.False(t, isEmpty, "Expected function to return false when directory does not exist")
}

func TestValidateFIeldsStructs_Positive(t *testing.T) {
	pdpupdate := model.PdpUpdate{Source: "pap-188b80c3-48de-43b2-a2cc-3d90fbedb373", PdpHeartbeatIntervalMs: 200000, PoliciesToBeDeployed: []model.ToscaPolicy{}, MessageType: "PDP_UPDATE", RequestId: "41e6f35c-35c9-4a64-b35e-cb0f1c5b15cc", TimestampMs: 1739269698262, Name: "opa-241cca97-89df-496f-8d87-2c6d7cd5b6d7", PdpGroup: "opaGroup", PdpSubgroup: "opa"}

	err := ValidateFieldsStructs(pdpupdate)
	assert.NoError(t, err)
}

func TestValidateFIeldsStructs_Negative(t *testing.T) {
	pdpupdate := model.PdpUpdate{Source: "pap-188b80c3-48de-43b2-a2cc-3d90fbedb373", PdpHeartbeatIntervalMs: 200000, PoliciesToBeDeployed: []model.ToscaPolicy{}, MessageType: "PDP_UPDATE", RequestId: "41e6f35c-35c9-4a64-b35e-cb0f1c5b15cc", TimestampMs: 1739269698262, Name: "opa-241cca97-89df-496f-8d87-2c6d7cd5b6d7", PdpGroup: "opaGroup"}

	err := ValidateFieldsStructs(pdpupdate)
	assert.Error(t, err)
}

// Positive test cases for IsPolicyNameAllowed
func TestIsPolicyNameAllowed_Positive(t *testing.T) {
	policy := model.ToscaPolicy{Name: "policy.test"}
	deployedPolicies := []map[string]interface{}{{"policy-id": "different.policy"}}

	allowed, err := IsPolicyNameAllowed(policy, deployedPolicies)
	assert.True(t, allowed)
	assert.NoError(t, err)
}

// Nested policies are allowed: a child name is accepted when its parent is already deployed
func TestIsPolicyNameAllowed_Negative(t *testing.T) {
	policy := model.ToscaPolicy{Name: "policy.test"}
	deployedPolicies := []map[string]interface{}{{"policy-id": "policy"}}

	allowed, err := IsPolicyNameAllowed(policy, deployedPolicies)
	assert.True(t, allowed)
	assert.NoError(t, err)
}

func TestIsPolicyNameAllowed_ParentOfExistingPolicy(t *testing.T) {
	policy := model.ToscaPolicy{Name: "test.policy"}

	deployedPolicies := []map[string]interface{}{
		{"policy-id": "test.policy.1"},
	}

	allowed, err := IsPolicyNameAllowed(policy, deployedPolicies)
	assert.NoError(t, err)
	assert.True(t, allowed, "Expected a parent policy to be allowed when its child is already deployed")
}

func TestIsPolicyNameAllowed_ChildOfExistingPolicy(t *testing.T) {
	policy := model.ToscaPolicy{Name: "test.policy.1.1"}

	deployedPolicies := []map[string]interface{}{
		{"policy-id": "test.policy.1"},
	}

	allowed, err := IsPolicyNameAllowed(policy, deployedPolicies)
	assert.NoError(t, err)
	assert.True(t, allowed, "Expected a child policy to be allowed when its parent is already deployed")
}

func TestIsPolicyNameAllowed_NoDeployedPolicies(t *testing.T) {
	policy := model.ToscaPolicy{Name: "test.policy.1"}

	deployedPolicies := []map[string]interface{}{}

	allowed, err := IsPolicyNameAllowed(policy, deployedPolicies)
	assert.NoError(t, err)
	assert.True(t, allowed, "Expected policy name to be allowed when no deployed policies exist")
}

func TestIsPolicyNameAllowed_EmptyPolicyName(t *testing.T) {
	policy := model.ToscaPolicy{Name: ""}

	deployedPolicies := []map[string]interface{}{
		{"policy-id": "test.policy.2"},
	}

	allowed, err := IsPolicyNameAllowed(policy, deployedPolicies)
	assert.Error(t, err)
	assert.False(t, allowed, "Expected policy name validation to fail")
	assert.Contains(t, err.Error(), "policy Name cannot be Empty")
}

// Positive test cases for isParentOfExistingPolicy
func TestIsParentOfExistingPolicy_Positive(t *testing.T) {
	parent := []string{"policy"}
	child := []string{"policy", "test"}

	result := isParentOfExistingPolicy(parent, child)
	assert.True(t, result)
}

// Negative test cases for isParentOfExistingPolicy
func TestIsParentOfExistingPolicy_Negative(t *testing.T) {
	parent := []string{"policy"}
	child := []string{"different", "test"}

	result := isParentOfExistingPolicy(parent, child)
	assert.False(t, result)
}

// Positive test cases for isChildOfExistingPolicy
func TestIsChildOfExistingPolicy_Positive(t *testing.T) {
	parent := []string{"policy"}
	child := []string{"policy", "test"}

	result := isChildOfExistingPolicy(child, parent)
	assert.True(t, result)
}

// Negative test cases for isChildOfExistingPolicy
func TestIsChildOfExistingPolicy_Negative(t *testing.T) {
	parent := []string{"policy"}
	child := []string{"different", "test"}

	result := isChildOfExistingPolicy(child, parent)
	assert.False(t, result)
}

// Positive test cases for ValidateToscaPolicyJsonFields
func TestValidateToscaPolicyJsonFields_Positive(t *testing.T) {
	policy := model.ToscaPolicy{
		Name:    "test-policy",
		Version: "1.0",
		Metadata: model.Metadata{
			PolicyID:      "test-policy",
			PolicyVersion: "1.0",
		},
		Properties: model.PolicyProperties{
			Data:   map[string]string{"node.test-policy": "value"},
			Policy: map[string]string{"test-policy-rule": "some_rule"},
		},
	}
	err := ValidateToscaPolicyJsonFields(policy)
	assert.NoError(t, err)
}

// Negative test cases for ValidateToscaPolicyJsonFields
func TestValidateToscaPolicyJsonFields_Negative(t *testing.T) {
	invalidPolicy := model.ToscaPolicy{
		Name:    "wrong-policy",
		Version: "1.0",
		Metadata: model.Metadata{
			PolicyID:      "test-policy",
			PolicyVersion: "1.0",
		},
	}
	err := ValidateToscaPolicyJsonFields(invalidPolicy)
	assert.Error(t, err)
}

func TestValidateToscaPolicyJsonFields_DuplicatePolicy(t *testing.T) {
	policy := model.ToscaPolicy{
		Name:    "cell.consistency",
		Version: "1.0",
		Metadata: model.Metadata{
			PolicyID:      "cell.consistency",
			PolicyVersion: "1.0",
		},
		Properties: model.PolicyProperties{
			Data:   map[string]string{"test-policy-key": "value"},
			Policy: map[string]string{"test-policy-rule": "some_rule"},
		},
	}

	policy.Properties.Policy["test-policy-rule"] = "duplicate-key-policy"

	err := ValidateToscaPolicyJsonFields(policy)
	assert.Error(t, err) // Expect an error due to missing fields
}

func TestValidateToscaPolicyJsonFields_DuplicateDataKey(t *testing.T) {
	policy := model.ToscaPolicy{
		Name:    "cell.consistency",
		Version: "1.0",
		Metadata: model.Metadata{
			PolicyID:      "cell.consistency",
			PolicyVersion: "1.0",
		},
		Properties: model.PolicyProperties{
			Data:   map[string]string{"test-policy-key": "value"},
			Policy: map[string]string{"test-policy-rule": "some_rule"},
		},
	}

	policy.Properties.Data["test-policy-key"] = "duplicatevalue"

	err := ValidateToscaPolicyJsonFields(policy)
	assert.Error(t, err) // Expect an error due to missing fields
}

func TestValidateToscaPolicyJsonFields_PolicyKeyName(t *testing.T) {
	policy := model.ToscaPolicy{
		Name:    "cell.consistency",
		Version: "1.0",
		Metadata: model.Metadata{
			PolicyID:      "cell.consistency",
			PolicyVersion: "1.0",
		},
		Properties: model.PolicyProperties{
			Data:   map[string]string{"test-policy-key": "value"},
			Policy: map[string]string{"test-policy-rule": "some_rule"},
		},
	}

	err := ValidateToscaPolicyJsonFields(policy)
	assert.Error(t, err) // Expect an error due to missing fields
}

func TestValidateToscaPolicyJsonFields_NameMismatch(t *testing.T) {
	policy := model.ToscaPolicy{
		Name:    "wrong-policy",
		Version: "1.0",
		Metadata: model.Metadata{
			PolicyID:      "test-policy",
			PolicyVersion: "1.0",
		},
	}

	err := ValidateToscaPolicyJsonFields(policy)
	assert.Error(t, err, "Expected error due to name mismatch")
	assert.Contains(t, err.Error(), "policy name 'wrong-policy' does not match metadata policy-id 'test-policy'")
}

func TestValidateToscaPolicyJsonFields_VersionMismatch(t *testing.T) {
	policy := model.ToscaPolicy{
		Name:    "test-policy",
		Version: "2.0",
		Metadata: model.Metadata{
			PolicyID:      "test-policy",
			PolicyVersion: "1.0",
		},
	}

	err := ValidateToscaPolicyJsonFields(policy)
	assert.Error(t, err, "Expected error due to version mismatch")
	assert.Contains(t, err.Error(), "policy version '2.0' does not match metadata policy-version '1.0'")
}

func TestValidateToscaPolicyJsonFields_InvalidDataKeyPrefix(t *testing.T) {
	policy := model.ToscaPolicy{
		Name:    "test-policy",
		Version: "1.0",
		Metadata: model.Metadata{
			PolicyID:      "test-policy",
			PolicyVersion: "1.0",
		},
		Properties: model.PolicyProperties{
			Data: map[string]string{
				"invalid-key": "value1",
			},
		},
	}

	err := ValidateToscaPolicyJsonFields(policy)
	assert.Error(t, err, "Expected error due to invalid data key prefix")
	assert.Contains(t, err.Error(), "data key 'invalid-key' does not have name 'node.test-policy' as a prefix, ")
}

func TestIsValidTime(t *testing.T) {
	now := time.Now()
	invalidTime := (*time.Time)(nil)

	if !IsValidTime(&now) {
		t.Errorf("Expected true for valid time")
	}
	if IsValidTime(invalidTime) {
		t.Errorf("Expected false for nil time")
	}
}

func TestIsValidTimeOffset(t *testing.T) {
	validOffsets := []string{"+02:00", "-05:00", "00:00"}
	invalidOffsets := []string{"25:00", "abc", "12:345", "-123:45", ""}

	for _, offset := range validOffsets {
		if !IsValidTimeOffset(&offset) {
			t.Errorf("Expected true for valid offset: %s", offset)
		}
	}

	for _, offset := range invalidOffsets {
		if IsValidTimeOffset(&offset) {
			t.Errorf("Expected false for invalid offset: %s", offset)
		}
	}
}

func TestIsValidTimeZone(t *testing.T) {
	validZones := []string{"America/New_York", "UTC", "Europe/London"}
	invalidZones := []string{"Invalid/Zone", "1234", "New_York/America", " "}

	for _, zone := range validZones {
		if !IsValidTimeZone(&zone) {
			t.Errorf("Expected true for valid time zone: %s", zone)
		}
	}

	for _, zone := range invalidZones {
		if IsValidTimeZone(&zone) {
			t.Errorf("Expected false for invalid time zone: %s", zone)
		}
	}
}

func TestIsValidData(t *testing.T) {
	validData := []map[string]interface{}{{"key": "value"}}
	invalidData := []map[string]interface{}{}

	if !IsValidData(&validData) {
		t.Errorf("Expected true for non-empty data")
	}
	if IsValidData(&invalidData) {
		t.Errorf("Expected false for empty data")
	}
}

func TestIsValidCurrentDate(t *testing.T) {
	validDates := []string{"2025-01-17", "1999-12-31", ""}
	invalidDates := []string{"20250117", "01-17-2025", "abcd-ef-gh"}

	for _, date := range validDates {
		if !IsValidCurrentDate(&date) {
			t.Errorf("Expected true for valid date: %s", date)
		}
	}

	for _, date := range invalidDates {
		if IsValidCurrentDate(&date) {
			t.Errorf("Expected false for invalid date: %s", date)
		}
	}
}

func TestIsValidCurrentTime(t *testing.T) {
	validTime := []string{"08:26:41.857Z", "12:35:55.873Z"}
	invalidTime := []string{"1:2:3:4", "", " "}

	for _, timeval := range validTime {
		if !IsValidCurrentTime(&timeval) {
			t.Errorf("Expected true for valid time: %s", timeval)
		}
	}

	for _, invalidt := range invalidTime {
		if IsValidCurrentTime(&invalidt) {
			t.Errorf("Expected false for invalid time: %s", invalidt)
		}
	}
}

func TestIsValidString(t *testing.T) {
	validStrings := []string{"test", "example"}
	invalidStrings := []string{"", " "}

	for _, str := range validStrings {
		if !IsValidString(&str) {
			t.Errorf("Expected true for valid string: %s", str)
		}
	}

	for _, str := range invalidStrings {
		if IsValidString(&str) {
			t.Errorf("Expected false for invalid string: %s", str)
		}
	}
}

// Test function for isSubDirEmpty using real directories
func TestIsSubDirEmpty(t *testing.T) {
	// Create a temporary directory for testing
	t.Run("Empty Directory - Should be removed", func(t *testing.T) {
		tempDir, err := os.MkdirTemp("", "emptyDir")
		require.NoError(t, err)

		// Call the function
		err = isSubDirEmpty(tempDir)

		// Assert no error and directory should be removed
		assert.NoError(t, err)
		_, err = os.Stat(tempDir)
		assert.True(t, os.IsNotExist(err)) // Directory should be gone
	})

	t.Run("Non-Empty Directory - Should not be removed", func(t *testing.T) {
		tempDir, err := os.MkdirTemp("", "nonEmptyDir")
		require.NoError(t, err)

		// Create a file inside to make the directory non-empty
		_, err = os.CreateTemp(tempDir, "file")
		require.NoError(t, err)

		// Call the function
		err = isSubDirEmpty(tempDir)

		// Assert directory still exists
		assert.NoError(t, err)
		_, err = os.Stat(tempDir)
		assert.NoError(t, err) // Directory should still exist

		// Clean up
		_ = os.RemoveAll(tempDir)
	})

	t.Run("Non-Existent Directory - Should return an error", func(t *testing.T) {
		tempDir := "/path/that/does/not/exist"

		err := isSubDirEmpty(tempDir)

		// Assert error
		assert.Error(t, err)
		// assert.True(t, os.IsNotExist(err))
	})

	t.Run("Error Removing Directory - Should return an error", func(t *testing.T) {
		// Create a temporary directory
		tempDir, err := os.MkdirTemp("", "errorDir")
		require.NoError(t, err)

		// Mock removeAll to return an error
		originalRemoveAll := removeAll
		defer func() { removeAll = originalRemoveAll }() // Restore after test

		removeAll = func(path string) error {
			return fmt.Errorf("failed to remove directory: %s", path)
		}

		err = isSubDirEmpty(tempDir)

		// Assert error
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to remove directory")

		// Clean up
		_ = os.RemoveAll(tempDir)
	})
}

// Helper function to create string pointers
func strPtr(s string) *string {
	return &s
}

func TestValidateOPADataRequest_UpdateRequest_Valid(t *testing.T) {

	parsedDate, err := time.Parse("2006-01-02", "2024-02-12")
	if err != nil {
		fmt.Println("error in parsedDate")
	}

	currentDate := openapi_types.Date{Time: parsedDate}
	currentDateTime, err := time.Parse(time.RFC3339, "2024-02-12T12:00:00Z")
	if err != nil {
		fmt.Println("error in currentDateTime")
	}
	ctime := "08:26:41.857Z"

	updateReq := &oapicodegen.OPADataUpdateRequest{
		CurrentDate:     &currentDate,
		CurrentDateTime: &currentDateTime,
		CurrentTime:     &ctime,
		TimeOffset:      strPtr("+00:00"),
		TimeZone:        strPtr("UTC"),
		OnapComponent:   strPtr("Component"),
		OnapInstance:    strPtr("Instance"),
		OnapName:        strPtr("Onap"),
		PolicyName:      "Policy1",
	}

	errors := ValidateOPADataRequest(updateReq)
	assert.Empty(t, errors, "Expected no validation errors")
}

func TestValidateOPADataRequest_UpdateRequest_MissingFields(t *testing.T) {
	updateReq := &oapicodegen.OPADataUpdateRequest{}

	errors := ValidateOPADataRequest(updateReq)
	assert.NotEmpty(t, errors, "Expected validation errors for missing fields")
}

func TestValidateOPADataRequest_DecisionRequest_Valid(t *testing.T) {
	parsedDate, err := time.Parse("2006-01-02", "2024-02-12")
	if err != nil {
		fmt.Println("error in parsedDate")
	}

	currentDate := openapi_types.Date{Time: parsedDate}
	currentDateTime, err := time.Parse(time.RFC3339, "2024-02-12T12:00:00Z")
	if err != nil {
		fmt.Println("error in currentDateTime")
	}
	ctime := "08:26:41.857Z"

	decisionReq := &oapicodegen.OPADecisionRequest{
		CurrentDate:     &currentDate,
		CurrentDateTime: &currentDateTime,
		CurrentTime:     &ctime,
		TimeOffset:      strPtr("+00:00"),
		TimeZone:        strPtr("UTC"),
		OnapComponent:   strPtr("Component"),
		OnapInstance:    strPtr("Instance"),
		OnapName:        strPtr("Onap"),
		PolicyName:      "Policy2",
	}

	errors := ValidateOPADataRequest(decisionReq)
	assert.Empty(t, errors, "Expected no validation errors")
}

func TestValidateOPADataRequest_DecisionRequest_MissingFields(t *testing.T) {
	decisionReq := &oapicodegen.OPADecisionRequest{}

	errors := ValidateOPADataRequest(decisionReq)
	assert.NotEmpty(t, errors, "Expected validation errors for missing fields")
}

func TestValidateOPADataRequest_InvalidRequestType(t *testing.T) {
	invalidReq := struct{}{}

	errors := ValidateOPADataRequest(invalidReq)
	assert.Equal(t, []string{"Invalid request type"}, errors, "Expected 'Invalid request type' error")
}

func TestConvertPtrToString(t *testing.T) {
	str := "test"
	assert.Equal(t, "test", convertPtrToString(&str), "Expected 'test' as output")
	assert.Equal(t, "", convertPtrToString(nil), "Expected empty string as output")
}

// Test validateKeys (unified policy and data key validator)
func TestValidateKeys(t *testing.T) {
	tests := []struct {
		name         string
		keys         map[string]string
		prefix       string
		propertyType string
		emphasize    string
		wantErr      string
	}{
		{
			name: "Valid policy keys",
			keys: map[string]string{
				"policy_1": "value1",
				"policy_2": "value2",
			},
			prefix:       "policy_",
			propertyType: "policy",
			emphasize:    "important",
			wantErr:      "",
		},
		{
			name: "Policy key without proper prefix",
			keys: map[string]string{
				"invalid_1": "value1",
			},
			prefix:       "policy_",
			propertyType: "policy",
			emphasize:    "important",
			wantErr:      "policy key 'invalid_1' does not have name 'policy_' as a prefix, 'important'",
		},
		{
			name:         "Empty policy map",
			keys:         map[string]string{},
			prefix:       "policy_",
			propertyType: "policy",
			emphasize:    "important",
			wantErr:      "",
		},
		{
			name: "Valid data keys",
			keys: map[string]string{
				"data_1": "value1",
				"data_2": "value2",
			},
			prefix:       "data_",
			propertyType: "data",
			emphasize:    "critical",
			wantErr:      "",
		},
		{
			name: "Data key without proper prefix",
			keys: map[string]string{
				"invalid_1": "value1",
			},
			prefix:       "data_",
			propertyType: "data",
			emphasize:    "critical",
			// Error message now includes emphasize (unified format)
			wantErr: "data key 'invalid_1' does not have name 'data_' as a prefix, 'critical'",
		},
		{
			name:         "Empty data map",
			keys:         map[string]string{},
			prefix:       "data_",
			propertyType: "data",
			emphasize:    "critical",
			wantErr:      "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateKeys(tt.keys, tt.prefix, tt.propertyType, tt.emphasize)
			if err != nil {
				if err.Error() != tt.wantErr {
					t.Errorf("Expected error: '%s', got: '%s'", tt.wantErr, err.Error())
				}
			} else if tt.wantErr != "" {
				t.Errorf("Expected error: '%s', got nil", tt.wantErr)
			}
		})
	}
}

// Test IsKeyOwnedByPolicy: ownership is judged on a dot boundary, not on plain text.
func TestIsKeyOwnedByPolicy(t *testing.T) {
	tests := []struct {
		name       string
		key        string
		policyName string
		want       bool
	}{
		{"Exact match", "onap.org.cell", "onap.org.cell", true},
		{"Direct child key", "onap.org.cell.consistency", "onap.org.cell", true},
		{"Deeply nested child key", "onap.org.cell.consistency.rules", "onap.org.cell", true},
		{"Data key exact match", "node.onap.org.cell", "node.onap.org.cell", true},
		{"Data child key", "node.onap.org.cell.consistency", "node.onap.org.cell", true},
		{"Look-alike sibling is not owned", "onap.org.cellular", "onap.org.cell", false},
		{"Look-alike child of sibling is not owned", "onap.org.cellular.x", "onap.org.cell", false},
		{"Hyphen suffix is not a dot boundary", "test-policy-rule", "test-policy", false},
		{"Parent key is not owned by its child", "onap.org.cell", "onap.org.cell.consistency", false},
		{"Unrelated key", "other.policy", "onap.org.cell", false},
		{"Trailing dot with nothing after it", "onap.org.cell.", "onap.org.cell", false},
		{"Empty key", "", "onap.org.cell", false},
		{"Empty policy name", "onap.org.cell", "", false},
		{"Both empty", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, IsKeyOwnedByPolicy(tt.key, tt.policyName))
		})
	}
}

func TestHasSegmentPrefix(t *testing.T) {
	assert.True(t, HasSegmentPrefix([]string{"node", "a", "b"}, []string{"node", "a"}))
	assert.True(t, HasSegmentPrefix([]string{"node", "a"}, []string{"node", "a"}))
	assert.True(t, HasSegmentPrefix([]string{"node"}, []string{}))
	assert.False(t, HasSegmentPrefix([]string{"node", "a"}, []string{"node", "a", "b"}))
	assert.False(t, HasSegmentPrefix([]string{"node", "cellular"}, []string{"node", "cell"}), "a longer name is not inside a shorter one")
}

// The owner of a key is the deployed policy with the longest matching name.
func TestFindKeyOwner(t *testing.T) {
	names := []string{"onap.org.cell", "onap.org.cell.consistency", "onap.org.cellular"}

	tests := []struct {
		name      string
		key       string
		keyPrefix string
		want      string
	}{
		{"Key of the parent", "onap.org.cell", "", "onap.org.cell"},
		{"Key of the child belongs to the child, not the parent", "onap.org.cell.consistency", "", "onap.org.cell.consistency"},
		{"Deeper key of the child", "onap.org.cell.consistency.rules", "", "onap.org.cell.consistency"},
		{"Key inside the parent but outside the child", "onap.org.cell.other", "", "onap.org.cell"},
		{"Look-alike sibling is its own owner", "onap.org.cellular", "", "onap.org.cellular"},
		{"Data key of the child", "node.onap.org.cell.consistency", DataKeyPrefix, "onap.org.cell.consistency"},
		{"Data key of the parent", "node.onap.org.cell", DataKeyPrefix, "onap.org.cell"},
		{"Key nobody owns", "other.policy", "", ""},
		{"Hyphenated key is nobody's", "onap.org.cell-v2", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, FindKeyOwner(tt.key, tt.keyPrefix, names))
		})
	}
}

func newNestedTestPolicy(name string, policyKeys, dataKeys []string) model.ToscaPolicy {
	policy := model.ToscaPolicy{Name: name}
	policy.Properties.Policy = map[string]string{}
	policy.Properties.Data = map[string]string{}
	for _, key := range policyKeys {
		policy.Properties.Policy[key] = "cG9saWN5"
	}
	for _, key := range dataKeys {
		policy.Properties.Data[key] = "e30="
	}
	return policy
}

// A deployment may only use keys that belong to itself; clashes name the owning policy.
func TestValidateKeyOwnership(t *testing.T) {
	tests := []struct {
		name     string
		policy   model.ToscaPolicy
		deployed []string
		wantErr  string
	}{
		{"No policy deployed", newNestedTestPolicy("onap.org.cell", []string{"onap.org.cell"}, []string{"node.onap.org.cell"}), nil, ""},
		{"Parent arrives after child, own keys only",
			newNestedTestPolicy("onap.org.cell", []string{"onap.org.cell"}, []string{"node.onap.org.cell"}),
			[]string{"onap.org.cell.consistency"}, ""},
		{"Child arrives after parent, own keys only",
			newNestedTestPolicy("onap.org.cell.consistency", []string{"onap.org.cell.consistency"}, []string{"node.onap.org.cell.consistency"}),
			[]string{"onap.org.cell"}, ""},
		{"Parent submits a policy key that is the child's key",
			newNestedTestPolicy("onap.org.cell", []string{"onap.org.cell", "onap.org.cell.consistency"}, nil),
			[]string{"onap.org.cell.consistency"},
			"policy key 'onap.org.cell.consistency' of policy 'onap.org.cell' belongs to deployed policy 'onap.org.cell.consistency'"},
		{"Parent adds a module inside the child's package",
			newNestedTestPolicy("onap.org.cell", []string{"onap.org.cell", "onap.org.cell.consistency.extra"}, nil),
			[]string{"onap.org.cell.consistency"},
			"belongs to deployed policy 'onap.org.cell.consistency'"},
		{"Parent submits a data key that is the child's data key",
			newNestedTestPolicy("onap.org.cell", []string{"onap.org.cell"}, []string{"node.onap.org.cell", "node.onap.org.cell.consistency"}),
			[]string{"onap.org.cell.consistency"},
			"data key 'node.onap.org.cell.consistency' of policy 'onap.org.cell' belongs to deployed policy 'onap.org.cell.consistency'"},
		{"Policy submits the key of a look-alike sibling",
			newNestedTestPolicy("onap.org.cell", []string{"onap.org.cell", "onap.org.cellular"}, nil),
			[]string{"onap.org.cellular"},
			"policy key 'onap.org.cellular' of policy 'onap.org.cell' belongs to deployed policy 'onap.org.cellular'"},
		{"Hyphenated key of an unrelated name is still accepted",
			newNestedTestPolicy("test-policy", []string{"test-policy-rule"}, []string{"node.test-policy"}),
			[]string{"other"}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateKeyOwnership(tt.policy, tt.deployed)
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestTopLevelItemNames(t *testing.T) {
	assert.Equal(t, []string{"a", "b"}, TopLevelItemNames(`{"b":1,"a":{"x":2}}`))
	assert.Empty(t, TopLevelItemNames(`{}`), "an empty object has no items")
	assert.Nil(t, TopLevelItemNames(`[1,2]`), "an array has no named items")
	assert.Nil(t, TopLevelItemNames(`"text"`))
	assert.Nil(t, TopLevelItemNames(`{not json`))
}

// Content clash: a data item of the parent must not land on the child's data.
func TestValidateDataItemsAvailable(t *testing.T) {
	other := map[string][]string{"onap.org.cell.consistency": {"node.onap.org.cell.consistency"}}

	t.Run("Item named like the child's folder is rejected", func(t *testing.T) {
		err := ValidateDataItemsAvailable("node.onap.org.cell", []string{"threshold", "consistency"}, other)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "data item 'consistency' of data key 'node.onap.org.cell' would replace the data of deployed policy 'onap.org.cell.consistency'")
	})
	t.Run("Items that do not touch the child are accepted", func(t *testing.T) {
		assert.NoError(t, ValidateDataItemsAvailable("node.onap.org.cell", []string{"threshold", "limits"}, other))
	})
	t.Run("A longer item name is not the child's folder", func(t *testing.T) {
		assert.NoError(t, ValidateDataItemsAvailable("node.onap.org.cell", []string{"consistency2"}, other))
	})
	t.Run("A child without data keys cannot be clashed with", func(t *testing.T) {
		assert.NoError(t, ValidateDataItemsAvailable("node.onap.org.cell", []string{"consistency"}, map[string][]string{"onap.org.cell.consistency": {}}))
	})
	t.Run("An item above a deeper child is rejected too", func(t *testing.T) {
		deep := map[string][]string{"onap.org.cell.consistency.rules": {"node.onap.org.cell.consistency.rules"}}
		assert.Error(t, ValidateDataItemsAvailable("node.onap.org.cell", []string{"consistency"}, deep))
	})
	t.Run("No other policy", func(t *testing.T) {
		assert.NoError(t, ValidateDataItemsAvailable("node.onap.org.cell", []string{"consistency"}, nil))
	})
}

// Content clash the other way round: a child must not be written where the parent already has an item.
func TestValidateDataKeyNotOccupied(t *testing.T) {
	occupied := map[string]map[string][]string{
		"onap.org.cell": {"node.onap.org.cell": {"threshold", "consistency"}},
	}

	t.Run("Child folder is already an item of the parent", func(t *testing.T) {
		err := ValidateDataKeyNotOccupied("node.onap.org.cell.consistency", occupied)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "data key 'node.onap.org.cell.consistency' is already used by data item 'node.onap.org.cell.consistency' of deployed policy 'onap.org.cell'")
	})
	t.Run("Deeper key below the occupied item is rejected too", func(t *testing.T) {
		assert.Error(t, ValidateDataKeyNotOccupied("node.onap.org.cell.consistency.rules", occupied))
	})
	t.Run("Free folder is accepted", func(t *testing.T) {
		assert.NoError(t, ValidateDataKeyNotOccupied("node.onap.org.cell.other", occupied))
	})
	t.Run("Look-alike folder is accepted", func(t *testing.T) {
		assert.NoError(t, ValidateDataKeyNotOccupied("node.onap.org.cell.consistency2", occupied))
	})
	t.Run("Nothing recorded", func(t *testing.T) {
		assert.NoError(t, ValidateDataKeyNotOccupied("node.onap.org.cell.consistency", nil))
	})
}

func TestChildPolicyNames(t *testing.T) {
	deployed := []string{"onap.org.cell.consistency", "onap.org.cell", "onap.org.cellular", "onap.org.cell.consistency.rules", "onap.org.cell.a", "other"}

	assert.Equal(t,
		[]string{"onap.org.cell.consistency.rules", "onap.org.cell.a", "onap.org.cell.consistency"},
		ChildPolicyNames("onap.org.cell", deployed), "deepest first, look-alike and the parent itself left out")
	assert.Equal(t, []string{"onap.org.cell.consistency.rules"}, ChildPolicyNames("onap.org.cell.consistency", deployed))
	assert.Empty(t, ChildPolicyNames("onap.org.cell.consistency.rules", deployed))
	assert.Empty(t, ChildPolicyNames("other", deployed))
}

func TestTopmostPaths(t *testing.T) {
	paths := [][]string{{"node", "a", "b"}, {"node", "a"}, {"node", "c"}, {"node", "c"}, {"node", "d", "e"}}

	assert.Equal(t, [][]string{{"node", "a"}, {"node", "c"}, {"node", "d", "e"}}, TopmostPaths(paths))
	assert.Empty(t, TopmostPaths(nil))
}

// Only the file asked for is removed; folders are pruned only while they are empty.
func TestRemoveFileAndEmptyParents(t *testing.T) {
	root := t.TempDir()
	write := func(relative string) string {
		full := filepath.Join(root, relative)
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0750))
		require.NoError(t, os.WriteFile(full, []byte("x"), 0600))
		return full
	}
	exists := func(relative string) bool {
		_, err := os.Stat(filepath.Join(root, relative))
		return err == nil
	}

	t.Run("Parent policy file leaves the child's file and folders alone", func(t *testing.T) {
		parent := write("onap/org/cell/policy.rego")
		write("onap/org/cell/consistency/policy.rego")

		require.NoError(t, RemoveFileAndEmptyParents(parent, root))

		assert.False(t, exists("onap/org/cell/policy.rego"))
		assert.True(t, exists("onap/org/cell/consistency/policy.rego"), "the child's file must survive")
	})
	t.Run("Empty folders are removed up to, but not including, the stop folder", func(t *testing.T) {
		only := write("solo/deep/er/policy.rego")

		require.NoError(t, RemoveFileAndEmptyParents(only, root))

		assert.False(t, exists("solo"), "emptied folders are removed")
		assert.True(t, exists(""), "the stop folder is kept")
	})
	t.Run("A folder shared with another policy is kept", func(t *testing.T) {
		mine := write("shared/mine/policy.rego")
		write("shared/theirs/policy.rego")

		require.NoError(t, RemoveFileAndEmptyParents(mine, root))

		assert.False(t, exists("shared/mine"))
		assert.True(t, exists("shared/theirs/policy.rego"))
	})
	t.Run("A missing file is not an error", func(t *testing.T) {
		assert.NoError(t, RemoveFileAndEmptyParents(filepath.Join(root, "never", "was", "here.rego"), root))
	})
	t.Run("A failing removal is reported", func(t *testing.T) {
		original := removeFile
		defer func() { removeFile = original }()
		removeFile = func(string) error { return fmt.Errorf("disk error") }

		err := RemoveFileAndEmptyParents(filepath.Join(root, "x", "policy.rego"), root)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "disk error")
	})
}

// Patch: which policy's data a path is.
func TestOtherPolicyHoldingPath(t *testing.T) {
	others := map[string][]string{"onap.org.cell.consistency": {"node.onap.org.cell.consistency"}, "onap.org.cellular": {"node.onap.org.cellular"}}
	own := []string{"node.onap.org.cell"}

	assert.Equal(t, "onap.org.cell.consistency", OtherPolicyHoldingPath([]string{"node", "onap", "org", "cell", "consistency", "limit"}, own, others),
		"a path inside the child's data is the child's, not the parent's")
	assert.Equal(t, "onap.org.cell.consistency", OtherPolicyHoldingPath([]string{"node", "onap", "org", "cell", "consistency"}, own, others))
	assert.Equal(t, "", OtherPolicyHoldingPath([]string{"node", "onap", "org", "cell", "threshold"}, own, others), "the parent's own data")
	assert.Equal(t, "", OtherPolicyHoldingPath([]string{"node", "onap", "org", "cell", "consistency2"}, own, others), "a longer name is not the child's folder")
	assert.Equal(t, "", OtherPolicyHoldingPath([]string{"node", "onap", "org", "cell", "consistency", "limit"},
		[]string{"node.onap.org.cell.consistency"}, others), "the child itself may change its own data")
	assert.Equal(t, "", OtherPolicyHoldingPath([]string{"node", "a"}, nil, nil))
}

func TestOtherPolicyUnderPath(t *testing.T) {
	others := map[string][]string{"onap.org.cell.consistency": {"node.onap.org.cell.consistency"}}

	assert.Equal(t, "onap.org.cell.consistency", OtherPolicyUnderPath([]string{"node", "onap", "org", "cell", "consistency"}, others), "exactly the child's folder")
	assert.Equal(t, "onap.org.cell.consistency", OtherPolicyUnderPath([]string{"node", "onap", "org", "cell"}, others), "a path above the child covers it")
	assert.Equal(t, "", OtherPolicyUnderPath([]string{"node", "onap", "org", "cell", "threshold"}, others))
	assert.Equal(t, "", OtherPolicyUnderPath([]string{"node", "onap", "org", "cell", "consistency", "limit"}, others), "inside the child is not above it")
}
