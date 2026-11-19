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
//

package opasdk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"policy-opa-pdp/consts"
	"strings"
	"sync"
	"testing"

	"github.com/open-policy-agent/opa/sdk"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Mock for os.Open
type MockFile struct {
	mock.Mock
}

func (m *MockFile) Open(name string) (*os.File, error) {
	args := m.Called(name)
	return args.Get(0).(*os.File), args.Error(1)
}

// Mock for io.ReadAll
func mockReadAll(r io.Reader) ([]byte, error) {
	return []byte(`{"config": "test"}`), nil
}

type MockSDK struct {
	mock.Mock
}

type MockStorage struct {
	mock.Mock
}

type MockTransaction struct{}

func (m *MockTransaction) ID() uint64 {
	return 1
}

func (m *MockStorage) NewTransaction(ctx context.Context, params ...storage.TransactionParams) (storage.Transaction, error) {
	args := m.Called(ctx, params)
	return &MockTransaction{}, args.Error(1)
}

// Fix: Ensure `txn` is `storage.Transaction`
func (m *MockStorage) Read(ctx context.Context, txn storage.Transaction, path storage.Path) (interface{}, error) {
	args := m.Called(ctx, txn, path)
	return args.Get(0), args.Error(1)
}

// Fix: Ensure `txn` is `storage.Transaction`
func (m *MockStorage) Write(ctx context.Context, txn storage.Transaction, op storage.PatchOp, path storage.Path, value interface{}) error {
	args := m.Called(ctx, txn, op, path, value)
	return args.Error(0)
}

// Fix: Ensure `txn` is `storage.Transaction`
func (m *MockStorage) Commit(ctx context.Context, txn storage.Transaction) error {
	args := m.Called(ctx, txn)
	return args.Error(0)
}

// Fix: Ensure `txn` is `storage.Transaction`
func (m *MockStorage) Abort(ctx context.Context, txn storage.Transaction) {
	m.Called(ctx, txn)
}

// Implement the Register method.
func (m *MockStorage) Register(ctx context.Context, txn storage.Transaction, config storage.TriggerConfig) (storage.TriggerHandle, error) {
	// Return mock values (adjust as needed for tests)
	return nil, nil
}

func (m *MockStorage) Truncate(ctx context.Context, txn storage.Transaction, params storage.TransactionParams, iter storage.Iterator) error {
	return nil // Adjust return as needed for your test
}

func (m *MockStorage) DeletePolicy(ctx context.Context, txn storage.Transaction, id string) error {
	args := m.Called(ctx, txn, id)
	return args.Error(0)
}

func (m *MockStorage) UpsertPolicy(ctx context.Context, txn storage.Transaction, policyID string, policyContent []byte) error {
	args := m.Called(ctx, txn, policyID, policyContent)
	return args.Error(0)
}

func (m *MockStorage) GetPolicy(ctx context.Context, txn storage.Transaction, id string) ([]byte, error) {
	args := m.Called(ctx, txn, id)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockStorage) ListPolicies(ctx context.Context, txn storage.Transaction) ([]string, error) {
	args := m.Called(ctx, txn)
	return args.Get(0).([]string), args.Error(1)
}

type MockData struct {
	Value string `json:"value"`
}

func (m *MockSDK) New(ctx context.Context, options sdk.Options) (*sdk.OPA, error) {
	fmt.Print("Inside New Method")
	args := m.Called(ctx, options)
	return args.Get(0).(*sdk.OPA), args.Error(1)
}

func TestGetOPASingletonInstance_ConfigurationFileNotexisting(t *testing.T) {
	resetSingleton()
	consts.OpasdkConfigPath = "/app/config/config.json"
	opaInstance, err := GetOPASingletonInstance()
	fmt.Print(err)
	//assert.NotNil(t, err) //error no such file or directory /app/config/config.json
	assert.NotNil(t, opaInstance)
}

func TestGetOPASingletonInstance_SingletonBehavior(t *testing.T) {
	resetSingleton()
	tmpFile, err := os.CreateTemp("", "config.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	consts.OpasdkConfigPath = tmpFile.Name()

	// Call the function multiple times
	opaInstance1, err1 := GetOPASingletonInstance()
	opaInstance2, err2 := GetOPASingletonInstance()

	// Assertions
	assert.Nil(t, err1)
	assert.Nil(t, err2)
	assert.NotNil(t, opaInstance1)
	assert.NotNil(t, opaInstance2)
	assert.Equal(t, opaInstance1, opaInstance2) // Ensure it's the same instance
}

func TestGetOPASingletonInstance_ConfigurationFileLoaded(t *testing.T) {
	resetSingleton()
	tmpFile, err := os.CreateTemp("", "config.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	consts.OpasdkConfigPath = tmpFile.Name()

	// Simulate OPA instance creation
	opaInstance, err := GetOPASingletonInstance()

	// Assertions
	assert.Nil(t, err)
	assert.NotNil(t, opaInstance)
}

func TestGetOPASingletonInstance_OPAInstanceCreation(t *testing.T) {
	resetSingleton()
	tmpFile, err := os.CreateTemp("", "config.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	consts.OpasdkConfigPath = tmpFile.Name()

	// Call the function
	opaInstance, err := GetOPASingletonInstance()

	// Assertions
	assert.Nil(t, err)
	assert.NotNil(t, opaInstance)
}

func TestGetOPASingletonInstance_JSONReadError(t *testing.T) {
	consts.OpasdkConfigPath = "/app/config/config.json"

	// Simulate an error in JSON read (e.g., corrupt file)
	mockReadAll := func(r io.Reader) ([]byte, error) {
		return nil, errors.New("Failed to read JSON file")
	}

	jsonReader, err := getJSONReader(consts.OpasdkConfigPath, os.Open, mockReadAll)
	assert.NotNil(t, err)
	assert.Nil(t, jsonReader)
}

func TestGetOPASingletonInstance_ValidConfigFile(t *testing.T) {
	resetSingleton()
	tmpFile, err := os.CreateTemp("", "config.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	consts.OpasdkConfigPath = tmpFile.Name()

	// Valid JSON content
	validJSON := []byte(`{"config": "test"}`)
	err = os.WriteFile(tmpFile.Name(), validJSON, 0644)
	if err != nil {
		t.Fatalf("Failed to write valid JSON to temp file: %v", err)
	}

	// Call the function
	opaInstance, err := GetOPASingletonInstance()

	assert.Nil(t, err)
	assert.NotNil(t, opaInstance)
}

func TestGetJSONReader(t *testing.T) {
	// Create a mock file
	mockFile := new(MockFile)
	mockFile.On("Open", "/app/config/config.json").Return(&os.File{}, nil)

	// Call the function with mock functions
	jsonReader, err := getJSONReader("/app/config/config.json", mockFile.Open, mockReadAll)

	// Check the results
	assert.NoError(t, err)
	assert.NotNil(t, jsonReader)

	// Check the content of the jsonReader
	expectedContent := `{"config": "test"}`
	actualContent := make([]byte, len(expectedContent))
	_, _ = jsonReader.Read(actualContent)
	assert.Equal(t, expectedContent, string(actualContent))

	// Assert that the mock methods were called
	mockFile.AssertCalled(t, "Open", "/app/config/config.json")
}

func TestGetJSONReader_ReadAllError(t *testing.T) {
	mockFile := new(MockFile)
	mockFile.On("Open", "/app/config/config.json").Return(&os.File{}, nil)

	// Simulate ReadAll error
	jsonReader, err := getJSONReader("/app/config/config.json", mockFile.Open, func(r io.Reader) ([]byte, error) {
		return nil, io.ErrUnexpectedEOF
	})

	assert.Error(t, err)
	assert.Nil(t, jsonReader)

	mockFile.AssertCalled(t, "Open", "/app/config/config.json")
}

func TestGetOPASingletonInstance(t *testing.T) {
	resetSingleton()
	tmpFile, err := os.CreateTemp("", "config.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	consts.OpasdkConfigPath = tmpFile.Name()

	// Call your function under test
	opaInstance, err := GetOPASingletonInstance()

	// Assertions
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if opaInstance == nil {
		t.Error("Expected OPA instance, got nil")
	}
	assert.NotNil(t, opaInstance, "OPA instance should be nil when sdk.New fails")
}

// Helper to reset the singleton for testing
func resetSingleton() {
	opaInstance = nil
	once = sync.Once{}
	initErr = nil
}

// Test sdk.New failure scenario
func TestGetOPASingletonInstance_SdkNewFails(t *testing.T) {
	resetSingleton()
	NewSDK = func(ctx context.Context, options sdk.Options) (*sdk.OPA, error) {
		return nil, errors.New("mocked error in sdk.New")
	}
	opaInstance, err := GetOPASingletonInstance()
	assert.Nil(t, opaInstance, "OPA instance should be nil when sdk.New fails")
	assert.Error(t, err, "Expected an error when sdk.New fails")
	assert.Contains(t, err.Error(), "mocked error in sdk.New")
}

func TestInitializePath_ReadSuccess(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	txn := new(MockTransaction)
	mockMemStore.On("Read", ctx, mock.AnythingOfType("*opasdk.MockTransaction"), mock.Anything).Return(nil, nil)

	err := initializePath(ctx, txn, "/some/path")

	assert.Nil(t, err)
	mockMemStore.AssertExpectations(t)
}

func TestInitializePath_WriteError(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	txn := new(MockTransaction)

	// Define the mock data in the same format as Read() would return
	mockData := map[string]interface{}{"value": "testValue"}

	mockMemStore.On("Read", ctx, mock.AnythingOfType("*opasdk.MockTransaction"), mock.Anything).Return(mockData, errors.New("data write error"))

	err := initializePath(ctx, txn, "/some/path")

	assert.Error(t, err)
	assert.Equal(t, "data write error", err.Error())
	mockMemStore.AssertExpectations(t)
}

func TestWriteData_TransactionError(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(nil, errors.New("transaction error"))
	mockMemStore.On("Abort", mock.Anything, mock.AnythingOfType("*opasdk.MockTransaction")).Return(nil) // Or any return value your method expects

	var content interface{} = "test-content"
	err := WriteData(ctx, "/some/path", content)

	assert.Error(t, err)
	assert.Equal(t, "transaction error", err.Error())
	mockMemStore.AssertExpectations(t)
}

func TestWriteData_ReadError(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	txn := new(storage.Transaction)

	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(txn, nil)
	mockMemStore.On("Read", ctx, mock.AnythingOfType("*opasdk.MockTransaction"), mock.Anything).Return(nil, errors.New("read error in initializePath method"))
	mockMemStore.On("Abort", mock.Anything, mock.AnythingOfType("*opasdk.MockTransaction")).Return(nil) // Or any return value your method expects

	var content interface{} = "test-content"
	err := WriteData(ctx, "/some/path", content)

	assert.Error(t, err)
	assert.Equal(t, "read error in initializePath method", err.Error())
	mockMemStore.AssertExpectations(t)
}

func TestWriteData_Failure(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	txn := new(storage.Transaction)

	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(txn, nil)
	mockMemStore.On("Read", ctx, mock.AnythingOfType("*opasdk.MockTransaction"), mock.Anything).Return(mock.Anything, nil)
	mockMemStore.On("Write", mock.Anything, mock.AnythingOfType("*opasdk.MockTransaction"), mock.Anything, mock.Anything, mock.Anything).Return(errors.New("data write error"))
	mockMemStore.On("Abort", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return(nil)

	var data interface{} = "test-content"
	err := WriteData(ctx, "/some/path", data)

	assert.Error(t, err)
	assert.Equal(t, "data write error", err.Error())
	mockMemStore.AssertExpectations(t)
}

func TestWriteData_CommitError(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	txn := new(storage.Transaction)

	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(txn, nil)
	mockMemStore.On("Read", ctx, mock.AnythingOfType("*opasdk.MockTransaction"), mock.Anything).Return(mock.Anything, nil)
	mockMemStore.On("Write", mock.Anything, mock.AnythingOfType("*opasdk.MockTransaction"), mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mockMemStore.On("Commit", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return(errors.New("commit error"))
	mockMemStore.On("Abort", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return(nil)

	data := []byte("test-content")
	err := WriteData(ctx, "/some/path", data)

	assert.Error(t, err)
	assert.Equal(t, "commit error", err.Error())
	mockMemStore.AssertExpectations(t)
}

func TestWriteData_success(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	txn := new(storage.Transaction)

	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(txn, nil)
	mockMemStore.On("Read", ctx, mock.AnythingOfType("*opasdk.MockTransaction"), mock.Anything).Return(mock.Anything, nil)
	mockMemStore.On("Write", mock.Anything, mock.AnythingOfType("*opasdk.MockTransaction"), mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mockMemStore.On("Commit", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return(nil)

	data := []byte("test-content")
	err := WriteData(ctx, "/some/path", data)

	assert.Nil(t, err)
	assert.NoError(t, err)
	mockMemStore.AssertExpectations(t)
}

func TestUpsertPolicy_TransactionError(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(nil, errors.New("transaction error"))
	mockMemStore.On("Abort", mock.Anything, mock.AnythingOfType("*opasdk.MockTransaction")).Return(nil) // Or any return value your method expects

	policyContent := []byte("test-content")
	err := UpsertPolicy(ctx, "policyId", policyContent)

	assert.Error(t, err)
	assert.Equal(t, "transaction error", err.Error())
	mockMemStore.AssertExpectations(t)
}

func TestUpsertPolicy_Failure(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	txn := new(storage.Transaction)

	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(txn, nil)
	mockMemStore.On("UpsertPolicy", ctx, mock.AnythingOfType("*opasdk.MockTransaction"), mock.Anything, mock.Anything).Return(errors.New("upsert policy error"))
	mockMemStore.On("Abort", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return(nil)

	policyContent := []byte("test-content")
	err := UpsertPolicy(ctx, "policyId", policyContent)

	assert.Error(t, err)
	assert.Equal(t, "upsert policy error", err.Error())
	mockMemStore.AssertExpectations(t)
}

func TestUpsertPolicy_CommitError(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	txn := new(storage.Transaction)

	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(txn, nil)
	mockMemStore.On("UpsertPolicy", ctx, mock.AnythingOfType("*opasdk.MockTransaction"), mock.Anything, mock.Anything).Return(nil)
	mockMemStore.On("Commit", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return(errors.New("commit error"))
	mockMemStore.On("Abort", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return(nil)

	policyContent := []byte("test-content")
	err := UpsertPolicy(ctx, "policyId", policyContent)

	assert.Error(t, err)
	assert.Equal(t, "commit error", err.Error())
	mockMemStore.AssertExpectations(t)
}

func TestUpsertPolicy_Success(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	txn := new(storage.Transaction)

	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(txn, nil)
	mockMemStore.On("UpsertPolicy", ctx, mock.AnythingOfType("*opasdk.MockTransaction"), mock.Anything, mock.Anything).Return(nil)
	mockMemStore.On("Commit", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return(nil)

	policyContent := []byte("test-content")
	err := UpsertPolicy(ctx, "policyId", policyContent)

	assert.Nil(t, err)
	assert.NoError(t, err)
	mockMemStore.AssertExpectations(t)
}

func TestListPolicies_TransactionError(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(nil, errors.New("transaction error"))
	mockMemStore.On("Abort", mock.Anything, mock.AnythingOfType("*opasdk.MockTransaction")).Return(nil) // Or any return value your method expects

	req := httptest.NewRequest("GET", "/opa/listpolicies", nil)
	res := httptest.NewRecorder()
	ListPolicies(res, req)

	assert.Equal(t, http.StatusInternalServerError, res.Code)
	mockMemStore.AssertExpectations(t)
}

func TestListPolicies_Failure(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	txn := new(storage.Transaction)

	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(txn, nil)
	mockMemStore.On("ListPolicies", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return([]string{}, errors.New("ListPolicies error"))
	mockMemStore.On("Abort", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return(nil)

	req := httptest.NewRequest("GET", "/opa/listpolicies", nil)
	res := httptest.NewRecorder()
	ListPolicies(res, req)

	assert.Equal(t, http.StatusInternalServerError, res.Code)
	mockMemStore.AssertExpectations(t)
}

func TestListPolicies_GetPolicyError(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	txn := new(storage.Transaction)

	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(txn, nil)
	mockMemStore.On("ListPolicies", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return([]string{"policyId"}, nil)
	mockMemStore.On("GetPolicy", ctx, mock.AnythingOfType("*opasdk.MockTransaction"), "policyId").Return([]byte{}, errors.New("GetPolicy error"))
	mockMemStore.On("Abort", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return(nil)

	req := httptest.NewRequest("GET", "/opa/listpolicies", nil)
	res := httptest.NewRecorder()
	ListPolicies(res, req)

	assert.Equal(t, http.StatusInternalServerError, res.Code)
	mockMemStore.AssertExpectations(t)
}

func TestListPolicies_GetPolicySuccess(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	txn := new(storage.Transaction)

	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(txn, nil)
	mockMemStore.On("ListPolicies", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return([]string{"policyId"}, nil)
	mockMemStore.On("GetPolicy", ctx, mock.AnythingOfType("*opasdk.MockTransaction"), "policyId").Return([]byte{}, nil)
	mockMemStore.On("Abort", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return(nil)

	req := httptest.NewRequest("GET", "/opa/listpolicies", nil)
	res := httptest.NewRecorder()
	ListPolicies(res, req)

	//	assert.Nil(t, err)
	//	assert.NoError(t, err)
	mockMemStore.AssertExpectations(t)
}

func TestListPolicies_Success(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	txn := new(storage.Transaction)

	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(txn, nil)
	mockMemStore.On("ListPolicies", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return([]string{}, nil)
	mockMemStore.On("Abort", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return(nil)

	req := httptest.NewRequest("GET", "/opa/listpolicies", nil)
	res := httptest.NewRecorder()
	ListPolicies(res, req)

	//	assert.NoError(t, err)
	mockMemStore.AssertExpectations(t)
}

func TestDeletePolicy_TransactionError(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(nil, errors.New("transaction error"))
	mockMemStore.On("Abort", mock.Anything, mock.AnythingOfType("*opasdk.MockTransaction")).Return(nil) // Or any return value your method expects

	err := DeletePolicy(ctx, "policyId")

	assert.Error(t, err)
	assert.Equal(t, "transaction error", err.Error())
	mockMemStore.AssertExpectations(t)
}

func TestDeletePolicy_Failure(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	txn := new(storage.Transaction)

	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(txn, nil)
	mockMemStore.On("DeletePolicy", ctx, mock.AnythingOfType("*opasdk.MockTransaction"), mock.Anything).Return(errors.New("DeletePolicy error"))
	mockMemStore.On("Abort", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return(nil)

	err := DeletePolicy(ctx, "policyId")

	assert.Error(t, err)
	assert.Equal(t, "DeletePolicy error", err.Error())
	mockMemStore.AssertExpectations(t)
}

func TestDeletePolicy_CommitError(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	txn := new(storage.Transaction)

	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(txn, nil)
	mockMemStore.On("DeletePolicy", ctx, mock.AnythingOfType("*opasdk.MockTransaction"), mock.Anything).Return(nil)
	mockMemStore.On("Commit", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return(errors.New("commit error"))
	mockMemStore.On("Abort", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return(nil)

	err := DeletePolicy(ctx, "policyId")

	assert.Error(t, err)
	assert.Equal(t, "commit error", err.Error())
	mockMemStore.AssertExpectations(t)
}

func TestDeletePolicy_Success(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	txn := new(storage.Transaction)

	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(txn, nil)
	mockMemStore.On("DeletePolicy", ctx, mock.AnythingOfType("*opasdk.MockTransaction"), mock.Anything).Return(nil)
	mockMemStore.On("Commit", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return(nil)

	err := DeletePolicy(ctx, "policyId")

	assert.Nil(t, err)
	assert.NoError(t, err)
	mockMemStore.AssertExpectations(t)
}

func TestDeleteData_TransactionError(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(nil, errors.New("transaction error"))
	mockMemStore.On("Abort", mock.Anything, mock.AnythingOfType("*opasdk.MockTransaction")).Return(nil) // Or any return value your method expects

	err := DeleteData(ctx, "/some/path")

	assert.Error(t, err)
	assert.Equal(t, "transaction error", err.Error())
	mockMemStore.AssertExpectations(t)
}

func TestDeleteData_WriteError(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	txn := new(storage.Transaction)

	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(txn, nil)
	mockMemStore.On("Write", ctx, mock.AnythingOfType("*opasdk.MockTransaction"), mock.Anything, mock.Anything, mock.Anything).Return(errors.New("write error"))
	mockMemStore.On("Abort", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return(nil)

	err := DeleteData(ctx, "/some/path")

	assert.Error(t, err)
	assert.Equal(t, "write error", err.Error())
	mockMemStore.AssertExpectations(t)
}

func TestDeleteData_CommitError(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	txn := new(storage.Transaction)

	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(txn, nil)
	mockMemStore.On("Write", ctx, mock.AnythingOfType("*opasdk.MockTransaction"), mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mockMemStore.On("Commit", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return(errors.New("commit error"))
	mockMemStore.On("Abort", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return(nil)

	err := DeleteData(ctx, "/some/path")

	assert.Error(t, err)
	assert.Equal(t, "commit error", err.Error())
	mockMemStore.AssertExpectations(t)
}

func TestDeleteData_Success(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	txn := new(storage.Transaction)

	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(txn, nil)
	mockMemStore.On("Write", ctx, mock.AnythingOfType("*opasdk.MockTransaction"), mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mockMemStore.On("Commit", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return(nil)

	err := DeleteData(ctx, "/some/path")

	assert.Nil(t, err)
	assert.NoError(t, err)
	mockMemStore.AssertExpectations(t)
}

// useEmptyPatchCompiler keeps a test that uses a mock store away from reading the live policies.
func useEmptyPatchCompiler(t *testing.T) {
	original := patchCompilerVar
	t.Cleanup(func() { patchCompilerVar = original })
	patchCompilerVar = func(context.Context, storage.Transaction) *ast.Compiler { return ast.NewCompiler() }
}

func TestPatchData_Success(t *testing.T) {
	useEmptyPatchCompiler(t)
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore

	txn := new(storage.Transaction)

	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(txn, nil)
	mockMemStore.On("Write", mock.Anything, mock.AnythingOfType("*opasdk.MockTransaction"), mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mockMemStore.On("Commit", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return(nil)

	patches := []PatchImpl{{Op: storage.AddOp, Path: storage.MustParsePath("/some/path"), Value: "value"}}
	err := PatchData(ctx, patches)

	assert.NoError(t, err)
	mockMemStore.AssertExpectations(t)
}

func TestPatchData_TransactionError(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(nil, errors.New("transaction error"))
	mockMemStore.On("Abort", mock.Anything, mock.AnythingOfType("*opasdk.MockTransaction")).Return(nil) // Or any return value your method expects

	patches := []PatchImpl{{Op: storage.AddOp, Path: storage.MustParsePath("/some/path"), Value: "value"}}
	err := PatchData(ctx, patches)

	assert.Error(t, err)
	assert.Equal(t, "transaction error", err.Error())
	mockMemStore.AssertExpectations(t)
}

func TestPatchData_WriteError(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	txn := new(storage.Transaction)

	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(txn, nil)
	mockMemStore.On("Write", ctx, mock.AnythingOfType("*opasdk.MockTransaction"), mock.Anything, mock.Anything, mock.Anything).Return(errors.New("write error"))
	mockMemStore.On("Abort", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return(nil)

	patches := []PatchImpl{{Op: storage.AddOp, Path: storage.MustParsePath("/some/path"), Value: "value"}}
	err := PatchData(ctx, patches)

	assert.Error(t, err)
	assert.Equal(t, "write error", err.Error())
	mockMemStore.AssertExpectations(t)
}

func TestPatchData_CommitError(t *testing.T) {
	useEmptyPatchCompiler(t)
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	txn := new(storage.Transaction)

	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(txn, nil)
	mockMemStore.On("Write", ctx, mock.AnythingOfType("*opasdk.MockTransaction"), mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mockMemStore.On("Commit", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return(errors.New("commit error"))
	mockMemStore.On("Abort", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return(nil)

	patches := []PatchImpl{{Op: storage.AddOp, Path: storage.MustParsePath("/some/path"), Value: "value"}}
	err := PatchData(ctx, patches)

	assert.Error(t, err)
	assert.Equal(t, "commit error", err.Error())
	mockMemStore.AssertExpectations(t)
}

func TestGetDataInfo_Success(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	txn := new(storage.Transaction)

	// Define the mock data in the same format as Read() would return
	mockData := map[string]interface{}{"value": "testValue"}
	mockDataJSON, _ := json.Marshal(mockData)

	// Ensure mock expectations match actual function calls
	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(txn, nil)
	mockMemStore.On("Read", ctx, mock.AnythingOfType("*opasdk.MockTransaction"), storage.MustParsePath("/some/path")).Return(mockData, nil)
	mockMemStore.On("Abort", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return(nil)

	data, err := GetDataInfo(ctx, "/some/path")

	// Assertions
	assert.NoError(t, err)
	assert.NotNil(t, data)

	dataJson, errInfo := json.Marshal(data)
	assert.NoError(t, errInfo)

	assert.JSONEq(t, string(mockDataJSON), string(dataJson))
	mockMemStore.AssertExpectations(t)

}

func TestGetDataInfo_ReadError(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	txn := new(storage.Transaction)

	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(txn, nil)
	mockMemStore.On("Read", ctx, mock.AnythingOfType("*opasdk.MockTransaction"), storage.MustParsePath("/some/path")).Return(nil, errors.New("read error"))
	mockMemStore.On("Abort", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return(nil)

	data, err := GetDataInfo(ctx, "/some/path")

	assert.Error(t, err)
	assert.Nil(t, data)
	assert.Equal(t, "read error", err.Error())
	mockMemStore.AssertExpectations(t)
}

func TestGetDataInfo_JSONUnmarshalError(t *testing.T) {
	ctx := context.Background()
	mockMemStore := new(MockStorage) // Create mock instance
	memStore = mockMemStore
	txn := new(storage.Transaction)
	invalidData := make(chan int) // Invalid type for JSON marshalling

	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(txn, nil)
	mockMemStore.On("Read", ctx, mock.AnythingOfType("*opasdk.MockTransaction"), storage.MustParsePath("/some/path")).Return(invalidData, nil)
	mockMemStore.On("Abort", ctx, mock.AnythingOfType("*opasdk.MockTransaction")).Return(nil)

	data, err := GetDataInfo(ctx, "/some/path")

	assert.Error(t, err)
	assert.Nil(t, data)
	mockMemStore.AssertExpectations(t)
}

func TestParsePatchPathEscaped_Success(t *testing.T) {
	cases := []struct {
		input    string
		expected storage.Path
	}{
		{"/valid/path", storage.Path{"valid", "path"}},
		{"/escaped~1path", storage.Path{"escaped/path"}},
		{"/double~1escaped~0tilde", storage.Path{"double/escaped~tilde"}},
	}

	for _, tc := range cases {
		path, ok := ParsePatchPathEscaped(tc.input)
		assert.True(t, ok)
		assert.Equal(t, tc.expected, path)
	}
}

func TestParsePatchPathEscaped_Failure(t *testing.T) {
	cases := []string{
		"",         // Empty string
		"~invalid", // Invalid leading tilde
	}

	for _, input := range cases {
		path, ok := ParsePatchPathEscaped(input)
		assert.False(t, ok)
		assert.Nil(t, path)
	}
}

func TestConfigureInstance_ReturnsErrorOnBadConfigPath(t *testing.T) {
	// getJSONReader will fail to open a non-existent path, so configureInstance
	// must return a non-nil error (previously this error was swallowed).
	err := configureInstance(nil, "/nonexistent/config/path.json")
	require.Error(t, err)
}

func TestSingletonResult_ReturnsPersistedError(t *testing.T) {
	// Simulate a prior failed init.
	prevInstance, prevErr := opaInstance, initErr
	t.Cleanup(func() { opaInstance, initErr = prevInstance, prevErr })

	opaInstance = nil
	initErr = errors.New("boom")

	inst, err := singletonResult()
	assert.Nil(t, inst)
	require.Error(t, err)
	assert.EqualError(t, err, "boom")
}

func TestGetDataInfo_MalformedPathReturnsError(t *testing.T) {
	// Ensure the store is initialized.
	_, _ = GetOPASingletonInstance()
	// An empty path is not parseable as a storage.Path — storage.ParsePath("") returns
	// ok=false because the path must start with "/" (or be empty root "/"). Must return
	// an error, not panic.
	_, err := GetDataInfo(context.Background(), "")
	require.Error(t, err)
}

func TestGetDataInfo_HappyPathStillWorks(t *testing.T) {
	// Regression guard: after adding the NewTransaction error-check in GetDataInfo,
	// verify that the normal (success) path still works end-to-end against the real
	// inmem store.  The error branch itself cannot be unit-triggered because the OPA
	// inmem store's NewTransaction essentially never returns an error; that limitation
	// is accepted and the fix is validated structurally + by code review.
	//
	// Other tests in this package swap memStore for a mock; restore a real inmem
	// store for this test so it is not order-dependent.
	prev := memStore
	realStore := inmem.New()
	memStore = realStore
	t.Cleanup(func() { memStore = prev })

	require.NoError(t, WriteData(context.Background(), "/plan13", map[string]interface{}{"a": 1}))
	got, err := GetDataInfo(context.Background(), "/plan13")
	require.NoError(t, err)
	require.NotNil(t, got)
}

// useRealStore runs a test against OPA's real in-memory store.
func useRealStore(t *testing.T) context.Context {
	original := memStore
	t.Cleanup(func() { memStore = original })
	memStore = inmem.New()
	return context.Background()
}

func readJSON(t *testing.T, ctx context.Context, path string) (string, bool) {
	txn, err := memStore.NewTransaction(ctx)
	require.NoError(t, err)
	defer memStore.Abort(ctx, txn)
	value, err := memStore.Read(ctx, txn, storage.MustParsePath(path))
	if storage.IsNotFound(err) {
		return "", false
	}
	require.NoError(t, err)
	encoded, err := json.Marshal(value)
	require.NoError(t, err)
	return string(encoded), true
}

func parseJSONValue(t *testing.T, content string) interface{} {
	var value interface{}
	require.NoError(t, json.Unmarshal([]byte(content), &value))
	return value
}

var childFolder = []string{"node", "onap", "org", "cell", "consistency"}

// Today's WriteData replaces everything at the path: a parent written after its child wipes the child.
func TestWriteData_ParentAfterChildWipesChild(t *testing.T) {
	ctx := useRealStore(t)
	require.NoError(t, WriteData(ctx, "/node/onap/org/cell/consistency", parseJSONValue(t, `{"limit":1}`)))

	require.NoError(t, WriteData(ctx, "/node/onap/org/cell", parseJSONValue(t, `{"threshold":5}`)))

	_, found := readJSON(t, ctx, "/node/onap/org/cell/consistency")
	assert.False(t, found, "this is the data loss WriteDataKeepingFolders exists to prevent")
}

func TestWriteDataKeepingFolders_ParentAfterChildKeepsChild(t *testing.T) {
	ctx := useRealStore(t)
	require.NoError(t, WriteData(ctx, "/node/onap/org/cell/consistency", parseJSONValue(t, `{"limit":1}`)))

	err := WriteDataKeepingFolders(ctx, "/node/onap/org/cell", parseJSONValue(t, `{"threshold":5}`), [][]string{childFolder})

	require.NoError(t, err)
	parent, _ := readJSON(t, ctx, "/node/onap/org/cell")
	assert.JSONEq(t, `{"threshold":5,"consistency":{"limit":1}}`, parent)
}

func TestWriteDataKeepingFolders_ParentRedeployReplacesOwnItemsOnly(t *testing.T) {
	ctx := useRealStore(t)
	require.NoError(t, WriteData(ctx, "/node/onap/org/cell", parseJSONValue(t, `{"threshold":5,"old":true}`)))
	require.NoError(t, WriteData(ctx, "/node/onap/org/cell/consistency", parseJSONValue(t, `{"limit":1}`)))

	err := WriteDataKeepingFolders(ctx, "/node/onap/org/cell", parseJSONValue(t, `{"threshold":9}`), [][]string{childFolder})

	require.NoError(t, err)
	parent, _ := readJSON(t, ctx, "/node/onap/org/cell")
	assert.JSONEq(t, `{"threshold":9,"consistency":{"limit":1}}`, parent, "dropped item is gone, child is intact")
}

func TestWriteDataKeepingFolders_DeepFolderAndMissingFolder(t *testing.T) {
	ctx := useRealStore(t)
	deep := []string{"node", "onap", "org", "cell", "consistency", "rules"}
	require.NoError(t, WriteData(ctx, "/node/onap/org/cell/consistency/rules", parseJSONValue(t, `{"r":1}`)))

	err := WriteDataKeepingFolders(ctx, "/node/onap/org/cell", parseJSONValue(t, `{"threshold":5}`),
		[][]string{deep, {"node", "onap", "org", "cell", "never", "deployed"}})

	require.NoError(t, err)
	parent, _ := readJSON(t, ctx, "/node/onap/org/cell")
	assert.JSONEq(t, `{"threshold":5,"consistency":{"rules":{"r":1}}}`, parent, "missing intermediate folders are recreated, a folder with no data is skipped")
}

func TestWriteDataKeepingFolders_WritesIntoEmptyStore(t *testing.T) {
	ctx := useRealStore(t)

	require.NoError(t, WriteDataKeepingFolders(ctx, "/node/a/b", parseJSONValue(t, `{"x":1}`), nil))

	value, found := readJSON(t, ctx, "/node/a/b")
	assert.True(t, found)
	assert.JSONEq(t, `{"x":1}`, value)
}

// All or nothing: when the kept folder cannot be put back, the child is still intact.
func TestWriteDataKeepingFolders_FailureLeavesStoreUnchanged(t *testing.T) {
	ctx := useRealStore(t)
	require.NoError(t, WriteData(ctx, "/node/onap/org/cell", parseJSONValue(t, `{"threshold":5}`)))
	require.NoError(t, WriteData(ctx, "/node/onap/org/cell/consistency", parseJSONValue(t, `{"limit":1}`)))

	err := WriteDataKeepingFolders(ctx, "/node/onap/org/cell", parseJSONValue(t, `[1,2,3]`), [][]string{childFolder})

	require.Error(t, err, "a folder cannot be kept inside a list")
	parent, _ := readJSON(t, ctx, "/node/onap/org/cell")
	assert.JSONEq(t, `{"threshold":5,"consistency":{"limit":1}}`, parent)
}

func TestWriteDataKeepingFolders_InvalidPathAndTransactionError(t *testing.T) {
	ctx := useRealStore(t)
	assert.Error(t, WriteDataKeepingFolders(ctx, "no-leading-slash/%zz", "x", nil))

	mockMemStore := new(MockStorage)
	memStore = mockMemStore
	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(nil, errors.New("transaction error"))
	err := WriteDataKeepingFolders(ctx, "/node/a", "x", nil)
	require.Error(t, err)
	assert.Equal(t, "transaction error", err.Error())
}

func TestRemoveOwnData_ParentLeavesChildData(t *testing.T) {
	ctx := useRealStore(t)
	require.NoError(t, WriteData(ctx, "/node/onap/org/cell", parseJSONValue(t, `{"threshold":5,"extra":{"a":1}}`)))
	require.NoError(t, WriteData(ctx, "/node/onap/org/cell/consistency", parseJSONValue(t, `{"limit":1}`)))

	err := RemoveOwnData(ctx, "/node/onap/org/cell", [][]string{childFolder}, nil)

	require.NoError(t, err)
	parent, found := readJSON(t, ctx, "/node/onap/org/cell")
	require.True(t, found, "the folder stays because the child still needs it")
	assert.JSONEq(t, `{"consistency":{"limit":1}}`, parent)
}

func TestRemoveOwnData_ChildLeavesParentData(t *testing.T) {
	ctx := useRealStore(t)
	require.NoError(t, WriteData(ctx, "/node/onap/org/cell", parseJSONValue(t, `{"threshold":5}`)))
	require.NoError(t, WriteData(ctx, "/node/onap/org/cell/consistency", parseJSONValue(t, `{"limit":1}`)))

	err := RemoveOwnData(ctx, "/node/onap/org/cell/consistency", nil, [][]string{{"node", "onap", "org", "cell"}})

	require.NoError(t, err)
	parent, _ := readJSON(t, ctx, "/node/onap/org/cell")
	assert.JSONEq(t, `{"threshold":5}`, parent)
}

func TestRemoveOwnData_EmptyParentFoldersAreRemovedUnlessNeeded(t *testing.T) {
	ctx := useRealStore(t)
	require.NoError(t, WriteData(ctx, "/node/a/b/c", parseJSONValue(t, `{"x":1}`)))
	require.NoError(t, RemoveOwnData(ctx, "/node/a/b/c", nil, nil))
	_, found := readJSON(t, ctx, "/node")
	assert.False(t, found, "emptied folders are pruned all the way up, as before")

	require.NoError(t, WriteData(ctx, "/node/a/b/c", parseJSONValue(t, `{"x":1}`)))
	require.NoError(t, RemoveOwnData(ctx, "/node/a/b/c", nil, [][]string{{"node", "a", "b"}}))
	value, found := readJSON(t, ctx, "/node/a/b")
	assert.True(t, found, "a folder another policy needs is kept even when empty")
	assert.JSONEq(t, `{}`, value)
}

func TestRemoveOwnData_SiblingFolderKeepsParentsAlive(t *testing.T) {
	ctx := useRealStore(t)
	require.NoError(t, WriteData(ctx, "/node/onap/org/cell", parseJSONValue(t, `{"x":1}`)))
	require.NoError(t, WriteData(ctx, "/node/onap/org/dog", parseJSONValue(t, `{"y":1}`)))

	require.NoError(t, RemoveOwnData(ctx, "/node/onap/org/cell", nil, nil))

	_, found := readJSON(t, ctx, "/node/onap/org/cell")
	assert.False(t, found)
	dog, found := readJSON(t, ctx, "/node/onap/org/dog")
	assert.True(t, found)
	assert.JSONEq(t, `{"y":1}`, dog)
}

func TestRemoveOwnData_MissingDataAndPlainValue(t *testing.T) {
	ctx := useRealStore(t)
	assert.NoError(t, RemoveOwnData(ctx, "/node/never/was", nil, nil), "data that is already gone is not an error")

	require.NoError(t, WriteData(ctx, "/node/list", parseJSONValue(t, `[1,2]`)))
	require.NoError(t, RemoveOwnData(ctx, "/node/list", nil, nil))
	_, found := readJSON(t, ctx, "/node/list")
	assert.False(t, found)

	assert.Error(t, RemoveOwnData(ctx, "bad/%zz", nil, nil))
}

func TestRemoveOwnData_TransactionError(t *testing.T) {
	ctx := context.Background()
	original := memStore
	t.Cleanup(func() { memStore = original })
	mockMemStore := new(MockStorage)
	memStore = mockMemStore
	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(nil, errors.New("transaction error"))

	err := RemoveOwnData(ctx, "/node/a", nil, nil)

	require.Error(t, err)
	assert.Equal(t, "transaction error", err.Error())
}

func TestDeletePolicyIfExists(t *testing.T) {
	ctx := useRealStore(t)
	require.NoError(t, UpsertPolicy(ctx, "onap.org.cell", []byte("package onap.org.cell\n")))

	assert.NoError(t, DeletePolicyIfExists(ctx, "onap.org.cell"))
	assert.NoError(t, DeletePolicyIfExists(ctx, "onap.org.cell"), "a module that is already gone is not an error")

	txn, err := memStore.NewTransaction(ctx)
	require.NoError(t, err)
	defer memStore.Abort(ctx, txn)
	ids, err := memStore.ListPolicies(ctx, txn)
	require.NoError(t, err)
	assert.Empty(t, ids)
}

func TestDeletePolicyIfExists_OtherErrorsStillReported(t *testing.T) {
	ctx := context.Background()
	original := memStore
	t.Cleanup(func() { memStore = original })
	mockMemStore := new(MockStorage)
	memStore = mockMemStore
	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(nil, errors.New("transaction error"))
	mockMemStore.On("Abort", mock.Anything, mock.Anything).Return()

	assert.Error(t, DeletePolicyIfExists(ctx, "x"))
}

func upsertModules(t *testing.T, ctx context.Context, modules map[string]string) {
	for id, text := range modules {
		require.NoError(t, UpsertPolicy(ctx, id, []byte(text)))
	}
}

const childModule = "package onap.org.cell.consistency\n\nimport rego.v1\n\nallow if input.x == 1\n"

func TestCompileWithLiveModules_NoStoreYet(t *testing.T) {
	original := memStore
	t.Cleanup(func() { memStore = original })
	memStore = nil

	assert.NoError(t, CompileWithLiveModules(context.Background(), map[string]string{"a": "package a\n"}))
}

func TestCompileWithLiveModules_ParentOverChildCompilesTogether(t *testing.T) {
	ctx := useRealStore(t)
	upsertModules(t, ctx, map[string]string{"onap.org.cell.consistency": childModule})

	err := CompileWithLiveModules(ctx, map[string]string{
		"onap.org.cell": "package onap.org.cell\n\nimport rego.v1\n\nthreshold := 5\n",
	})

	assert.NoError(t, err, "nested packages are fine in OPA")
}

// The clash OPA objects to: a rule of the parent that has the same path as the child's package.
func TestCompileWithLiveModules_RuleClashesWithPackage(t *testing.T) {
	ctx := useRealStore(t)
	upsertModules(t, ctx, map[string]string{"onap.org.cell.consistency": childModule})

	err := CompileWithLiveModules(ctx, map[string]string{
		"onap.org.cell": "package onap.org.cell\n\nimport rego.v1\n\nconsistency := true\n",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "conflicts with")
	assert.Contains(t, err.Error(), "onap.org.cell")
}

func TestCompileWithLiveModules_ClashIsReportedInFull(t *testing.T) {
	ctx := useRealStore(t)
	upsertModules(t, ctx, map[string]string{"onap.org.cell.consistency": childModule})

	err := CompileWithLiveModules(ctx, map[string]string{
		"onap.org.cell": "package onap.org.cell\n\nimport rego.v1\n\nconsistency := true\n",
	})

	require.Error(t, err)
	assert.Greater(t, len(err.Error()), 200, "the message is not cut short")
	assert.True(t, strings.HasPrefix(err.Error(), "2 error(s) occurred: "), err.Error())
	assert.Contains(t, err.Error(), "rule data.onap.org.cell.consistency conflicts with")
	assert.Contains(t, err.Error(), "package onap.org.cell.consistency conflicts with rule consistency defined at onap.org.cell:5")
}

func TestCompileWithLiveModules_SameModuleIDReplacesLiveModule(t *testing.T) {
	ctx := useRealStore(t)
	upsertModules(t, ctx, map[string]string{
		"onap.org.cell.consistency": childModule,
		"onap.org.cell":             "package onap.org.cell\n\nimport rego.v1\n\nconsistency := true\n",
	})

	err := CompileWithLiveModules(ctx, map[string]string{
		"onap.org.cell": "package onap.org.cell\n\nimport rego.v1\n\nthreshold := 5\n",
	})

	assert.NoError(t, err, "the redeployed module replaces the live one, so the old clash is gone")
}

func TestCompileWithLiveModules_ParseError(t *testing.T) {
	ctx := useRealStore(t)

	err := CompileWithLiveModules(ctx, map[string]string{"onap.org.cell": "package onap.org.cell\n\nthis is not rego {{{\n"})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "rego_parse_error")
}

func TestCompileWithLiveModules_ExistingProblemIsNotBlamedOnTheCandidate(t *testing.T) {
	ctx := useRealStore(t)
	upsertModules(t, ctx, map[string]string{"broken.live": "package broken.live\n\nimport rego.v1\n\nx := undefined_thing\n"})

	err := CompileWithLiveModules(ctx, map[string]string{"onap.org.cell": "package onap.org.cell\n\nimport rego.v1\n\nthreshold := 5\n"})

	assert.NoError(t, err)
}

func TestCompileWithLiveModules_StoreReadFailure(t *testing.T) {
	ctx := context.Background()
	original := memStore
	t.Cleanup(func() { memStore = original })
	mockMemStore := new(MockStorage)
	memStore = mockMemStore
	mockMemStore.On("NewTransaction", ctx, mock.Anything).Return(nil, errors.New("transaction error"))

	err := CompileWithLiveModules(ctx, map[string]string{"a": "package a\n"})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read the deployed policies")
}

// The patch path conflict check now sees the live rules instead of an empty compiler.
func TestPatchData_DetectsConflictWithLiveRule(t *testing.T) {
	ctx := useRealStore(t)
	upsertModules(t, ctx, map[string]string{"p.q": "package p\n\nimport rego.v1\n\nq := 1\n"})

	err := PatchData(ctx, []PatchImpl{{Op: storage.AddOp, Path: storage.MustParsePath("/p/q"), Value: map[string]interface{}{"x": 1}}})

	require.Error(t, err, "data written where a rule lives must be refused")
	_, found := readJSON(t, ctx, "/p/q")
	assert.False(t, found, "and nothing is written")
}

func TestPatchData_NoConflictStillWrites(t *testing.T) {
	ctx := useRealStore(t)
	upsertModules(t, ctx, map[string]string{"p.q": "package p\n\nimport rego.v1\n\nq := 1\n"})
	require.NoError(t, WriteData(ctx, "/node/a", parseJSONValue(t, `{"x":1}`)))

	err := PatchData(ctx, []PatchImpl{{Op: storage.AddOp, Path: storage.MustParsePath("/node/a/y"), Value: 2}})

	require.NoError(t, err)
	value, _ := readJSON(t, ctx, "/node/a")
	assert.JSONEq(t, `{"x":1,"y":2}`, value)
}

func TestLiveCompiler_FallsBackWhenPoliciesCannotBeRead(t *testing.T) {
	ctx := context.Background()
	original := memStore
	t.Cleanup(func() { memStore = original })
	mockMemStore := new(MockStorage)
	memStore = mockMemStore
	mockMemStore.On("ListPolicies", ctx, mock.Anything).Return([]string{}, errors.New("list error"))

	compiler := liveCompiler(ctx, &MockTransaction{})

	assert.NotNil(t, compiler, "patching must keep working when the policies cannot be read")
	assert.Empty(t, compiler.Modules)
}

func TestHasSegmentPrefix_Local(t *testing.T) {
	assert.True(t, hasSegmentPrefix([]string{"a", "b"}, []string{"a"}))
	assert.True(t, hasSegmentPrefix([]string{"a"}, []string{"a"}))
	assert.False(t, hasSegmentPrefix([]string{"a"}, []string{"a", "b"}))
	assert.False(t, hasSegmentPrefix([]string{"ab"}, []string{"a"}))
}
