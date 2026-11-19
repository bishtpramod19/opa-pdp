// -
//   ========================LICENSE_START=================================
//   Copyright (C) 2025: Deutsche Telekom
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

package policymap

import (
	// "encoding/json"
	"encoding/base64"
	"fmt"
	"sync"
	"testing"

	"policy-opa-pdp/pkg/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFormatPolicyAndDataMap(t *testing.T) {
	deployedPolicies := []map[string]interface{}{
		{"policy-id": "test.policy.1", "policy-version": "1.0"},
	}

	result, err := formatPolicyAndDataMap(deployedPolicies)
	assert.NoError(t, err)
	assert.Contains(t, result, `"policy-id": "test.policy.1"`)
}

func TestFormatMapofAnyType(t *testing.T) {
	testMap := map[string]string{"key1": "value1"}
	result, err := FormatMapofAnyType(testMap)
	assert.NoError(t, err)
	assert.Contains(t, result, `"key1": "value1"`)
}

func TestFormatPolicyAndDataMap_EmptyMap(t *testing.T) {
	deployedPolicies := []map[string]interface{}{
		{"policy-id": "test.policy.1", "data": make(chan int)},
	}

	_, err := formatPolicyAndDataMap(deployedPolicies)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to format json", "Expected JSONformatting error")
}

func TestUnmarshalLastDeployedPolicies_EmptyString(t *testing.T) {
	result, err := UnmarshalLastDeployedPolicies("")
	assert.NoError(t, err)
	assert.Equal(t, 0, len(result))
}

func TestUnmarshalLastDeployedPolicies_ValidJSON(t *testing.T) {
	jsonData := `{"deployed_policies_dict": [{"data": ["role"],"policy": ["role"],"policy-id": "test.policy.1","policy-version": "1.0"}]}`
	result, err := UnmarshalLastDeployedPolicies(jsonData)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(result))
	assert.Equal(t, "test.policy.1", result[0]["policy-id"])
}

func TestUpdateDeployedPoliciesinMap(t *testing.T) {
	SetLastDeployedPolicies(`{"deployed_policies_dict":[]}`)

	policy := model.ToscaPolicy{
		Metadata: model.Metadata{
			PolicyID:      "new.policy",
			PolicyVersion: "1.0",
		},
		Properties: model.PolicyProperties{
			Data:   map[string]string{"key1": "value1"},
			Policy: map[string]string{"rule1": "allow"},
		},
	}

	result, err := UpdateDeployedPoliciesinMap(policy)
	assert.NoError(t, err)
	assert.Contains(t, result, `"policy-id": "new.policy"`)
}

func TestUpdateDeployedPoliciesinMap_Negative(t *testing.T) {
	SetLastDeployedPolicies(`{deployed_policies_dict:[]}`)

	policy := model.ToscaPolicy{
		Metadata: model.Metadata{
			PolicyID:      "new.policy",
			PolicyVersion: "1.0",
		},
		Properties: model.PolicyProperties{
			Data:   map[string]string{"key1": "value1"},
			Policy: map[string]string{"rule1": "allow"},
		},
	}

	result, _ := UpdateDeployedPoliciesinMap(policy)
	assert.NotContains(t, result, "new.policy canot be added due to invalid json format")
}

func TestRemoveUndeployedPoliciesfromMap(t *testing.T) {
	SetLastDeployedPolicies(`{"deployed_policies_dict":[{"policy-id":"test.policy.1","policy-version":"1.0"}]}`)

	undeploy := map[string]interface{}{
		"policy-id":      "test.policy.1",
		"policy-version": "1.0",
	}

	result, err := RemoveUndeployedPoliciesfromMap(undeploy)
	assert.NoError(t, err)
	assert.NotContains(t, result, `"policy-id": "test.policy.1"`)
}

func TestRemoveUndeployedPoliciesfromMap_Negative(t *testing.T) {
	SetLastDeployedPolicies(`{"deployed_policies_dict":[{"policy-id":"test.policy.1"policy-version":"1.0"}]}`)

	undeploy := map[string]interface{}{
		"policy-id":      "test.policy.1",
		"policy-version": "1.0",
	}

	result, _ := RemoveUndeployedPoliciesfromMap(undeploy)
	assert.NotContains(t, result, `"policy-id": "test.policy.1"`)
}

func TestRemoveUndeployedPolicies_NonExistingPolicyfromMap(t *testing.T) {
	SetLastDeployedPolicies(`{"deployed_policies_dict":[{"policy-id":"test.policy.1","policy-version":"1.0"}]}`)

	undeploy := map[string]interface{}{
		"policy-id":      "new.policy",
		"policy-version": "1.0",
	}

	result, err := RemoveUndeployedPoliciesfromMap(undeploy)
	assert.NoError(t, err)
	assert.Contains(t, result, `"policy-id": "test.policy.1"`)
	assert.NotContains(t, result, `"policy-id": "new.policy"`)
}

func TestVerifyAndReturnPoliciesToBeDeployed(t *testing.T) {
	lastDeployedPolicies := `{"deployed_policies_dict":[{"policy-id":"test.policy.1","policy-version":"1.0"}]}`
	pdpUpdate := model.PdpUpdate{
		PoliciesToBeDeployed: []model.ToscaPolicy{
			{Name: "new.policy", Version: "1.0"},
		},
	}

	result := VerifyAndReturnPoliciesToBeDeployed(lastDeployedPolicies, pdpUpdate)
	assert.Equal(t, 1, len(result))
	assert.Equal(t, "new.policy", result[0].Name)
}

func TestVerifyAndReturnPoliciesToBeDeployed_Negative(t *testing.T) {
	lastDeployedPolicies := `{"deployed_policies_dict":[{"policy-id":"test.policy.1""policy-version":"1.0"}]}`
	pdpUpdate := model.PdpUpdate{
		PoliciesToBeDeployed: []model.ToscaPolicy{
			{Name: "new.policy", Version: "1.0"},
		},
	}

	result := VerifyAndReturnPoliciesToBeDeployed(lastDeployedPolicies, pdpUpdate)
	assert.NotEqual(t, "new.policy", result)
}

func TestVerifyAndReturnPoliciesToBeDeployedi_ExistingPolicy(t *testing.T) {
	lastDeployedPolicies := `{"deployed_policies_dict":[{"policy-id":"test.policy.1","policy-version":"1.0"}]}`
	pdpUpdate := model.PdpUpdate{
		PoliciesToBeDeployed: []model.ToscaPolicy{
			{Name: "test.policy.1", Version: "1.0"},
		},
	}

	result := VerifyAndReturnPoliciesToBeDeployed(lastDeployedPolicies, pdpUpdate)
	assert.Empty(t, result, "Expected result tobe empty as policy is already deployed")
}

func TestExtractDeployedPolicies(t *testing.T) {
	policiesMap := `{"deployed_policies_dict":[{"policy-id":"test.policy.1","policy-version":"1.0"}]}`

	result := ExtractDeployedPolicies(policiesMap)
	assert.Equal(t, 1, len(result))
	assert.Equal(t, "test.policy.1", result[0].Name)
}

func TestExtractDeployedPolicies_Negative(t *testing.T) {
	policiesMap := `{"deployed_policies_dict":[{"policy-id":"test.policy.1","policy-version":1.0"}]}`

	result := ExtractDeployedPolicies(policiesMap)
	assert.Equal(t, 0, len(result))
	assert.NotEqual(t, "test.policy.1", result)
}

func TestExtractDeployedPolicies_MissingPolicyID(t *testing.T) {
	// A single entry with a non-string policy-id should be skipped, not cause
	// the whole call to return nil. The result is an empty (non-nil) slice.
	policiesMap := `{"deployed_policies_dict":[{"policy-id": 123,"policy-version":"1.0"}]}`

	result := ExtractDeployedPolicies(policiesMap)
	assert.Empty(t, result)
}

func TestCheckIfPolicyAlreadyExists(t *testing.T) {
	SetLastDeployedPolicies(`{"deployed_policies_dict":[{"policy-id":"existing.policy","policy-version":"1.0"}]}`)

	exists := CheckIfPolicyAlreadyExists("existing.policy")
	assert.True(t, exists)

	notExists := CheckIfPolicyAlreadyExists("nonexistent.policy")
	assert.False(t, notExists)
}

func TestCheckIfPolicyAlreadyExists_JSONParsingFailure(t *testing.T) {
	SetLastDeployedPolicies(`{"deployed_policies_dict":[{"policy-id":"existing.policy,"policy-version":"1.0"}]}`)

	exists := CheckIfPolicyAlreadyExists("existing.policy")
	assert.False(t, exists)
}

func TestGetTotalDeployedPoliciesCountFromMap(t *testing.T) {
	SetLastDeployedPolicies(`{"deployed_policies_dict":[{"policy-id":"test.policy.1","policy-version":"1.0"}]}`)

	count := GetTotalDeployedPoliciesCountFromMap()
	assert.Equal(t, 1, count)
}

func TestGetTotalDeployedPoliciesCountFromMap_Negative(t *testing.T) {
	SetLastDeployedPolicies(`{"deployed_policies_dict":[{"policy-id":test.policy.1","policy-version":"1.0"}]}`)

	count := GetTotalDeployedPoliciesCountFromMap()
	assert.Equal(t, 0, count)
}

func TestUpdateDeployedPolicies_AbortsOnCorruptState(t *testing.T) {
	orig := GetLastDeployedPolicies()
	t.Cleanup(func() { SetLastDeployedPolicies(orig) })
	SetLastDeployedPolicies("{not valid json") // corrupt

	_, err := UpdateDeployedPoliciesinMap(model.ToscaPolicy{})
	require.Error(t, err, "must not silently wipe the policy list")
	assert.Equal(t, "{not valid json", GetLastDeployedPolicies(), "state must be untouched on error")
}

// The Kafka handler goroutine deploys and undeploys while decision/data requests, the
// status publisher and the heartbeat read the map. Run those two roles against each
// other: without the lock this is a data race, and concurrent deployments lose each
// other's updates because the read-modify-write is not atomic.
func TestDeployedPoliciesMap_ConcurrentAccess(t *testing.T) {
	orig := GetLastDeployedPolicies()
	t.Cleanup(func() { SetLastDeployedPolicies(orig) })
	SetLastDeployedPolicies(`{"deployed_policies_dict":[]}`)

	const deployers = 50
	var readerWg, deployWg sync.WaitGroup
	stopReaders := make(chan struct{})

	for i := 0; i < 4; i++ {
		readerWg.Add(1)
		go func() {
			defer readerWg.Done()
			for {
				select {
				case <-stopReaders:
					return
				default:
					GetLastDeployedPolicies()
					GetTotalDeployedPoliciesCountFromMap()
					CheckIfPolicyAlreadyExists("concurrent.policy.1")
				}
			}
		}()
	}

	for i := 0; i < deployers; i++ {
		deployWg.Add(1)
		go func(i int) {
			defer deployWg.Done()
			policy := model.ToscaPolicy{
				Metadata: model.Metadata{
					PolicyID:      fmt.Sprintf("concurrent.policy.%d", i),
					PolicyVersion: "1.0.0",
				},
			}
			_, err := UpdateDeployedPoliciesinMap(policy)
			assert.NoError(t, err)
		}(i)
	}

	deployWg.Wait()
	close(stopReaders)
	readerWg.Wait()

	assert.Equal(t, deployers, GetTotalDeployedPoliciesCountFromMap(),
		"every concurrent deployment must survive; a lower count means updates were lost")
}

func TestExtractDeployedPolicies_SkipsBadEntryKeepsGood(t *testing.T) {
	// One entry missing policy-id, one valid.
	m := `{"deployed_policies_dict":[{"policy-version":"1.0.0"},{"policy-id":"good","policy-version":"1.0.0"}]}`
	got := ExtractDeployedPolicies(m)
	require.Len(t, got, 1)
	assert.Equal(t, "good", got[0].Name)
}

// GetDeployedPolicyNames lists every deployed policy name, once, in stored order.
func TestGetDeployedPolicyNames(t *testing.T) {
	orig := GetLastDeployedPolicies()
	t.Cleanup(func() { SetLastDeployedPolicies(orig) })

	tests := []struct {
		name    string
		state   string
		want    []string
		wantErr string
	}{
		{"Nothing deployed (empty state)", "", []string{}, ""},
		{"Nothing deployed (empty list)", `{"deployed_policies_dict":[]}`, []string{}, ""},
		{"Parent and child both deployed",
			`{"deployed_policies_dict":[{"policy-id":"onap.org.cell","policy-version":"1.0"},{"policy-id":"onap.org.cell.consistency","policy-version":"1.0"}]}`,
			[]string{"onap.org.cell", "onap.org.cell.consistency"}, ""},
		{"Same name listed twice is returned once",
			`{"deployed_policies_dict":[{"policy-id":"onap.org.cell","policy-version":"1.0"},{"policy-id":"onap.org.cell","policy-version":"2.0"}]}`,
			[]string{"onap.org.cell"}, ""},
		{"Entry without policy-id",
			`{"deployed_policies_dict":[{"policy-version":"1.0"}]}`, nil, "invalid or missing policy-id field"},
		{"Entry with empty policy-id",
			`{"deployed_policies_dict":[{"policy-id":"","policy-version":"1.0"}]}`, nil, "invalid or missing policy-id field"},
		{"Entry with non-text policy-id",
			`{"deployed_policies_dict":[{"policy-id":5,"policy-version":"1.0"}]}`, nil, "invalid or missing policy-id field"},
		{"Corrupt state", "{not valid json", nil, "failed to unmarshal LastDeployedPolicies"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SetLastDeployedPolicies(tt.state)

			got, err := GetDeployedPolicyNames()

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.state, GetLastDeployedPolicies(), "lookup must not change the deployed policies map")
		})
	}
}

func encodedJSON(content string) string {
	return base64.StdEncoding.EncodeToString([]byte(content))
}

// The top-level data items of a deployed policy are recorded in the map, so that a child
// deployed later can be checked against what its parent already holds.
func TestUpdateDeployedPoliciesinMap_RecordsDataItems(t *testing.T) {
	orig := GetLastDeployedPolicies()
	t.Cleanup(func() { SetLastDeployedPolicies(orig) })
	SetLastDeployedPolicies(`{"deployed_policies_dict":[]}`)

	policy := model.ToscaPolicy{
		Metadata: model.Metadata{PolicyID: "onap.org.cell", PolicyVersion: "1.0"},
		Properties: model.PolicyProperties{
			Data: map[string]string{
				"node.onap.org.cell":       encodedJSON(`{"threshold":5,"consistency":{"x":1}}`),
				"node.onap.org.cell.other": encodedJSON(`[1,2,3]`),
				"node.onap.org.cell.bad":   "not-base64!",
			},
			Policy: map[string]string{"onap.org.cell": "cG9saWN5"},
		},
	}

	_, err := UpdateDeployedPoliciesinMap(policy)
	require.NoError(t, err)

	details, err := GetDeployedPolicyDetails()
	require.NoError(t, err)
	require.Len(t, details, 1)
	assert.Equal(t, "onap.org.cell", details[0].Name)
	assert.Equal(t, "1.0", details[0].Version)
	assert.Equal(t, []string{"onap.org.cell"}, details[0].PolicyKeys)
	assert.ElementsMatch(t, []string{"node.onap.org.cell", "node.onap.org.cell.other", "node.onap.org.cell.bad"}, details[0].DataKeys)
	assert.Equal(t, map[string][]string{"node.onap.org.cell": {"consistency", "threshold"}}, details[0].DataItems,
		"only readable JSON objects are recorded")
}

func TestUpdateDeployedPoliciesinMap_NoItemsRecordedWhenThereAreNone(t *testing.T) {
	orig := GetLastDeployedPolicies()
	t.Cleanup(func() { SetLastDeployedPolicies(orig) })
	SetLastDeployedPolicies(`{"deployed_policies_dict":[]}`)

	policy := model.ToscaPolicy{
		Metadata:   model.Metadata{PolicyID: "plain.policy", PolicyVersion: "1.0"},
		Properties: model.PolicyProperties{Data: map[string]string{"node.plain.policy": encodedJSON(`{}`)}},
	}

	result, err := UpdateDeployedPoliciesinMap(policy)
	require.NoError(t, err)
	assert.NotContains(t, result, "data-items", "the map keeps its old shape when there is nothing to record")
}

func TestGetDeployedPolicyDetails(t *testing.T) {
	orig := GetLastDeployedPolicies()
	t.Cleanup(func() { SetLastDeployedPolicies(orig) })

	t.Run("Entries deployed before items were recorded", func(t *testing.T) {
		SetLastDeployedPolicies(`{"deployed_policies_dict":[{"policy-id":"a.b","policy-version":"1.0","data":["node.a.b"],"policy":["a.b"]}]}`)

		details, err := GetDeployedPolicyDetails()

		require.NoError(t, err)
		require.Len(t, details, 1)
		assert.Equal(t, []string{"node.a.b"}, details[0].DataKeys)
		assert.Empty(t, details[0].DataItems)
	})
	t.Run("Nothing deployed", func(t *testing.T) {
		SetLastDeployedPolicies("")

		details, err := GetDeployedPolicyDetails()

		require.NoError(t, err)
		assert.Empty(t, details)
	})
	t.Run("Entry without policy-id", func(t *testing.T) {
		SetLastDeployedPolicies(`{"deployed_policies_dict":[{"policy-version":"1.0"}]}`)

		_, err := GetDeployedPolicyDetails()

		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid or missing policy-id field")
	})
	t.Run("Corrupt state", func(t *testing.T) {
		SetLastDeployedPolicies("{broken")

		_, err := GetDeployedPolicyDetails()

		require.Error(t, err)
	})
	t.Run("Non-text members are ignored", func(t *testing.T) {
		SetLastDeployedPolicies(`{"deployed_policies_dict":[{"policy-id":"a.b","data":["node.a.b",5,null],"policy":"not-a-list"}]}`)

		details, err := GetDeployedPolicyDetails()

		require.NoError(t, err)
		assert.Equal(t, []string{"node.a.b"}, details[0].DataKeys)
		assert.Empty(t, details[0].PolicyKeys)
	})
}

func TestDeployedPolicyViews(t *testing.T) {
	deployed := []DeployedPolicy{
		{Name: "onap.org.cell", Version: "1.0", DataKeys: []string{"node.onap.org.cell"}, DataItems: map[string][]string{"node.onap.org.cell": {"threshold"}}},
		{Name: "onap.org.cell.consistency", Version: "1.0", DataKeys: []string{"node.onap.org.cell.consistency"}},
		{Name: "onap.org.cell", Version: "2.0", DataKeys: []string{"node.onap.org.cell.extra"}, DataItems: map[string][]string{"node.onap.org.cell": {"limits"}}},
	}

	assert.Equal(t, []string{"onap.org.cell", "onap.org.cell.consistency"}, PolicyNames(deployed), "each name once")

	others := WithoutPolicy(deployed, "onap.org.cell")
	require.Len(t, others, 1)
	assert.Equal(t, "onap.org.cell.consistency", others[0].Name)
	assert.Len(t, WithoutPolicy(deployed, "unknown"), 3)

	assert.Equal(t, map[string][]string{
		"onap.org.cell":             {"node.onap.org.cell", "node.onap.org.cell.extra"},
		"onap.org.cell.consistency": {"node.onap.org.cell.consistency"},
	}, DataKeysByPolicy(deployed), "versions of one policy are merged")

	assert.Equal(t, map[string]map[string][]string{
		"onap.org.cell":             {"node.onap.org.cell": {"threshold", "limits"}},
		"onap.org.cell.consistency": {},
	}, DataItemsByPolicy(deployed))
}
