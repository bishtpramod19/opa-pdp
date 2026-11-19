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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"policy-opa-pdp/consts"
	"policy-opa-pdp/pkg/log"
	"policy-opa-pdp/pkg/model"
	"policy-opa-pdp/pkg/utils"
	"sync"
)

const dataItemsField = "data-items"

type DeployedPolicy struct {
	Name       string
	Version    string
	PolicyKeys []string
	DataKeys   []string
	DataItems  map[string][]string
}

type (
	FormatMapOfAnyTypeFunc[T any] func(mapOfAnyType T) (string, error)
)

var (
	// lastDeployedPolicies is written by the Kafka handler goroutine while the decision
	// and data HTTP handlers, the status publisher and the heartbeat all read it, so
	// every access goes through mu. Read-modify-write callers hold the write lock for
	// the whole sequence: taking it only around the store would let two concurrent
	// updates each drop the other's policy.
	mu                   sync.RWMutex
	lastDeployedPolicies string

	FormatMapOfAnyTypeVar FormatMapOfAnyTypeFunc[interface{}] = FormatMapofAnyType
)

// GetLastDeployedPolicies returns the JSON document describing what is currently deployed.
func GetLastDeployedPolicies() string {
	mu.RLock()
	defer mu.RUnlock()
	return lastDeployedPolicies
}

// SetLastDeployedPolicies replaces the deployed policies document.
func SetLastDeployedPolicies(policiesMap string) {
	mu.Lock()
	defer mu.Unlock()
	lastDeployedPolicies = policiesMap
}

func formatPolicyAndDataMap(deployedPolicies []map[string]interface{}) (string, error) {

	// Create the final JSON
	finalMap := map[string]interface{}{
		"deployed_policies_dict": deployedPolicies,
	}

	// Marshal the final map into JSON
	policyDataJSON, err := FormatMapOfAnyTypeVar(finalMap)
	if err != nil {
		return "", fmt.Errorf("failed to format json: %v", err)
	}

	return policyDataJSON, nil
}

// storeDeployedPoliciesLocked renders deployedPolicies and publishes the result.
// mu must already be held for writing.
func storeDeployedPoliciesLocked(deployedPolicies []map[string]interface{}) (string, error) {
	policyDataJSON, err := formatPolicyAndDataMap(deployedPolicies)
	if err != nil {
		return lastDeployedPolicies, err
	}

	lastDeployedPolicies = policyDataJSON
	log.Infof("PoliciesDeployed Map: %v", lastDeployedPolicies)

	return lastDeployedPolicies, nil
}

func FormatMapofAnyType[T any](mapOfAnyType T) (string, error) {
	// Marshal the final map into JSON
	jsonBytes, err := json.MarshalIndent(mapOfAnyType, "", " ")
	if err != nil {
		return "", fmt.Errorf("failed to format json: %v", err)
	}

	return string(jsonBytes), nil
}

func UnmarshalLastDeployedPolicies(lastdeployedPolicies string) ([]map[string]interface{}, error) {
	if len(lastdeployedPolicies) == 0 {
		return []map[string]interface{}{}, nil
	}

	var policiesMap struct {
		DeployedPoliciesDict []map[string]interface{} `json:"deployed_policies_dict"`
	}

	err := json.Unmarshal([]byte(lastdeployedPolicies), &policiesMap)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal LastDeployedPolicies: %v", err)
	}

	return policiesMap.DeployedPoliciesDict, nil
}

func UpdateDeployedPoliciesinMap(policy model.ToscaPolicy) (string, error) {
	mu.Lock()
	defer mu.Unlock()

	// Unmarshal the last known policies
	deployedPolicies, err := UnmarshalLastDeployedPolicies(lastDeployedPolicies)
	if err != nil {
		log.Warnf("Aborting update; LastDeployedPolicies is corrupt: %v", err)
		return lastDeployedPolicies, err
	}

	dataKeys := make([]string, 0, len(policy.Properties.Data))
	policyKeys := make([]string, 0, len(policy.Properties.Policy))

	for key := range policy.Properties.Data {
		dataKeys = append(dataKeys, key)
	}

	for key := range policy.Properties.Policy {
		policyKeys = append(policyKeys, key)
	}

	directoryMap := map[string]interface{}{
		consts.PolicyId:      policy.Metadata.PolicyID,
		consts.PolicyVersion: policy.Metadata.PolicyVersion,
		"data":               dataKeys,
		"policy":             policyKeys,
	}
	if recordedItems := recordedDataItems(policy.Properties.Data); len(recordedItems) > 0 {
		directoryMap[dataItemsField] = recordedItems
	}
	deployedPolicies = append(deployedPolicies, directoryMap)
	return storeDeployedPoliciesLocked(deployedPolicies)
}

func RemoveUndeployedPoliciesfromMap(undeployedPolicy map[string]interface{}) (string, error) {
	mu.Lock()
	defer mu.Unlock()

	// Unmarshal the last known policies
	deployedPolicies, err := UnmarshalLastDeployedPolicies(lastDeployedPolicies)
	if err != nil {
		log.Warnf("Aborting update; LastDeployedPolicies is corrupt: %v", err)
		return lastDeployedPolicies, err
	}

	remainingPolicies := []map[string]interface{}{}

	for _, policy := range deployedPolicies {
		shouldRetain := true
		if policy[consts.PolicyId] == undeployedPolicy[consts.PolicyId] && policy[consts.PolicyVersion] == undeployedPolicy[consts.PolicyVersion] {
			shouldRetain = false
		}
		if shouldRetain {
			remainingPolicies = append(remainingPolicies, policy)
		}
	}

	return storeDeployedPoliciesLocked(remainingPolicies)
}

func VerifyAndReturnPoliciesToBeDeployed(lastdeployedPoliciesMap string, pdpUpdate model.PdpUpdate) []model.ToscaPolicy {
	type PoliciesMap struct {
		DeployedPoliciesDict []map[string]interface{} `json:"deployed_policies_dict"`
	}

	var policiesMap PoliciesMap
	err := json.Unmarshal([]byte(lastdeployedPoliciesMap), &policiesMap)
	if err != nil {
		log.Warnf("Failed to unmarshal LastDeployedPolicies While Verifying Policies to be deployed: %v", err)
		return pdpUpdate.PoliciesToBeDeployed
	}

	deployedPolicies := policiesMap.DeployedPoliciesDict
	var policiesToBeDeployed []model.ToscaPolicy

	for _, deployingPolicy := range pdpUpdate.PoliciesToBeDeployed {
		shouldDeploy := true
		for _, deployedPolicy := range deployedPolicies {
			if deployedPolicy[consts.PolicyId] == deployingPolicy.Name && deployedPolicy[consts.PolicyVersion] == deployingPolicy.Version {
				log.Infof("Policy Previously deployed: %v %v, skipping", deployingPolicy.Name, deployingPolicy.Version)
				shouldDeploy = false
				break
			}
		}

		if shouldDeploy {
			log.Infof("Policy is new and should be deployed: %v %v", deployingPolicy.Name, deployingPolicy.Version)
			policiesToBeDeployed = append(policiesToBeDeployed, deployingPolicy)
		}
	}

	return policiesToBeDeployed

}

func ExtractDeployedPolicies(policiesMap string) []model.ToscaConceptIdentifier {

	// Unmarshal the last known policies
	deployedPolicies, err := UnmarshalLastDeployedPolicies(policiesMap)
	if err != nil {
		log.Warnf("Failed to unmarshal LastDeployedPolicies While Extracting Deployed Policies: %v", err)
	}

	pdpstatus := model.PdpStatus{
		Policies: []model.ToscaConceptIdentifier{},
	}

	for _, policy := range deployedPolicies {

		// Extract policy-id and policy-version
		policyID, idOk := policy[consts.PolicyId].(string)
		policyVersion, versionOk := policy[consts.PolicyVersion].(string)
		if !idOk || !versionOk {
			log.Warnf("Skipping deployed policy with missing/invalid policy-id or policy-version")
			continue
		}
		tosca := model.ToscaConceptIdentifier{
			Name:    policyID,
			Version: policyVersion,
		}
		pdpstatus.Policies = append(pdpstatus.Policies, tosca)
	}
	return pdpstatus.Policies
}

func CheckIfPolicyAlreadyExists(policyId string) bool {
	policiesMap := GetLastDeployedPolicies()
	if len(policiesMap) > 0 {
		// Unmarshal the last known policies
		deployedPolicies, err := UnmarshalLastDeployedPolicies(policiesMap)
		if err != nil {
			log.Warnf("Failed to unmarshal LastDeployedPolicies While Checking if Policy Already Exists: %v", err)
		}

		log.Debugf("deployedPolicies %s", deployedPolicies)

		for _, policy := range deployedPolicies {
			if policy[consts.PolicyId] == policyId {
				return true
			}
		}
	}
	return false
}

// GetDeployedPolicyNames returns the name (policy-id) of every currently deployed policy
func GetDeployedPolicyNames() ([]string, error) {
	deployedPolicies, err := UnmarshalLastDeployedPolicies(GetLastDeployedPolicies())
	if err != nil {
		return nil, err
	}
	return extractPolicyNames(deployedPolicies)
}

func extractPolicyNames(deployedPolicies []map[string]any) ([]string, error) {
	names := make([]string, 0, len(deployedPolicies))
	seen := make(map[string]struct{}, len(deployedPolicies))
	for _, deployedPolicy := range deployedPolicies {
		name, ok := deployedPolicy[consts.PolicyId].(string)
		if !ok || name == "" {
			return nil, fmt.Errorf("invalid or missing policy-id field")
		}
		if _, duplicate := seen[name]; duplicate {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	return names, nil
}

// recordedDataItems returns, per data key, the top-level items of its JSON content.
// Content that cannot be read is left out: the deployment reports that problem itself.
func recordedDataItems(data map[string]string) map[string][]string {
	items := make(map[string][]string)
	for dataKey, encodedContent := range data {
		decoded, err := base64.StdEncoding.DecodeString(encodedContent)
		if err != nil {
			continue
		}
		if names := utils.TopLevelItemNames(string(decoded)); len(names) > 0 {
			items[dataKey] = names
		}
	}
	return items
}

// GetDeployedPolicyDetails returns every deployed policy with the policy keys, data keys
// and recorded data items it was deployed with.
func GetDeployedPolicyDetails() ([]DeployedPolicy, error) {
	entries, err := UnmarshalLastDeployedPolicies(GetLastDeployedPolicies())
	if err != nil {
		return nil, err
	}
	details := make([]DeployedPolicy, 0, len(entries))
	for _, entry := range entries {
		name, ok := entry[consts.PolicyId].(string)
		if !ok || name == "" {
			return nil, fmt.Errorf("invalid or missing policy-id field")
		}
		version, _ := entry[consts.PolicyVersion].(string)
		details = append(details, DeployedPolicy{
			Name:       name,
			Version:    version,
			PolicyKeys: stringList(entry["policy"]),
			DataKeys:   stringList(entry["data"]),
			DataItems:  stringListsByKey(entry[dataItemsField]),
		})
	}
	return details, nil
}

// stringList reads a JSON array of strings; anything that is not a string is ignored.
func stringList(value interface{}) []string {
	list, _ := value.([]interface{})
	result := make([]string, 0, len(list))
	for _, element := range list {
		if text, ok := element.(string); ok {
			result = append(result, text)
		}
	}
	return result
}

// stringListsByKey reads a JSON object whose values are arrays of strings.
func stringListsByKey(value interface{}) map[string][]string {
	object, _ := value.(map[string]interface{})
	result := make(map[string][]string, len(object))
	for key, list := range object {
		result[key] = stringList(list)
	}
	return result
}

// PolicyNames returns the names of the policies
func PolicyNames(deployed []DeployedPolicy) []string {
	names := make([]string, 0, len(deployed))
	seen := make(map[string]struct{}, len(deployed))
	for _, policy := range deployed {
		if _, duplicate := seen[policy.Name]; !duplicate {
			seen[policy.Name] = struct{}{}
			names = append(names, policy.Name)
		}
	}
	return names
}

// WithoutPolicy returns the deployed policies other than the one called name.
func WithoutPolicy(deployed []DeployedPolicy, name string) []DeployedPolicy {
	others := make([]DeployedPolicy, 0, len(deployed))
	for _, policy := range deployed {
		if policy.Name != name {
			others = append(others, policy)
		}
	}
	return others
}

// DataKeysByPolicy returns the data keys of each policy, keyed by policy name
func DataKeysByPolicy(deployed []DeployedPolicy) map[string][]string {
	keys := make(map[string][]string, len(deployed))
	for _, policy := range deployed {
		keys[policy.Name] = append(keys[policy.Name], policy.DataKeys...)
	}
	return keys
}

// DataItemsByPolicy returns the recorded data items of each policy, keyed by policy name and data key
func DataItemsByPolicy(deployed []DeployedPolicy) map[string]map[string][]string {
	items := make(map[string]map[string][]string, len(deployed))
	for _, policy := range deployed {
		if items[policy.Name] == nil {
			items[policy.Name] = make(map[string][]string)
		}
		for dataKey, names := range policy.DataItems {
			items[policy.Name][dataKey] = append(items[policy.Name][dataKey], names...)
		}
	}
	return items
}

func GetTotalDeployedPoliciesCountFromMap() int {
	deployedPolicies, err := UnmarshalLastDeployedPolicies(GetLastDeployedPolicies())
	if err != nil {
		log.Warnf("Failed to unmarshal LastDeployedPolicies While Getting TotalDeployedPoliciesCountFromMap: %v", err)
		return 0
	}
	return len(deployedPolicies)
}
