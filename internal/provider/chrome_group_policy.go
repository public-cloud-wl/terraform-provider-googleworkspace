// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package googleworkspace

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"google.golang.org/api/chromepolicy/v1"
)

const chromePolicyAPIBaseURL = "https://chromepolicy.googleapis.com/v1"

type chromeGroupPolicyDeleteRequest struct {
	PolicyTargetKey *chromepolicy.GoogleChromePolicyV1PolicyTargetKey `json:"policyTargetKey"`
	PolicySchema    string                                            `json:"policySchema"`
}

func chromePolicyTargetResource(d *schema.ResourceData) string {
	if groupID, ok := d.Get("group_id").(string); ok && groupID != "" {
		groupID = strings.TrimPrefix(groupID, "groups/")
		groupID = strings.TrimPrefix(groupID, "id:")
		return "groups/" + groupID
	}
	orgUnitID, _ := d.Get("org_unit_id").(string)
	orgUnitID = strings.TrimPrefix(orgUnitID, "orgunits/")
	orgUnitID = strings.TrimPrefix(orgUnitID, "id:")
	return "orgunits/" + orgUnitID
}

func diffSuppressChromeGroupId(k, old, new string, d *schema.ResourceData) bool {
	normalize := func(value string) string {
		value = strings.TrimPrefix(value, "groups/")
		return strings.TrimPrefix(value, "id:")
	}
	return normalize(old) == normalize(new)
}

func (c *apiClient) chromePolicyAPIURL() string {
	if c.ChromePolicyAPIBaseURL != "" {
		return strings.TrimRight(c.ChromePolicyAPIBaseURL, "/")
	}
	return chromePolicyAPIBaseURL
}

func (c *apiClient) batchModifyChromeGroupPolicies(ctx context.Context, targetResource string, requests []*chromepolicy.GoogleChromePolicyV1ModifyOrgUnitPolicyRequest) error {
	batches := map[string][]*chromepolicy.GoogleChromePolicyV1ModifyOrgUnitPolicyRequest{}
	var namespaces []string
	for _, request := range requests {
		namespace := chromePolicyRootNamespace(request.PolicyValue.PolicySchema)
		if _, ok := batches[namespace]; !ok {
			namespaces = append(namespaces, namespace)
		}
		batches[namespace] = append(batches[namespace], request)
	}

	for _, namespace := range namespaces {
		batch := batches[namespace]
		bodyRequests := make([]map[string]interface{}, 0, len(batch))
		for _, request := range batch {
			var value map[string]interface{}
			if err := json.Unmarshal(request.PolicyValue.Value, &value); err != nil {
				return fmt.Errorf("decoding Chrome policy %q value: %w", request.PolicyValue.PolicySchema, err)
			}
			bodyRequests = append(bodyRequests, map[string]interface{}{
				"policyTargetKey": map[string]interface{}{"targetResource": targetResource},
				"policyValue": map[string]interface{}{
					"policySchema": request.PolicyValue.PolicySchema,
					"value":        value,
				},
				"updateMask": request.UpdateMask,
			})
		}
		if err := c.callChromeGroupPolicyMethod(ctx, "batchModify", map[string]interface{}{"requests": bodyRequests}); err != nil {
			return fmt.Errorf("modifying Chrome policies in namespace %q: %w", namespace, err)
		}
	}
	return nil
}

func (c *apiClient) batchDeleteChromeGroupPolicies(ctx context.Context, targetResource string, schemaNames []string) error {
	batches := map[string][]string{}
	var namespaces []string
	for _, schemaName := range schemaNames {
		namespace := chromePolicyRootNamespace(schemaName)
		if _, ok := batches[namespace]; !ok {
			namespaces = append(namespaces, namespace)
		}
		batches[namespace] = append(batches[namespace], schemaName)
	}

	for _, namespace := range namespaces {
		batch := batches[namespace]
		requests := make([]chromeGroupPolicyDeleteRequest, 0, len(batch))
		for _, schemaName := range batch {
			requests = append(requests, chromeGroupPolicyDeleteRequest{
				PolicyTargetKey: &chromepolicy.GoogleChromePolicyV1PolicyTargetKey{TargetResource: targetResource},
				PolicySchema:    schemaName,
			})
		}
		if err := c.callChromeGroupPolicyMethod(ctx, "batchDelete", map[string]interface{}{"requests": requests}); err != nil {
			return fmt.Errorf("deleting Chrome policies in namespace %q: %w", namespace, err)
		}
	}
	return nil
}

func chromePolicyRootNamespace(schemaName string) string {
	parts := strings.Split(schemaName, ".")
	if len(parts) < 2 {
		return schemaName
	}
	return strings.Join(parts[:2], ".")
}

func (c *apiClient) callChromeGroupPolicyMethod(ctx context.Context, method string, body interface{}) error {
	encoded, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("encoding Chrome group policy request: %w", err)
	}
	endpoint := fmt.Sprintf("%s/customers/%s/policies/groups:%s", c.chromePolicyAPIURL(), url.PathEscape(c.Customer), method)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	if c.client == nil {
		return fmt.Errorf("Google API client is not configured")
	}
	response, err := c.client.Do(request)
	if err != nil {
		return fmt.Errorf("calling Chrome Policy API group %s: %w", method, err)
	}
	defer response.Body.Close()
	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("reading Chrome Policy API response: %w", err)
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		message := strings.TrimSpace(string(responseBody))
		var apiResponse struct {
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(responseBody, &apiResponse) == nil && apiResponse.Error.Message != "" {
			message = apiResponse.Error.Message
		}
		return fmt.Errorf("Chrome Policy API group %s returned HTTP %d: %s", method, response.StatusCode, message)
	}
	return nil
}
