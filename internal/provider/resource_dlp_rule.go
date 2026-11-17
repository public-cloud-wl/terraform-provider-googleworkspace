// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package googleworkspace

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

const (
	cloudIdentityPolicyScope = "https://www.googleapis.com/auth/cloud-identity.policies"
	cloudIdentityPolicyAPI   = "https://cloudidentity.googleapis.com/v1"
	dlpRuleSettingType       = "settings/rule.dlp"
)

type policyAPIError struct {
	StatusCode int
	Message    string
}

func (e *policyAPIError) Error() string {
	return fmt.Sprintf("Cloud Identity Policy API returned HTTP %d: %s", e.StatusCode, e.Message)
}

type policyOperation struct {
	Name     string          `json:"name"`
	Done     bool            `json:"done"`
	Error    *operationError `json:"error"`
	Response json.RawMessage `json:"response"`
}

type operationError struct {
	Code    int               `json:"code"`
	Message string            `json:"message"`
	Details []json.RawMessage `json:"details"`
}

func resourceDlpRule() *schema.Resource {
	return &schema.Resource{
		Description: "Manages a Google Workspace DLP rule using the Cloud Identity Policy API. " +
			"The API requires the `https://www.googleapis.com/auth/cloud-identity.policies` OAuth scope and a super administrator. " +
			"The rule setting is supplied as JSON because the API's DLP setting schema, including alert recipient fields, may evolve.",

		CreateContext: resourceDlpRuleCreate,
		ReadContext:   resourceDlpRuleRead,
		UpdateContext: resourceDlpRuleUpdate,
		DeleteContext: resourceDlpRuleDelete,

		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(10 * time.Minute),
			Update: schema.DefaultTimeout(10 * time.Minute),
			Delete: schema.DefaultTimeout(10 * time.Minute),
		},

		Schema: map[string]*schema.Schema{
			"org_unit_id": {
				Description: "ID of the organizational unit to which this DLP rule applies. Accepts the raw ID or `orgUnits/{id}`. " +
					"Exactly one of `org_unit_id`, `group_id`, or `policy_query` is required; the scope is immutable.",
				Type:             schema.TypeString,
				Optional:         true,
				ForceNew:         true,
				ExactlyOneOf:     []string{"org_unit_id", "group_id", "policy_query"},
				DiffSuppressFunc: diffSuppressOrgUnitPath,
			},
			"group_id": {
				Description: "Google Workspace group ID targeted by this DLP rule. Accepts the raw ID or `groups/{id}`. " +
					"Exactly one of `group_id`, `org_unit_id`, or `policy_query` is required; the scope is immutable.",
				Type:             schema.TypeString,
				Optional:         true,
				ForceNew:         true,
				ExactlyOneOf:     []string{"org_unit_id", "group_id", "policy_query"},
				DiffSuppressFunc: diffSuppressChromeGroupId,
			},
			"policy_query": {
				Description:      "JSON object containing an advanced Cloud Identity Policy query scope. Use this instead of `org_unit_id` or `group_id` for policies whose policyQuery uses a CEL `query` expression. The scope is immutable.",
				Type:             schema.TypeString,
				Optional:         true,
				ForceNew:         true,
				ExactlyOneOf:     []string{"org_unit_id", "group_id", "policy_query"},
				StateFunc:        normalizeJSONState,
				ValidateDiagFunc: validation.ToDiagFunc(validation.StringIsJSON),
			},
			"setting_value": {
				Description: "JSON object for the DLP rule's `setting.value`. Supply the exact structure accepted by the Policy API. " +
					"Alert notifications support at most 10 recipients; use a Google Group email address to notify more users.",
				Type:             schema.TypeString,
				Required:         true,
				StateFunc:        normalizeJSONState,
				ValidateDiagFunc: validation.ToDiagFunc(validateDlpSettingValue),
			},
		},
	}
}

func resourceDlpRuleCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*apiClient)
	payload, err := dlpPolicyPayload(client.Customer, d.Get("org_unit_id").(string), d.Get("group_id").(string), d.Get("policy_query").(string), d.Get("setting_value").(string))
	if err != nil {
		return diag.FromErr(err)
	}

	var operation policyOperation
	if err := client.callPolicyAPI(ctx, http.MethodPost, "/policies", nil, payload, &operation); err != nil {
		return diag.FromErr(err)
	}
	if err := client.waitPolicyOperation(ctx, &operation, d.Timeout(schema.TimeoutCreate)); err != nil {
		return diag.FromErr(err)
	}

	policyName, err := operationPolicyName(operation.Response)
	if err != nil {
		return diag.Errorf("DLP rule create operation completed but did not return the created policy name: %s", err)
	}
	d.SetId(policyName)
	return resourceDlpRuleRead(ctx, d, meta)
}

func resourceDlpRuleRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*apiClient)
	var policy struct {
		Name        string          `json:"name"`
		Customer    string          `json:"customer"`
		PolicyQuery json.RawMessage `json:"policyQuery"`
		Setting     struct {
			Type  string          `json:"type"`
			Value json.RawMessage `json:"value"`
		} `json:"setting"`
	}

	err := client.callPolicyAPI(ctx, http.MethodGet, "/"+policyPath(d.Id()), nil, nil, &policy)
	if err != nil {
		if apiErr, ok := err.(*policyAPIError); ok && apiErr.StatusCode == http.StatusNotFound {
			d.SetId("")
			return nil
		}
		return diag.FromErr(err)
	}
	if policy.Setting.Type != dlpRuleSettingType {
		return diag.Errorf("policy %q has setting type %q, not %q", d.Id(), policy.Setting.Type, dlpRuleSettingType)
	}
	if policy.Customer != "" && policy.Customer != "customers/"+client.Customer {
		return diag.Errorf("policy %q belongs to customer %q, not configured customer %q", d.Id(), policy.Customer, client.Customer)
	}
	var policyQueryFields struct {
		OrgUnit string `json:"orgUnit"`
		Group   string `json:"group"`
		Query   string `json:"query"`
	}
	if err := json.Unmarshal(policy.PolicyQuery, &policyQueryFields); err != nil {
		return diag.Errorf("policy %q returned an invalid policyQuery: %s", d.Id(), err)
	}
	if policyQueryFields.Query != "" {
		if err := d.Set("policy_query", normalizeJSON(string(policy.PolicyQuery))); err != nil {
			return diag.FromErr(err)
		}
	} else if policyQueryFields.OrgUnit != "" {
		orgUnitID := strings.TrimPrefix(policyQueryFields.OrgUnit, "orgUnits/")
		if err := d.Set("org_unit_id", orgUnitID); err != nil {
			return diag.FromErr(err)
		}
	} else if policyQueryFields.Group != "" {
		groupID := strings.TrimPrefix(policyQueryFields.Group, "groups/")
		if err := d.Set("group_id", groupID); err != nil {
			return diag.FromErr(err)
		}
	} else if len(policy.PolicyQuery) > 0 && string(policy.PolicyQuery) != "null" {
		if err := d.Set("policy_query", normalizeJSON(string(policy.PolicyQuery))); err != nil {
			return diag.FromErr(err)
		}
	} else {
		return diag.Errorf("policy %q does not contain a supported policyQuery scope", d.Id())
	}
	if len(policy.Setting.Value) == 0 || string(policy.Setting.Value) == "null" {
		return diag.Errorf("policy %q returned an empty DLP setting value", d.Id())
	}
	if err := d.Set("setting_value", normalizeDlpSettingValue(string(policy.Setting.Value))); err != nil {
		return diag.FromErr(err)
	}
	return nil
}

func resourceDlpRuleUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*apiClient)
	payload, err := dlpPolicyPayload(client.Customer, d.Get("org_unit_id").(string), d.Get("group_id").(string), d.Get("policy_query").(string), d.Get("setting_value").(string))
	if err != nil {
		return diag.FromErr(err)
	}
	patchPayload := map[string]interface{}{
		"policyQuery": payload["policyQuery"],
		"setting":     payload["setting"],
	}

	var operation policyOperation
	if err := client.callPolicyAPI(ctx, http.MethodPatch, "/"+policyPath(d.Id()), nil, patchPayload, &operation); err != nil {
		return diag.FromErr(err)
	}
	if err := client.waitPolicyOperation(ctx, &operation, d.Timeout(schema.TimeoutUpdate)); err != nil {
		return diag.FromErr(err)
	}
	return resourceDlpRuleRead(ctx, d, meta)
}

func resourceDlpRuleDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*apiClient)
	var operation policyOperation
	err := client.callPolicyAPI(ctx, http.MethodDelete, "/"+policyPath(d.Id()), nil, nil, &operation)
	if err != nil {
		if apiErr, ok := err.(*policyAPIError); ok && apiErr.StatusCode == http.StatusNotFound {
			d.SetId("")
			return nil
		}
		return diag.FromErr(err)
	}
	if err := client.waitPolicyOperation(ctx, &operation, d.Timeout(schema.TimeoutDelete)); err != nil {
		return diag.FromErr(err)
	}
	d.SetId("")
	return nil
}

func dlpPolicyPayload(customer, orgUnitID, groupID, policyQueryJSON, settingValue string) (map[string]interface{}, error) {
	decoded, err := decodeJSON(settingValue)
	if err != nil {
		return nil, fmt.Errorf("setting_value must be a JSON object: %w", err)
	}
	value, ok := decoded.(map[string]interface{})
	if !ok || value == nil {
		return nil, fmt.Errorf("setting_value must be a JSON object")
	}

	if err := validateDlpRecipients(value); err != nil {
		return nil, err
	}
	// Workspace owns these timestamps; do not send them on create or update.
	delete(value, "createTime")
	delete(value, "updateTime")

	orgUnitID = strings.TrimPrefix(orgUnitID, "orgUnits/")
	orgUnitID = strings.TrimPrefix(orgUnitID, "id:")
	groupID = strings.TrimPrefix(groupID, "groups/")
	groupID = strings.TrimPrefix(groupID, "id:")
	scopeCount := 0
	if orgUnitID != "" {
		scopeCount++
	}
	if groupID != "" {
		scopeCount++
	}
	if policyQueryJSON != "" {
		scopeCount++
	}
	if scopeCount != 1 {
		return nil, fmt.Errorf("exactly one of org_unit_id, group_id, or policy_query must be set")
	}
	if customer == "" {
		return nil, fmt.Errorf("provider customer_id must not be empty")
	}
	policyQuery := map[string]interface{}{}
	if policyQueryJSON != "" {
		decodedQuery, err := decodeJSON(policyQueryJSON)
		if err != nil {
			return nil, fmt.Errorf("policy_query must be a JSON object: %w", err)
		}
		var ok bool
		policyQuery, ok = decodedQuery.(map[string]interface{})
		if !ok || policyQuery == nil {
			return nil, fmt.Errorf("policy_query must be a JSON object")
		}
	} else if orgUnitID != "" {
		policyQuery["orgUnit"] = "orgUnits/" + orgUnitID
	} else {
		policyQuery["group"] = "groups/" + groupID
	}
	// sortOrder is returned by GET but is output-only, not part of the scope
	// accepted by mutations. Keep the configured query intact in Terraform.
	delete(policyQuery, "sortOrder")
	return map[string]interface{}{
		"customer":    "customers/" + customer,
		"policyQuery": policyQuery,
		"setting": map[string]interface{}{
			"type":  dlpRuleSettingType,
			"value": value,
		},
	}, nil
}

func validateDlpSettingValue(raw interface{}, key string) ([]string, []error) {
	decoded, err := decodeJSON(raw.(string))
	if err != nil {
		return nil, []error{fmt.Errorf("%s must be a JSON object: %w", key, err)}
	}
	value, ok := decoded.(map[string]interface{})
	if !ok || value == nil {
		return nil, []error{fmt.Errorf("%s must be a JSON object", key)}
	}
	if err := validateDlpRecipients(value); err != nil {
		return nil, []error{err}
	}
	return nil, nil
}

func validateDlpRecipients(value map[string]interface{}) error {
	action, _ := value["action"].(map[string]interface{})
	alert, _ := action["alertCenterAction"].(map[string]interface{})
	recipients, _ := alert["recipients"].([]interface{})
	if len(recipients) > 10 {
		return fmt.Errorf("setting_value.action.alertCenterAction.recipients has %d entries; Google Workspace DLP supports at most 10 recipients per rule. Use a Google Group email address to notify more users", len(recipients))
	}
	return nil
}

func diffSuppressOrgUnitPath(k, old, new string, d *schema.ResourceData) bool {
	normalize := func(value string) string {
		value = strings.TrimPrefix(value, "orgUnits/")
		return strings.TrimPrefix(value, "id:")
	}
	return normalize(old) == normalize(new)
}

func normalizeJSONState(value interface{}) string {
	return normalizeJSON(value.(string))
}

func normalizeDlpSettingValue(value string) string {
	decoded, err := decodeJSON(value)
	if err != nil {
		return normalizeJSON(value)
	}
	setting, ok := decoded.(map[string]interface{})
	if !ok {
		return normalizeJSON(value)
	}
	// These timestamps are generated by Workspace and should not be configured
	// or sent back in setting.value updates.
	delete(setting, "createTime")
	delete(setting, "updateTime")
	canonical, err := json.Marshal(setting)
	if err != nil {
		return normalizeJSON(value)
	}
	return string(canonical)
}

func normalizeJSON(value string) string {
	decoded, err := decodeJSON(value)
	if err != nil {
		return value
	}
	canonical, err := json.Marshal(decoded)
	if err != nil {
		return value
	}
	return string(canonical)
}

func decodeJSON(value string) (interface{}, error) {
	decoder := json.NewDecoder(strings.NewReader(value))
	decoder.UseNumber()
	var decoded interface{}
	if err := decoder.Decode(&decoded); err != nil {
		return nil, err
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("unexpected trailing JSON value")
		}
		return nil, err
	}
	return decoded, nil
}

func policyPath(name string) string {
	parts := strings.Split(strings.Trim(name, "/"), "/")
	for i, part := range parts {
		parts[i] = url.PathEscape(part)
	}
	return strings.Join(parts, "/")
}

func (c *apiClient) policyAPIURL() string {
	baseURL := c.PolicyAPIBaseURL
	if baseURL == "" {
		baseURL = cloudIdentityPolicyAPI
	}
	return strings.TrimRight(baseURL, "/")
}

func (c *apiClient) callPolicyAPI(ctx context.Context, method, path string, query url.Values, body interface{}, result interface{}) error {
	endpoint := c.policyAPIURL() + "/" + strings.TrimLeft(path, "/")
	if query != nil {
		endpoint += "?" + query.Encode()
	}

	var requestBody *bytes.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encoding Cloud Identity Policy API request: %w", err)
		}
		requestBody = bytes.NewReader(encoded)
	} else {
		requestBody = bytes.NewReader(nil)
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint, requestBody)
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	if c.client == nil {
		return fmt.Errorf("Google API client is not configured")
	}

	response, err := c.client.Do(request)
	if err != nil {
		return fmt.Errorf("calling Cloud Identity Policy API: %w", err)
	}
	defer response.Body.Close()
	responseBytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("reading Cloud Identity Policy API response: %w", err)
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		message := strings.TrimSpace(string(responseBytes))
		var apiResponse struct {
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(responseBytes, &apiResponse) == nil && apiResponse.Error.Message != "" {
			message = apiResponse.Error.Message
		}
		return &policyAPIError{StatusCode: response.StatusCode, Message: message}
	}
	if result != nil && len(responseBytes) > 0 {
		if err := json.Unmarshal(responseBytes, result); err != nil {
			return fmt.Errorf("decoding Cloud Identity Policy API response: %w", err)
		}
	}
	return nil
}

func (c *apiClient) waitPolicyOperation(ctx context.Context, operation *policyOperation, timeout time.Duration) error {
	if operation.Done {
		return policyOperationResultError(*operation)
	}
	if operation.Name == "" {
		return fmt.Errorf("Cloud Identity Policy API returned an operation without a name")
	}
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-waitCtx.Done():
			return fmt.Errorf("timed out waiting for Cloud Identity Policy API operation %q: %w", operation.Name, waitCtx.Err())
		case <-ticker.C:
			var current policyOperation
			if err := c.callPolicyAPI(waitCtx, http.MethodGet, "/"+policyPath(operation.Name), nil, nil, &current); err != nil {
				return fmt.Errorf("checking Cloud Identity Policy API operation %q: %w", operation.Name, err)
			}
			if current.Done {
				*operation = current
				return policyOperationResultError(current)
			}
		}
	}
}

func policyOperationResultError(operation policyOperation) error {
	if operation.Error != nil {
		if operation.Error.Message != "" {
			return fmt.Errorf("Cloud Identity Policy API operation failed (%d): %s", operation.Error.Code, operation.Error.Message)
		}
		if len(operation.Error.Details) > 0 {
			details, err := json.Marshal(operation.Error.Details)
			if err == nil {
				return fmt.Errorf("Cloud Identity Policy API operation failed (%d), details: %s", operation.Error.Code, details)
			}
		}
		return fmt.Errorf("Cloud Identity Policy API operation failed (%d) without a message", operation.Error.Code)
	}
	return nil
}

func operationPolicyName(response json.RawMessage) (string, error) {
	if len(response) == 0 || string(response) == "null" {
		return "", fmt.Errorf("operation response was empty")
	}
	var policy struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(response, &policy); err != nil {
		return "", err
	}
	if !strings.HasPrefix(policy.Name, "policies/") || strings.ContainsAny(policy.Name, "?\\#") {
		return "", fmt.Errorf("operation response did not contain a valid policies/{policy} name")
	}
	return policy.Name, nil
}
