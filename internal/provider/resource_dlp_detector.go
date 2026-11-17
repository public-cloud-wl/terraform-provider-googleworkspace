// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package googleworkspace

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

var supportedDlpDetectorTypes = map[string]struct{}{
	"settings/detector.url_list":           {},
	"settings/detector.regular_expression": {},
	"settings/detector.word_list":          {},
}

func resourceDlpDetector() *schema.Resource {
	return &schema.Resource{
		Description: "Manages a Google Workspace DLP detector using the Cloud Identity Policy API. " +
			"The detector setting is supplied as JSON so detector-specific fields can evolve with the API.",

		CreateContext: resourceDlpDetectorCreate,
		ReadContext:   resourceDlpDetectorRead,
		UpdateContext: resourceDlpDetectorUpdate,
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
				Description: "ID of the Workspace organization-wide DLP scope or an organizational unit to which the detector applies. " +
					"Use `googleworkspace_dlp_organization_scope` to look up the organization-wide scope. Accepts the raw ID or `orgUnits/{id}`. " +
					"Exactly one of `org_unit_id`, `group_id`, or `policy_query` is required; the scope is immutable.",
				Type:             schema.TypeString,
				Optional:         true,
				ForceNew:         true,
				DiffSuppressFunc: diffSuppressOrgUnitPath,
			},
			"group_id": {
				Description: "Google Workspace group ID targeted by the detector. Accepts the raw ID or `groups/{id}`. " +
					"Exactly one of `group_id`, `org_unit_id`, or `policy_query` is required; the scope is immutable.",
				Type:             schema.TypeString,
				Optional:         true,
				ForceNew:         true,
				DiffSuppressFunc: diffSuppressChromeGroupId,
			},
			"policy_query": {
				Description:      "JSON object containing an advanced Cloud Identity Policy query scope. Use this instead of `org_unit_id` or `group_id` for CEL-scoped detectors. The scope is immutable.",
				Type:             schema.TypeString,
				Optional:         true,
				ForceNew:         true,
				StateFunc:        normalizeJSONState,
				ValidateDiagFunc: validation.ToDiagFunc(validation.StringIsJSON),
			},
			"setting_type": {
				Description: "Cloud Identity Policy detector setting type. Supported values are URL lists, regular expressions, and word lists.",
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				ValidateDiagFunc: validation.ToDiagFunc(validation.StringInSlice([]string{
					"settings/detector.url_list",
					"settings/detector.regular_expression",
					"settings/detector.word_list",
				}, false)),
			},
			"setting_value": {
				Description:      "JSON object for the detector's `setting.value`.",
				Type:             schema.TypeString,
				Required:         true,
				StateFunc:        normalizeJSONState,
				ValidateDiagFunc: validation.ToDiagFunc(validation.StringIsJSON),
			},
		},
	}
}

func resourceDlpDetectorCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*apiClient)
	payload, err := dlpDetectorPolicyPayload(
		client.Customer,
		d.Get("org_unit_id").(string),
		d.Get("group_id").(string),
		d.Get("policy_query").(string),
		d.Get("setting_type").(string),
		d.Get("setting_value").(string),
	)
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
		return diag.Errorf("DLP detector create operation completed but did not return the created policy name: %s", err)
	}
	d.SetId(policyName)
	return resourceDlpDetectorRead(ctx, d, meta)
}

func resourceDlpDetectorRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
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

	if err := client.callPolicyAPI(ctx, http.MethodGet, "/"+policyPath(d.Id()), nil, nil, &policy); err != nil {
		if apiErr, ok := err.(*policyAPIError); ok && apiErr.StatusCode == http.StatusNotFound {
			d.SetId("")
			return nil
		}
		return diag.FromErr(err)
	}
	if _, ok := supportedDlpDetectorTypes[policy.Setting.Type]; !ok {
		return diag.Errorf("policy %q has unsupported detector setting type %q", d.Id(), policy.Setting.Type)
	}
	if configuredType := d.Get("setting_type").(string); configuredType != "" && configuredType != policy.Setting.Type {
		return diag.Errorf("policy %q has detector setting type %q, not configured type %q", d.Id(), policy.Setting.Type, configuredType)
	}
	if policy.Customer != "" && policy.Customer != "customers/"+client.Customer {
		return diag.Errorf("policy %q belongs to customer %q, not configured customer %q", d.Id(), policy.Customer, client.Customer)
	}
	if len(policy.Setting.Value) == 0 || string(policy.Setting.Value) == "null" {
		return diag.Errorf("policy %q returned an empty detector setting value", d.Id())
	}

	var query struct {
		OrgUnit string `json:"orgUnit"`
		Group   string `json:"group"`
		CEL     string `json:"query"`
	}
	if err := json.Unmarshal(policy.PolicyQuery, &query); err != nil {
		return diag.Errorf("policy %q returned an invalid policyQuery: %s", d.Id(), err)
	}
	switch {
	case query.CEL != "":
		if err := d.Set("policy_query", normalizeJSON(string(policy.PolicyQuery))); err != nil {
			return diag.FromErr(err)
		}
	case query.OrgUnit != "":
		if err := d.Set("org_unit_id", strings.TrimPrefix(query.OrgUnit, "orgUnits/")); err != nil {
			return diag.FromErr(err)
		}
	case query.Group != "":
		if err := d.Set("group_id", strings.TrimPrefix(query.Group, "groups/")); err != nil {
			return diag.FromErr(err)
		}
	case len(policy.PolicyQuery) > 0 && string(policy.PolicyQuery) != "null":
		if err := d.Set("policy_query", normalizeJSON(string(policy.PolicyQuery))); err != nil {
			return diag.FromErr(err)
		}
	default:
		return diag.Errorf("policy %q does not contain a supported policyQuery scope", d.Id())
	}

	if err := d.Set("setting_type", policy.Setting.Type); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("setting_value", normalizeDlpSettingValue(string(policy.Setting.Value))); err != nil {
		return diag.FromErr(err)
	}
	return nil
}

func resourceDlpDetectorUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*apiClient)
	payload, err := dlpDetectorPolicyPayload(
		client.Customer,
		d.Get("org_unit_id").(string),
		d.Get("group_id").(string),
		d.Get("policy_query").(string),
		d.Get("setting_type").(string),
		d.Get("setting_value").(string),
	)
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
	return resourceDlpDetectorRead(ctx, d, meta)
}

func dlpDetectorPolicyPayload(customer, orgUnitID, groupID, policyQueryJSON, settingType, settingValue string) (map[string]interface{}, error) {
	if _, ok := supportedDlpDetectorTypes[settingType]; !ok {
		return nil, fmt.Errorf("unsupported DLP detector setting type %q", settingType)
	}
	decoded, err := decodeJSON(settingValue)
	if err != nil {
		return nil, fmt.Errorf("setting_value must be a JSON object: %w", err)
	}
	value, ok := decoded.(map[string]interface{})
	if !ok || value == nil {
		return nil, fmt.Errorf("setting_value must be a JSON object")
	}
	delete(value, "createTime")
	delete(value, "updateTime")

	orgUnitID = strings.TrimPrefix(strings.TrimPrefix(orgUnitID, "orgUnits/"), "id:")
	groupID = strings.TrimPrefix(strings.TrimPrefix(groupID, "groups/"), "id:")
	scopeCount := 0
	for _, scope := range []string{orgUnitID, groupID, policyQueryJSON} {
		if scope != "" {
			scopeCount++
		}
	}
	if scopeCount != 1 {
		return nil, fmt.Errorf("exactly one of org_unit_id, group_id, or policy_query must be set")
	}
	if customer == "" {
		return nil, fmt.Errorf("provider customer_id must not be empty")
	}

	policyQuery := map[string]interface{}{}
	switch {
	case policyQueryJSON != "":
		decodedQuery, err := decodeJSON(policyQueryJSON)
		if err != nil {
			return nil, fmt.Errorf("policy_query must be a JSON object: %w", err)
		}
		var ok bool
		policyQuery, ok = decodedQuery.(map[string]interface{})
		if !ok || policyQuery == nil {
			return nil, fmt.Errorf("policy_query must be a JSON object")
		}
	case orgUnitID != "":
		policyQuery["orgUnit"] = "orgUnits/" + orgUnitID
	default:
		policyQuery["group"] = "groups/" + groupID
	}
	delete(policyQuery, "sortOrder")

	return map[string]interface{}{
		"customer":    "customers/" + customer,
		"policyQuery": policyQuery,
		"setting": map[string]interface{}{
			"type":  settingType,
			"value": value,
		},
	}, nil
}
