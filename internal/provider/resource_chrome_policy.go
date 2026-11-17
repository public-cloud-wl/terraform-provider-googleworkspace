// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package googleworkspace

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"google.golang.org/api/chromepolicy/v1"
	"google.golang.org/api/googleapi"
)

func resourceChromePolicy() *schema.Resource {
	return &schema.Resource{
		Description: "Chrome Policy resource in the Terraform Googleworkspace provider. " +
			"Supports organizational unit and group targets, and currently only policies not requiring additionalTargetKeys. Chrome Policy Schema " +
			"resides under the `https://www.googleapis.com/auth/chrome.management.policy` client scope.",

		CreateContext: resourceChromePolicyCreate,
		UpdateContext: resourceChromePolicyUpdate,
		ReadContext:   resourceChromePolicyRead,
		DeleteContext: resourceChromePolicyDelete,

		Schema: map[string]*schema.Schema{
			"org_unit_id": {
				Description:      "The target org unit on which this policy is applied. Exactly one of `org_unit_id` or `group_id` must be set.",
				Type:             schema.TypeString,
				Optional:         true,
				ForceNew:         true,
				ExactlyOneOf:     []string{"org_unit_id", "group_id"},
				DiffSuppressFunc: diffSuppressOrgUnitId,
			},
			"group_id": {
				Description:      "The Google Workspace group ID receiving this policy override. Exactly one of `group_id` or `org_unit_id` must be set.",
				Type:             schema.TypeString,
				Optional:         true,
				ForceNew:         true,
				ExactlyOneOf:     []string{"org_unit_id", "group_id"},
				DiffSuppressFunc: diffSuppressChromeGroupId,
			},
			"policies": {
				Description: "Policies to set for the selected org unit or group target",
				Type:        schema.TypeList,
				Required:    true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"schema_name": {
							Description: "The full qualified name of the policy schema.",
							Type:        schema.TypeString,
							Required:    true,
						},
						"schema_values": {
							Description: "JSON encoded map that represents key/value pairs that " +
								"correspond to the given schema. ",
							Type:     schema.TypeMap,
							Required: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
								ValidateDiagFunc: validation.ToDiagFunc(
									validation.StringIsJSON,
								),
							},
						},
					},
				},
			},
		},
	}
}

func resourceChromePolicyCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*apiClient)

	chromePolicyService, diags := client.NewChromePolicyService()
	if diags.HasError() {
		return diags
	}

	chromePoliciesService, diags := GetChromePoliciesService(chromePolicyService)
	if diags.HasError() {
		return diags
	}

	targetResource := chromePolicyTargetResource(d)
	log.Printf("[DEBUG] Creating Chrome Policy for target:%s", targetResource)

	policyTargetKey := &chromepolicy.GoogleChromePolicyV1PolicyTargetKey{
		TargetResource: targetResource,
	}

	diags = validateChromePolicies(ctx, d, client)
	if diags.HasError() {
		return diags
	}

	policies, diags := expandChromePoliciesValues(d.Get("policies").([]interface{}))
	if diags.HasError() {
		return diags
	}

	var requests []*chromepolicy.GoogleChromePolicyV1ModifyOrgUnitPolicyRequest
	for _, p := range policies {
		var keys []string
		var schemaValues map[string]interface{}
		if err := json.Unmarshal(p.Value, &schemaValues); err != nil {
			return diag.FromErr(err)
		}
		for key := range schemaValues {
			keys = append(keys, key)
		}
		requests = append(requests, &chromepolicy.GoogleChromePolicyV1ModifyOrgUnitPolicyRequest{
			PolicyTargetKey: policyTargetKey,
			PolicyValue:     p,
			UpdateMask:      strings.Join(keys, ","),
		})
	}

	var err error
	if d.Get("group_id").(string) != "" {
		err = retryTimeDuration(ctx, time.Minute, func() error {
			return client.batchModifyChromeGroupPolicies(ctx, targetResource, requests)
		})
	} else {
		err = retryTimeDuration(ctx, time.Minute, func() error {
			_, retryErr := chromePoliciesService.Orgunits.BatchModify(fmt.Sprintf("customers/%s", client.Customer), &chromepolicy.GoogleChromePolicyV1BatchModifyOrgUnitPoliciesRequest{Requests: requests}).Do()
			return retryErr
		})
	}
	if err != nil {
		return diag.FromErr(err)
	}

	log.Printf("[DEBUG] Finished creating Chrome Policy for target:%s", targetResource)
	if d.Get("group_id").(string) != "" {
		d.SetId(targetResource)
	} else {
		d.SetId(strings.TrimPrefix(d.Get("org_unit_id").(string), "id:"))
	}

	return resourceChromePolicyRead(ctx, d, meta)
}

func resourceChromePolicyUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*apiClient)

	chromePolicyService, diags := client.NewChromePolicyService()
	if diags.HasError() {
		return diags
	}

	chromePoliciesService, diags := GetChromePoliciesService(chromePolicyService)
	if diags.HasError() {
		return diags
	}

	targetResource := chromePolicyTargetResource(d)
	log.Printf("[DEBUG] Updating Chrome Policy for target:%s", targetResource)

	policyTargetKey := &chromepolicy.GoogleChromePolicyV1PolicyTargetKey{
		TargetResource: targetResource,
	}

	// Update is achieved by inheriting defaults for the previous policySchemas, and then applying the new set
	old, _ := d.GetChange("policies")

	var requests []*chromepolicy.GoogleChromePolicyV1InheritOrgUnitPolicyRequest
	for _, p := range old.([]interface{}) {
		policy := p.(map[string]interface{})
		schemaName := policy["schema_name"].(string)

		requests = append(requests, &chromepolicy.GoogleChromePolicyV1InheritOrgUnitPolicyRequest{
			PolicyTargetKey: policyTargetKey,
			PolicySchema:    schemaName,
		})
	}

	var err error
	if d.Get("group_id").(string) != "" {
		var schemaNames []string
		for _, request := range requests {
			schemaNames = append(schemaNames, request.PolicySchema)
		}
		err = retryTimeDuration(ctx, time.Minute, func() error {
			return client.batchDeleteChromeGroupPolicies(ctx, targetResource, schemaNames)
		})
	} else {
		err = retryTimeDuration(ctx, time.Minute, func() error {
			_, retryErr := chromePoliciesService.Orgunits.BatchInherit(fmt.Sprintf("customers/%s", client.Customer), &chromepolicy.GoogleChromePolicyV1BatchInheritOrgUnitPoliciesRequest{Requests: requests}).Do()
			return retryErr
		})
	}
	if err != nil {
		return diag.FromErr(err)
	}

	// run create
	diags = resourceChromePolicyCreate(ctx, d, meta)
	if diags.HasError() {
		return diags
	}

	log.Printf("[DEBUG] Finished Updating Chrome Policy for target:%s", targetResource)

	return diags
}

func resourceChromePolicyRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*apiClient)

	chromePolicyService, diags := client.NewChromePolicyService()
	if diags.HasError() {
		return diags
	}

	chromePoliciesService, diags := GetChromePoliciesService(chromePolicyService)
	if diags.HasError() {
		return diags
	}

	targetResource := chromePolicyTargetResource(d)
	log.Printf("[DEBUG] Getting Chrome Policy for target:%s", targetResource)

	policyTargetKey := &chromepolicy.GoogleChromePolicyV1PolicyTargetKey{
		TargetResource: targetResource,
	}

	policiesObj := []*chromepolicy.GoogleChromePolicyV1PolicyValue{}
	for _, p := range d.Get("policies").([]interface{}) {
		policy := p.(map[string]interface{})
		schemaName := policy["schema_name"].(string)

		var resp *chromepolicy.GoogleChromePolicyV1ResolveResponse
		err := retryTimeDuration(ctx, time.Minute, func() error {
			var retryErr error

			// we will resolve each individual policySchema by fully qualified name, so the responses should be a single result
			resp, retryErr = chromePoliciesService.Resolve(fmt.Sprintf("customers/%s", client.Customer), &chromepolicy.GoogleChromePolicyV1ResolveRequest{
				PolicySchemaFilter: schemaName,
				PolicyTargetKey:    policyTargetKey,
			}).Do()

			return retryErr
		})
		if err != nil {
			return diag.FromErr(err)
		}

		if len(resp.ResolvedPolicies) != 1 {
			return diag.Errorf("unexpected number of resolved policies for schema: %s", schemaName)
		}

		value := resp.ResolvedPolicies[0].Value

		policiesObj = append(policiesObj, value)
	}

	policies, diags := flattenChromePolicies(ctx, policiesObj, client)
	if diags.HasError() {
		return diags
	}

	if err := d.Set("policies", policies); err != nil {
		return diag.FromErr(err)
	}

	log.Printf("[DEBUG] Finished getting Chrome Policy for target:%s", targetResource)
	return nil
}

func resourceChromePolicyDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*apiClient)

	chromePolicyService, diags := client.NewChromePolicyService()
	if diags.HasError() {
		return diags
	}

	chromePoliciesService, diags := GetChromePoliciesService(chromePolicyService)
	if diags.HasError() {
		return diags
	}

	targetResource := chromePolicyTargetResource(d)
	log.Printf("[DEBUG] Deleting Chrome Policy for target:%s", targetResource)

	policyTargetKey := &chromepolicy.GoogleChromePolicyV1PolicyTargetKey{
		TargetResource: targetResource,
	}

	var requests []*chromepolicy.GoogleChromePolicyV1InheritOrgUnitPolicyRequest
	for _, p := range d.Get("policies").([]interface{}) {
		policy := p.(map[string]interface{})
		schemaName := policy["schema_name"].(string)

		requests = append(requests, &chromepolicy.GoogleChromePolicyV1InheritOrgUnitPolicyRequest{
			PolicyTargetKey: policyTargetKey,
			PolicySchema:    schemaName,
		})
	}

	var err error
	if d.Get("group_id").(string) != "" {
		var schemaNames []string
		for _, request := range requests {
			schemaNames = append(schemaNames, request.PolicySchema)
		}
		err = retryTimeDuration(ctx, time.Minute, func() error {
			return client.batchDeleteChromeGroupPolicies(ctx, targetResource, schemaNames)
		})
	} else {
		err = retryTimeDuration(ctx, time.Minute, func() error {
			_, retryErr := chromePoliciesService.Orgunits.BatchInherit(fmt.Sprintf("customers/%s", client.Customer), &chromepolicy.GoogleChromePolicyV1BatchInheritOrgUnitPoliciesRequest{Requests: requests}).Do()
			return retryErr
		})
	}
	if err != nil {
		return diag.FromErr(err)
	}

	log.Printf("[DEBUG] Finished deleting Chrome Policy for target:%s", targetResource)
	return nil
}

// Chrome Policies

const chromeDataControlsRulesSchemaName = "chrome.users.DataControlsRules"

func chromePolicySchemaLookupDiagnostics(schemaName, customer string, err error) diag.Diagnostics {
	var apiErr *googleapi.Error
	if schemaName == chromeDataControlsRulesSchemaName && errors.As(err, &apiErr) && apiErr.Code == 404 {
		return diag.Errorf("Chrome policy schema %q is not available for customer %q. Google documents DataControlsRules as available only to users assigned a Chrome Enterprise Premium license. Verify licensing and feature availability for the target users/customer; the provider cannot apply this policy until Google exposes the schema. Original error: %s", schemaName, customer, err)
	}
	return diag.FromErr(err)
}

func validateChromePolicies(ctx context.Context, d *schema.ResourceData, client *apiClient) diag.Diagnostics {
	var diags diag.Diagnostics

	new := d.Get("policies")

	chromePolicyService, diags := client.NewChromePolicyService()
	if diags.HasError() {
		return diags
	}

	chromePolicySchemasService, diags := GetChromePolicySchemasService(chromePolicyService)
	if diags.HasError() {
		return diags
	}

	// Validate config against schemas
	for _, policy := range new.([]interface{}) {
		schemaName := policy.(map[string]interface{})["schema_name"].(string)

		var schemaDef *chromepolicy.GoogleChromePolicyV1PolicySchema
		err := retryTimeDuration(ctx, time.Minute, func() error {
			var retryErr error

			schemaDef, retryErr = chromePolicySchemasService.Get(fmt.Sprintf("customers/%s/policySchemas/%s", client.Customer, schemaName)).Do()
			return retryErr
		})
		if err != nil {
			return chromePolicySchemaLookupDiagnostics(schemaName, client.Customer, err)
		}

		if schemaDef == nil || schemaDef.Definition == nil || schemaDef.Definition.MessageType == nil {
			return append(diags, diag.Diagnostic{
				Summary:  fmt.Sprintf("schema definition (%s) is empty", schemaName),
				Severity: diag.Error,
			})
		}

		schemaFieldMap := map[string][]*chromepolicy.Proto2FieldDescriptorProto{}
		for _, schemaField := range schemaDef.Definition.MessageType {
			for _, schemaNestedField := range schemaField.Field {
				schemaFieldMap[schemaNestedField.Name] = schemaField.Field
			}
		}

		policyDef := policy.(map[string]interface{})["schema_values"].(map[string]interface{})

		for polKey, polJsonVal := range policyDef {
			if _, ok := schemaFieldMap[polKey]; !ok {
				return append(diags, diag.Diagnostic{
					Summary:  fmt.Sprintf("field name (%s) is not found in this schema definition (%s)", polKey, schemaName),
					Severity: diag.Error,
				})
			}

			var polVal interface{}
			err := json.Unmarshal([]byte(polJsonVal.(string)), &polVal)
			if err != nil {
				return diag.FromErr(err)
			}

			for _, schemaField := range schemaFieldMap[polKey] {

				if schemaField == nil {
					return append(diags, diag.Diagnostic{
						Summary:  fmt.Sprintf("field type is not defined for field name (%s)", polKey),
						Severity: diag.Warning,
					})
				}

				validType := validatePolicyFieldValueType(schemaField.Type, schemaField.Label, polVal)
				if !validType {
					return append(diags, diag.Diagnostic{
						Summary:  fmt.Sprintf("value provided for %s is of incorrect type (expected type: %s)", schemaField.Name, schemaField.Type),
						Severity: diag.Error,
					})
				}
			}
		}
	}

	return nil
}

// This will take a value and validate whether the type is correct
func validatePolicyFieldValueType(fieldType, fieldLabel string, fieldValue interface{}) bool {
	if fieldLabel == "LABEL_REPEATED" {
		values := reflect.ValueOf(fieldValue)
		if values.Kind() != reflect.Slice && values.Kind() != reflect.Array {
			return false
		}
		for i := 0; i < values.Len(); i++ {
			if !validatePolicyFieldValueType(fieldType, "", values.Index(i).Interface()) {
				return false
			}
		}
		return true
	}

	valid := false

	switch fieldType {
	case "TYPE_BOOL":
		valid = reflect.ValueOf(fieldValue).Kind() == reflect.Bool
	case "TYPE_FLOAT":
		fallthrough
	case "TYPE_DOUBLE":
		valid = reflect.ValueOf(fieldValue).Kind() == reflect.Float64
	case "TYPE_INT64":
		fallthrough
	case "TYPE_FIXED64":
		fallthrough
	case "TYPE_SFIXED64":
		fallthrough
	case "TYPE_SINT64":
		fallthrough
	case "TYPE_UINT64":
		// this is unmarshalled as a float, check that it's an int
		if reflect.ValueOf(fieldValue).Kind() == reflect.Float64 &&
			fieldValue == float64(int(fieldValue.(float64))) {
			valid = true
		}
	case "TYPE_INT32":
		fallthrough
	case "TYPE_FIXED32":
		fallthrough
	case "TYPE_SFIXED32":
		fallthrough
	case "TYPE_SINT32":
		fallthrough
	case "TYPE_UINT32":
		// this is unmarshalled as a float, check that it's an int
		if reflect.ValueOf(fieldValue).Kind() == reflect.Float32 &&
			fieldValue == float32(int(fieldValue.(float32))) {
			valid = true
		}
	case "TYPE_MESSAGE":
		valid = reflect.ValueOf(fieldValue).Kind() == reflect.Map
		// TODO we should probably recursively ensure the type is correct
	case "TYPE_ENUM":
		fallthrough
	case "TYPE_STRING":
		fallthrough
	default:
		valid = reflect.ValueOf(fieldValue).Kind() == reflect.String
	}

	return valid
}

// The API returns numeric values as strings. This will convert it to the appropriate type
func convertPolicyFieldValueType(fieldType string, fieldValue interface{}) (interface{}, error) {
	// If it's not of type string, then we'll assume it's the right type
	if reflect.ValueOf(fieldValue).Kind() != reflect.String {
		return fieldValue, nil
	}

	var err error
	var value interface{}

	switch fieldType {
	case "TYPE_BOOL":
		value, err = strconv.ParseBool(fieldValue.(string))
	case "TYPE_FLOAT":
		fallthrough
	case "TYPE_DOUBLE":
		value, err = strconv.ParseFloat(fieldValue.(string), 64)
	case "TYPE_INT64":
		fallthrough
	case "TYPE_FIXED64":
		fallthrough
	case "TYPE_SFIXED64":
		fallthrough
	case "TYPE_SINT64":
		fallthrough
	case "TYPE_UINT64":
		value, err = strconv.ParseInt(fieldValue.(string), 10, 64)
	case "TYPE_INT32":
		fallthrough
	case "TYPE_FIXED32":
		fallthrough
	case "TYPE_SFIXED32":
		fallthrough
	case "TYPE_SINT32":
		fallthrough
	case "TYPE_UINT32":
		value, err = strconv.ParseInt(fieldValue.(string), 10, 32)
	case "TYPE_ENUM":
		fallthrough
	case "TYPE_MESSAGE":
		fallthrough
	case "TYPE_STRING":
		fallthrough
	default:
		value = fieldValue
	}

	return value, err
}

func expandChromePoliciesValues(policies []interface{}) ([]*chromepolicy.GoogleChromePolicyV1PolicyValue, diag.Diagnostics) {
	var diags diag.Diagnostics
	result := []*chromepolicy.GoogleChromePolicyV1PolicyValue{}

	for _, p := range policies {
		policy := p.(map[string]interface{})

		schemaName := policy["schema_name"].(string)
		schemaValues := policy["schema_values"].(map[string]interface{})

		policyValuesObj := map[string]interface{}{}

		for k, v := range schemaValues {
			var polVal interface{}
			err := json.Unmarshal([]byte(v.(string)), &polVal)
			if err != nil {
				return nil, diag.FromErr(err)
			}

			policyValuesObj[k] = polVal
		}

		// create the json object and assign to the schema
		schemaValuesJson, err := json.Marshal(policyValuesObj)
		if err != nil {
			return nil, diag.FromErr(err)
		}

		policyObj := chromepolicy.GoogleChromePolicyV1PolicyValue{
			PolicySchema: schemaName,
			Value:        schemaValuesJson,
		}

		result = append(result, &policyObj)
	}

	return result, diags
}

func flattenChromePolicies(ctx context.Context, policiesObj []*chromepolicy.GoogleChromePolicyV1PolicyValue, client *apiClient) ([]map[string]interface{}, diag.Diagnostics) {
	var policies []map[string]interface{}

	chromePolicyService, diags := client.NewChromePolicyService()
	if diags.HasError() {
		return nil, diags
	}

	schemaService, diags := GetChromePolicySchemasService(chromePolicyService)
	if diags.HasError() {
		return nil, diags
	}

	for _, polObj := range policiesObj {
		var schemaDef *chromepolicy.GoogleChromePolicyV1PolicySchema
		err := retryTimeDuration(ctx, time.Minute, func() error {
			var retryErr error

			schemaDef, retryErr = schemaService.Get(fmt.Sprintf("customers/%s/policySchemas/%s", client.Customer, polObj.PolicySchema)).Do()
			return retryErr
		})
		if err != nil {
			return nil, diag.FromErr(err)
		}

		if schemaDef == nil || schemaDef.Definition == nil || schemaDef.Definition.MessageType == nil {
			return nil, append(diags, diag.Diagnostic{
				Summary:  fmt.Sprintf("schema definition (%s) is not defined", polObj.PolicySchema),
				Severity: diag.Warning,
			})
		}

		schemaFieldMap := map[string][]*chromepolicy.Proto2FieldDescriptorProto{}
		for _, schemaField := range schemaDef.Definition.MessageType {
			for _, schemaNestedField := range schemaField.Field {
				schemaFieldMap[schemaNestedField.Name] = schemaField.Field
			}
		}

		var schemaValuesObj map[string]interface{}

		err = json.Unmarshal(polObj.Value, &schemaValuesObj)
		if err != nil {
			return nil, diag.FromErr(err)
		}

		schemaValues := map[string]interface{}{}
		for k, v := range schemaValuesObj {
			if _, ok := schemaFieldMap[k]; !ok {
				return nil, append(diags, diag.Diagnostic{
					Summary:  fmt.Sprintf("field name (%s) is not found in this schema definition (%s)", k, polObj.PolicySchema),
					Severity: diag.Warning,
				})
			}

			for _, schemaField := range schemaFieldMap[k] {

				if schemaField == nil {
					return nil, append(diags, diag.Diagnostic{
						Summary:  fmt.Sprintf("field type is not defined for field name (%s)", k),
						Severity: diag.Warning,
					})
				}

				val, err := convertPolicyFieldValueType(schemaField.Type, v)
				if err != nil {
					return nil, diag.FromErr(err)
				}

				jsonVal, err := json.Marshal(val)
				if err != nil {
					return nil, diag.FromErr(err)
				}
				schemaValues[k] = string(jsonVal)
			}
		}

		policies = append(policies, map[string]interface{}{
			"schema_name":   polObj.PolicySchema,
			"schema_values": schemaValues,
		})
	}

	return policies, nil
}
