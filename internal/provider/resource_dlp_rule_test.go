// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package googleworkspace

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func TestDlpPolicyPayload(t *testing.T) {
	payload, err := dlpPolicyPayload("C123456", "orgUnits/abc123", "", "", `{"displayName":"Example"}`)
	if err != nil {
		t.Fatalf("dlpPolicyPayload returned error: %v", err)
	}
	if payload["customer"] != "customers/C123456" {
		t.Fatalf("unexpected customer: %#v", payload["customer"])
	}
	query := payload["policyQuery"].(map[string]interface{})
	if query["orgUnit"] != "orgUnits/abc123" {
		t.Fatalf("unexpected org unit: %#v", query["orgUnit"])
	}
	setting := payload["setting"].(map[string]interface{})
	if setting["type"] != dlpRuleSettingType {
		t.Fatalf("unexpected setting type: %#v", setting["type"])
	}
	if _, ok := setting["value"].(map[string]interface{}); !ok {
		t.Fatalf("setting value should be an object, got %#v", setting["value"])
	}
}

func TestDlpPolicyPayloadGroupScope(t *testing.T) {
	payload, err := dlpPolicyPayload("C123456", "", "groups/group-123", "", `{"displayName":"Example"}`)
	if err != nil {
		t.Fatalf("dlpPolicyPayload returned error: %v", err)
	}
	query := payload["policyQuery"].(map[string]interface{})
	if query["group"] != "groups/group-123" {
		t.Fatalf("unexpected group target: %#v", query["group"])
	}
	if _, ok := query["orgUnit"]; ok {
		t.Fatalf("group policy unexpectedly includes orgUnit: %#v", query)
	}
}

func TestDlpPolicyPayloadAdvancedQueryScope(t *testing.T) {
	policyQuery := `{"query":"entity.groups.exists(group, group.group_id in [groupId('group-123')])","sortOrder":1}`
	payload, err := dlpPolicyPayload("C123456", "", "", policyQuery, `{"displayName":"Query scoped"}`)
	if err != nil {
		t.Fatalf("dlpPolicyPayload returned error: %v", err)
	}
	query := payload["policyQuery"].(map[string]interface{})
	if query["query"] != "entity.groups.exists(group, group.group_id in [groupId('group-123')])" {
		t.Fatalf("unexpected advanced query: %#v", query["query"])
	}
	if _, ok := query["sortOrder"]; ok {
		t.Fatalf("mutation query contains output-only sortOrder: %#v", query)
	}
}

func TestResourceDlpRuleReadGroupScope(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/policies/group-rule" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.String())
			http.NotFound(w, r)
			return
		}
		writeJSON(t, w, map[string]interface{}{
			"name":     "policies/group-rule",
			"customer": "customers/C123456",
			"policyQuery": map[string]interface{}{
				"group": "groups/group-123",
			},
			"setting": map[string]interface{}{
				"type":  dlpRuleSettingType,
				"value": map[string]interface{}{"displayName": "Group rule"},
			},
		})
	}))
	defer server.Close()

	client := &apiClient{
		Customer:         "C123456",
		client:           server.Client(),
		PolicyAPIBaseURL: server.URL + "/v1",
	}
	d := schema.TestResourceDataRaw(t, resourceDlpRule().Schema, map[string]interface{}{
		"setting_value": `{"displayName":"Group rule"}`,
	})
	d.SetId("policies/group-rule")
	if diags := resourceDlpRuleRead(context.Background(), d, client); diags.HasError() {
		t.Fatalf("read failed: %v", diags)
	}
	if got := d.Get("group_id"); got != "group-123" {
		t.Fatalf("group_id = %#v, want group-123", got)
	}
}

func TestResourceDlpRuleReadAdvancedQueryScope(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/policies/query-rule" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.String())
			http.NotFound(w, r)
			return
		}
		writeJSON(t, w, map[string]interface{}{
			"name":     "policies/query-rule",
			"customer": "customers/C123456",
			"policyQuery": map[string]interface{}{
				"query":     "entity.groups.exists(group, group.group_id in [groupId('group-123')])",
				"sortOrder": 1,
			},
			"setting": map[string]interface{}{
				"type":  dlpRuleSettingType,
				"value": map[string]interface{}{"displayName": "Query rule"},
			},
		})
	}))
	defer server.Close()

	client := &apiClient{Customer: "C123456", client: server.Client(), PolicyAPIBaseURL: server.URL + "/v1"}
	d := schema.TestResourceDataRaw(t, resourceDlpRule().Schema, map[string]interface{}{
		"policy_query":  `{"query":"entity.groups.exists(group, group.group_id in [groupId('group-123')])","sortOrder":1}`,
		"setting_value": `{"displayName":"Query rule"}`,
	})
	d.SetId("policies/query-rule")
	if diags := resourceDlpRuleRead(context.Background(), d, client); diags.HasError() {
		t.Fatalf("read failed: %v", diags)
	}
	if got := d.Get("policy_query"); got != `{"query":"entity.groups.exists(group, group.group_id in [groupId('group-123')])","sortOrder":1}` {
		t.Fatalf("policy_query = %#v", got)
	}
}

func TestNormalizeDlpSettingValueDropsServerTimestamps(t *testing.T) {
	got := normalizeDlpSettingValue(`{"displayName":"Example","createTime":"2026-01-01T00:00:00Z","updateTime":"2026-01-02T00:00:00Z"}`)
	if got != `{"displayName":"Example"}` {
		t.Fatalf("normalizeDlpSettingValue() = %q", got)
	}
}

func TestNormalizeJSON(t *testing.T) {
	got := normalizeJSON(`{ "b": 2, "a": 1 }`)
	if got != `{"a":1,"b":2}` {
		t.Fatalf("normalizeJSON() = %q", got)
	}
	got = normalizeJSON(`{"large":1234567890123456789}`)
	if got != `{"large":1234567890123456789}` {
		t.Fatalf("normalizeJSON() lost numeric precision: %q", got)
	}
}

func TestResourceDlpRuleCRUD(t *testing.T) {
	var currentPolicy map[string]interface{}
	var deleted bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/policies":
			if err := json.NewDecoder(r.Body).Decode(&currentPolicy); err != nil {
				t.Errorf("decoding create body: %v", err)
			}
			writeJSON(t, w, map[string]interface{}{"name": "operations/create-1", "done": false})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/operations/create-1":
			writeJSON(t, w, map[string]interface{}{
				"name":     "operations/create-1",
				"done":     true,
				"response": map[string]interface{}{"name": "policies/rule-1"},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/policies/rule-1":
			if deleted {
				w.WriteHeader(http.StatusNotFound)
				writeJSON(t, w, map[string]interface{}{"error": map[string]interface{}{"message": "not found"}})
				return
			}
			currentPolicy["name"] = "policies/rule-1"
			writeJSON(t, w, currentPolicy)
		case r.Method == http.MethodPatch && r.URL.Path == "/v1/policies/rule-1":
			if got := r.URL.RawQuery; got != "" {
				t.Errorf("patch query = %q, want no query parameters", got)
			}
			var patched map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&patched); err != nil {
				t.Errorf("decoding patch body: %v", err)
			}
			for _, outputOnlyField := range []string{"name", "customer"} {
				if _, ok := patched[outputOnlyField]; ok {
					t.Errorf("patch body unexpectedly contains output-only field %q", outputOnlyField)
				}
			}
			if _, ok := patched["policyQuery"]; !ok {
				t.Error("patch body is missing the policyQuery required by the Policy API")
			}
			currentPolicy["setting"] = patched["setting"]
			writeJSON(t, w, map[string]interface{}{"name": "operations/update-1", "done": true})
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/policies/rule-1":
			deleted = true
			writeJSON(t, w, map[string]interface{}{"name": "operations/delete-1", "done": true})
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.String())
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := &apiClient{
		Customer:         "C123456",
		client:           server.Client(),
		PolicyAPIBaseURL: server.URL + "/v1",
	}
	resourceData := schema.TestResourceDataRaw(t, resourceDlpRule().Schema, map[string]interface{}{
		"org_unit_id":   "ou-1",
		"setting_value": `{"displayName":"First"}`,
	})

	if diags := resourceDlpRuleCreate(context.Background(), resourceData, client); diags.HasError() {
		t.Fatalf("create failed: %v", diags)
	}
	if got := resourceData.Id(); got != "policies/rule-1" {
		t.Fatalf("created ID = %q", got)
	}
	if got := currentPolicy["setting"].(map[string]interface{})["value"].(map[string]interface{})["displayName"]; got != "First" {
		t.Fatalf("created displayName = %#v", got)
	}

	if err := resourceData.Set("setting_value", `{"displayName":"Updated"}`); err != nil {
		t.Fatal(err)
	}
	if diags := resourceDlpRuleUpdate(context.Background(), resourceData, client); diags.HasError() {
		t.Fatalf("update failed: %v", diags)
	}
	if got := currentPolicy["setting"].(map[string]interface{})["value"].(map[string]interface{})["displayName"]; got != "Updated" {
		t.Fatalf("updated displayName = %#v", got)
	}

	if diags := resourceDlpRuleDelete(context.Background(), resourceData, client); diags.HasError() {
		t.Fatalf("delete failed: %v", diags)
	}
	if resourceData.Id() != "" {
		t.Fatalf("ID was not cleared after delete: %q", resourceData.Id())
	}
}

func TestPolicyOperationResultErrorIncludesDetails(t *testing.T) {
	operation := policyOperation{
		Error: &operationError{
			Code:    13,
			Details: []json.RawMessage{json.RawMessage(`{"reason":"backend rejected update"}`)},
		},
	}
	if err := policyOperationResultError(operation); err == nil || !strings.Contains(err.Error(), "backend rejected update") {
		t.Fatalf("policyOperationResultError() = %v, want structured details", err)
	}
}

func TestOperationPolicyName(t *testing.T) {
	name, err := operationPolicyName(json.RawMessage(`{"name":"policies/123"}`))
	if err != nil || name != "policies/123" {
		t.Fatalf("operationPolicyName() = %q, %v", name, err)
	}
	if _, err := operationPolicyName(json.RawMessage(`{"name":"operations/123"}`)); err == nil {
		t.Fatal("expected an error for non-policy operation response")
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, value interface{}) {
	t.Helper()
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Errorf("writing JSON response: %v", err)
	}
}

func TestPolicyPathEscapesSegments(t *testing.T) {
	got := policyPath("policies/a b")
	if strings.Contains(got, " ") || got != "policies/a%20b" {
		t.Fatalf("policyPath() = %q", got)
	}
}

func TestDlpSettingValueRecipientLimit(t *testing.T) {
	for _, count := range []int{0, 1, 10, 11} {
		recipients := make([]interface{}, count)
		for i := range recipients {
			recipients[i] = map[string]interface{}{"email": "user@example.com"}
		}
		encoded, err := json.Marshal(map[string]interface{}{
			"action": map[string]interface{}{"alertCenterAction": map[string]interface{}{"recipients": recipients}},
		})
		if err != nil {
			t.Fatal(err)
		}
		_, errors := validateDlpSettingValue(string(encoded), "setting_value")
		_, payloadErr := dlpPolicyPayload("C123456", "ou-1", "", "", string(encoded))
		if count <= 10 {
			if len(errors) != 0 || payloadErr != nil {
				t.Fatalf("%d recipients unexpectedly rejected: %v, %v", count, errors, payloadErr)
			}
		} else if len(errors) == 0 || payloadErr == nil || !strings.Contains(payloadErr.Error(), "at most 10") {
			t.Fatalf("%d recipients should fail both plan and mutation validation: %v, %v", count, errors, payloadErr)
		}
	}
	for _, invalid := range []string{`{`, `[]`, `null`, `{} {}`} {
		if _, errors := validateDlpSettingValue(invalid, "setting_value"); len(errors) == 0 {
			t.Errorf("invalid object %q accepted", invalid)
		}
	}
}

func TestResourceDlpRuleUpdateOmitsOutputOnlyFields(t *testing.T) {
	const query = `{"group":"groups/group-123","query":"entity.groups.exists(group, group.group_id == groupId('group-123'))","sortOrder":1}`
	const value = `{"displayName":"Example","createTime":"2026-01-01T00:00:00Z","updateTime":"2026-01-02T00:00:00Z","action":{"alertCenterAction":{"recipients":[{"email":"security@example.com"}]}}}`
	var patched map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPatch:
			if r.URL.Path != "/v1/policies/rule-1" || r.URL.RawQuery != "" {
				t.Errorf("unexpected patch URL: %s", r.URL)
			}
			if err := json.NewDecoder(r.Body).Decode(&patched); err != nil {
				t.Fatal(err)
			}
			writeJSON(t, w, map[string]interface{}{"name": "operations/update-1", "done": true})
		case http.MethodGet:
			writeJSON(t, w, map[string]interface{}{
				"customer": "customers/C123456", "policyQuery": json.RawMessage(query),
				"setting": map[string]interface{}{"type": dlpRuleSettingType, "value": json.RawMessage(value)},
			})
		default:
			t.Errorf("unexpected method: %s", r.Method)
		}
	}))
	defer server.Close()
	client := &apiClient{Customer: "C123456", client: server.Client(), PolicyAPIBaseURL: server.URL + "/v1"}
	d := schema.TestResourceDataRaw(t, resourceDlpRule().Schema, map[string]interface{}{"policy_query": query, "setting_value": value})
	d.SetId("policies/rule-1")
	if diags := resourceDlpRuleUpdate(context.Background(), d, client); diags.HasError() {
		t.Fatalf("update failed: %v", diags)
	}
	if len(patched) != 2 {
		t.Fatalf("patch should contain policyQuery and setting only: %#v", patched)
	}
	gotQuery := patched["policyQuery"].(map[string]interface{})
	if _, ok := gotQuery["sortOrder"]; ok {
		t.Error("PATCH includes output-only sortOrder")
	}
	if gotQuery["group"] != "groups/group-123" || gotQuery["query"] == nil {
		t.Errorf("PATCH changed scope: %#v", gotQuery)
	}
	gotValue := patched["setting"].(map[string]interface{})["value"].(map[string]interface{})
	for _, field := range []string{"createTime", "updateTime"} {
		if _, ok := gotValue[field]; ok {
			t.Errorf("PATCH includes output-only %s", field)
		}
	}
	if normalizeJSONState(d.Get("policy_query")) != normalizeJSON(query) {
		t.Error("output-only filtering must not change Terraform scope")
	}
	if gotValue["action"] == nil {
		t.Error("PATCH dropped notification action")
	}
}
