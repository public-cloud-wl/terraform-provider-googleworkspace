// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package googleworkspace

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"google.golang.org/api/chromepolicy/v1"
)

func TestValidateChromePolicyRepeatedField(t *testing.T) {
	if !validatePolicyFieldValueType("TYPE_MESSAGE", "LABEL_REPEATED", []interface{}{map[string]interface{}{"name": "rule"}}) {
		t.Fatal("expected repeated message value to be accepted")
	}
	if validatePolicyFieldValueType("TYPE_MESSAGE", "LABEL_REPEATED", map[string]interface{}{"name": "rule"}) {
		t.Fatal("expected non-list repeated value to be rejected")
	}
}

func TestChromePolicyRootNamespace(t *testing.T) {
	if got := chromePolicyRootNamespace("chrome.users.DataControlsRules"); got != "chrome.users" {
		t.Fatalf("root namespace = %q, want chrome.users", got)
	}
	if got := chromePolicyRootNamespace("chrome.devices.DevicePolicy"); got != "chrome.devices" {
		t.Fatalf("root namespace = %q, want chrome.devices", got)
	}
}

func TestChromePolicyTargetResource(t *testing.T) {
	d := schema.TestResourceDataRaw(t, resourceChromePolicy().Schema, map[string]interface{}{
		"group_id": "groups/group-123",
		"policies": []interface{}{},
	})
	if got := chromePolicyTargetResource(d); got != "groups/group-123" {
		t.Fatalf("target = %q, want groups/group-123", got)
	}

	d = schema.TestResourceDataRaw(t, resourceChromePolicy().Schema, map[string]interface{}{
		"org_unit_id": "id:ou-123",
		"policies":    []interface{}{},
	})
	if got := chromePolicyTargetResource(d); got != "orgunits/ou-123" {
		t.Fatalf("target = %q, want orgunits/ou-123", got)
	}
}

func TestChromeGroupPolicyMethods(t *testing.T) {
	var requests []map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		switch r.URL.Path {
		case "/v1/customers/C123/policies/groups:batchModify", "/v1/customers/C123/policies/groups:batchDelete":
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		var body struct {
			Requests []map[string]interface{} `json:"requests"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decoding request: %v", err)
		}
		requests = body.Requests
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := &apiClient{
		Customer:               "C123",
		client:                 server.Client(),
		ChromePolicyAPIBaseURL: server.URL + "/v1",
	}
	policy := &chromepolicy.GoogleChromePolicyV1PolicyValue{
		PolicySchema: "chrome.users.DataControlsRules",
		Value:        []byte(`{"rules":[]}`),
	}
	modifyRequest := &chromepolicy.GoogleChromePolicyV1ModifyOrgUnitPolicyRequest{
		PolicyTargetKey: &chromepolicy.GoogleChromePolicyV1PolicyTargetKey{TargetResource: "groups/group-123"},
		PolicyValue:     policy,
		UpdateMask:      "rules",
	}
	if err := client.batchModifyChromeGroupPolicies(context.Background(), "groups/group-123", []*chromepolicy.GoogleChromePolicyV1ModifyOrgUnitPolicyRequest{modifyRequest}); err != nil {
		t.Fatalf("batchModifyChromeGroupPolicies() error: %v", err)
	}
	if len(requests) != 1 || requests[0]["policyTargetKey"].(map[string]interface{})["targetResource"] != "groups/group-123" {
		t.Fatalf("unexpected batchModify requests: %#v", requests)
	}

	requests = nil
	if err := client.batchDeleteChromeGroupPolicies(context.Background(), "groups/group-123", []string{"chrome.users.DataControlsRules"}); err != nil {
		t.Fatalf("batchDeleteChromeGroupPolicies() error: %v", err)
	}
	if len(requests) != 1 || requests[0]["policySchema"] != "chrome.users.DataControlsRules" {
		t.Fatalf("unexpected batchDelete requests: %#v", requests)
	}
}
