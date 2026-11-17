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
)

func TestDlpDetectorPolicyPayload(t *testing.T) {
	payload, err := dlpDetectorPolicyPayload(
		"C123456",
		"orgUnits/root-ou",
		"",
		"",
		"settings/detector.url_list",
		`{"displayName":"Example URLs","urlList":{"urls":["example.com"]},"createTime":"generated"}`,
	)
	if err != nil {
		t.Fatalf("dlpDetectorPolicyPayload returned error: %v", err)
	}
	if payload["customer"] != "customers/C123456" {
		t.Fatalf("customer = %#v", payload["customer"])
	}
	query := payload["policyQuery"].(map[string]interface{})
	if query["orgUnit"] != "orgUnits/root-ou" {
		t.Fatalf("policyQuery = %#v", query)
	}
	if _, ok := query["sortOrder"]; ok {
		t.Fatalf("mutation policyQuery contains output-only sortOrder: %#v", query)
	}
	setting := payload["setting"].(map[string]interface{})
	if setting["type"] != "settings/detector.url_list" {
		t.Fatalf("setting type = %#v", setting["type"])
	}
	value := setting["value"].(map[string]interface{})
	if _, ok := value["createTime"]; ok {
		t.Fatalf("mutation setting contains output-only createTime: %#v", value)
	}
}

func TestDlpDetectorPolicyPayloadRejectsUnsupportedType(t *testing.T) {
	_, err := dlpDetectorPolicyPayload("C123456", "root", "", "", "settings/rule.dlp", `{"displayName":"Wrong type"}`)
	if err == nil {
		t.Fatal("expected unsupported setting type error")
	}
}

func TestResourceDlpDetectorCRUD(t *testing.T) {
	var currentPolicy map[string]interface{}
	deleted := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/policies":
			if err := json.NewDecoder(r.Body).Decode(&currentPolicy); err != nil {
				t.Errorf("decoding create body: %v", err)
			}
			writeJSON(t, w, map[string]interface{}{
				"name":     "operations/create-detector",
				"done":     true,
				"response": map[string]interface{}{"name": "policies/detector-1"},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/policies/detector-1":
			if deleted {
				w.WriteHeader(http.StatusNotFound)
				writeJSON(t, w, map[string]interface{}{"error": map[string]interface{}{"message": "not found"}})
				return
			}
			currentPolicy["name"] = "policies/detector-1"
			currentPolicy["customer"] = "customers/C123456"
			writeJSON(t, w, currentPolicy)
		case r.Method == http.MethodPatch && r.URL.Path == "/v1/policies/detector-1":
			var patch map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
				t.Errorf("decoding patch body: %v", err)
			}
			if _, ok := patch["policyQuery"]; !ok {
				t.Error("patch is missing policyQuery")
			}
			currentPolicy["setting"] = patch["setting"]
			writeJSON(t, w, map[string]interface{}{"name": "operations/update-detector", "done": true})
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/policies/detector-1":
			deleted = true
			writeJSON(t, w, map[string]interface{}{"name": "operations/delete-detector", "done": true})
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.String())
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := &apiClient{Customer: "C123456", client: server.Client(), PolicyAPIBaseURL: server.URL + "/v1"}
	resource := resourceDlpDetector()
	data := schema.TestResourceDataRaw(t, resource.Schema, map[string]interface{}{
		"org_unit_id":   "root-ou",
		"setting_type":  "settings/detector.url_list",
		"setting_value": `{"displayName":"Example URLs","urlList":{"urls":["example.com"]}}`,
	})

	if diagnostics := resource.CreateContext(context.Background(), data, client); diagnostics.HasError() {
		t.Fatalf("create failed: %v", diagnostics)
	}
	if data.Id() != "policies/detector-1" {
		t.Fatalf("id = %q", data.Id())
	}
	query := currentPolicy["policyQuery"].(map[string]interface{})
	if query["orgUnit"] != "orgUnits/root-ou" {
		t.Fatalf("created policyQuery = %#v", query)
	}

	updated := schema.TestResourceDataRaw(t, resource.Schema, map[string]interface{}{
		"org_unit_id":   "root-ou",
		"setting_type":  "settings/detector.url_list",
		"setting_value": `{"displayName":"Updated URLs","urlList":{"urls":["example.com","example.org"]}}`,
	})
	updated.SetId(data.Id())
	if diagnostics := resource.UpdateContext(context.Background(), updated, client); diagnostics.HasError() {
		t.Fatalf("update failed: %v", diagnostics)
	}

	if diagnostics := resource.DeleteContext(context.Background(), updated, client); diagnostics.HasError() {
		t.Fatalf("delete failed: %v", diagnostics)
	}
	if updated.Id() != "" {
		t.Fatalf("id after delete = %q, want empty", updated.Id())
	}
}
