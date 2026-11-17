// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package googleworkspace

import (
	"fmt"
	"strings"
	"testing"

	"google.golang.org/api/googleapi"
)

func TestChromePolicySchemaLookupDiagnosticsDataControlsNotFound(t *testing.T) {
	apiErr := fmt.Errorf("policy schema lookup: %w", &googleapi.Error{Code: 404, Message: "notFound"})

	diags := chromePolicySchemaLookupDiagnostics(chromeDataControlsRulesSchemaName, "C00wifwqs", apiErr)
	if !diags.HasError() {
		t.Fatal("expected an error diagnostic")
	}

	diagnostic := diags[0]
	for _, want := range []string{
		"Chrome Enterprise Premium",
		"C00wifwqs",
		"Verify licensing and feature availability",
	} {
		if !strings.Contains(diagnostic.Summary, want) {
			t.Errorf("diagnostic summary %q does not contain %q", diagnostic.Summary, want)
		}
	}
}
