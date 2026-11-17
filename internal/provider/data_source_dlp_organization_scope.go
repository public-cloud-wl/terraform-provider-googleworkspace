// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package googleworkspace

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	directory "google.golang.org/api/admin/directory/v1"
)

func dataSourceDlpOrganizationScope() *schema.Resource {
	return &schema.Resource{
		Description: "Returns the customer-wide scope identifier required by Cloud Identity DLP policies. " +
			"The identifier represents the Workspace organization root in DLP PolicyQuery; it is not the Workspace customer ID. " +
			"Requires the `https://www.googleapis.com/auth/admin.directory.orgunit.readonly` OAuth scope.",
		ReadContext: dataSourceDlpOrganizationScopeRead,
		Schema: map[string]*schema.Schema{
			"organization_scope_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The root organization scope ID to use as org_unit_id on a googleworkspace_dlp_detector.",
			},
		},
	}
}

func dataSourceDlpOrganizationScopeRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*apiClient)

	directoryService, diags := client.NewDirectoryService()
	if diags.HasError() {
		return diags
	}

	orgUnitsService, diags := GetOrgUnitsService(directoryService)
	if diags.HasError() {
		return diags
	}

	const listTypeIncludingOrganizationRoot = "ALL_INCLUDING_PARENT"
	result, err := orgUnitsService.List(client.Customer).Type(listTypeIncludingOrganizationRoot).Do()
	if err != nil {
		return diag.FromErr(err)
	}
	if result == nil {
		return diag.Errorf("Directory API returned an empty organization listing for customer %q", client.Customer)
	}

	if organization := findDlpOrganizationRoot(result.OrganizationUnits); organization != nil {
		if err := d.Set("organization_scope_id", organization.OrgUnitId); err != nil {
			return diag.FromErr(err)
		}
		d.SetId(organization.OrgUnitId)
		return nil
	}

	return diag.Errorf("Directory API returned no organization-root DLP scope ID for customer %q", client.Customer)
}

func findDlpOrganizationRoot(orgUnits []*directory.OrgUnit) *directory.OrgUnit {
	for _, orgUnit := range orgUnits {
		if orgUnit == nil || orgUnit.OrgUnitId == "" {
			continue
		}
		if orgUnit.OrgUnitPath == "/" || orgUnit.OrgUnitPath == "" {
			return orgUnit
		}
	}
	return nil
}
