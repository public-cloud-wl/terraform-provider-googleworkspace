// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package googleworkspace

import (
	"testing"

	directory "google.golang.org/api/admin/directory/v1"
)

func TestFindDlpOrganizationRoot(t *testing.T) {
	root := &directory.OrgUnit{OrgUnitId: "root-scope-id", OrgUnitPath: "/"}
	child := &directory.OrgUnit{OrgUnitId: "child-id", OrgUnitPath: "/engineering"}

	if got := findDlpOrganizationRoot([]*directory.OrgUnit{child, root}); got != root {
		t.Fatalf("findDlpOrganizationRoot() = %#v, want organization root", got)
	}
}

func TestFindDlpOrganizationRootWithEmptyPath(t *testing.T) {
	root := &directory.OrgUnit{OrgUnitId: "root-scope-id"}

	if got := findDlpOrganizationRoot([]*directory.OrgUnit{root}); got != root {
		t.Fatalf("findDlpOrganizationRoot() = %#v, want root with empty path", got)
	}
}

func TestFindDlpOrganizationRootMissing(t *testing.T) {
	units := []*directory.OrgUnit{
		{OrgUnitId: "child-id", OrgUnitPath: "/engineering"},
		{OrgUnitPath: "/"},
	}

	if got := findDlpOrganizationRoot(units); got != nil {
		t.Fatalf("findDlpOrganizationRoot() = %#v, want nil when no root ID is returned", got)
	}
}
