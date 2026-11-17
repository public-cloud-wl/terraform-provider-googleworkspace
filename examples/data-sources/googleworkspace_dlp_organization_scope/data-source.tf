// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

data "googleworkspace_dlp_organization_scope" "current" {}

output "organization_scope_id" {
  value = data.googleworkspace_dlp_organization_scope.current.organization_scope_id
}
