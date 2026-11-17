# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

# The provider reads direct group members. Filter out nested groups because
# their members are not expanded by the Directory API data source.
data "googleworkspace_group" "dlp_alerts" {
  email = "security@example.com"
}

data "googleworkspace_group_members" "dlp_alerts" {
  group_id = data.googleworkspace_group.dlp_alerts.id
}

locals {
  dlp_alert_recipients = [
    for member in data.googleworkspace_group_members.dlp_alerts.members : member.email
    if member.type == "USER"
  ]
}

resource "googleworkspace_dlp_rule" "sensitive_drive_sharing" {
  org_unit_id = "03ph8a2z"

  # This JSON is passed as setting.value to the Cloud Identity Policy API.
  # Add alert recipients only using the exact field/shape verified by reading
  # a comparable rule created in the Admin console. The API schema is evolving.
  setting_value = jsonencode({
    displayName = "Sensitive data sharing warning"
    state       = "ACTIVE"
    triggers    = ["google.workspace.drive.file.v1.share"]
    condition = {
      contentCondition = "all_content.matches_dlp_detector('US_SOCIAL_SECURITY_NUMBER', google.privacy.dlp.v2.Likelihood.LIKELY, {minimum_match_count: 1, minimum_unique_match_count: 1})"
    }
    action = {
      driveAction = {
        warnUser = {}
      }
    }
  })
}
