data "googleworkspace_org_unit" "root" {
  org_unit_path = "/"
}

resource "googleworkspace_dlp_detector" "goanywhere_urls" {
  org_unit_id = data.googleworkspace_org_unit.root.org_unit_id

  setting_type = "settings/detector.url_list"
  setting_value = jsonencode({
    displayName = "GoAnywhere URLs"
    urlList = {
      urls = ["goanywhere.example.com"]
    }
  })
}
