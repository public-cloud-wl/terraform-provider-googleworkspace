package googleworkspace

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"

	cloudidentity "google.golang.org/api/cloudidentity/v1"
)

func resourceCompanyOwnedDevice() *schema.Resource {
	return &schema.Resource{
		Description: "Device resource manages Google Workspace Devices through Cloud Identity API. Device resides under the " +
			"`https://www.googleapis.com/auth/cloud-identity.devices` client scope.",

		CreateContext: resourceCompanyOwnedDeviceCreate,
		ReadContext:   resourceCompanyOwnedDeviceRead,
		// No UpdateContext - all changes force recreation
		DeleteContext: resourceCompanyOwnedDeviceDelete,

		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"serial_number": {
				Description:  "The serial number of the device.",
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.StringIsNotEmpty,
			},
			"device_type": {
				Description: "The type of device. Valid values are: WINDOWS, MAC_OS, LINUX, CHROME_OS, ANDROID, IOS.",
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				ValidateFunc: validation.StringInSlice([]string{
					"WINDOWS",
					"MAC_OS",
					"LINUX",
					"CHROME_OS",
					"ANDROID",
					"IOS",
				}, false),
			},
			"asset_tag": {
				Description: "Asset tag or owner information for the device.",
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
			},
			"name": {
				Description: "The full resource name of the device.",
				Type:        schema.TypeString,
				Computed:    true,
			},
			"create_time": {
				Description: "The time the device was created.",
				Type:        schema.TypeString,
				Computed:    true,
			},
			"last_sync_time": {
				Description: "The last time the device synced with the service.",
				Type:        schema.TypeString,
				Computed:    true,
			},
			"management_state": {
				Description: "The current management state of the device.",
				Type:        schema.TypeString,
				Computed:    true,
			},
			// Adding a computed id simply to override the `optional` id that gets added in the SDK
			// that will then display improperly in the docs
			"id": {
				Description: "The ID of this resource.",
				Type:        schema.TypeString,
				Computed:    true,
			},
		},
	}
}

func resourceCompanyOwnedDeviceCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	// use the meta value to retrieve your client from the provider configure method
	client := meta.(*apiClient)

	serialNumber := d.Get("serial_number").(string)
	log.Printf("[DEBUG] Creating Device %q: %#v", d.Id(), serialNumber)

	cloudIdentityService, diags := client.NewCloudIdentityService()
	if diags.HasError() {
		return diags
	}

	devicesService, diags := GetCloudIdentityDevicesService(cloudIdentityService)
	if diags.HasError() {
		return diags
	}

	// Create the device object
	deviceObj := &cloudidentity.GoogleAppsCloudidentityDevicesV1Device{
		SerialNumber: serialNumber,
		DeviceType:   d.Get("device_type").(string),
	}

	// Add optional fields
	if assetTag := d.Get("asset_tag").(string); assetTag != "" {
		deviceObj.AssetTag = assetTag
	}

	// Create the device
	device, err := devicesService.Create(deviceObj).Do()
	if err != nil {
		return diag.FromErr(err)
	}

	// Parse the response to extract the name field
	var responseData map[string]interface{}
	if err := json.Unmarshal(device.Response, &responseData); err != nil {
		return diag.FromErr(fmt.Errorf("failed to parse device response: %v", err))
	}

	deviceName, ok := responseData["name"].(string)
	if !ok {
		return diag.FromErr(fmt.Errorf("device name not found in response"))
	}

	// Use the device name as the ID
	d.SetId(deviceName)

	log.Printf("[DEBUG] Finished creating Device %q: %#v", d.Id(), serialNumber)

	return diags
}

func resourceCompanyOwnedDeviceRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	// use the meta value to retrieve your client from the provider configure method
	client := meta.(*apiClient)

	cloudIdentityService, diags := client.NewCloudIdentityService()
	if diags.HasError() {
		return diags
	}

	devicesService, diags := GetCloudIdentityDevicesService(cloudIdentityService)
	if diags.HasError() {
		return diags
	}

	deviceName := d.Id()
	log.Printf("[DEBUG] Getting Device %q: %#v", d.Id(), deviceName)

	device, err := devicesService.Get(deviceName).Context(ctx).Do()
	if err != nil {
		return handleNotFoundError(err, d, deviceName)
	}

	if device == nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  fmt.Sprintf("No device was returned for %s.", d.Get("serial_number").(string)),
		})

		return diags
	}

	d.Set("name", device.Name)
	d.Set("serial_number", device.SerialNumber)
	d.Set("device_type", device.DeviceType)
	d.Set("asset_tag", device.AssetTag)
	d.Set("create_time", device.CreateTime)
	d.Set("last_sync_time", device.LastSyncTime)
	d.Set("management_state", device.ManagementState)
	d.SetId(device.Name)

	log.Printf("[DEBUG] Finished getting Device %q: %#v", d.Id(), device.Name)

	return diags
}

func resourceCompanyOwnedDeviceDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	// use the meta value to retrieve your client from the provider configure method
	client := meta.(*apiClient)

	deviceName := d.Id()
	log.Printf("[DEBUG] Deleting Device %q: %#v", d.Id(), deviceName)

	cloudIdentityService, diags := client.NewCloudIdentityService()
	if diags.HasError() {
		return diags
	}

	devicesService, diags := GetCloudIdentityDevicesService(cloudIdentityService)
	if diags.HasError() {
		return diags
	}

	call := devicesService.Delete(deviceName)
	_, err := call.Context(ctx).Do()
	if err != nil {
		return handleNotFoundError(err, d, deviceName)
	}

	log.Printf("[DEBUG] Finished deleting Device %q: %#v", d.Id(), deviceName)

	return diags
}
