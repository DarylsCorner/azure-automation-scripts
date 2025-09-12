# Azure Quota Management Tool

A PowerShell script for interactively managing Azure VM quota increases with Azure CLI integration.

## Prerequisites

- **Azure CLI**: Must be installed and logged in
  ```powershell
  az login
  ```
- **PowerShell**: Windows PowerShell 5.1 or PowerShell Core 6+
- **Azure Permissions**: Requires appropriate RBAC permissions for quota operations
  - Reader role (minimum for viewing quotas)
  - Quota Request Operator role (for quota increases)
  - Contributor role (for broader access)

## Features

- **Interactive Subscription Selection**: Choose from available subscriptions
- **Provider Support**: Microsoft.Compute and Microsoft.Network
- **Region Flexibility**: Works with any Azure region
- **VM SKU Filtering**: Filter results by specific VM family (e.g., EDSv5, DSv3)
- **Real-time Quota Verification**: Refreshes quota values from API
- **Usage Information**: Shows current usage where available
- **Error Handling**: Comprehensive error handling with helpful guidance
- **Azure CLI Integration**: Uses reliable Azure CLI commands for quota operations

## Usage

### Basic Usage
```powershell
.\Increase-AzureQuota.ps1
```

### With Custom API Version
```powershell
.\Increase-AzureQuota.ps1 -ApiVersion "2025-09-01"
```

## Script Workflow

1. **Subscription Selection**: Choose from available Azure subscriptions
2. **Provider Selection**: Select Microsoft.Compute or Microsoft.Network
3. **Region Input**: Enter target Azure region (e.g., westus2, eastus)
4. **SKU Filtering** (Compute only): Optionally filter by VM SKU family
5. **Quota Listing**: View all available quotas with current limits
6. **Quota Selection**: Choose specific quota to modify
7. **Value Input**: Enter new quota value
8. **Submission**: Submit quota increase request via Azure CLI
9. **Verification**: Confirm final quota status

## Common VM SKU Families

| SKU Family | Description | Common Use Cases |
|------------|-------------|------------------|
| DSv3 | General Purpose D-series v3 | Balanced compute/memory |
| DSv4 | General Purpose D-series v4 | Latest general purpose |
| DSv5 | General Purpose D-series v5 | Newest general purpose |
| EDSv5 | Memory Optimized E-series Dense | High memory workloads |
| FSv2 | Compute Optimized F-series | CPU-intensive workloads |
| EAv4 | AMD-based E-series | Cost-effective memory optimized |
| NCv3 | GPU N-series v3 | GPU compute workloads |
| HBv3 | High Performance Computing | HPC workloads |

## Useful Commands Reference

### List All VM Quotas in a Region
```powershell
# Basic listing - all quotas
az quota list --scope "subscriptions/$(az account show --query 'id' -o tsv)/providers/Microsoft.Compute/locations/westus2" --query "[].{Name:name,Current:properties.limit.value,Unit:properties.unit}" --output table
```

### List Only VM Family Quotas in a specific Region (Formatted Table)
```powershell
# Clean formatted table with VM families only
$subscription = az account show --query 'id' -o tsv
$quotas = az quota list --scope "subscriptions/$subscription/providers/Microsoft.Compute/locations/westus2" --output json | ConvertFrom-Json
$quotas | Where-Object { $_.name -like "*Family" } | ForEach-Object { 
  $cleanSku = $_.name -replace '^standard' -replace 'Family$' -replace '^Standard'
  [PSCustomObject]@{ 
    Region = 'westus2'
    Family = $_.name + ' vCPUs'
    SKU = $cleanSku
    Quota = $_.properties.limit.value 
  } 
} | Format-Table -AutoSize
```

### Check Specific Quota
```powershell
# Check specific VM family quota
az quota show --resource-name "standardEDSv5Family" --scope "subscriptions/$(az account show --query 'id' -o tsv)/providers/Microsoft.Compute/locations/westus2" --query "{Name:name,Limit:properties.limit.value,Unit:properties.unit}" --output table
```

### List Quotas for Multiple Regions
```powershell
# Check quotas across multiple regions
$regions = @('westus2', 'eastus', 'westeurope')
$subscription = az account show --query 'id' -o tsv

foreach ($region in $regions) {
  Write-Host "=== $region ===" -ForegroundColor Cyan
  az quota show --resource-name "standardEDSv5Family" --scope "subscriptions/$subscription/providers/Microsoft.Compute/locations/$region" --query "{Region:'$region',Quota:properties.limit.value}" --output table
}
```

### Export Quotas to CSV
```powershell
# Export all VM family quotas to CSV
$subscription = az account show --query 'id' -o tsv
$region = 'westus2'
$quotas = az quota list --scope "subscriptions/$subscription/providers/Microsoft.Compute/locations/$region" --output json | ConvertFrom-Json

$quotas | Where-Object { $_.name -like "*Family" } | ForEach-Object { 
  $cleanSku = $_.name -replace '^standard' -replace 'Family$' -replace '^Standard'
  [PSCustomObject]@{ 
    Region = $region
    FullName = $_.name
    SKU = $cleanSku
    CurrentQuota = $_.properties.limit.value
    Unit = $_.properties.unit
  } 
} | Export-Csv -Path "quotas-$region-$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation

Write-Host "Quotas exported to quotas-$region-$(Get-Date -Format 'yyyyMMdd').csv"
```

### Quick Quota Summary
```powershell
# Quick summary of key quota metrics
$subscription = az account show --query 'id' -o tsv
$region = 'westus2'

Write-Host "=== Azure Quota Summary for $region ===" -ForegroundColor Cyan
Write-Host "Total Regional vCPUs: $(az quota show --resource-name 'cores' --scope "subscriptions/$subscription/providers/Microsoft.Compute/locations/$region" --query 'properties.limit.value' -o tsv)"
Write-Host "Low Priority vCPUs: $(az quota show --resource-name 'lowPriorityCores' --scope "subscriptions/$subscription/providers/Microsoft.Compute/locations/$region" --query 'properties.limit.value' -o tsv)"
Write-Host "Total VMs: $(az quota show --resource-name 'virtualMachines' --scope "subscriptions/$subscription/providers/Microsoft.Compute/locations/$region" --query 'properties.limit.value' -o tsv)"
Write-Host "EDSv5 Family: $(az quota show --resource-name 'standardEDSv5Family' --scope "subscriptions/$subscription/providers/Microsoft.Compute/locations/$region" --query 'properties.limit.value' -o tsv)"
```

## API Versions

- **Current**: 2025-09-01 (Latest stable)
- **Previous**: 2024-03-01 (Deprecated for some operations)

The script uses the latest API version (2025-09-01) by default but can be overridden with the `-ApiVersion` parameter.

## Error Handling

The script includes comprehensive error handling for common scenarios:

- **Service Unavailable**: Azure Quota service temporary outages
- **Authentication Issues**: Azure CLI login problems
- **Permission Errors**: Insufficient RBAC permissions
- **Invalid Regions**: Non-existent or inaccessible regions
- **API Failures**: REST API call failures with fallback to Azure CLI

## Troubleshooting

### Common Issues

1. **"No subscriptions found"**
   - Run `az login` to authenticate
   - Verify subscription access with `az account list`

2. **"Insufficient permissions"**
   - Check RBAC roles: `az role assignment list --assignee $(az account show --query user.name -o tsv)`
   - Request Quota Request Operator role from subscription admin

3. **"No quota items found"**
   - Verify region name spelling (e.g., 'westus2', not 'west us 2')
   - Ensure subscription has access to resources in that region

4. **"Quota update failed"**
   - Some quotas require manual approval
   - Try submitting via Azure Portal: portal.azure.com → Subscriptions → Usage + quotas
   - Contact Azure Support for high-limit requests

### Getting Help

- **Azure CLI Help**: `az quota --help`
- **Quota Documentation**: [Azure subscription and service limits](https://docs.microsoft.com/azure/azure-resource-manager/management/azure-subscription-service-limits)
- **Support**: Create Azure Support ticket for quota increase requests

## Version History

- **v1.0**: Initial version with REST API integration
- **v1.1**: Added Azure CLI integration for reliability
- **v1.2**: Updated to API version 2025-09-01
- **v1.3**: Enhanced error handling and user guidance

## Contributing

Feel free to submit issues and enhancement requests!

## License

This project is provided as-is for educational and administrative purposes.