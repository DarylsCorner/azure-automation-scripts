#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Interactive Azure quota increase tool for VM and networking resources

.DESCRIPTION
    This script provides an interactive interface for managing Azure service quotas,
    specifically focusing on Microsoft.Compute (VM families, vCPUs) and Microsoft.Network
    (Public IPs, etc.) resources. It uses Azure CLI integration for reliable quota
    operations and supports filtering by VM SKU families for targeted quota management.

.PARAMETER ApiVersion
    The Azure REST API version to use for quota operations.
    Default: 2025-09-01

.EXAMPLE
    .\Increase-AzureQuota.ps1
    
.EXAMPLE
    .\Increase-AzureQuota.ps1 -ApiVersion "2024-03-01"

.NOTES
    Author: Generated for Azure Quota Management
    Requires: Azure CLI installed and configured (az login)
    Last Updated: September 11, 2025
    Prerequisites:
    - Azure CLI logged in (az login)
    - Appropriate RBAC permissions for quota operations
#>

param(
  [string]$ApiVersion = "2025-09-01"
)

Write-Host "== Azure Quota Increase (interactive) ==" -ForegroundColor Cyan

$subs = az account list --query "[].{name:name,id:id}" -o json | ConvertFrom-Json
if (!$subs) { throw "No subscriptions found. Run az login." }

$idx = 1
$subs | ForEach-Object {
  "{0,2}) {1} ({2})" -f $idx, $_.name, $_.id
  $idx++
}

$sel = [int](Read-Host "Select subscription [1-$($subs.Count)]")
$sub = $subs[$sel-1]
az account set --subscription $sub.id | Out-Null
Write-Host ""
Write-Host "Choose provider:" -ForegroundColor Yellow
Write-Host " 1) Microsoft.Compute   (vCPU families, total regional vCPUs, Spot, etc.)"
Write-Host " 2) Microsoft.Network   (Public IPs, etc.)"
$pv = Read-Host "Select provider [1-2]"
$provider = if ($pv -eq "1") { "Microsoft.Compute" } else { "Microsoft.Network" }

$location = (Read-Host "Enter Azure region (e.g., westus2, eastus)").ToLower()
$scope = "subscriptions/$($sub.id)/providers/$provider/locations/$location"

# Optional filtering for Compute provider
$vmSkuFilter = ""
if ($provider -eq "Microsoft.Compute") {
  Write-Host ""
  Write-Host "To limit results, you can filter by VM SKU:" -ForegroundColor Yellow
  Write-Host "Common VM SKUs (enter just the SKU part):"
  Write-Host "  - DSv3 (for D-series v3)"
  Write-Host "  - FSv2 (for F-series v2)"
  Write-Host "  - EAv4 (for E-series AMD v4)"
  Write-Host "  - EDSv5 (for E-series Dense v5)"
  Write-Host "  - NCv3 (for GPU N-series v3)"
  Write-Host "  - Or press Enter to see all quotas"
  $vmSkuFilter = Read-Host "Enter VM SKU (optional, e.g., EDSv5)"
}

Write-Host ""
Write-Host "Loading quota items for $provider in $location ..." -ForegroundColor Yellow

try {
  $quotaResponse = az rest --method get --url "https://management.azure.com/$scope/providers/Microsoft.Quota/quotas?api-version=$ApiVersion"
  
  # Check for HTML error response (service unavailable)
  if ($quotaResponse -like "*DOCTYPE html*" -or $quotaResponse -like "*Our services aren't available*") {
    Write-Host "ERROR: Azure Quota service is temporarily unavailable." -ForegroundColor Red
    Write-Host "This is usually a temporary Azure service issue. Please try again in a few minutes." -ForegroundColor Yellow
    Write-Host "Error details: Azure Resource Manager service unavailable" -ForegroundColor Gray
    exit 1
  }
  
  $quotas = $quotaResponse | ConvertFrom-Json
  
  if (!$quotas -or !$quotas.value -or $quotas.value.Count -eq 0) { 
    Write-Host "ERROR: No quota items found for provider '$provider' in region '$location'." -ForegroundColor Red
    Write-Host "Please verify:" -ForegroundColor Yellow
    Write-Host "  - The region name is correct (e.g., 'westus2', 'eastus')" -ForegroundColor Yellow
    Write-Host "  - Your subscription has access to $provider resources in $location" -ForegroundColor Yellow
    exit 1
  }
  
  Write-Host "Total quota items found: $($quotas.value.Count)" -ForegroundColor Green
  
} catch {
  Write-Host "ERROR: Failed to retrieve quota information." -ForegroundColor Red
  Write-Host "Error details: $_" -ForegroundColor Red
  Write-Host ""
  Write-Host "Possible causes:" -ForegroundColor Yellow
  Write-Host "  - Azure service temporarily unavailable" -ForegroundColor Yellow
  Write-Host "  - Network connectivity issues" -ForegroundColor Yellow
  Write-Host "  - Invalid subscription or region" -ForegroundColor Yellow
  Write-Host "  - Insufficient permissions" -ForegroundColor Yellow
  exit 1
}

if ($vmSkuFilter -and $provider -eq "Microsoft.Compute") {
  $originalCount = $quotas.value.Count
  $quotas.value = $quotas.value | Where-Object { 
    $quotaName = $null
    if ($_.name -and $_.name.value) { $quotaName = $_.name.value }
    elseif ($_.name -and ($_.name -is [string])) { $quotaName = $_.name }
    elseif ($_.id) { $quotaName = ($_.id -split "/")[-1] }
    
    if ($quotaName) { $quotaName -like "*$vmSkuFilter*" } else { $false }
  }
  if (!$quotas.value) { 
    Write-Host "No quota items found matching '$vmSkuFilter'. Showing all quotas instead." -ForegroundColor Yellow
    $quotas = az rest --method get --url "https://management.azure.com/$scope/providers/Microsoft.Quota/quotas?api-version=$ApiVersion" | ConvertFrom-Json
  } else {
    Write-Host "Found $($quotas.value.Count) quota items matching '$vmSkuFilter' (out of $originalCount total)" -ForegroundColor Green
  }
}

"{0,-4} {1,-50} {2,-12} {3,-12} {4,-8}" -f "#","name","current","usage","unit"
Write-Host ("-" * 90)
for ($i=0; $i -lt $quotas.value.Count; $i++) {
  $q = $quotas.value[$i]
  
  # Extract quota name from response object
  $name = $null
  if ($q.name -and $q.name.value) { $name = $q.name.value }
  elseif ($q.name -and ($q.name -is [string])) { $name = $q.name }
  elseif ($q.id) { 
    $idParts = $q.id -split "/"
    $name = $idParts[-1]
  }
  
  if (!$name) { $name = "quota-$($i+1)" }
  
  # Use cached values for listing (detailed refresh happens when quota is selected)
  $curr = if ($q.properties.limit.value) { $q.properties.limit.value } else { "N/A" }
  $unit = if ($q.properties.limit.unit) { $q.properties.limit.unit } else { "count" }
  $usage = "n/a"

  "{0,-4} {1,-50} {2,-12} {3,-12} {4,-8}" -f ($i+1), $name, $curr, $usage, $unit
}

Write-Host ""
Write-Host "Note: Current limits shown above may be cached. Actual current values will be refreshed when you select a quota." -ForegroundColor Cyan

$choice = [int](Read-Host "Select a quota item by # [1-$($quotas.value.Count)]")
$qSel = $quotas.value[$choice-1]

# Extract quota name using same logic as display
$name = $null
if ($qSel.name -and $qSel.name.value) { $name = $qSel.name.value }
elseif ($qSel.name -and ($qSel.name -is [string])) { $name = $qSel.name }
elseif ($qSel.id) { 
  $idParts = $qSel.id -split "/"
  $name = $idParts[-1]
}
if (!$name) { $name = "quota-$choice" }

# Refresh quota value from API
Write-Host ""
Write-Host "Refreshing current quota information..." -ForegroundColor Yellow

try {
  $curr = az quota show --resource-name $name --scope $scope --query "properties.limit.value" -o tsv
  $curr = [int]$curr
  $unit = az quota show --resource-name $name --scope $scope --query "properties.unit" -o tsv
  if (!$unit) { $unit = "count" }
  Write-Host "Current quota: $curr $unit" -ForegroundColor Green
} catch {
  Write-Host "Warning: Could not refresh quota from API: $_" -ForegroundColor Yellow
  Write-Host "Using cached value instead" -ForegroundColor Yellow
  $curr = [int]$qSel.properties.limit.value
  $unit = if ($qSel.properties.limit.unit) { $qSel.properties.limit.unit } else { "count" }
}

# Try to get current usage (not all quota types support this)
$usage = "n/a"
try {
  $usage = az quota usage show --resource-name $name --scope $scope --query "properties.currentValue" -o tsv 2>$null
  if (!$usage) { $usage = "n/a" }
} catch {
  $usage = "n/a"
}

Write-Host ""
Write-Host "Selected: $name"
Write-Host "Current limit: $curr $unit"
Write-Host "Current usage: $usage $unit"

$newVal = Read-Host "Enter NEW limit value (integer, must be >= current)"
if (-not ($newVal -as [int])) { throw "Invalid number." }
$newVal = [int]$newVal
if ($newVal -lt $curr) { throw "New limit must be >= current limit ($curr)." }

Write-Host ""
Write-Host "Submitting quota increase request..." -ForegroundColor Yellow

try {
  $cliResult = az quota update --resource-name $name --scope $scope --limit-object value=$newVal 2>&1
  if ($LASTEXITCODE -eq 0) {
    Write-Host "SUCCESS! Quota increase request submitted." -ForegroundColor Green
  } else {
    Write-Host "ERROR: Quota update failed." -ForegroundColor Red
    Write-Host "Error details: $cliResult" -ForegroundColor Red
    Write-Host ""
    Write-Host "This likely indicates:" -ForegroundColor Yellow
    Write-Host "- Insufficient permissions (need 'Quota Request Operator' role or similar)" -ForegroundColor Yellow
    Write-Host "- Manual approval required for this quota type" -ForegroundColor Yellow
    Write-Host "- Policy restrictions preventing automated quota increases" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "To resolve:" -ForegroundColor Cyan
    Write-Host "1. Check RBAC permissions with: az role assignment list --assignee \$(az account show --query user.name -o tsv)" -ForegroundColor Cyan
    Write-Host "2. Try submitting via Azure portal: portal.azure.com -> Subscriptions -> Usage + quotas" -ForegroundColor Cyan
    Write-Host "3. Contact Azure support if portal submission also fails" -ForegroundColor Cyan
  }
} catch {
  Write-Host "ERROR: Azure CLI quota command failed: $_" -ForegroundColor Red
}

# Verify final quota status
Write-Host ""
Write-Host "Verifying current quota value..." -ForegroundColor Yellow
Start-Sleep -Seconds 2

try {
  $finalLimit = az quota show --resource-name $name --scope $scope --query "properties.limit.value" -o tsv
  $finalLimit = [int]$finalLimit
  
  Write-Host "=== FINAL QUOTA STATUS ===" -ForegroundColor Cyan
  Write-Host "Quota Name: $name"
  Write-Host "Previous Limit: $curr"
  Write-Host "Requested Limit: $newVal"
  Write-Host "Current Limit: $finalLimit" -ForegroundColor $(if ($finalLimit -eq $newVal) { "Green" } else { "Yellow" })
  
  if ($finalLimit -eq $newVal) {
    Write-Host "✓ SUCCESS: Quota has been increased to $finalLimit!" -ForegroundColor Green
  } elseif ($finalLimit -gt $curr) {
    Write-Host "✓ PARTIAL: Quota increased from $curr to $finalLimit (requested $newVal)" -ForegroundColor Yellow
  } else {
    Write-Host "✗ NO CHANGE: Quota remains at $finalLimit" -ForegroundColor Red
  }
} catch {
  Write-Host "Could not verify final quota value. Please check Azure portal." -ForegroundColor Yellow
  Write-Host "Verification error: $_" -ForegroundColor Red
}
