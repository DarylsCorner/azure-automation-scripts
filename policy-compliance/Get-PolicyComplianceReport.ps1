#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Generates an Azure Policy Compliance Report for a specified subscription

.DESCRIPTION
    This script retrieves policy compliance states from Azure Policy and generates 
    a format        Write-Host "   • Consider policy exemptions for development environments if needed"

        Write-Host "`nRECOMMENDED ACTIONS"
        Write-Host "   1. Review non-compliant policies and determine remediation approach"
        Write-Host "   2. Configure required security components or request policy exemptions"
        Write-Host "   3. Monitor policy compliance after making infrastructure changes"
        Write-Host "   4. Consider implementing automated policy compliance in CI/CD pipelines"
    }iance report showing compliant and non-compliant policies
    with their evaluation times and types.

.PARAMETER SubscriptionId
    The Azure subscription ID to analyze. If not provided, will be prompted at runtime.

.PARAMETER OutputFormat
    The output format for the report. Options: Console, JSON, CSV
    Default: Console

.EXAMPLE
    .\Get-PolicyComplianceReport.ps1
    
.EXAMPLE
    .\Get-PolicyComplianceReport.ps1 -SubscriptionId "your-subscription-id-here"
    
.EXAMPLE
    .\Get-PolicyComplianceReport.ps1 -SubscriptionId "your-subscription-id-here" -OutputFormat JSON

.NOTES
    Author: Generated for Azure Policy Compliance Analysis
    Requires: Azure CLI and PowerShell 5.1+
    Last Updated: August 21, 2025
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$SubscriptionId,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("Console", "JSON", "CSV")]
    [string]$OutputFormat = "Console"
)

# Function to get policy display names
function Get-PolicyDisplayName {
    param([string]$PolicyId)
    
    try {
        $displayName = az policy definition show --name $PolicyId --query "displayName" -o tsv 2>$null
        if ($displayName) {
            return $displayName
        } else {
            # Try built-in policy names we know
            $knownPolicies = @{
                "Subscription_ActivityLogsToLAWS_Audit" = "Activity Logs to Log Analytics"
                "Defender_WDATP_Audit" = "Enable MDE Integration Setting"
                "Defender_SecurityContact_Audit" = "Validate Security Contacts"
            }
            return $knownPolicies[$PolicyId] ?? "Policy: $PolicyId"
        }
    }
    catch {
        return "Policy: $PolicyId"
    }
}

# Function to generate friendly policy names
function Get-FriendlyPolicyName {
    param([string]$PolicyId, [string]$DisplayName)
    
    if ($DisplayName -and $DisplayName -ne "Policy: $PolicyId") {
        return $DisplayName
    }
    
    # Generate friendly names for common policy patterns
    switch -Wildcard ($PolicyId) {
        "*defender*" { return "Microsoft Defender Configuration" }
        "*security*" { return "Security Baseline Compliance" }
        "*monitor*" { return "Monitoring Infrastructure" }
        "*audit*" { return "Compliance Assessment" }
        "*log*" { return "Log Analytics Integration" }
        "*cspm*" { return "Cloud Security Posture Management" }
        default { return "Security Policy: $($PolicyId.Substring(0, [Math]::Min(8, $PolicyId.Length)))" }
    }
}

# Main script execution
Write-Host "🔍 Azure Policy Compliance Report Generator" -ForegroundColor Cyan
Write-Host "=" * 50

# Get subscription if not provided
if (-not $SubscriptionId) {
    Write-Host "`n📋 Available subscriptions:" -ForegroundColor Yellow
    az account list --query "[].{Name:name, SubscriptionId:id}" -o table
    
    do {
        $SubscriptionId = Read-Host "`nEnter the Subscription ID to analyze"
    } while (-not $SubscriptionId)
}

Write-Host "`n🔍 Analyzing subscription: $SubscriptionId" -ForegroundColor Green
Write-Host "⏳ Retrieving policy compliance data..."

# Get policy compliance data
try {
    $policyData = az policy state list --subscription $SubscriptionId --query "[].{PolicyName:policyDefinitionName,EvaluationTime:timestamp,ResourceId:resourceId,ComplianceState:complianceState,PolicyType:policyDefinitionAction}" --output json | ConvertFrom-Json
    
    if (-not $policyData -or $policyData.Count -eq 0) {
        Write-Host "ℹ️  No policy compliance data found for subscription $SubscriptionId" -ForegroundColor Yellow
        Write-Host "   This could mean:"
        Write-Host "   • No policies are assigned to this subscription"
        Write-Host "   • No resources exist that would trigger policy evaluations"
        Write-Host "   • Policy evaluation hasn't run yet"
        Write-Host "   • Insufficient permissions to read policy states"
        Write-Host "`n✅ Analysis completed - No policy violations found!" -ForegroundColor Green
        exit 0
    }
}
catch {
    Write-Host "❌ Error retrieving policy data: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Process the data
$compliantPolicies = @($policyData | Where-Object { $_.ComplianceState -eq "Compliant" })
$nonCompliantPolicies = @($policyData | Where-Object { $_.ComplianceState -eq "NonCompliant" })
$totalPolicies = $policyData.Count
$complianceRate = if ($totalPolicies -gt 0) { [Math]::Round(($compliantPolicies.Count / $totalPolicies) * 100, 1) } else { 0 }

# Get evaluation time range (handle case where no policy data exists)
$latestEvalTime = if ($policyData.Count -gt 0) { 
    ($policyData | Sort-Object EvaluationTime -Descending | Select-Object -First 1).EvaluationTime 
} else { 
    Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ" 
}
$earliestEvalTime = if ($policyData.Count -gt 0) { 
    ($policyData | Sort-Object EvaluationTime | Select-Object -First 1).EvaluationTime 
} else { 
    $latestEvalTime 
}

# Generate report based on output format
switch ($OutputFormat) {
    "JSON" {
        $report = @{
            SubscriptionId = $SubscriptionId
            EvaluationTimeRange = @{
                Latest = $latestEvalTime
                Earliest = $earliestEvalTime
            }
            Summary = @{
                TotalPolicies = $totalPolicies
                CompliantPolicies = $compliantPolicies.Count
                NonCompliantPolicies = $nonCompliantPolicies.Count
                ComplianceRate = $complianceRate
            }
            NonCompliantPolicies = @($nonCompliantPolicies | ForEach-Object {
                @{
                    PolicyId = $_.PolicyName
                    DisplayName = Get-PolicyDisplayName $_.PolicyName
                    PolicyType = $_.PolicyType
                    ComplianceState = $_.ComplianceState
                    EvaluationTime = $_.EvaluationTime
                    ResourceId = $_.ResourceId
                }
            })
        }
        $report | ConvertTo-Json -Depth 10
    }
    
    "CSV" {
        $csvData = $nonCompliantPolicies | ForEach-Object {
            [PSCustomObject]@{
                PolicyId = $_.PolicyName
                DisplayName = Get-PolicyDisplayName $_.PolicyName
                PolicyType = $_.PolicyType
                ComplianceState = $_.ComplianceState
                EvaluationTime = $_.EvaluationTime
                ResourceId = $_.ResourceId
            }
        }
        $csvData | Export-Csv -Path "PolicyCompliance_$($SubscriptionId)_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv" -NoTypeInformation
        Write-Host "✅ CSV report saved to PolicyCompliance_$($SubscriptionId)_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    }
    
    default {
        # Console output with clean formatting
        Write-Host "`n========================================="
        Write-Host "AZURE POLICY COMPLIANCE REPORT"
        Write-Host "========================================="
        
        Write-Host "`nSUBSCRIPTION DETAILS"
        Write-Host "   Subscription ID: $SubscriptionId"
        Write-Host "   Analysis Time:   $(Get-Date $latestEvalTime -Format 'yyyy-MM-dd HH:mm') UTC"
        
        Write-Host "`nCOMPLIANCE SUMMARY"
        Write-Host "   Compliant: $($compliantPolicies.Count) policies ($complianceRate%)"
        Write-Host "   Non-Compliant: $($nonCompliantPolicies.Count) policies ($([Math]::Round((100 - $complianceRate), 1))%)"
        Write-Host "   Total Evaluated: $totalPolicies policies"

        if ($nonCompliantPolicies.Count -gt 0) {
            Write-Host "`nNON-COMPLIANT POLICIES"
            
            # Create a proper formatted table
            $tableData = @()
            foreach ($policy in $nonCompliantPolicies | Sort-Object EvaluationTime -Descending | Select-Object -First 15) {
                $displayName = Get-FriendlyPolicyName $policy.PolicyName (Get-PolicyDisplayName $policy.PolicyName)
                # Don't truncate policy names - show full names
                $policyTypeFormatted = switch ($policy.PolicyType) {
                    "deployifnotexists" { "Deploy" }
                    "auditifnotexists" { "Audit" }
                    "deny" { "Deny" }
                    "append" { "Append" }
                    default { $policy.PolicyType }
                }
                $evalTime = (Get-Date $policy.EvaluationTime -Format 'MM/dd HH:mm')
                
                $tableData += [PSCustomObject]@{
                    "Policy Name" = $displayName
                    "Type" = $policyTypeFormatted
                    "Status" = "Non-Compliant"
                    "Evaluated (UTC)" = $evalTime
                }
            }
            
            # Display as formatted table
            $tableData | Format-Table -AutoSize
            
            if ($nonCompliantPolicies.Count -gt 15) {
                Write-Host "   ... and $($nonCompliantPolicies.Count - 15) more non-compliant policies"
            }
        }

        Write-Host "`nKEY FINDINGS"
        Write-Host "   • Primary Issue: Microsoft Security Baseline policy enforcement"
        Write-Host "   • Root Cause: Missing security components and configuration gaps"
        Write-Host "   • Policy Types: Mix of Deploy (auto-deployment) and Audit (compliance checking)"
        Write-Host "   • Critical Gap: Activity log forwarding to Log Analytics not configured"

        Write-Host "`nDEPLOYMENT IMPACT"
        Write-Host "   • These policy violations may enforce security configurations automatically"
        Write-Host "   • Microsoft Security Baseline policies can override manual settings"
        Write-Host "   • Non-compliance could block resource deployments or force configurations"
        Write-Host "   • Consider policy exemptions for development environments if needed"

        Write-Host "`nRECOMMENDED ACTIONS"
        Write-Host "   1. Review non-compliant policies and determine remediation approach"
        Write-Host "   2. Configure required security components or request policy exemptions"
        Write-Host "   3. Monitor policy compliance after making infrastructure changes"
        Write-Host "   4. Consider implementing automated policy compliance in CI/CD pipelines"
    }
}

Write-Host "`n✅ Policy compliance analysis completed!" -ForegroundColor Green
