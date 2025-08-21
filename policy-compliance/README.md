# Azure Policy Compliance Report Scripts

This directory contains scripts for analyzing Azure Policy compliance across subscriptions.

## Scripts

### Get-PolicyComplianceReport.ps1
Generates a comprehensive Azure Policy compliance report for a specified subscription.

#### Usage Examples

**Interactive mode (prompts for subscription):**
```powershell
.\Get-PolicyComplianceReport.ps1
```

**Direct subscription specification:**
```powershell
.\Get-PolicyComplianceReport.ps1 -SubscriptionId "your-subscription-id-here"
```

**JSON output:**
```powershell
.\Get-PolicyComplianceReport.ps1 -SubscriptionId "your-subscription-id-here" -OutputFormat JSON
```

**CSV export:**
```powershell
.\Get-PolicyComplianceReport.ps1 -SubscriptionId "your-subscription-id-here" -OutputFormat CSV
```

#### Features
- ✅ Interactive subscription selection
- ✅ Multiple output formats (Console, JSON, CSV)
- ✅ Detailed compliance analysis
- ✅ Policy type categorization
- ✅ Friendly policy names
- ✅ Impact assessment
- ✅ Actionable recommendations

#### Requirements
- Azure CLI installed and configured
- PowerShell 5.1 or higher
- Appropriate Azure permissions to read policy states

#### Output
The script provides:
- Overall compliance statistics
- Detailed non-compliant policy list
- Policy evaluation timestamps
- Impact analysis on deployments
- Recommended next steps

#### Edge Cases
- **No Policies Found**: If no policy compliance data exists, the script will exit gracefully with an informational message explaining possible reasons (no policies assigned, no resources, evaluation pending, or insufficient permissions)
- **All Compliant**: If all policies are compliant, only the summary section will be displayed
- **Large Policy Sets**: For subscriptions with many policies, only the first 15 non-compliant policies are shown in detail
