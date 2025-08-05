# AWS Hello Credentials - PowerShell Integration Example
# This script demonstrates how to integrate the Python AWS Hello Credentials
# manager with PowerShell workflows

<#
.SYNOPSIS
    Example PowerShell functions to work with AWS Hello Credentials

.DESCRIPTION
    This script provides PowerShell wrapper functions around the Python
    AWS Hello Credentials manager for seamless integration with existing
    PowerShell-based AWS workflows.

.EXAMPLE
    Add-AWSHelloProfile -ProfileName "my-profile" -AccessKey "AKIA..." -SecretKey "xyz..." -Region "us-east-1"
    
.EXAMPLE
    Get-AWSHelloProfiles
    
.EXAMPLE
    Test-AWSHelloProfile -ProfileName "my-profile"
#>

# Path to the Python script (adjust as needed)
$script:PythonScriptPath = Join-Path $PSScriptRoot "aws_hello_creds.py"

function Add-AWSHelloProfile {
    <#
    .SYNOPSIS
        Add AWS credentials to Hello encrypted storage
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ProfileName,
        
        [Parameter(Mandatory = $true)]
        [string]$AccessKey,
        
        [Parameter(Mandatory = $true)]
        [string]$SecretKey,
        
        [Parameter(Mandatory = $false)]
        [string]$SessionToken,
        
        [Parameter(Mandatory = $false)]
        [string]$Region
    )
    
    $arguments = @(
        "add-profile", $ProfileName,
        "--access-key", $AccessKey,
        "--secret-key", $SecretKey
    )
    
    if ($SessionToken) {
        $arguments += @("--session-token", $SessionToken)
    }
    
    if ($Region) {
        $arguments += @("--region", $Region)
    }
    
    try {
        $result = & python $script:PythonScriptPath @arguments
        Write-Host "✅ Successfully added profile '$ProfileName'" -ForegroundColor Green
        return $result
    }
    catch {
        Write-Error "❌ Failed to add profile '$ProfileName': $_"
        throw
    }
}

function Get-AWSHelloProfiles {
    <#
    .SYNOPSIS
        List all encrypted AWS profiles
    #>
    [CmdletBinding()]
    param()
    
    try {
        $result = & python $script:PythonScriptPath "list-profiles"
        return $result
    }
    catch {
        Write-Error "❌ Failed to list profiles: $_"
        throw
    }
}

function Remove-AWSHelloProfile {
    <#
    .SYNOPSIS
        Remove an encrypted AWS profile
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ProfileName
    )
    
    try {
        $result = & python $script:PythonScriptPath "remove-profile" $ProfileName
        Write-Host "✅ Successfully removed profile '$ProfileName'" -ForegroundColor Green
        return $result
    }
    catch {
        Write-Error "❌ Failed to remove profile '$ProfileName': $_"
        throw
    }
}

function Test-AWSHelloProfile {
    <#
    .SYNOPSIS
        Test AWS profile by getting caller identity
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ProfileName
    )
    
    try {
        Write-Host "Testing profile '$ProfileName'..." -ForegroundColor Yellow
        $identity = aws sts get-caller-identity --profile $ProfileName | ConvertFrom-Json
        
        Write-Host "✅ Profile '$ProfileName' is working!" -ForegroundColor Green
        Write-Host "   Account: $($identity.Account)" -ForegroundColor Cyan
        Write-Host "   User/Role: $($identity.Arn)" -ForegroundColor Cyan
        Write-Host "   User ID: $($identity.UserId)" -ForegroundColor Cyan
        
        return $identity
    }
    catch {
        Write-Error "❌ Profile '$ProfileName' test failed: $_"
        throw
    }
}

function Import-AWSCredentialsFromFile {
    <#
    .SYNOPSIS
        Import AWS credentials from a CSV file
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CsvPath,
        
        [Parameter(Mandatory = $false)]
        [string]$DefaultRegion = "us-east-1"
    )
    
    if (-not (Test-Path $CsvPath)) {
        throw "File not found: $CsvPath"
    }
    
    $credentials = Import-Csv $CsvPath
    
    foreach ($cred in $credentials) {
        $region = if ($cred.Region) { $cred.Region } else { $DefaultRegion }
        
        try {
            Add-AWSHelloProfile -ProfileName $cred.ProfileName -AccessKey $cred.AccessKey -SecretKey $cred.SecretKey -Region $region
        }
        catch {
            Write-Warning "Failed to import profile '$($cred.ProfileName)': $_"
        }
    }
}

# Example usage functions
function Show-AWSHelloExamples {
    Write-Host @"

🔐 AWS Hello Credentials - PowerShell Examples
===============================================

# Add a profile
Add-AWSHelloProfile -ProfileName "my-aws" -AccessKey "AKIA..." -SecretKey "xyz..." -Region "us-east-1"

# List profiles  
Get-AWSHelloProfiles

# Test a profile
Test-AWSHelloProfile -ProfileName "my-aws"

# Remove a profile
Remove-AWSHelloProfile -ProfileName "old-profile"

# Use with AWS CLI
aws s3 ls --profile my-aws

# Use with AWS PowerShell
Set-AWSCredential -ProfileName my-aws
Get-S3Bucket

"@ -ForegroundColor Cyan
}

# Export functions
Export-ModuleMember -Function @(
    'Add-AWSHelloProfile',
    'Get-AWSHelloProfiles', 
    'Remove-AWSHelloProfile',
    'Test-AWSHelloProfile',
    'Import-AWSCredentialsFromFile',
    'Show-AWSHelloExamples'
)
