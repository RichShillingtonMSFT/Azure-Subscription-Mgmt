<#
.SYNOPSIS
    Deploy Subscription Management Solution Script

.DESCRIPTION
    This script will deploy the Subscription Management Solution to the selected Subscription.

.PARAMETER ResourceGroupName
    Define a name for the Resource Group to be used. It can be a new or exisiting Resource Group
    Example: "Subscription-Management-RG"

.PARAMETER AutomationAccountNamePrefix
    Define the prefix for the Automation Account Name.
    Maximum of 37 characters
    Example: "Subscription-Mgmt-Automation-Account-"

.PARAMETER KeyVaultNamePrefix
    Define the prefix for the Key Vault Name.
    Maximum of 10 characters
    Example: "ADE-KV-"

.EXAMPLE
    .\Deploy-SubscriptionManagementSolution.ps1
#>
[CmdletBinding()]
Param
(
    # Define a name for the Resource Group to be used. It can be a new or exisiting Resource Group
    # Example: "Subscription-Management-RG"
    [parameter(Mandatory=$false,HelpMessage='Example: Subscription-Management-RG')]
    [String]$ResourceGroupName = 'Subscription-Management-RG',

    # Define the prefix for the Automation Account Name.
    # Maximum of 37 characters
    # Example: "Subscription-Mgmt-Automation-Account-"
    [parameter(Mandatory=$false,HelpMessage='Example: Subscription-Mgmt-Automation-Account-')]
    [ValidateLength(1,37)]
    [String]$AutomationAccountNamePrefix = 'Subscription-Mgmt-Automation-Account-',

    # Define the prefix for the Key Vault Name.
    # Maximum of 10 characters
    # Example: "ADE-KV-"
    [parameter(Mandatory=$false,HelpMessage='Example: ADE-KV-')]
    [ValidateLength(1,10)]
    [String]$KeyVaultNamePrefix = 'ADE-KV-'
)

# Set verbose preference
$VerbosePreference = 'Continue'

#region Enviornment Selection
$Environments = Get-AzureRmEnvironment
$Environment = $Environments | Out-GridView -Title "Please Select an Azure Enviornment." -PassThru
#endregion

#region Connect to Azure
try
{
    $AzureRMAccount = Connect-AzureRmAccount -Environment $($Environment.Name) -ErrorAction 'Stop'
}
catch
{
    Write-Error -Message $_.Exception
    break
}

try 
{
    $Subscriptions = Get-AzureRmSubscription
    if ($Subscriptions.Count -gt '1')
    {
        $Subscription = $Subscriptions | Out-GridView -Title "Please Select a Subscription." -PassThru
        Select-AzureRmSubscription $Subscription
        $SubscriptionID = $Subscription.SubscriptionID
        $TenantID = $Subscription.TenantId
    }
    else
    {
        $SubscriptionID = $Subscriptions.SubscriptionID
        $TenantID = $Subscriptions.TenantId
    }
}
catch
{
    Write-Error -Message $_.Exception
    break
}
#endregion

#region Location Selection
$Locations = Get-AzureRmLocation
$Location = ($Locations | Out-GridView -Title "Please Select a location." -PassThru).Location
#endregion

#region Set Script Variables
# External IP Information
$ExternalIP = Invoke-RestMethod -Uri 'http://ipinfo.io/json' | Select-Object -ExpandProperty IP

# Enviornment
$AuthorityURL = $($AzureRMAccount.Context.Environment.ActiveDirectoryAuthority)
$ResourceManagerUrl = $($AzureRMAccount.Context.Environment.ResourceManagerUrl)
$TokenAuthority = $AuthorityURL + $TenantID + '/'
$ResourceManagerUrl = $($Environment.ResourceManagerUrl)
$ResourceURL = $($Environment.ServiceManagementUrl)

# Automation Account
$AutomationAccountName = $AutomationAccountNamePrefix + ($SubscriptionID.substring(0,13)).ToUpper()

# Key Vault
$KeyVaultName = $KeyVaultNamePrefix + ($SubscriptionID.substring(0,13)).ToUpper()

# Storage Account
$StorageAccountName = 'sharedsa' + ($SubscriptionID.Replace('-','').substring(0,13)).ToLower()
$StorageAccountType = 'Standard_GRS'
$StorageKind = 'StorageV2'
$StorageAccessTier = 'Hot'
$AdminScriptsContainerName = 'administrationscripts'
$WindowsUpdateScriptsFolderName = 'WindowsUpdateScripts'
$OrphanedObjectReportsFolderName = 'OrphanedObjectReports'
$SubscriptionReportsContainerName = 'subscriptionreports'
#endregion

#region Create Custom Role Definitions

#region Create Virtual Machine Extension Operator Custom Role
$VirtualMachineExtensionOperatorCustomRoleName = "Virtual Machine Extension Operator for Subscription $SubscriptionID"
$CustomRoleDescription = "Can deploy Extensions to virtual machines in Subscription $SubscriptionID"

$CustomRole = Get-AzureRmRoleDefinition -Name $VirtualMachineExtensionOperatorCustomRoleName
if (!$CustomRole)
{
    Write-Output "Creating $VirtualMachineExtensionOperatorCustomRoleName Custom Role"

    $Permissions = @(
    'Microsoft.Compute/virtualMachines/extensions/read',
    'Microsoft.Compute/virtualMachines/extensions/delete',
    'Microsoft.Compute/virtualMachines/extensions/write'
    )

    $NewRole = [Microsoft.Azure.Commands.Resources.Models.Authorization.PSRoleDefinition]::new()
    $NewRole.Name = $VirtualMachineExtensionOperatorCustomRoleName
    $NewRole.Description = $CustomRoleDescription
    $NewRole.IsCustom = $true
    $NewRole.Actions = $Permissions
    $Subscription = '/subscriptions/' + $SubscriptionID
    $NewRole.AssignableScopes = $Subscription
    New-AzureRmRoleDefinition -Role $NewRole -Verbose -ErrorAction 'Stop'
}
#endregion

#region Create Service Endpoint Manager Custom Role
$ServiceEndpointManagerCutomRoleName = "Service Endpoint Manager for Subscription $SubscriptionID"
$CustomRoleDescription = "Can manage Service Endpoints and Endpoint Policies in Subscription $SubscriptionID"

$CustomRole = Get-AzureRmRoleDefinition -Name $ServiceEndpointManagerCutomRoleName
if (!$CustomRole)
{
    Write-Output "Creating $ServiceEndpointManagerCutomRoleName Custom Role"

    $Permissions = @(
    'Microsoft.Network/serviceEndpointPolicies/delete',
    'Microsoft.Network/serviceEndpointPolicies/join/action',
    'Microsoft.Network/serviceEndpointPolicies/joinSubnet/action',
    'Microsoft.Network/locations/virtualNetworkAvailableEndpointServices/read',
    'Microsoft.Network/serviceEndpointPolicies/read',
    'Microsoft.Network/serviceEndpointPolicies/serviceEndpointPolicyDefinitions/delete',
    'Microsoft.Network/serviceEndpointPolicies/serviceEndpointPolicyDefinitions/read',
    'Microsoft.Network/serviceEndpointPolicies/serviceEndpointPolicyDefinitions/write',
    'Microsoft.Network/serviceEndpointPolicies/write',
    'Microsoft.Network/virtualNetworks/subnets/joinViaServiceEndpoint/action',
    'Microsoft.Network/virtualNetworks/write'
    )

    $NewRole = [Microsoft.Azure.Commands.Resources.Models.Authorization.PSRoleDefinition]::new()
    $NewRole.Name = $ServiceEndpointManagerCutomRoleName
    $NewRole.Description = $CustomRoleDescription
    $NewRole.IsCustom = $true
    $NewRole.Actions = $Permissions
    $Subscription = '/subscriptions/' + $SubscriptionID
    $NewRole.AssignableScopes = $Subscription
    New-AzureRmRoleDefinition -Role $NewRole -Verbose -ErrorAction 'Stop'
}
#endregion

#endregion

#region Resource Group
# Create the resource group if needed
try 
{
    Get-AzureRmResourceGroup -Name $ResourceGroupName -ErrorAction 'Stop'
    Write-Output "Found Resource Group $ResourceGroupName"
}
catch 
{
    Write-Output "Creating Resource Group $ResourceGroupName"
    New-AzureRmResourceGroup -Name $ResourceGroupName -Location $Location -ErrorAction 'Stop'
}
#endregion

#region KeyVault
Write-Output "Checking for Key Vault $KeyVaultName"
$KeyVaultTest = Get-AzureRmKeyVault -ResourceGroupName $ResourceGroupName | Where-Object {$_.VaultName -eq $KeyVaultName}

if (!$KeyVaultTest)
{
    Write-Warning -Message "Key Vault not found. Creating the Key Vault $keyVaultName"
    try
    {
        $KeyVault = New-AzureRmKeyVault -VaultName $keyVaultName -ResourceGroupName $ResourceGroupName -Location $Location -Sku 'Premium' -Verbose -ErrorAction 'Stop'
        Write-Output "Key Vault $keyVaultName created successfully"
    }   
    catch
    {
        if ($Error[0].Exception -like "*LocationNotAvailableForResourceType:*")
        {
            $Locations = (Get-AzureRmResourceProvider -ProviderNamespace 'Microsoft.KeyVault' | Where-Object  {$_.ResourceTypes.ResourceTypeName -eq 'vaults'}).Locations
            $NewLocationSelection = $Locations | Out-GridView -Title "The location selected is not valid for Key Vault, please select a new location." -PassThru
            $NewLocation = $NewLocationSelection.Replace(' ','').ToLower()
            $KeyVault = New-AzureRmKeyVault -VaultName $keyVaultName -ResourceGroupName $ResourceGroupName -Location $NewLocation -Sku 'Premium' -Verbose -ErrorAction 'Stop'

        }
        else
        {
            Write-Output $Error[0].Exception
            break
        }
    }
}

try
{
    Write-Output 'Setting Key Vault Access Policy'
    Set-AzureRmKeyVaultAccessPolicy -ResourceID $KeyVault.ResourceId -EnabledForDeployment -EnabledForTemplateDeployment -EnabledForDiskEncryption -Verbose -ErrorAction 'Stop'
}
catch 
{
    Write-Warning $_
    break
}

Write-Output "Key Vault $KeyVaultName configuration completed successfully"
#endregion

#region Automation Account
Write-Output "Creating Automation Account $AutomationAccountName"
# Create Automation Account
try
{
    New-AzureRmAutomationAccount -ResourceGroupName $ResourceGroupName -Name $AutomationAccountName -Location $Location -ErrorAction 'Stop' -Verbose
    Write-Output "Automation Account $AutomationAccountName created successfully"
}
catch
{
    if ($Error[0].Exception -like "*LocationNotAvailableForResourceType:*")
    {
        $Locations = (Get-AzureRmResourceProvider -ProviderNamespace 'Microsoft.Automation' | Where-Object  {$_.ResourceTypes.ResourceTypeName -eq 'automationAccounts'}).Locations
        $NewLocationSelection = $Locations | Out-GridView -Title "The location selected is not valid for Automation Accounts, please select a new location." -PassThru
        $NewLocation = $NewLocationSelection.Replace(' ','').ToLower()
        New-AzureRmAutomationAccount -ResourceGroupName $ResourceGroupName -Name $AutomationAccountName -Location $NewLocation -Verbose -ErrorAction 'Stop'

    }
    else
    {
        Write-Output $Error[0].Exception
        break
    }
}

$AutomationAccountResourceID = (Get-AzureRmResource -ResourceType Microsoft.Automation/automationAccounts -ResourceGroupName $ResourceGroupName).ResourceId
#endregion

#region Automation Account Certificate
[String] $ApplicationDisplayName = $AutomationAccountName
[String] $SelfSignedCertPlainPassword = [Guid]::NewGuid().ToString().Substring(0, 8) + "!" 
[int]$NumberOfMonthsUntilExpired = '36'
$CertifcateAssetName = "AzureRunAsCertificate"
$CertificateName = $AutomationAccountName + $CertifcateAssetName
$PfxCertificatePathForRunAsAccount = Join-Path $env:TEMP ($CertificateName + ".pfx")
$PfxCertificatePlainPasswordForRunAsAccount = $SelfSignedCertPlainPassword
$CerCertificatePathForRunAsAccount = Join-Path $env:TEMP ($CertificateName + ".cer")
$CertificateSubjectName = "cn=" + $CertificateName

# Create Certificate Using Key Vault
Write-Output "Generating the Automation Account Certificate using Key Vault $keyVaultName"

Write-Output 'Creating Key Vault Certificate Policy'
$Policy = New-AzureKeyVaultCertificatePolicy -SecretContentType "application/x-pkcs12" -SubjectName $CertificateSubjectName -IssuerName "Self" -ValidityInMonths $NumberOfMonthsUntilExpired -ReuseKeyOnRenewal

try 
{
    Write-Output 'Adding Azure Key Vault Certificate'
    $AddAzureKeyVaultCertificateStatus = Add-AzureKeyVaultCertificate -VaultName $keyVaultName -Name $CertificateName -CertificatePolicy $Policy -ErrorAction 'Stop'
    While ($AddAzureKeyVaultCertificateStatus.Status -eq "inProgress")
    {
        Start-Sleep -s 10
        $AddAzureKeyVaultCertificateStatus = Get-AzureKeyVaultCertificateOperation -VaultName $keyVaultName -Name $CertificateName
    }

}
catch 
{
    Write-Error -Message "Key vault certificate creation was not sucessfull."
    break
}

#endregion

#region Create RunAsAccount
# Get Certificate Information from Key Vault
Write-Output "Get Certificate Information from Key Vault $keyVaultName"
$SecretRetrieved = Get-AzureKeyVaultSecret -VaultName $KeyVaultName -Name $CertificateName -ErrorAction 'Stop'
$PfxBytes = [System.Convert]::FromBase64String($SecretRetrieved.SecretValueText)
$CertificateCollection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
$CertificateCollection.Import($PfxBytes, $null, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
   
# Export  the .pfx file 
$protectedCertificateBytes = $CertificateCollection.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $PfxCertificatePlainPasswordForRunAsAccount)
[System.IO.File]::WriteAllBytes($PfxCertificatePathForRunAsAccount, $protectedCertificateBytes)

# Export the .cer file 
$Certificate = Get-AzureKeyVaultCertificate -VaultName $keyVaultName -Name $CertificateName -ErrorAction 'Stop'
$CertificateBytes = $Certificate.Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
[System.IO.File]::WriteAllBytes($CerCertificatePathForRunAsAccount, $CertificateBytes)

Write-Output "Creating Service Principal"
# Create Service Principal
$PfxCertificate = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @($PfxCertificatePathForRunAsAccount, $PfxCertificatePlainPasswordForRunAsAccount)
$KeyValue = [System.Convert]::ToBase64String($PfxCertificate.GetRawCertData())
$KeyId = [Guid]::NewGuid()
$StartDate = Get-Date
$EndDate = (Get-Date $PfxCertificate.GetExpirationDateString()).AddDays(-1)

# Use Key credentials and create AAD Application
Write-Output "Creating Azure AD Application"
try
{
    $Application = New-AzureRmADApplication -DisplayName $ApplicationDisplayName -HomePage ("http://" + $applicationDisplayName) -IdentifierUris ("http://" + $KeyId) -ErrorAction 'Stop'
    New-AzureRmADAppCredential -ApplicationId $Application.ApplicationId -CertValue $KeyValue -StartDate $StartDate -EndDate $EndDate -ErrorAction 'Stop'
    New-AzureRMADServicePrincipal -ApplicationId $Application.ApplicationId -ErrorAction 'Stop'
}
catch
{
    Write-Warning $_
    break
}

# Allow the service principal application to become active
Start-Sleep -s 30
Write-Output "Service Principal created successfully"

# Create the automation certificate asset
Write-Output "Creating Automation Certificate"
$CertificatePassword = ConvertTo-SecureString $PfxCertificatePlainPasswordForRunAsAccount -AsPlainText -Force
try
{
    New-AzureRmAutomationCertificate -ResourceGroupName $ResourceGroupName -automationAccountName $AutomationAccountName -Path $PfxCertificatePathForRunAsAccount -Name $CertifcateAssetName -Password $CertificatePassword -Exportable -ErrorAction 'Stop'
}
catch 
{
    Write-Warning $_
    break
}

# Populate the Connection Field Values
$ConnectionTypeName = "AzureServicePrincipal"
$ConnectionAssetName = "AzureRunAsConnection"
$ConnectionFieldValues = @{"ApplicationId" = $($Application.ApplicationId); "TenantId" = $TenantID; "CertificateThumbprint" = $($PfxCertificate.Thumbprint); "SubscriptionId" = $SubscriptionID} 

# Create a Automation connection asset named AzureRunAsConnection in the Automation account. This connection uses the service principal.
Write-Output "Creating Automation Connection"
try
{
    New-AzureRmAutomationConnection -ResourceGroupName $ResourceGroupName -automationAccountName $AutomationAccountName -Name $ConnectionAssetName -ConnectionTypeName $connectionTypeName -ConnectionFieldValues $connectionFieldValues -ErrorAction 'Stop'
}
catch 
{
    Write-Warning $_
    break
}
Write-Output "Automation Account $AutomationAccountName creation & configuration completed successfully"
#endregion

#region Assign Automation Account Permissions
Write-Output "Assigning permissions to the Automation Account"

# Assign Subscription Reader
Write-Output "Assigning Subscription Reader to the Automation Account"
$NewRole = $null
[Int]$Retries = '0'
While ($NewRole -eq $null -and $Retries -le 6) 
{
    New-AzureRMRoleAssignment -RoleDefinitionName Reader -ServicePrincipalName $Application.ApplicationId -scope ("/subscriptions/" + $SubscriptionID) -ErrorAction 'SilentlyContinue'
    Start-Sleep -s 10
    $NewRole = Get-AzureRMRoleAssignment -ServicePrincipalName $Application.ApplicationId -ErrorAction 'SilentlyContinue'
    $Retries++;
}

# Assign Key Vault Contributor
Write-Output "Assigning Key Vault Contributor to the Automation Account"
$NewRole = $null
[Int]$Retries = '0'
While ($NewRole -eq $null -and $Retries -le 6) 
{
    New-AzureRMRoleAssignment -RoleDefinitionName Contributor -ServicePrincipalName $Application.ApplicationId -scope ($KeyVault.ResourceId) -ErrorAction 'SilentlyContinue'
    Start-Sleep -s 10
    $NewRole = Get-AzureRMRoleAssignment -ServicePrincipalName $Application.ApplicationId -ErrorAction 'SilentlyContinue'
    $Retries++;
}

# Assign Virtual Machine Contributor
Write-Output "Assigning Virtual Machine Contributor to the Automation Account"
$NewRole = $null
[Int]$Retries = '0'
While ($NewRole -eq $null -and $Retries -le 6) 
{
    New-AzureRMRoleAssignment -RoleDefinitionName 'Virtual Machine Contributor' -ServicePrincipalName $Application.ApplicationId -scope ("/subscriptions/" + $SubscriptionID) -ErrorAction 'SilentlyContinue'
    Start-Sleep -s 10
    $NewRole = Get-AzureRMRoleAssignment -ServicePrincipalName $Application.ApplicationId -ErrorAction 'SilentlyContinue'
    $Retries++;
}


# Assign Virtual Machine Extension Operator
Write-Output "Assigning Virtual Machine Extension Operator to the Automation Account"
$NewRole = $null
[Int]$Retries = '0'
While ($NewRole -eq $null -and $Retries -le 6) 
{
    New-AzureRMRoleAssignment -RoleDefinitionName $VirtualMachineExtensionOperatorCustomRoleName -ServicePrincipalName $Application.ApplicationId -scope ("/subscriptions/" + $SubscriptionID) -ErrorAction 'SilentlyContinue'
    Start-Sleep -s 10
    $NewRole = Get-AzureRMRoleAssignment -ServicePrincipalName $Application.ApplicationId -ErrorAction 'SilentlyContinue'
    $Retries++;
}

# Assign Service Endpoint Manager
Write-Output "Assigning Service Endpoint Manager to the Automation Account"
$NewRole = $null
[Int]$Retries = '0'
While ($NewRole -eq $null -and $Retries -le 6) 
{
    New-AzureRMRoleAssignment -RoleDefinitionName $ServiceEndpointManagerCutomRoleName -ServicePrincipalName $Application.ApplicationId -scope ("/subscriptions/" + $SubscriptionID) -ErrorAction 'SilentlyContinue'
    Start-Sleep -s 10
    $NewRole = Get-AzureRMRoleAssignment -ServicePrincipalName $Application.ApplicationId -ErrorAction 'SilentlyContinue'
    $Retries++;
}

# Assign Contributor to Automation Account
Write-Output "Assigning Contributor of the Automation Account to the Automation Account"
$NewRole = $null
[Int]$Retries = '0'
While ($NewRole -eq $null -and $Retries -le 6) 
{
    New-AzureRMRoleAssignment -RoleDefinitionName 'Contributor' -ServicePrincipalName $Application.ApplicationId -scope $AutomationAccountResourceID -ErrorAction 'SilentlyContinue'
    Start-Sleep -s 10
    $NewRole = Get-AzureRMRoleAssignment -ServicePrincipalName $Application.ApplicationId -ErrorAction 'SilentlyContinue'
    $Retries++;
}

#endregion

#region Install Automation Account Modules
Write-Output "Installing AzureRM.Profile, AzureRM.KeyVault and AzureRM.Network Modules in Automation Account"
$ModuleTemplateFilePath = New-Item -Path "$env:TEMP\ModuleTemplate.json" -ItemType File -Force
$ModuleTemplateData = @"
{
    "`$schema": "http://schema.management.azure.com/schemas/2015-01-01/deploymentTemplate.json#",
    "contentVersion": "1.0",
    "parameters": {
        "accountName": {
            "type": "String"
        },
        "accountLocation": {
            "type": "String"
        },
        "Level1": {
            "type": "Object"
        },
        "Level0": {
            "type": "Object"
        }
    },
    "variables": {},
    "resources": [
        {
            "type": "Microsoft.Automation/automationAccounts/modules",
            "name": "[concat(parameters('accountName'), '/', parameters('Level1').Modules[copyIndex()].Name)]",
            "apiVersion": "2015-10-31",
            "location": "[parameters('accountLocation')]",
            "copy": {
                "name": "Level1ModulesInstall",
                "count": "[length(parameters('Level1').Modules)]",
                "mode": "Serial",
                "batchSize": 1
            },
            "tags": {},
            "properties": {
                "contentLink": {
                    "uri": "[parameters('Level1').Modules[copyIndex()].Uri]"
                }
            },
            "dependsOn": []
        },
        {
            "type": "Microsoft.Automation/automationAccounts/modules",
            "name": "[concat(parameters('accountName'), '/', parameters('Level0').Modules[copyIndex()].Name)]",
            "apiVersion": "2015-10-31",
            "location": "[parameters('accountLocation')]",
            "copy": {
                "name": "Level0ModulesInstall",
                "count": "[length(parameters('Level0').Modules)]",
                "mode": "Serial",
                "batchSize": 1
            },
            "tags": {},
            "properties": {
                "contentLink": {
                    "uri": "[parameters('Level0').Modules[copyIndex()].Uri]"
                }
            },
            "dependsOn": [
                "Level1ModulesInstall"
            ]
        }
    ],
    "outputs": {}
}
"@
Add-Content -Path $ModuleTemplateFilePath -Value $ModuleTemplateData

$ModuleParametersFilePath = New-Item -Path "$env:TEMP\ModuleParameters.json" -ItemType File -Force
$ModuleParametersData = @"
{
    "`$schema": "https://schema.management.azure.com/schemas/2015-01-01/deploymentParameters.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {
        "accountName": {
            "value": "$AutomationAccountName"
        },
        "accountLocation": {
            "value": "$Location"
        },
        "level1": {
            "value": {
                "Modules": [
                    {
                        "Name": "AzureRM.profile",
                        "Uri": "https://devopsgallerystorage.blob.core.windows.net:443/packages/azurerm.profile.5.8.3.nupkg"
                    }
                ]
            }
        },
        "level0": {
            "value": {
                "Modules": [
                    {
                        "Name": "AzureRM.KeyVault",
                        "Uri": "https://devopsgallerystorage.blob.core.windows.net:443/packages/azurerm.keyvault.5.2.1.nupkg"
                    },
                    {
                        "Name": "AzureRM.Network",
                        "Uri": "https://devopsgallerystorage.blob.core.windows.net:443/packages/azurerm.network.6.11.1.nupkg"
                    }
                ]
            }
        }
    }
}
"@
Add-Content -Path $ModuleParametersFilePath -Value $ModuleParametersData 

try
{
    Write-Output "Installing Azure Automation Modules. This may take a few minutes."
    New-AzureRmResourceGroupDeployment -ResourceGroupName $ResourceGroupName -TemplateFile $($ModuleTemplateFilePath.FullName) -TemplateParameterFile $($ModuleParametersFilePath.FullName) -ErrorAction 'Stop'
    Write-Output "Azure Automation Modules installation completed successfully"
}
catch
{
    Write-Warning $_
    break
}
#endregion

#region Create Schedules
Write-Output "Creating Azure Automation Schedules"
# Create Hourly Schedule
$HourlyScheduleName = 'Every Hour on the Hour'
Write-Output "Creating Automation Schedule Name $HourlyScheduleName"
try
{
    New-AzureRmAutomationSchedule -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name $HourlyScheduleName -StartTime ([datetime]::Today).AddDays(1) -HourInterval 1 -Verbose -ErrorAction 'Stop'
}
catch
{
    Write-Warning $_
}

# Create Daily Schedule
$DailyScheduleName = 'Every Day Once a Day'
Write-Output "Creating Automation Schedule Name $DailyScheduleName"
try
{
    New-AzureRmAutomationSchedule -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name $DailyScheduleName -StartTime ([datetime]::Today).AddDays(1) -DayInterval 1 -Verbose -ErrorAction 'Stop'
}
catch
{
    Write-Warning $_
}
Write-Output "Creation of Azure Automation Schedules completed successfully"
#endregion

#region Create Shared Storage Account
Write-Output "Creating Shared Storage Account $StorageAccountName"
# Create JSON Hashtable
$ArrayParameters = 
@'
{
    "type": "array",
    "defaultValue": []
}
'@ | ConvertFrom-Json

# Get all Subnet IDs and add them to an array
Write-Output "Making sure Microsoft.Storage Service Endpoint is on all Virtual Network Subnets"
$SubnetIDs = @()
$VirtualNetworks = Get-AzureRmVirtualNetwork -Verbose -WarningAction 'SilentlyContinue' -ErrorAction 'Stop' | Where-Object {$_.Location -eq $Location}
foreach ($VirtualNetwork in $VirtualNetworks)
{
    foreach ($Subnet in $VirtualNetwork.Subnets | Where-Object {$_.Name -ne 'GatewaySubnet'})
    {
        $VirtualNetworkSubnetConfig = Get-AzureRmVirtualNetworkSubnetConfig -Name $Subnet.Name -VirtualNetwork $VirtualNetwork -Verbose -WarningAction 'SilentlyContinue'
        if (!$VirtualNetworkSubnetConfig.ServiceEndpoints.Service)
        {
            Write-Output "$($Subnet.Name) has no Service Endpoints"
            Write-Output "Adding Microsoft.Storage Service Endpoint to $($Subnet.Name) in Virtual Network $($VirtualNetwork.Name)"
            Set-AzureRmVirtualNetworkSubnetConfig -Name $Subnet.Name -VirtualNetwork $VirtualNetwork -AddressPrefix $Subnet.AddressPrefix -ServiceEndpoint 'Microsoft.Storage' -WarningAction 'SilentlyContinue' | Set-AzureRmVirtualNetwork -WarningAction 'SilentlyContinue' -Verbose -ErrorAction 'Stop'
        }
        else
        {
            if ($VirtualNetworkSubnetConfig.ServiceEndpoints.Service -notcontains 'Microsoft.Storage')
            {
                Write-Output "$($Subnet.Name) is missing Microsoft.Storage Service Endpoint"
                Write-Output "Adding Microsoft.Storage Service Endpoint to $($Subnet.Name) in Virtual Network $($VirtualNetwork.Name)"
                $ServiceEnpoints = @('Microsoft.Storage')
                $ServiceEnpoints += $VirtualNetworkSubnetConfig.ServiceEndpoints.Service
                Set-AzureRmVirtualNetworkSubnetConfig -Name $Subnet.Name -VirtualNetwork $VirtualNetwork -AddressPrefix $Subnet.AddressPrefix -ServiceEndpoint $ServiceEnpoints -WarningAction 'SilentlyContinue' | Set-AzureRmVirtualNetwork -WarningAction 'SilentlyContinue' -Verbose -ErrorAction 'Stop'
            }
        }
        $SubnetIDs += $Subnet.Id
    }
}
Write-Output 'Virtual Network Subnet Configuration completed successfully'

# Add each Subnet Id to JSON Hashtable
foreach ($SubnetID in $SubnetIDs)
{
    $ArrayParameters.defaultValue += @{id=$SubnetID}
}

# Convert Hashtable to JSON
$SubnetParameters = $ArrayParameters | ConvertTo-Json

# Create JSON File Template
$SharedStorageAccountFilePath = New-Item -Path "$env:TEMP\SharedStorageAccount.json" -ItemType File -Force
$SharedStorageAccountData = @"
{
    "`$schema": "http://schema.management.azure.com/schemas/2015-01-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {
        "location": {
            "type": "string",
            "defaultValue": "$Location"
        },
        "storageAccountName": {
            "type": "string",
            "defaultValue": "$StorageAccountName"
        },
        "accountType": {
            "type": "string",
            "defaultValue": "$StorageAccountType"
        },
        "kind": {
            "type": "string",
            "defaultValue": "$StorageKind"
        },
        "accessTier": {
            "type": "string",
            "defaultValue": "$StorageAccessTier"
        },
        "containerName": {
            "type": "string",
            "defaultValue": "$AdminScriptsContainerName"
        },
        "supportsHttpsTrafficOnly": {
            "type": "bool",
            "defaultValue": true
        },
        "networkAclsBypass": {
            "type": "string",
            "defaultValue": "AzureServices"
        },
        "networkAclsDefaultAction": {
            "type": "string",
            "defaultValue": "Deny"
        },
        "networkAclsVirtualNetworkRules": $SubnetParameters
    },
    "variables": {},
    "resources": [
        {
            "name": "[parameters('storageAccountName')]",
            "type": "Microsoft.Storage/storageAccounts",
            "apiVersion": "2018-02-01",
            "location": "[parameters('location')]",
            "properties": {
                "accessTier": "[parameters('accessTier')]",
                "supportsHttpsTrafficOnly": "[parameters('supportsHttpsTrafficOnly')]",
                "networkAcls": {
                    "bypass": "[parameters('networkAclsBypass')]",
                    "defaultAction": "[parameters('networkAclsDefaultAction')]",
                    "ipRules": [  
                        {
                            "value": "$ExternalIP",
                            "action": "Allow"
                        }
                    ],
                    "virtualNetworkRules": "[parameters('networkAclsVirtualNetworkRules')]"
                }
            },
            "dependsOn": [],
            "sku": {
                "name": "[parameters('accountType')]"
            },
            "kind": "[parameters('kind')]",
            "resources": [
                {
                    "type": "blobServices/containers",
                    "apiVersion": "2018-03-01-preview",
                    "name": "[concat('default/', parameters('containerName'))]",
                    "dependsOn": [
                        "[parameters('storageAccountName')]"
                    ],
                    "properties": {
                        "publicAccess": "None"
                    }
                }
            ]
        }
    ],
    "outputs": {}
}
"@
Add-Content -Path $SharedStorageAccountFilePath -Value $SharedStorageAccountData

try
{
    Write-Output "Creating Shared Storage Account. This may take a few minutes."
    New-AzureRmResourceGroupDeployment -ResourceGroupName $ResourceGroupName -TemplateFile $($SharedStorageAccountFilePath.FullName) -ErrorAction 'Stop'
    Write-Output "Creation of Shared Storage Account $StorageAccountName completed successfully"
}
catch
{
    Write-Warning $_
    break
}

$StorageAccount = Get-AzureRmStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName
$BlobServiceEndpoint = $($StorageAccount.PrimaryEndpoints.Blob)
$ContainerURL = $BlobServiceEndpoint + $AdminScriptsContainerName
$WindowsUpdateScriptsFolderURL = $ContainerURL + '/' + $WindowsUpdateScriptsFolderName

# Assign Storage Account Contributor
Write-Output "Assigning Storage Account Contributor to the Automation Account"
$NewRole = $null
[Int]$Retries = '0'
While ($NewRole -eq $null -and $Retries -le 6) 
{
    New-AzureRMRoleAssignment -RoleDefinitionName Owner -ServicePrincipalName $Application.ApplicationId -scope ($StorageAccount.Id) -ErrorAction 'SilentlyContinue'
    Start-Sleep -s 10
    $NewRole = Get-AzureRMRoleAssignment -ServicePrincipalName $Application.ApplicationId -ErrorAction 'SilentlyContinue'
    $Retries++;
}

Write-Output "Creation and configuration of Shared Storage Account $StorageAccountName completed successfully"
#endregion

#region Upload Windows Update Scripts to Common Storage Account
Write-Output "Uploading Windows Update Scripts to Storage Account $StorageAccountName"
# Upload Invoke-WindowsUpdate.ps1 to Storage Account
Write-Output "Uploading Invoke-WindowsUpdate.ps1 to Storage Account $($StorageAccount.StorageAccountName)"
$WindowsUpdateFilePath = New-Item -Path "$env:TEMP\Invoke-WindowsUpdate.ps1" -ItemType File -Force
$WindowsUpdateFileContent = @'
<#
.SYNOPSIS
	Script to Invoke immediate Windows Update Check and Install

.DESCRIPTION
	This script was developed to be run as a Custom Script Extension on a Windows Azure Virtual Machine
	The script will force Windows Update client to check for and install Windows Updates according to the computers Windows Update Settings
	If a computer is set to use WSUS, an online check can be forced using the -ForceOnlineUpdate switch

.PARAMETER RestartOption

    Specify if you want to restart the Virtual Machine upon Windows Update installation completion
	"Example: AutoReboot or IgnoreReboot"
	
.PARAMETER ForceOnlineUpdate
	This is a switch that will force the computer to check online for Windows Updates

.EXAMPLE

    .\Invoke-WindowsUpdate.ps1 -RestartOption 'AutoReboot'
#>
[CmdletBinding()]
param
(
    [parameter(Mandatory=$true,HelpMessage="Example: AutoReboot or IgnoreReboot")]
    [ValidateSet('AutoReboot', 'IgnoreReboot')]
    $RestartOption,

    [Switch]$ForceOnlineUpdate
)

# Get Script Start Time and Date
$DateTime = (Get-Date)

# Set Verbose and ErrorAction Preference
$VerbosePreference = 'Continue'
$ErrorActionPreference = 'Stop'

# Create Script Log File
$ScriptLogFilePath = New-Item -Path "$env:TEMP\InvokeWindowsUpdate.log" -ItemType File -Force
Add-Content -Path $ScriptLogFilePath -Value "Script Processing Started at $DateTime"

Function Invoke-WindowsUpdate
{
	[CmdletBinding()]	
	Param
	(	
		#Mode options
		[Switch]$AcceptAll,
		[Switch]$AutoReboot,
		[Switch]$IgnoreReboot,
        [Switch]$ForceOnlineUpdate
	)

	# Check for administrative rights, break if not Administrator
	$User = [Security.Principal.WindowsIdentity]::GetCurrent()
	$Role = (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)

	if(!$Role)
	{
		Write-Warning "To perform some operations you must run an elevated Windows PowerShell console."
        Break
	}	
		
    # Get updates list
	Write-Verbose "Getting updates list"
    Add-Content -Path $ScriptLogFilePath -Value "Getting updates list"
	$objServiceManager = New-Object -ComObject "Microsoft.Update.ServiceManager" 
		
	Write-Verbose "Create Microsoft.Update.Session object"
    Add-Content -Path $ScriptLogFilePath -Value "Create Microsoft.Update.Session object"
	$SessionObject = New-Object -ComObject "Microsoft.Update.Session" 
		
	Write-Verbose "Create Microsoft.Update.Session.Searcher object"
    Add-Content -Path $ScriptLogFilePath -Value "Create Microsoft.Update.Session.Searcher object"
	$objSearcher = $SessionObject.CreateUpdateSearcher()
    
    # Check the registry for Windows Update settings and set searcher service
    $WindowsUpdatePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    $WindowsUpdateAUPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"

    if (!($ForceOnlineUpdate))
    {
        $WSUSRegistryValue = (Get-ItemProperty -Path $WindowsUpdatePath -Name WUServer -ErrorAction SilentlyContinue).WUServer
        if ($WSUSRegistryValue)
        {
            Write-Verbose "Computer is set to use WSUS Server $WSUSRegistryValue"
            Add-Content -Path $ScriptLogFilePath -Value "Computer is set to use WSUS Server $WSUSRegistryValue"
            $objSearcher.ServerSelection = 1
        }

        if ([String]::IsNullOrEmpty($WSUSRegistryValue))
        {
            $FeaturedSoftwareRegistryValue = (Get-ItemProperty -Path $WindowsUpdateAUPath -Name EnableFeaturedSoftware -ErrorAction SilentlyContinue).EnableFeaturedSoftware
            if ($FeaturedSoftwareRegistryValue)
            {
                Write-Verbose "Set source of updates to Microsoft Update"
                Add-Content -Path $ScriptLogFilePath -Value "Set source of updates to Microsoft Update"
                $serviceName = $null
                foreach ($objService in $objServiceManager.Services) 
                {
	                If($objService.Name -eq "Microsoft Update")
	                {
		                $objSearcher.ServerSelection = 3
		                $objSearcher.ServiceID = $objService.ServiceID
		                $serviceName = $objService.Name
		                Break
	                }
                }
            }
            else
            {
                Write-Verbose "Set source of updates to Windows Update"
                Add-Content -Path $ScriptLogFilePath -Value "Set source of updates to Windows Update"
		        $objSearcher.ServerSelection = 2
		        $serviceName = "Windows Update"
            }
        }
    }

    if ($ForceOnlineUpdate)
    {
        $FeaturedSoftwareRegistryValue = (Get-ItemProperty -Path $WindowsUpdateAUPath -Name EnableFeaturedSoftware -ErrorAction SilentlyContinue).EnableFeaturedSoftware
        if ($FeaturedSoftwareRegistryValue)
        {
            Write-Verbose "Set source of updates to Microsoft Update"
            Add-Content -Path $ScriptLogFilePath -Value "Set source of updates to Microsoft Update"
            $serviceName = $null
            foreach ($objService in $objServiceManager.Services) 
            {
	            If($objService.Name -eq "Microsoft Update")
	            {
		            $objSearcher.ServerSelection = 3
		            $objSearcher.ServiceID = $objService.ServiceID
		            $serviceName = $objService.Name
		            Break
	            }
            }
        }
        else
        {
            Write-Verbose "Set source of updates to Windows Update"
            Add-Content -Path $ScriptLogFilePath -Value "Set source of updates to Windows Update"
		    $objSearcher.ServerSelection = 2
		    $serviceName = "Windows Update"
        }
    }
		
	Write-Verbose "Connecting to $serviceName server. Please wait..."
    Add-Content -Path $ScriptLogFilePath -Value "Connecting to $serviceName server. Please wait..."

	Try
	{
		# Search for updates
        $Search = 'IsInstalled = 0'
        $objResults = $objSearcher.Search($Search)
	}
	Catch
	{
		If($_ -match "HRESULT: 0x80072EE2")
		{
			Write-Warning "Cannot connect to Windows Update server"
            Add-Content -Path $ScriptLogFilePath -Value "Cannot connect to Windows Update server"
		}
		Return
	}

	$objCollectionUpdate = New-Object -ComObject "Microsoft.Update.UpdateColl" 
		
	$NumberOfUpdate = 1
	$UpdatesExtraDataCollection = @{}
	$PreFoundUpdatesToDownload = $objResults.Updates.count

	Write-Verbose "Found $($PreFoundUpdatesToDownload) Updates in pre search criteria"	
    Add-Content -Path $ScriptLogFilePath -Value "Found $($PreFoundUpdatesToDownload) Updates in pre search criteria"	
        
    # Set updates to install variable
    $UpdatesToInstall = $objResults.Updates

	Foreach($Update in $UpdatesToInstall)
	{
		$UpdateAccess = $true
		Write-Verbose "Found Update: $($Update.Title)"
        Add-Content -Path $ScriptLogFilePath -Value "Found Update: $($Update.Title)"
			
		If($UpdateAccess -eq $true)
		{
			# Convert update size so it is readable
			Switch($Update.MaxDownloadSize)
			{
				{[System.Math]::Round($_/1KB,0) -lt 1024} { $Size = [String]([System.Math]::Round($_/1KB,0))+" KB"; break }
				{[System.Math]::Round($_/1MB,0) -lt 1024} { $Size = [String]([System.Math]::Round($_/1MB,0))+" MB"; break }  
				{[System.Math]::Round($_/1GB,0) -lt 1024} { $Size = [String]([System.Math]::Round($_/1GB,0))+" GB"; break }    
				{[System.Math]::Round($_/1TB,0) -lt 1024} { $Size = [String]([System.Math]::Round($_/1TB,0))+" TB"; break }
				default { $Size = $_+"B" }
			}
		
			# Convert KB Article IDs so it is readable
			If($Update.KBArticleIDs -ne "")    
			{
				$KB = "KB"+$Update.KBArticleIDs
			}
			Else 
			{
				$KB = ""
			}
				
            # Add updates
			$objCollectionUpdate.Add($Update) | Out-Null
			$UpdatesExtraDataCollection.Add($Update.Identity.UpdateID,@{KB = $KB; Size = $Size})

		}
			
		$NumberOfUpdate++
	}
		
	Write-Verbose "Update Search Completed"
    Add-Content -Path $ScriptLogFilePath -Value "Update Search Completed"
		
    $FoundUpdatesToDownload = $objCollectionUpdate.count

	If($FoundUpdatesToDownload -eq 0)
	{
        Write-Verbose 'No updates were found to download'
        Add-Content -Path $ScriptLogFilePath -Value 'No updates were found to download'		
        Return
	}

	Write-Verbose "Found $($FoundUpdatesToDownload) Updates"
    Add-Content -Path $ScriptLogFilePath -Value "Found $($FoundUpdatesToDownload) Updates"
		
	$NumberOfUpdate = 1
			
	$UpdateCollectionObject = New-Object -ComObject "Microsoft.Update.UpdateColl"

	Foreach($Update in $objCollectionUpdate)
	{	
		$Size = $UpdatesExtraDataCollection[$Update.Identity.UpdateID].Size
		Write-Verbose "Selected Update $($Update.Title)"

		$Status = "Accepted"

		If($Update.EulaAccepted -eq 0)
		{ 
			$Update.AcceptEula() 
		}
			
		Write-Verbose "Adding update to collection"
		$UpdateCollectionObject.Add($Update) | Out-Null

		$log = New-Object PSObject -Property @{
			Title = $Update.Title
			KB = $UpdatesExtraDataCollection[$Update.Identity.UpdateID].KB
			Size = $UpdatesExtraDataCollection[$Update.Identity.UpdateID].Size
			Status = $Status
			X = 2
		}
				
		Add-Content -Path $ScriptLogFilePath -Value $log
				
		$NumberOfUpdate++
	}

	Write-Verbose "Update Selection Completed"
    Add-Content -Path $ScriptLogFilePath -Value "Update Selection Completed"
			
	$AcceptUpdatesToDownload = $UpdateCollectionObject.count
	Write-Verbose "$($AcceptUpdatesToDownload) Updates to Download"
    Add-Content -Path $ScriptLogFilePath -Value "$($AcceptUpdatesToDownload) Updates to Download"
			
	If($AcceptUpdatesToDownload -eq 0)
	{
		Return
	}
			
	Write-Verbose "Downloading updates"
    Add-Content -Path $ScriptLogFilePath -Value "Downloading updates"

	$NumberOfUpdate = 1
	$UpdateDownloadCollectionObject = New-Object -ComObject "Microsoft.Update.UpdateColl" 

	Foreach($Update in $UpdateCollectionObject)
	{
		Write-Verbose "$($Update.Title) will be downloaded"
        Add-Content -Path $ScriptLogFilePath -Value "$($Update.Title) will be downloaded"

		$TempUpdateCollectionObject = New-Object -ComObject "Microsoft.Update.UpdateColl"
		$TempUpdateCollectionObject.Add($Update) | Out-Null
					
		$Downloader = $SessionObject.CreateUpdateDownloader() 
		$Downloader.Updates = $TempUpdateCollectionObject

		Try
		{
			Write-Verbose "Attempting to download update $($Update.Title)"
            Add-Content -Path $ScriptLogFilePath -Value "Attempting to download update $($Update.Title)"
			$DownloadResult = $Downloader.Download()
		}
		Catch
		{
			If ($_ -match "HRESULT: 0x80240044")
			{
				Write-Warning "Your security policy does not allow a non-administator to perform this task"
			}
					
			Return
		}
				
		Write-Verbose "Check ResultCode"
		Switch -exact ($DownloadResult.ResultCode)
		{
			0   { $Status = "NotStarted" }
			1   { $Status = "InProgress" }
			2   { $Status = "Downloaded" }
			3   { $Status = "DownloadedWithErrors" }
			4   { $Status = "Failed" }
			5   { $Status = "Aborted" }
		}

		$log = New-Object PSObject -Property @{
			Title = $Update.Title
			KB = $UpdatesExtraDataCollection[$Update.Identity.UpdateID].KB
			Size = $UpdatesExtraDataCollection[$Update.Identity.UpdateID].Size
			Status = $Status
			X = 3
		}
				
		Add-Content -Path $ScriptLogFilePath -Value "Update $($log.Title) KB $($log.KB) Size $($log.Size) Download Status $($log.Status)"
				
		If($DownloadResult.ResultCode -eq 2)
		{
			Write-Verbose "$($Update.Title) Downloaded"
            Add-Content -Path $ScriptLogFilePath -Value "$($Update.Title) Downloaded"
			$UpdateDownloadCollectionObject.Add($Update) | Out-Null
		}
				
		$NumberOfUpdate++
				
	}

	Write-Verbose "Downloading Updates Completed"
    Add-Content -Path $ScriptLogFilePath -Value "Downloading Updates Completed"

	$ReadyUpdatesToInstall = $UpdateDownloadCollectionObject.count
	Write-Verbose "Downloaded $($ReadyUpdatesToInstall) Updates to Install"
    Add-Content -Path $ScriptLogFilePath -Value "Downloaded $($ReadyUpdatesToInstall) Updates to Install"
		
	If($ReadyUpdatesToInstall -eq 0)
	{
        Write-Verbose "No Updates are ready to Install"
        Add-Content -Path $ScriptLogFilePath -Value "No Updates are ready to Install"		
        Return
	}

			
	Write-Verbose "Installing updates"
    Add-Content -Path $ScriptLogFilePath -Value "Installing updates"

	$NumberOfUpdate = 1			
	#install updates	
	Foreach($Update in $UpdateDownloadCollectionObject)
	{
		Write-Verbose "Update to install: $($Update.Title)"
        Add-Content -Path $ScriptLogFilePath -Value "Update to install: $($Update.Title)"

		$TempUpdateCollectionObject = New-Object -ComObject "Microsoft.Update.UpdateColl"
		$TempUpdateCollectionObject.Add($Update) | Out-Null
					
		$InstallerObject = $SessionObject.CreateUpdateInstaller()
		$InstallerObject.Updates = $TempUpdateCollectionObject
						
		Try
		{
			Write-Verbose "Attempting to install update"
            Add-Content -Path $ScriptLogFilePath -Value "Attempting to install update"
			$InstallResult = $InstallerObject.Install()
		}
		Catch
		{
			If($_ -match "HRESULT: 0x80240044")
			{
				Write-Warning "Your security policy does not allow a non-administator to perform this task"
                Add-Content -Path $ScriptLogFilePath -Value "Your security policy does not allow a non-administator to perform this task"
			}
			Return
		}
					
		Switch -exact ($InstallResult.ResultCode)
		{
			0   { $Status = "NotStarted"}
			1   { $Status = "InProgress"}
			2   { $Status = "Installed"}
			3   { $Status = "InstalledWithErrors"}
			4   { $Status = "Failed"}
			5   { $Status = "Aborted"}
		}

		$log = New-Object PSObject -Property @{
			Title = $Update.Title
			KB = $UpdatesExtraDataCollection[$Update.Identity.UpdateID].KB
			Size = $UpdatesExtraDataCollection[$Update.Identity.UpdateID].Size
			Status = $Status
			X = 4
		}
		
        Add-Content -Path $ScriptLogFilePath -Value "Update $($log.Title) KB $($log.KB) Size $($log.Size) Install Status $($log.Status)"
		$NumberOfUpdate++
	}

	Write-Verbose "Installing updates Completed"
    Add-Content -Path $ScriptLogFilePath -Value "Installing updates Completed"
}

Try
{
	$SystemInfoObject = New-Object -ComObject "Microsoft.Update.SystemInfo"	
	If($SystemInfoObject.RebootRequired)
	{
		Write-Warning "Reboot is required to continue"
		If($RestartOption -eq 'AutoReboot')
		{
			Restart-Computer -Force
		}
				
	}
}
Catch
{
	Write-Warning $_
}

if ($ForceOnlineUpdate)
{
    Invoke-WindowsUpdate -AcceptAll -ForceOnlineUpdate
}
else
{
    Invoke-WindowsUpdate -AcceptAll
}

$DateTime = (Get-Date)
Add-Content -Path $ScriptLogFilePath -Value "Script Processing Completed at $DateTime"

Try
{
	$SystemInfoObject = New-Object -ComObject "Microsoft.Update.SystemInfo"	
	If($SystemInfoObject.RebootRequired)
	{
		Write-Warning "Reboot is required to continue"
		If($RestartOption -eq 'AutoReboot')
		{
			Restart-Computer -Force
		}
				
	}
}
Catch
{
	Write-Warning $_
}
'@
Add-Content -Path $WindowsUpdateFilePath -Value $WindowsUpdateFileContent
Set-AzureStorageBlobContent -File $($WindowsUpdateFilePath.FullName) -Container $AdminScriptsContainerName -Blob "$WindowsUpdateScriptsFolderName\$($WindowsUpdateFilePath.Name)" -Context $StorageAccount.Context

# Upload Set-LocalWindowsUpdateSettings.ps1 to Storage Account
Write-Output "Uploading Set-LocalWindowsUpdateSettings.ps1 to Storage Account $($StorageAccount.StorageAccountName)"
$WindowsUpdateSettingsFilePath = New-Item -Path "$env:TEMP\Set-LocalWindowsUpdateSettings.ps1" -ItemType File -Force
$WindowsUpdateSettingsFileContent = @'
<#
.SYNOPSIS
    This script will set Windows Update local settings on Windows

.DESCRIPTION
    This script was developed to be run as a Custom Script Extension on a Windows Azure Virtual Machine
    This script will set Windows Update local settings on Windows.
    It uses the same registry keys that are used for Group Policies.

.PARAMETER AutomaticUpdateOptions
    This parameter accepts a numerical single digit value. Example: '4'
    The values and settings are: 
        2 = Notify before downloading and installing any updates. When Windows finds updates that apply to this computer, users will be notified that updates 
        3 = Download the updates automatically and notify when they are ready to be installed
        4 = (Default setting) Automatically download updates and install them on the schedule specified with ScheduledInstallDay and  ScheduledInstallTime.
        5 = Allow local administrators to select the configuration mode that Automatic Updates should notify and install updates.

.PARAMETER AutomaticMaintenanceEnabled
    Setting this to Enabled will set updates to install during automatic maintenance instead of a specific schedule. 
    Automatic maintenance will install updates when the computer is not in use, and avoid doing so when the computer is running on battery power
    Example: Enabled or Disabled

.PARAMETER ScheduledInstallDay
    This parameter accepts a numeric single digit value. Example: '0'
    0 = Everyday
    1 = Sunday
    2 = Monday, 3 Tuesday, 4 Wednesday, 5 Thursday, 6 Friday, 7 Saturday
    Specify the day schedule. If no schedule is specified, the default schedule for all installations will be every Sunday

.PARAMETER ScheduledInstallTime
    Specify the time schedule. If no schedule is specified, the default schedule for all installations will be at 3:00 AM
    Enter a 2 digit hour. Example: '20' for 8pm, 03 for 3am"
    
.PARAMETER WindowsUpdateServerURL
    This setting lets you specify a server on your network to function as an internal update service.
    The Automatic Updates client will search this service for updates that apply.
    To use this setting, you must set two servername values:
        The server from which the Automatic Updates client detects and downloads updates, and the server to which updated workstations upload statistics (WindowsUpdateStatisticsServerURL).
        You can set both values to be the same server.
    Example: 'http://updateserver1:8530'

.PARAMETER WindowsUpdateStatisticsServerURL
    Specifies an intranet server to upload statistics from Microsoft Update.
    If WindowsUpdateServerURL is used, this option must also be used.
    Example: 'http://updateserver1:8530'

.PARAMETER TargetGroup
    Specifies the target group name or names that should be used to receive updates from an intranet Microsoft update service.
    Example: 'TestGroup'

.PARAMETER DoNotConnectToWindowsUpdateInternetLocations
    Even when Windows Update is configured to receive updates from an intranet update service,
    it will periodically retrieve information from the public Windows Update service to enable future connections to Windows Update,
    and other services like Microsoft Update or the Windows Store.
    Enabling this policy will disable that functionality, and will cause connection to public services such as the Windows Store to stop working.
    Note: This policy applies only when this PC is configured to connect to an intranet update service using the "WindowsUpdateServerURL" policy.
    Example: Enabled or Disabled

.PARAMETER AllowNonAdminsToReceiveUpdateNotifications
    This policy setting allows you to control whether non-administrative users will receive update notifications based on the "Configure Automatic Updates" policy setting.
    If you enable this policy setting,
    Windows Automatic Update and Microsoft Update will include non-administrators when determining which logged-on user should receive update notifications.
    Non-administrative users will be able to install all optional, recommended, and important content for which they received a notification.
    Users will not see a User Account Control window and do not need elevated permissions to install these updates,
    except in the case of updates that contain User Interface , End User License Agreement , or Windows Update setting changes.
    Example: Enabled or Disabled

.PARAMETER AllowSignedUpdatesFromThirdParty
    This policy setting allows you to manage whether Automatic Updates accepts updates signed by entities other than Microsoft when the update is found on an intranet Microsoft update service location.
    If you enable this policy setting,
    Automatic Updates accepts updates received through an intranet Microsoft update service location,
    if they are signed by a certificate found in the "Trusted Publishers" certificate store of the local computer.
    Example: Enabled or Disabled

.PARAMETER DisplayInstallUpdatesAndShutDown
    This policy setting allows you to manage whether the 'Install Updates and Shut Down' option is displayed in the Shut Down Windows dialog box.
    If you enable this policy setting, 
    'Install Updates and Shut Down' will not appear as a choice in the Shut Down Windows dialog box,
    even if updates are available for installation when the user selects the Shut Down option in the Start menu.
    Example: Enabled or Disabled

.PARAMETER DoNotSetInstallUpdatesAndShutDownAsDefault
    This policy setting allows you to manage whether the 'Install Updates and Shut Down' option is allowed to be the default choice in the Shut Down Windows dialog.
    If you enable this policy setting,
    the user's last shut down choice (Hibernate, Restart, etc.) is the default option in the Shut Down Windows dialog box,
    regardless of whether the 'Install Updates and Shut Down' option is available in the 'What do you want the computer to do?' list.
    Example: Enabled or Disabled

.PARAMETER UpdateDetectionFrequencyHours
    Specifies the hours that Windows will use to determine how long to wait before checking for available updates.
    The exact wait time is determined by using the hours specified here minus zero to twenty percent of the hours specified.
    For example, if this policy is used to specify a 20 hour detection frequency,
    then all clients to which this policy is applied will check for updates anywhere between 16 and 20 hours.
    Example: '22'

.PARAMETER RebootRelaunchTimeoutMinutes
    Specifies the amount of time for Automatic Updates to wait before prompting again with a scheduled restart.
    If this is set, a scheduled restart will occur the specified number of minutes after the previous prompt for restart was postponed.
    Example: '5'

.PARAMETER RebootWarningTimeoutMinutes
    Specifies the amount of time for Automatic Updates to wait before proceeding with a scheduled restart.
    If this is set, a scheduled restart will occur the specified number of minutes after the installation is finished.
    If this is Not Configured, the default wait time is 15 minutes.
    Example: '5'

.PARAMETER RescheduleUpdateAfterRebootMinutes
    Specifies the amount of time for Automatic Updates to wait, following system startup, before proceeding with a scheduled installation that was missed previously.
    If this is set, a scheduled installation that did not take place earlier will occur the specified number of minutes after the computer is next started.
    If this is Not Configured, a missed scheduled installation will occur with the next scheduled installation.
    Example: '5'

.PARAMETER AlwaysAutoRebootAtScheduledTimeMinutes
    If you enable this policy, a restart timer will always begin immediately after Windows Update installs important updates,
    instead of first notifying users on the login screen for at least two days.
    The restart timer can be configured to start with any value from 15 to 180 minutes.
    When the timer runs out, the restart will proceed even if the PC has signed-in users.
    Example: '15'

.PARAMETER UseWindowsPowerManagementToWakeSystem
    Specifies whether the Windows Update will use the Windows Power Management features to automatically wake up the system from hibernation,
    if there are updates scheduled for installation.
    Example: Enabled or Disabled

.PARAMETER NoAutoRebootWithLoggedOnUsers
    Specifies that to complete a scheduled installation,
    Automatic Updates will wait for the computer to be restarted by any user who is logged on,
    instead of causing the computer to restart automatically.
    If the status is set to Enabled,
    Automatic Updates will not restart a computer automatically during a scheduled installation if a user is logged in to the computer.
    Instead, Automatic Updates will notify the user to restart the computer.
    Be aware that the computer needs to be restarted for the updates to take effect.
    Example: Enabled or Disabled

.PARAMETER EnableFeaturedSoftware
    This policy setting allows you to control whether users see detailed enhanced notification messages about featured software from the Microsoft Update service.
    Enhanced notification messages convey the value and promote the installation and use of optional software.
    This policy setting is intended for use in loosely managed environments in which you allow the end user access to the Microsoft Update service.
    If you enable this policy setting,
    a notification message will appear on the user's computer when featured software is available.
    The user can click the notification to open the Windows Update Application and get more information about the software or install it.
    The user can also click "Close this message" or "Show me later" to defer the notification as appropriate.
    Example: Enabled or Disabled

.PARAMETER IncludeRecommendedUpdates
    Specifies whether Automatic Updates will deliver both important as well as recommended updates from the Windows Update update service.
    When this policy is enabled, Automatic Updates will install recommended updates as well as important updates from Windows Update update service.
    When disabled or not configured Automatic Updates will continue to deliver important updates if it is already configured to do so.
    Example: Enabled or Disabled

.EXAMPLE
    .\Set-LocalWindowsUpdateSettings.ps1
#>
[CmdletBinding()]
Param
(
    [parameter(Mandatory=$false,HelpMessage="Example: '3' ")]
    [ValidateSet('2','3','4','5')]
    [Int]$AutomaticUpdateOptions = '3',

    [parameter(Mandatory=$false,HelpMessage="Example: Enabled or Disabled")]
    [ValidateSet('Enabled','Disabled')]
    [String]$AutomaticMaintenanceEnabled = 'Enabled',

    [parameter(Mandatory=$false,HelpMessage="0 Everyday, 1 Sunday, 2 Monday, 3 Tuesday, 4 Wednesday, 5 Thursday, 6 Friday, 7 Saturday Example: '1' ")]
    [ValidateSet('0','1','3','4','5','6','7')]
    [Int]$ScheduledInstallDay = '0',

    [parameter(Mandatory=$false,HelpMessage="Enter a 2 digit hour. Example: '20' for 8pm, 03 for 3am")]
    [ValidatePattern("^\d{0,2}$")]
    [ValidateRange(1,24)]
    [Int]$ScheduledInstallTime = '03',
    
    [parameter(Mandatory=$false,HelpMessage="WSUS Server URL. Example: 'http://updateserver1:8530' ")]
    [String]$WindowsUpdateServerURL,

    [parameter(Mandatory=$false,HelpMessage="WSUS Statistics Server URL. Example: 'http://updateserver1:8530' ")]
    [String]$WindowsUpdateStatisticsServerURL,

    [parameter(Mandatory=$false,HelpMessage="WSUS Server Group Name. Example: 'TestGroup' ")]
    [String]$TargetGroup,

    [parameter(Mandatory=$false,HelpMessage="Example: Enabled or Disabled")]
    [ValidateSet('Enabled','Disabled')]
    [String]$DoNotConnectToWindowsUpdateInternetLocations,

    [parameter(Mandatory=$false,HelpMessage="Example: Enabled or Disabled")]
    [ValidateSet('Enabled','Disabled')]
    [String]$AllowNonAdminsToReceiveUpdateNotifications = 'Enabled',

    [parameter(Mandatory=$false,HelpMessage="Example: Enabled or Disabled")]
    [ValidateSet('Enabled','Disabled')]
    [String]$AllowSignedUpdatesFromThirdParty,

    [parameter(Mandatory=$false,HelpMessage="Example: Enabled or Disabled")]
    [ValidateSet('Enabled','Disabled')]
    [String]$DisplayInstallUpdatesAndShutDown = 'Enabled',

    [parameter(Mandatory=$false,HelpMessage="Example: Enabled or Disabled")]
    [ValidateSet('Enabled','Disabled')]
    [String]$DoNotSetInstallUpdatesAndShutDownAsDefault,

    [parameter(Mandatory=$false,HelpMessage="Example: '22' ")]
    [ValidateRange(1,22)]
    [Int]$UpdateDetectionFrequencyHours = '1',

    [parameter(Mandatory=$false,HelpMessage="Example: '5' ")]
    [ValidateRange(1,480)]
    [Int]$RebootRelaunchTimeoutMinutes = '5',

    [parameter(Mandatory=$false,HelpMessage="Example: '1' ")]
    [ValidateRange(1,480)]
    [Int]$RebootWarningTimeoutMinutes = '15',

    [parameter(Mandatory=$false,HelpMessage="Example: '15' ")]
    [ValidateRange(1,60)]
    [Int]$RescheduleUpdateAfterRebootMinutes = '15',

    [parameter(Mandatory=$false,HelpMessage="Example: '15' ")]
    [ValidateRange(15,180)]
    [Int]$AlwaysAutoRebootAtScheduledTimeMinutes = '15' ,

    [parameter(Mandatory=$false,HelpMessage="Example: Enabled or Disabled")]
    [ValidateSet('Enabled','Disabled')]
    [String]$UseWindowsPowerManagementToWakeSystem,

    [parameter(Mandatory=$false,HelpMessage="Example: Enabled or Disabled")]
    [ValidateSet('Enabled','Disabled')]
    [String]$NoAutoRebootWithLoggedOnUsers,

    [parameter(Mandatory=$false,HelpMessage="Example: Enabled or Disabled")]
    [ValidateSet('Enabled','Disabled')]
    [String]$EnableFeaturedSoftware,

    [parameter(Mandatory=$false,HelpMessage="Example: Enabled or Disabled")]
    [ValidateSet('Enabled','Disabled')]
    [String]$IncludeRecommendedUpdates = 'Enabled'
)

# Get Script Start Time and Date
$DateTime = (Get-Date)

# Set Verbose Preference
$VerbosePreference = 'Continue'

# Create Script Log File
$ScriptLogFilePath = New-Item -Path "$env:TEMP\WindowsUpdateConfig.log" -ItemType File -Force
Add-Content -Path $ScriptLogFilePath -Value "Script Processing Started at $DateTime"

#region Create Windows Update Registry Keys
$WindowsUpdatePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
$WindowsUpdateAUPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"

Add-Content -Path $ScriptLogFilePath -Value "Checking for registry paths and creating them if they do not exist"

if (!(Test-Path $WindowsUpdatePath))
{
	New-Item -Path $WindowsUpdatePath -Force | Out-Null
}

if (!(Test-Path $WindowsUpdateAUPath))
{
	New-Item -Path $WindowsUpdateAUPath -Force | Out-Null
}
#endregion

#region WindowsUpdate Items
$WindowsUpdateItems = @()

if ($DoNotConnectToWindowsUpdateInternetLocations -eq 'Enabled')
{
    $WindowsUpdateItems += New-Object PSObject -Property ([ordered]@{PropertyName='DoNotConnectToWindowsUpdateInternetLocations';PropertyValue='1';PropertyType='DWORD'})
}

if ($AllowNonAdminsToReceiveUpdateNotifications  -eq 'Enabled')
{
    $WindowsUpdateItems += New-Object PSObject -Property ([ordered]@{PropertyName='ElevateNonAdmins';PropertyValue='1';PropertyType='DWORD'})
}

if ($AllowSignedUpdatesFromThirdParty -eq 'Enabled')
{
    $WindowsUpdateItems += New-Object PSObject -Property ([ordered]@{PropertyName='AcceptTrustedPublisherCerts';PropertyValue='1';PropertyType='DWORD'})
}

if ($TargetGroup)
{
    $WindowsUpdateItems += New-Object PSObject -Property ([ordered]@{PropertyName='TargetGroupEnabled';PropertyValue='1';PropertyType='DWORD'})
    $WindowsUpdateItems += New-Object PSObject -Property ([ordered]@{PropertyName='TargetGroup';PropertyValue=$TargetGroup;PropertyType='String'})
}

if ($WindowsUpdateServerURL)
{
    $WindowsUpdateItems += New-Object PSObject -Property ([ordered]@{PropertyName='WUServer';PropertyValue=$WindowsUpdateServerURL;PropertyType='String'})
    if ([String]::IsNullOrEmpty($WindowsUpdateStatisticsServerURL))
    {
        $WindowsUpdateStatisticsServerURL = $WindowsUpdateServerURL
    }
    $WindowsUpdateItems += New-Object PSObject -Property ([ordered]@{PropertyName='WUStatusServer';PropertyValue=$WindowsUpdateStatisticsServerURL;PropertyType='String'})
}

foreach ($WindowsUpdateItem in $WindowsUpdateItems)
{
    # Add Content to Script Log
    Add-Content -Path $ScriptLogFilePath -Value "Adding $($WindowsUpdateItem.PropertyName) with a value of $($WindowsUpdateItem.PropertyValue) to $WindowsUpdatePath"
    
    # Add Registry Properties
    New-ItemProperty -Path $WindowsUpdatePath -Name $WindowsUpdateItem.PropertyName -Value $WindowsUpdateItem.PropertyValue -PropertyType $WindowsUpdateItem.PropertyType -Force -Verbose
}
#endregion

#region Windows Update AU Items
$WindowsUpdateAUItems = @()
$WindowsUpdateAUItems += New-Object PSObject -Property ([ordered]@{PropertyName='NoAutoUpdate';PropertyValue='0';PropertyType='DWORD'})
$WindowsUpdateAUItems += New-Object PSObject -Property ([ordered]@{PropertyName='AUOptions';PropertyValue=$AutomaticUpdateOptions;PropertyType='DWORD'})
$WindowsUpdateAUItems += New-Object PSObject -Property ([ordered]@{PropertyName='ScheduledInstallDay';PropertyValue=$ScheduledInstallDay;PropertyType='DWORD'})
$WindowsUpdateAUItems += New-Object PSObject -Property ([ordered]@{PropertyName='ScheduledInstallTime';PropertyValue=$ScheduledInstallTime;PropertyType='DWORD'})

if ($AutomaticMaintenanceEnabled -eq 'Enabled')
{
    $WindowsUpdateAUItems += New-Object PSObject -Property ([ordered]@{PropertyName='AutomaticMaintenanceEnabled';PropertyValue='1';PropertyType='DWORD'})
}

if ($WindowsUpdateServerURL)
{
    $WindowsUpdateAUItems += New-Object PSObject -Property ([ordered]@{PropertyName='UseWUServer';PropertyValue='1';PropertyType='DWORD'})
}

if ($UpdateDetectionFrequencyHours)
{
    $WindowsUpdateAUItems += New-Object PSObject -Property ([ordered]@{PropertyName='DetectionFrequencyEnabled';PropertyValue='1';PropertyType='DWORD'})
    $WindowsUpdateAUItems += New-Object PSObject -Property ([ordered]@{PropertyName='DetectionFrequency';PropertyValue=$UpdateDetectionFrequencyHours;PropertyType='DWORD'})
}

if ($RebootRelaunchTimeoutMinutes)
{
    $WindowsUpdateAUItems += New-Object PSObject -Property ([ordered]@{PropertyName='RebootRelaunchTimeoutEnabled';PropertyValue='1';PropertyType='DWORD'})
    $WindowsUpdateAUItems += New-Object PSObject -Property ([ordered]@{PropertyName='RebootRelaunchTimeout';PropertyValue=$RebootRelaunchTimeoutMinutes;PropertyType='DWORD'})
}

if ($DisplayInstallUpdatesAndShutDown -eq 'Enabled')
{
    $WindowsUpdateAUItems += New-Object PSObject -Property ([ordered]@{PropertyName='NoAUShutdownOption';PropertyValue='1';PropertyType='DWORD'})
}

if ($DoNotSetInstallUpdatesAndShutDownAsDefault -eq 'Enabled')
{
    $WindowsUpdateAUItems += New-Object PSObject -Property ([ordered]@{PropertyName='NoAUAsDefaultShutdownOption';PropertyValue='1';PropertyType='DWORD'})
}

if ($RescheduleUpdateAfterRebootMinutes)
{
    $WindowsUpdateAUItems += New-Object PSObject -Property ([ordered]@{PropertyName='RescheduleWaitTimeEnabled';PropertyValue='1';PropertyType='DWORD'})
    $WindowsUpdateAUItems += New-Object PSObject -Property ([ordered]@{PropertyName='RescheduleWaitTime';PropertyValue=$RescheduleUpdateAfterRebootMinutes;PropertyType='DWORD'})
}

if ($RebootWarningTimeoutMinutes)
{
    $WindowsUpdateAUItems += New-Object PSObject -Property ([ordered]@{PropertyName='RebootWarningTimeoutEnabled';PropertyValue='1';PropertyType='DWORD'})
    $WindowsUpdateAUItems += New-Object PSObject -Property ([ordered]@{PropertyName='RebootWarningTimeout';PropertyValue=$RebootWarningTimeoutMinutes;PropertyType='DWORD'})
}

if ($AlwaysAutoRebootAtScheduledTimeMinutes)
{
    $WindowsUpdateAUItems += New-Object PSObject -Property ([ordered]@{PropertyName='AlwaysAutoRebootAtScheduledTime';PropertyValue='1';PropertyType='DWORD'})
    $WindowsUpdateAUItems += New-Object PSObject -Property ([ordered]@{PropertyName='AlwaysAutoRebootAtScheduledTimeMinutes';PropertyValue=$AlwaysAutoRebootAtScheduledTimeMinutes;PropertyType='DWORD'})
}

if ($UseWindowsPowerManagementToWakeSystem -eq 'Enabled')
{
    $WindowsUpdateAUItems += New-Object PSObject -Property ([ordered]@{PropertyName='AUPowerManagement';PropertyValue='1';PropertyType='DWORD'})
}

if ($NoAutoRebootWithLoggedOnUsers -eq 'Enabled')
{
    $WindowsUpdateAUItems += New-Object PSObject -Property ([ordered]@{PropertyName='NoAutoRebootWithLoggedOnUsers';PropertyValue='1';PropertyType='DWORD'})
}

if ($EnableFeaturedSoftware -eq 'Enabled')
{
    $WindowsUpdateAUItems += New-Object PSObject -Property ([ordered]@{PropertyName='EnableFeaturedSoftware';PropertyValue='1';PropertyType='DWORD'})
}

if ($AutoInstallMinorUpdates -eq 'Enabled')
{
    $WindowsUpdateAUItems += New-Object PSObject -Property ([ordered]@{PropertyName='AutoInstallMinorUpdates';PropertyValue='1';PropertyType='DWORD'})
}

if ($IncludeRecommendedUpdates -eq 'Enabled')
{
    $WindowsUpdateAUItems += New-Object PSObject -Property ([ordered]@{PropertyName='IncludeRecommendedUpdates';PropertyValue='1';PropertyType='DWORD'})
}

foreach ($WindowsUpdateAUItem in $WindowsUpdateAUItems)
{
    # Add Content to Script Log
    Add-Content -Path $ScriptLogFilePath -Value "Adding $($WindowsUpdateAUItem.PropertyName) with a value of $($WindowsUpdateAUItem.PropertyValue) to $WindowsUpdateAUPath"
    
    # Add Registry Properties
    New-ItemProperty -Path $WindowsUpdateAUPath -Name $WindowsUpdateAUItem.PropertyName -Value $WindowsUpdateAUItem.PropertyValue -PropertyType $WindowsUpdateAUItem.PropertyType -Force -Verbose
}
#endregion

# Restart Windows Update Service
Add-Content -Path $ScriptLogFilePath -Value "Restarting Windows Update Service"
Get-Service -Name 'wuauserv' | Restart-Service -Force

# Get Script Completion Time and Date
$DateTime = (Get-Date)

# Add Content to Script Log
Add-Content -Path $ScriptLogFilePath -Value "Script Completed at $DateTime"
'@
Add-Content -Path $WindowsUpdateSettingsFilePath -Value $WindowsUpdateSettingsFileContent
Set-AzureStorageBlobContent -File $($WindowsUpdateSettingsFilePath.FullName) -Container $AdminScriptsContainerName -Blob "$WindowsUpdateScriptsFolderName\$($WindowsUpdateSettingsFilePath.Name)" -Context $StorageAccount.Context
Write-Output "Script upload complete"
#endregion

#region Create, Import, Publish and Schedule Runbooks
Write-Output "Creating, Importing, Publishing and Scheduling Runbooks. This may take some time.."

#region Add Invoke-ConfigureAzureDiskEncryption Runbook and set an hourly schedule
$RunbookType = 'PowerShellWorkflow'
$RunbookFilePath = New-Item -Path "$env:TEMP\Invoke-ConfigureAzureDiskEncryption.ps1" -ItemType File -Force
$RunbookFileContent = @'
<#
.SYNOPSIS
    Script to run Invoke-ConfigureAzureDiskEncryption on VMs that have the OS Volume encrypted.

.DESCRIPTION
    This runbook will run Invoke-ConfigureAzureDiskEncryption on VMs that have the OS Volume encrypted, but data disks are not.

.PARAMETER SubscriptionID
    Provide Target Subscription ID
    Example: "aed90f7c-19ff-4b65-a0fb-c0186d3a7265"

.EXAMPLE
    .\Invoke-ConfigureAzureDiskEncryption.ps1 -SubscriptionID 'aed90f7c-19ff-4b65-a0fb-c0186d3a7265'
#>
Workflow Invoke-ConfigureAzureDiskEncryption
{
    [CmdletBinding()]
    param
    (                
        # Provide Target Subscription ID
        # Example: "aed90f7c-19ff-4b65-a0fb-c0186d3a7265"
        [parameter(Mandatory=$false,HelpMessage='Example: aed90f7c-19ff-4b65-a0fb-c0186d3a7265')]
        [String]$SubscriptionID
    )

    $ErrorActionPreference = 'Stop'
   
    try
    {
        # Get RunAsConnection
        $RunAsConnection = Get-AutomationConnection -Name "AzureRunAsConnection"

        Add-AzureRmAccount -ServicePrincipal `
        -TenantId $RunAsConnection.TenantId `
        -ApplicationId $RunAsConnection.ApplicationId `
        -CertificateThumbprint $RunAsConnection.CertificateThumbprint `
        -EnvironmentName '[Environment]' -Verbose

        # Get Subscription Id if not provided
        if (!$SubscriptionId)
        {
            $SubscriptionId = $RunAsConnection.SubscriptionId
        }
    }
    catch
    {
        if (!$RunAsConnection)
        {
            $ErrorMessage = "Connection $ConnectionName not found."
            throw $ErrorMessage
        }
        else
        {
            Write-Error -Message $_.Exception
            throw $_.Exception
        }
    }

    # Get All Resource Groups in the Subscription
    Write-Output "Getting Resource Groups"
    $ResourceGroups = (Get-AzureRmResourceGroup | Where-Object {$_.ResourceId -like "/subscriptions/$SubscriptionID/resourceGroups/*"}).ResourceGroupName

    foreach -parallel ($ResourceGroup in $ResourceGroups)
    {
        # Find all Powered On VMs in the Resource Group
        Write-Output "Getting all Powered On VMs in ResourceGroup $ResourceGroup"
        $PoweredOnAzureRMVirtualMachines = (Get-AzureRMVM -ResourceGroupName $ResourceGroup -Status | Where-Object {$_.PowerState -eq "VM running"})

        foreach -parallel ($PoweredOnAzureRMVirtualMachine in $PoweredOnAzureRMVirtualMachines)
        {
            # Get encryption status for each VM
            Write-Output "Checking Encryption Status for VM $($PoweredOnAzureRMVirtualMachine.Name)"
            $EncryptionStatus = (Get-AzureRmVMDiskEncryptionStatus -ResourceGroupName $PoweredOnAzureRMVirtualMachine.ResourceGroupName -VMName $PoweredOnAzureRMVirtualMachine.Name)
            # Check to see if encryption is enabled for all disks
            if (($EncryptionStatus.OsVolumeEncrypted -eq 'Encrypted') -and ($EncryptionStatus.DataVolumesEncrypted -ne 'Encrypted'))
            {
                # Enable disk encryption for all disks
                Write-Output "VM $($PoweredOnAzureRMVirtualMachine.Name) has disks that are not encrypted"
                Write-Output "Setting disk encryption on disks"
                $KeyVaultResourceID =  $($EncryptionStatus.OsVolumeEncryptionSettings.DiskEncryptionKey.SourceVault).ID
                $KeyVaultName = ($KeyVaultResourceID.Split('/') | Select-Object -Last 1)
                $KeyVaultResourceGroup = ($KeyVaultResourceID.Split('/'))[4]
                $KeyVault = Get-AzureRmKeyVault -VaultName $KeyVaultName -ResourceGroupName $KeyVaultResourceGroup
                $DiskEncryptionKeyVaultUrl = $KeyVault.VaultUri
                $SequenceVersion = ([Guid]::NewGuid()).guid

                try
                {
                    Set-AzureRmVMDiskEncryptionExtension -ResourceGroupName $PoweredOnAzureRMVirtualMachine.ResourceGroupName `
                    -VMName $PoweredOnAzureRMVirtualMachine.Name -DiskEncryptionKeyVaultUrl $DiskEncryptionKeyVaultUrl `
                    -DiskEncryptionKeyVaultId $KeyVaultResourceID -KeyEncryptionKeyVaultId $KeyVaultResourceId `
                    -VolumeType 'All' -SequenceVersion $SequenceVersion -Force -ErrorAction 'Stop'
                }
                catch
                {
                    Write-Warning $_
                    Write-Warning $_.Exception
                }
            }
        }
    }
    Write-Output 'Script Complete'
}
'@
Add-Content -Path $RunbookFilePath -Value $RunbookFileContent
(Get-Content $RunbookFilePath.FullName).replace('[Environment]', $($Environment.Name)) | Set-Content $RunbookFilePath.FullName
try
{
    Write-Output "Importing Runbook $($RunbookFilePath.BaseName)"
    Import-AzureRmAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Path $RunbookFilePath.FullName -Type $RunbookType -Verbose -ErrorAction 'Stop'
    Publish-AzureRmAutomationRunbook -Name $($RunbookFilePath.BaseName) -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Verbose -ErrorAction 'Stop'
    Register-AzureRmAutomationScheduledRunbook -RunbookName $($RunbookFilePath.BaseName) -ScheduleName $HourlyScheduleName -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Verbose -ErrorAction 'Stop'
}
catch 
{
    Write-Warning $_
    break
}
#endregion

#region Add Add-AllAvailableServiceEndpointsToVirtualNetworks Runbook and set a daily schedule
$RunbookType = 'PowerShell'
$RunbookFilePath = New-Item -Path "$env:TEMP\Add-AllAvailableServiceEndpointsToVirtualNetworks.ps1" -ItemType File -Force
$RunbookFileContent = @'
<#
.SYNOPSIS
    Script to run Add-AllAvailableServiceEndpointsToVirtualNetworks.

.DESCRIPTION
    This runbook will run Add-AllAvailableServiceEndpointsToVirtualNetworks.
    It will find all Virtual Networks and Subnets not name GatewaySubnet.
    It will then add all Available Service Endpoints to the Virtual Network Subnet Configs.

.PARAMETER SubscriptionID
    Provide Target Subscription ID
    Example: "aed90f7c-19ff-4b65-a0fb-c0186d3a7265"

.PARAMETER Location
    Provide the location
    Example: '[Location]'

.EXAMPLE
    .\Add-AllAvailableServiceEndpointsToVirtualNetworks.ps1 -SubscriptionID 'aed90f7c-19ff-4b65-a0fb-c0186d3a7265'
#>
[CmdletBinding()]
param
(                
    # Provide Target Subscription ID
    # Example: "aed90f7c-19ff-4b65-a0fb-c0186d3a7265"
    [parameter(Mandatory=$false,HelpMessage='Example: aed90f7c-19ff-4b65-a0fb-c0186d3a7265')]
    [String]$SubscriptionID,

    # Provide the location
    # Example: '[Location]'
    [parameter(Mandatory=$false,HelpMessage='Example: [Location]')]
    [String]$Location = '[Location]'
)

$ErrorActionPreference = 'Stop'

try
{
    # Pull Azure environment settings
    $AzureEnvironmentSettings = Get-AzureRmEnvironment -Name '[Environment]'

    # Azure management uri
    $ResourceAppIdURI = $AzureEnvironmentSettings.ActiveDirectoryServiceEndpointResourceId

    # Login uri for Azure AD
    $LoginURI = $AzureEnvironmentSettings.ActiveDirectoryAuthority

    # Get RunAsConnection
    $RunAsConnection = Get-AutomationConnection -Name "AzureRunAsConnection"

    # Get RunAsCertificate
    $Certifcate = Get-AutomationCertificate -Name "AzureRunAsCertificate"

    Add-AzureRmAccount -ServicePrincipal `
    -TenantId $RunAsConnection.TenantId `
    -ApplicationId $RunAsConnection.ApplicationId `
    -CertificateThumbprint $RunAsConnection.CertificateThumbprint `
    -EnvironmentName '[Environment]' -Verbose

    # Get Subscription Id if not provided
    if (!$SubscriptionId)
    {
        $SubscriptionId = $RunAsConnection.SubscriptionId
    }
}
catch
{
    if (!$RunAsConnection)
    {
        $ErrorMessage = "Connection $ConnectionName not found."
        throw $ErrorMessage
    }
    else
    {
        Write-Error -Message $_.Exception
        throw $_.Exception
    }
}

# Set up authentication using service principal client certificate
$Authority = $LoginURI + $RunAsConnection.TenantId
$AuthContext = [Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext]::new($Authority, $false)
$ClientCertificate = [Microsoft.IdentityModel.Clients.ActiveDirectory.ClientAssertionCertificate]::new($RunAsConnection.ApplicationId, $Certifcate)
$AuthResult = $AuthContext.AcquireToken($ResourceAppIdURI, $ClientCertificate)

# Set up header with authorization token
$AuthToken = $AuthResult.CreateAuthorizationHeader()
$RequestHeader = @{
    "Content-Type" = "application/json";
    "Authorization" = "$AuthToken"
}

# Get Available Service Endpoints
function Get-AvailableServiceEndpoints
{
    $restUri = "[ResourceManagerUrl]subscriptions/$SubscriptionID/providers/Microsoft.Network/locations/$Location/virtualNetworkAvailableEndpointServices?api-version=2018-11-01"
    $Response = Invoke-RestMethod -Uri $restUri -Method GET -Headers $RequestHeader
    return $Response
}

$AvailableServiceEndpoints = (Get-AvailableServiceEndpoints).Value.Name

#region Add Available Service Endpoints to All Subnets in Subscription
Write-Output "Adding Available Service Endpoints to All Subnets"
$VirtualNetworks = Get-AzureRmVirtualNetwork -Verbose -WarningAction 'SilentlyContinue'
foreach ($VirtualNetwork in $VirtualNetworks)
{
    foreach ($Subnet in $VirtualNetwork.Subnets | Where-Object {$_.Name -ne 'GatewaySubnet'})
    {
        $VirtualNetworkSubnetConfig = Get-AzureRmVirtualNetworkSubnetConfig -Name $Subnet.Name -VirtualNetwork $VirtualNetwork -Verbose -WarningAction 'SilentlyContinue'
        if (!$VirtualNetworkSubnetConfig.ServiceEndpoints.Service)
        {
            Write-Output "$($Subnet.Name) has no Service Endpoints"
            Write-Output "Adding missing Service Endpoints to $($Subnet.Name) in Virtual Network $($VirtualNetwork.Name)"
            Set-AzureRmVirtualNetworkSubnetConfig -Name $Subnet.Name -VirtualNetwork $VirtualNetwork -AddressPrefix $Subnet.AddressPrefix -ServiceEndpoint $AvailableServiceEndpoints -WarningAction 'SilentlyContinue' | Set-AzureRmVirtualNetwork -WarningAction 'SilentlyContinue' -Verbose
        }
        else
        {
            $CompareObject = Compare-Object -DifferenceObject ($VirtualNetworkSubnetConfig.ServiceEndpoints.Service) -ReferenceObject $AvailableServiceEndpoints
            if ($CompareObject)
            {
                Write-Output "$($Subnet.Name) is missing some Service Endpoints"
                Write-Output "Adding missing Service Endpoints to $($Subnet.Name) in Virtual Network $($VirtualNetwork.Name)"
                Set-AzureRmVirtualNetworkSubnetConfig -Name $Subnet.Name -VirtualNetwork $VirtualNetwork -AddressPrefix $Subnet.AddressPrefix -ServiceEndpoint $AvailableServiceEndpoints -WarningAction 'SilentlyContinue' | Set-AzureRmVirtualNetwork -WarningAction 'SilentlyContinue' -Verbose
            }
        }
    }
}
#endregion
Write-Output 'Script Complete'
'@
Add-Content -Path $RunbookFilePath -Value $RunbookFileContent
(Get-Content $RunbookFilePath.FullName).replace('[Location]', $Location) | Set-Content $RunbookFilePath.FullName
(Get-Content $RunbookFilePath.FullName).replace('[Environment]', $($Environment.Name)) | Set-Content $RunbookFilePath.FullName
(Get-Content $RunbookFilePath.FullName).replace('[ResourceManagerUrl]', $ResourceManagerUrl) | Set-Content $RunbookFilePath.FullName
try
{
    Write-Output "Importing Runbook $($RunbookFilePath.BaseName)"
    Import-AzureRmAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Path $RunbookFilePath.FullName -Type $RunbookType -Verbose -ErrorAction 'Stop'
    Publish-AzureRmAutomationRunbook -Name $($RunbookFilePath.BaseName) -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Verbose -ErrorAction 'Stop'
    Register-AzureRmAutomationScheduledRunbook -RunbookName $($RunbookFilePath.BaseName) -ScheduleName $DailyScheduleName -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Parameters $RunbookParameters -Verbose -ErrorAction 'Stop'
}
catch 
{
    Write-Warning $_
    break
}
#endregion

#region Add Add-AllSubnetsToKeyVaultFirewall Runbook and set a daily schedule
$RunbookType = 'PowerShell'
$RunbookFilePath = New-Item -Path "$env:TEMP\Add-AllSubnetsToKeyVaultFirewall.ps1" -ItemType File -Force
$RunbookFileContent = @'
<#
.SYNOPSIS
    Script to add all Subnets to Key Vault Firewall

.DESCRIPTION
    This script will find all Virtual Networks and ensure that the Service Endpoint for Microsoft.KeyVault is added.
    It will then update the Key Vault Firewall with the new Subnet(s)

.PARAMETER SubscriptionID
    Provide Target Subscription ID
    Example: "aed90f7c-19ff-4b65-a0fb-c0186d3a7265"

.PARAMETER ResourceGroupName
    Define a name for the Resource Group to be used. It can be a new or exisiting Resource Group
    Example: "Subscription-Management-RG"

.EXAMPLE
    .\Add-AllSubnetsToKeyVaultFirewall.ps1 -ResourceGroupName 'Subscription-Management-RG'
#>
[CmdletBinding()]
param
(
    # Provide Target Subscription ID
    # Example: "aed90f7c-19ff-4b65-a0fb-c0186d3a7265"
    [parameter(Mandatory=$false,HelpMessage='Example: aed90f7c-19ff-4b65-a0fb-c0186d3a7265')]
    [String]$SubscriptionID,

    # Define a name for the Resource Group to be used. It can be a new or exisiting Resource Group
    # Example: "Subscription-Management-RG"
    [parameter(Mandatory=$false,HelpMessage='Example: Subscription-Management-RG')]
    [String]$ResourceGroupName = 'Subscription-Management-RG'
)

$ErrorActionPreference = 'Stop'

try
{
    # Get RunAsConnection
    $RunAsConnection = Get-AutomationConnection -Name "AzureRunAsConnection"

    Add-AzureRmAccount -ServicePrincipal `
    -TenantId $RunAsConnection.TenantId `
    -ApplicationId $RunAsConnection.ApplicationId `
    -CertificateThumbprint $RunAsConnection.CertificateThumbprint `
    -EnvironmentName '[Environment]' -Verbose

    # Get Subscription Id if not provided
    if (!$SubscriptionId)
    {
        $SubscriptionId = $RunAsConnection.SubscriptionId
    }
}
catch
{
    if (!$RunAsConnection)
    {
        $ErrorMessage = "Connection $ConnectionName not found."
        throw $ErrorMessage
    }
    else
    {
        Write-Error -Message $_.Exception
        throw $_.Exception
    }
}

$KeyVault = Get-AzureRmKeyVault -ResourceGroupName $ResourceGroupName
$KeyVaultName = $($KeyVault.VaultName)

# Add all VNets to Key Vault Firewall and Enable Service Endpoints
Write-Output "Making sure Microsoft.KeyVault Service Endpoint is on all Virtual Network Subnets and Updating Key Vault Firewall"
$VirtualNetworks = Get-AzureRmVirtualNetwork -Verbose -WarningAction 'SilentlyContinue' -ErrorAction 'Stop'

foreach ($VirtualNetwork in $VirtualNetworks)
{
    foreach ($Subnet in $VirtualNetwork.Subnets | Where-Object {$_.Name -ne 'GatewaySubnet'})
    {
        $VirtualNetworkSubnetConfig = Get-AzureRmVirtualNetworkSubnetConfig -Name $Subnet.Name -VirtualNetwork $VirtualNetwork -Verbose -WarningAction 'SilentlyContinue' -ErrorAction 'Stop'
        if (($StorageAccountNetworkRuleSet.VirtualNetworkRules.VirtualNetworkResourceId -contains $($Subnet.Id)) -and ($VirtualNetworkSubnetConfig.ServiceEndpoints.Service -contains 'Microsoft.KeyVault'))
        {
            Write-Output "Subnet $($Subnet.Name) contains and is already in Key Vault Network Rule Set"
            Continue
        }
        if (!$VirtualNetworkSubnetConfig.ServiceEndpoints.Service)
        {
            Write-Output "$($Subnet.Name) has no Service Endpoints"
            Write-Output "Adding Microsoft.KeyVault Service Endpoint to $($Subnet.Name) in Virtual Network $($VirtualNetwork.Name)"
            Set-AzureRmVirtualNetworkSubnetConfig -Name $Subnet.Name -VirtualNetwork $VirtualNetwork -AddressPrefix $Subnet.AddressPrefix -ServiceEndpoint 'Microsoft.KeyVault' -WarningAction 'SilentlyContinue' | Set-AzureRmVirtualNetwork -WarningAction 'SilentlyContinue' -Verbose -ErrorAction 'Stop'
            Add-AzureRmKeyVaultNetworkRule -VaultName $KeyVaultName -VirtualNetworkResourceId $($Subnet.Id) -Verbose -WarningAction 'SilentlyContinue'
        }
        else
        {
            if ($VirtualNetworkSubnetConfig.ServiceEndpoints.Service -notcontains 'Microsoft.KeyVault')
            {
                Write-Output "$($Subnet.Name) is missing Microsoft.Storage Service Endpoint"
                Write-Output "Adding Microsoft.KeyVault Service Endpoint to $($Subnet.Name) in Virtual Network $($VirtualNetwork.Name)"
                $ServiceEnpoints = @('Microsoft.KeyVault')
                $ServiceEnpoints += $VirtualNetworkSubnetConfig.ServiceEndpoints.Service
                Set-AzureRmVirtualNetworkSubnetConfig -Name $Subnet.Name -VirtualNetwork $VirtualNetwork -AddressPrefix $Subnet.AddressPrefix -ServiceEndpoint $ServiceEnpoints -WarningAction 'SilentlyContinue' | Set-AzureRmVirtualNetwork -WarningAction 'SilentlyContinue' -Verbose -ErrorAction 'Stop'
                Add-AzureRmKeyVaultNetworkRule -VaultName $KeyVaultName -VirtualNetworkResourceId $($Subnet.Id) -Verbose -WarningAction 'SilentlyContinue'
            }
            else
            {
                Write-Output "Microsoft.KeyVault Service Endpoint found on Subnet $($Subnet.Name)"
                Write-Output "Updating Key Vault Network Rule with Subnet $($Subnet.Name)"
                Add-AzureRmKeyVaultNetworkRule -VaultName $KeyVaultName -VirtualNetworkResourceId $($Subnet.Id) -Verbose -WarningAction 'SilentlyContinue' -ErrorAction 'Stop'
            }
        }
    }
}

Write-Output "Updating Key Vault Network Rule with default deny rule"
Update-AzureRmKeyVaultNetworkRuleSet -VaultName $KeyVaultName -DefaultAction Deny -Verbose -WarningAction 'SilentlyContinue' -ErrorAction 'Stop'
Write-Output "Key Vault Network Rule Set configuration complete"
'@
Add-Content -Path $RunbookFilePath -Value $RunbookFileContent
(Get-Content $RunbookFilePath.FullName).replace('[Environment]', $($Environment.Name)) | Set-Content $RunbookFilePath.FullName
try
{
    Write-Output "Importing Runbook $($RunbookFilePath.BaseName)"
    Import-AzureRmAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Path $RunbookFilePath.FullName -Type $RunbookType -Verbose -ErrorAction 'Stop'
    Publish-AzureRmAutomationRunbook -Name $($RunbookFilePath.BaseName) -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Verbose -ErrorAction 'Stop'
    Register-AzureRmAutomationScheduledRunbook -RunbookName $($RunbookFilePath.BaseName) -ScheduleName $DailyScheduleName -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Verbose -ErrorAction 'Stop'
}
catch 
{
    Write-Warning $_
    break
}
#endregion

#region Add Add-AllSubnetsToSharedStorageAccountFirewall Runbook and set a daily schedule
$RunbookType = 'PowerShell'
$RunbookFilePath = New-Item -Path "$env:TEMP\Add-AllSubnetsToSharedStorageAccountFirewall.ps1" -ItemType File -Force
$RunbookFileContent = @'
<#
.SYNOPSIS
    Script to add all Subnets to Storage Account Firewall

.DESCRIPTION
    This script will find all Virtual Networks and ensure that the Service Endpoint for Microsoft.Storage is added.
    It will then update the Storage Account Firewall with the new Subnet(s)

.PARAMETER SubscriptionID
    Provide Target Subscription ID
    Example: "aed90f7c-19ff-4b65-a0fb-c0186d3a7265"

.PARAMETER ResourceGroupName
    Define a name for the Resource Group to be used. It can be a new or exisiting Resource Group
    Example: "Subscription-Management-RG"

.EXAMPLE
    .\Add-AllSubnetsToSharedStorageAccountFirewall.ps1 -ResourceGroupName 'Subscription-Management-RG'
#>
[CmdletBinding()]
param
(                
    # Provide Target Subscription ID
    # Example: "aed90f7c-19ff-4b65-a0fb-c0186d3a7265"
    [parameter(Mandatory=$false,HelpMessage='Example: aed90f7c-19ff-4b65-a0fb-c0186d3a7265')]
    [String]$SubscriptionID,
    
    # Define a name for the Resource Group to be used. It can be a new or exisiting Resource Group
    # Example: "Subscription-Management-RG"
    [parameter(Mandatory=$false,HelpMessage='Example: Subscription-Management-RG')]
    [String]$ResourceGroupName = 'Subscription-Management-RG'
)

$ErrorActionPreference = 'Stop'

try
{
    # Get RunAsConnection
    $RunAsConnection = Get-AutomationConnection -Name "AzureRunAsConnection"

    Add-AzureRmAccount -ServicePrincipal `
    -TenantId $RunAsConnection.TenantId `
    -ApplicationId $RunAsConnection.ApplicationId `
    -CertificateThumbprint $RunAsConnection.CertificateThumbprint `
    -EnvironmentName '[Environment]' -Verbose

    # Get Subscription Id if not provided
    if (!$SubscriptionId)
    {
        $SubscriptionId = $RunAsConnection.SubscriptionId
    }
}
catch
{
    if (!$RunAsConnection)
    {
        $ErrorMessage = "Connection $ConnectionName not found."
        throw $ErrorMessage
    }
    else
    {
        Write-Error -Message $_.Exception
        throw $_.Exception
    }
}

$StorageAccount = Get-AzureRmStorageAccount -ResourceGroupName $ResourceGroupName
$StorageAccountName = $($StorageAccount.StorageAccountName)

# Add all VNets to Storage Account Firewall and Enable Service Endpoints
Write-Output "Making sure Microsoft.Storage Service Endpoint is on all Virtual Network Subnets"
$VirtualNetworks = Get-AzureRmVirtualNetwork -Verbose -WarningAction 'SilentlyContinue' -ErrorAction 'Stop'  | Where-Object {$_.Location -eq $($StorageAccount.Location)}
$StorageAccountNetworkRuleSet = Get-AzureRmStorageAccountNetworkRuleSet -ResourceGroupName $ResourceGroupName -Name $StorageAccountName

foreach ($VirtualNetwork in $VirtualNetworks)
{
    foreach ($Subnet in $VirtualNetwork.Subnets | Where-Object {$_.Name -ne 'GatewaySubnet'})
    {
        $VirtualNetworkSubnetConfig = Get-AzureRmVirtualNetworkSubnetConfig -Name $Subnet.Name -VirtualNetwork $VirtualNetwork -Verbose -WarningAction 'SilentlyContinue' -ErrorAction 'Stop'
        if (($StorageAccountNetworkRuleSet.VirtualNetworkRules.VirtualNetworkResourceId -contains $($Subnet.Id)) -and ($VirtualNetworkSubnetConfig.ServiceEndpoints.Service -contains 'Microsoft.Storage'))
        {
            Write-Output "Subnet $($Subnet.Name) contains and is already in Storage Account Network Rule Set"
            Continue
        }
        if (!$VirtualNetworkSubnetConfig.ServiceEndpoints.Service)
        {
            Write-Output "$($Subnet.Name) has no Service Endpoints"
            Write-Output "Adding Microsoft.Storage Service Endpoint to $($Subnet.Name) in Virtual Network $($VirtualNetwork.Name)"
            Set-AzureRmVirtualNetworkSubnetConfig -Name $Subnet.Name -VirtualNetwork $VirtualNetwork -AddressPrefix $Subnet.AddressPrefix -ServiceEndpoint 'Microsoft.Storage' -WarningAction 'SilentlyContinue' | Set-AzureRmVirtualNetwork -WarningAction 'SilentlyContinue' -Verbose -ErrorAction 'Stop'
            Add-AzureRmStorageAccountNetworkRule -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -VirtualNetworkResourceId $($Subnet.Id)
        }
        else
        {
            if ($VirtualNetworkSubnetConfig.ServiceEndpoints.Service -notcontains 'Microsoft.Storage')
            {
                Write-Output "$($Subnet.Name) is missing Microsoft.Storage Service Endpoint"
                Write-Output "Adding Microsoft.Storage Service Endpoint to $($Subnet.Name) in Virtual Network $($VirtualNetwork.Name)"
                $ServiceEnpoints = @('Microsoft.Storage')
                $ServiceEnpoints += $VirtualNetworkSubnetConfig.ServiceEndpoints.Service
                Set-AzureRmVirtualNetworkSubnetConfig -Name $Subnet.Name -VirtualNetwork $VirtualNetwork -AddressPrefix $Subnet.AddressPrefix -ServiceEndpoint $ServiceEnpoints -WarningAction 'SilentlyContinue' | Set-AzureRmVirtualNetwork -WarningAction 'SilentlyContinue' -Verbose -ErrorAction 'Stop'
                Add-AzureRmStorageAccountNetworkRule -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -VirtualNetworkResourceId $($Subnet.Id)
            }
            else
            {
                Write-Output "Microsoft.Storage Service Endpoint found on Subnet $($Subnet.Name)"
                Write-Output "Updating Storage Account Network Rule with Subnet $($Subnet.Name)"
                Add-AzureRmStorageAccountNetworkRule -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -VirtualNetworkResourceId $($Subnet.Id) -WarningAction 'SilentlyContinue' -Verbose -ErrorAction 'Stop'
            }
        }
    }
}
Write-Output "Updating Storage Account Network Rule with default deny rule"
Update-AzureRmStorageAccountNetworkRuleSet -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -DefaultAction Deny  -WarningAction 'SilentlyContinue' -Verbose -ErrorAction 'Stop'
Write-Output 'Storage Account Network Rule Set Configuration completed successfully'
'@
Add-Content -Path $RunbookFilePath -Value $RunbookFileContent
(Get-Content $RunbookFilePath.FullName).replace('[Environment]', $($Environment.Name)) | Set-Content $RunbookFilePath.FullName
try
{
    Write-Output "Importing Runbook $($RunbookFilePath.BaseName)"
    Import-AzureRmAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Path $RunbookFilePath.FullName -Type $RunbookType -Verbose -ErrorAction 'Stop'
    Publish-AzureRmAutomationRunbook -Name $($RunbookFilePath.BaseName) -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Verbose -ErrorAction 'Stop'
    Register-AzureRmAutomationScheduledRunbook -RunbookName $($RunbookFilePath.BaseName) -ScheduleName $DailyScheduleName -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Verbose -ErrorAction 'Stop'
}
catch 
{
    Write-Warning $_
    break
}
#endregion

#region Add Start-DeployWindowsUpdateSettingsByResourceGroup Runbook
$RunbookType = 'PowerShellWorkflow'
$RunbookFilePath = New-Item -Path "$env:TEMP\Start-DeployWindowsUpdateSettingsByResourceGroup.ps1" -ItemType File -Force
$RunbookFileContent = @'
<#
.SYNOPSIS
    Script to deploy a custom script extension to an Azure Virtual Machine

.DESCRIPTION
    This runbook will deploy Set-LocalWindowsUpdateSettings.ps1 from a Azure Storage Account to Azure Virtual Machines in specified Resource Groups.
    This runbook is designed to use Azure Automation and an Automation Account.
    It will deploy the script as a Custom Script Extension.
    You must provide Resource Group Name(s) to start.
    The Automation Account must have permissions to deploy script extensions to the Virtual Machines

.PARAMETER ResourceGroups
    Provide Target Resource Group(s) name(s)
    Example:
        For a single ResourceGroup use a JSON format string: ['RG-01']
        For multiple ResourceGroups use a JSON format string: ['RG-01','RG-02','RG-03']

.PARAMETER SubscriptionId
    Provide Target Subscription ID
    Example: "14a0628d-1afd-4d05-8183-3d2541882900"

.EXAMPLE
    .\Start-DeployWindowsUpdateSettingsByResourceGroup.ps1 -ResourceGroups ['RG-01','RG-02','RG-03']
#>
Workflow Start-DeployWindowsUpdateSettingsByResourceGroup
{
    [CmdletBinding()]
    param
    (
        # Provide Target Resource Group(s) name(s)
        # Example:
        # For a single ResourceGroup use a JSON format string: ['RG-01']
        # For multiple ResourceGroups use a JSON format string: ['RG-01','RG-02','RG-03']
        [parameter(Mandatory=$true,HelpMessage="'Example: ['RG-01','RG-02','RG-03']'")]
        [String[]]$ResourceGroups,

        # Provide Target Subscription ID
        # Example: "aed90f7c-19ff-4b65-a0fb-c0186d3a7265"
        [parameter(Mandatory=$false,HelpMessage='Example: 14a0628d-1afd-4d05-8183-3d2541882900')]
        [String]$SubscriptionId
    )

    $ErrorActionPreference = 'Stop'
    $VerbosePreference = 'Continue'

    $FileUri = '[WindowsUpdateScriptsFolderURL]/Set-LocalWindowsUpdateSettings.ps1'
    $RunPath = './[WindowsUpdateScriptsFolderName]/Set-LocalWindowsUpdateSettings.ps1'

    $ResourceGroupName = '[ResourceGroupName]'
    $StorageAccountName = '[StorageAccountName]'
    $WindowsUpdateScriptsFolderName = '[WindowsUpdateScriptsFolderName]'

    $ScriptName = ($FileUri.Split('/') | Select-Object -Last 1)
    $ContainerName = ($FileUri.Split('/'))[3]

    try
    {
        # Pull Azure environment settings
        $AzureEnvironmentSettings = Get-AzureRmEnvironment -Name '[Environment]'

        # Azure management uri
        $ResourceAppIdURI = $AzureEnvironmentSettings.ActiveDirectoryServiceEndpointResourceId

        # Login uri for Azure AD
        $LoginURI = $AzureEnvironmentSettings.ActiveDirectoryAuthority

        # Get RunAsConnection
        $RunAsConnection = Get-AutomationConnection -Name "AzureRunAsConnection"

        # Get RunAsCertificate
        $Certifcate = Get-AutomationCertificate -Name "AzureRunAsCertificate"

        Add-AzureRmAccount -ServicePrincipal `
        -TenantId $RunAsConnection.TenantId `
        -ApplicationId $RunAsConnection.ApplicationId `
        -CertificateThumbprint $RunAsConnection.CertificateThumbprint `
        -EnvironmentName '[Environment]' -Verbose

        # Get Subscription Id if not provided
        if (!$SubscriptionId)
        {
            $SubscriptionId = $RunAsConnection.SubscriptionId
        }

        # Set up authentication using service principal client certificate
        $Authority = $LoginURI + $RunAsConnection.TenantId
        $AuthContext = [Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext]::new($Authority, $false)
        $ClientCertificate = [Microsoft.IdentityModel.Clients.ActiveDirectory.ClientAssertionCertificate]::new($RunAsConnection.ApplicationId, $Certifcate)
        $AuthResult = $AuthContext.AcquireToken($ResourceAppIdURI, $ClientCertificate)

        # Set up header with authorization token
        $AuthToken = $AuthResult.CreateAuthorizationHeader()
        $RequestHeader = @{
          "Content-Type" = "application/json";
          "Authorization" = "$AuthToken"
        }

        $DownloadLink = InlineScript {
            $StorageAccount = Get-AzureRmStorageAccount -ResourceGroupName $Using:ResourceGroupName -Name $Using:StorageAccountName -ErrorAction Stop
            $StartTime = Get-Date
            $EndTime = $startTime.AddHours(2.0)
            $DownloadLink = New-AzureStorageBlobSASToken -Context $StorageAccount.Context -Container "$Using:ContainerName/$Using:WindowsUpdateScriptsFolderName" -Blob $Using:ScriptName -Permission r -FullUri -StartTime $StartTime -ExpiryTime $EndTime -ErrorAction Stop
            return $DownloadLink
        }

        foreach -parallel ($ResourceGroup in $ResourceGroups)
        {
            Write-Output "Getting all Powered On VMs in ResourceGroup $ResourceGroup"
            $PoweredOnAzureRMVirtualMachines = (Get-AzureRMVM -ResourceGroupName $ResourceGroup -Status | Where-Object {($_.PowerState -eq "VM running") -and ($_.storageprofile.osdisk.ostype -eq 'Windows')})

            Write-Output "Checking for old Custom script extensions"
            foreach -parallel ($PoweredOnAzureRMVirtualMachine in $PoweredOnAzureRMVirtualMachines)
            {
                $CustomScriptExtension = $PoweredOnAzureRMVirtualMachine.Extensions | Where-Object {$_.Type -eq 'Microsoft.Compute.CustomScriptExtension'}
                # If a Custom Script Extension is found, remove it
                if ($CustomScriptExtension)
                {
                    try
                    {
                        Write-Output "Please wait while old deployment jobs are removed. This may take some time..."
                        Write-Output "Removing old Custom Script Extension from $($PoweredOnAzureRMVirtualMachine.Name)"

                        # Remove the discovered Custom Script Extension
                        Remove-AzureRmVMCustomScriptExtension -ResourceGroupName $($PoweredOnAzureRMVirtualMachine.ResourceGroupName) -VMName $($PoweredOnAzureRMVirtualMachine.Name) -Name $CustomScriptExtension.Name -Force -Verbose
                        Write-Output "Custom Script Extension was removed from $($PoweredOnAzureRMVirtualMachine.Name)"
                    }
                    catch
                    {
                        Write-Output "Failed to remove Custom Script Extensions"
                        Write-Output $Error[0].Exception
                    }
                }

                Write-Output "Preparing to deploy new Custom Script Extensions to $($PoweredOnAzureRMVirtualMachine.Name)"

                # Create the RestAPI Uri
                $RestUri = "[ResourceManagerUrl]subscriptions/$SubscriptionID/resourceGroups/$($PoweredOnAzureRMVirtualMachine.ResourceGroupName)/providers/Microsoft.Compute/virtualMachines/$($PoweredOnAzureRMVirtualMachine.Name)/extensions/CustomScriptExtension?api-version=2018-10-01"

                # Create the JSON Body
                $Body = @"
                {
                    "type": "Microsoft.Compute/virtualMachines/extensions",
                    "name": "CustomScriptExtension",
                    "location": "$($PoweredOnAzureRMVirtualMachine.Location)",
                    "tags": {
                        "displayName": "CustomScriptExtension"
                    },
                    "properties": {
                        "publisher": "Microsoft.Compute",
                        "type": "CustomScriptExtension",
                        "typeHandlerVersion": "1.9",
                        "autoUpgradeMinorVersion": true,
                        "settings": {
                            "fileUris": [
                                "$DownloadLink"
                            ]
                        },
                        "protectedSettings": {
                            "commandToExecute": "powershell -ExecutionPolicy Unrestricted -file $RunPath"
                        }
                    }
                }
"@
                Write-Output "Deploying Script Extension to $($PoweredOnAzureRMVirtualMachine.Name)"
                # Send the URI, Body and Authtoken using Invoke-RestMethod
                $Result = Invoke-RestMethod -Uri $RestUri -Method Put -body $body -Headers $RequestHeader -Verbose -ErrorAction Stop
                Write-Output $Result

            }
        }
    }
    catch
    {
        throw $_
    }
}
'@
Add-Content -Path $RunbookFilePath -Value $RunbookFileContent
(Get-Content $RunbookFilePath.FullName).replace('[WindowsUpdateScriptsFolderURL]', $WindowsUpdateScriptsFolderURL) | Set-Content $RunbookFilePath.FullName
(Get-Content $RunbookFilePath.FullName).replace('[WindowsUpdateScriptsFolderName]', $WindowsUpdateScriptsFolderName) | Set-Content $RunbookFilePath.FullName
(Get-Content $RunbookFilePath.FullName).replace('[ResourceGroupName]', $ResourceGroupName) | Set-Content $RunbookFilePath.FullName
(Get-Content $RunbookFilePath.FullName).replace('[StorageAccountName]', $StorageAccountName) | Set-Content $RunbookFilePath.FullName
(Get-Content $RunbookFilePath.FullName).replace('[Environment]', $($Environment.Name)) | Set-Content $RunbookFilePath.FullName
(Get-Content $RunbookFilePath.FullName).replace('[ResourceManagerUrl]', $ResourceManagerUrl) | Set-Content $RunbookFilePath.FullName
try
{
    Write-Output "Importing Runbook $($RunbookFilePath.BaseName)"
    Import-AzureRmAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Path $RunbookFilePath.FullName -Type $RunbookType -Verbose -ErrorAction 'Stop'
    Publish-AzureRmAutomationRunbook -Name $($RunbookFilePath.BaseName) -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Verbose -ErrorAction 'Stop'
}
catch 
{
    Write-Warning $_
    break
}
#endregion

#region Add Start-DeployWindowsUpdateSettingsByVMName Runbook
$RunbookType = 'PowerShellWorkflow'
$RunbookFilePath = New-Item -Path "$env:TEMP\Start-DeployWindowsUpdateSettingsByVMName.ps1" -ItemType File -Force
$RunbookFileContent = @'
<#
.SYNOPSIS
    Script to deploy a custom script extension to an Azure Virtual Machine

.DESCRIPTION
    This runbook will deploy Set-LocalWindowsUpdateSettings.ps1 from a Azure Storage Account to Azure Virtual Machines.
    This runbook is designed to use Azure Automation and an Automation Account.
    It will deploy the script as a Custom Script Extension.
    You must provide a Azure Virtual Machine Name(s) to start.
    The Automation Account must have permissions to deploy script extensions to the Virtual Machines 

.PARAMETER VirtualMachineNames
    Provide Target Virtual Machine(s) name(s)
    Example:
        For a single VM use a JSON format string: ['VM-01']
        For multiple VM use a JSON format string: ['VM-01','VM-02','VM-03']

.PARAMETER SubscriptionId
    Provide Target Subscription ID
    Example: "14a0628d-1afd-4d05-8183-3d2541882900"

.EXAMPLE
    
    .\Start-DeployWindowsUpdateSettingsByVMName.ps1 -VirtualMachineNames ["VM-01","VM-02","VM-03"]
#>
Workflow Start-DeployWindowsUpdateSettingsByVMName
{
    [CmdletBinding()]
    param
    (
        # Provide Target Virtual Machine(s) name(s)
        # Example:
        # For a single VM use a simple string: VM-01
        # For multiple VM use a JSON format string: ['VM-01','VM-02','VM-03']        
        [parameter(Mandatory=$true,HelpMessage="'Example: ['VM-01','VM-02','VM-03']'")]
        [String[]]$VirtualMachineNames,

        # Provide Target Subscription ID
        # Example: "14a0628d-1afd-4d05-8183-3d2541882900"
        [parameter(Mandatory=$false,HelpMessage='Example: 14a0628d-1afd-4d05-8183-3d2541882900')]
        [String]$SubscriptionId
    )

    $ErrorActionPreference = 'Stop'
    $VerbosePreference = 'Continue'

    $FileUri = '[WindowsUpdateScriptsFolderURL]/Set-LocalWindowsUpdateSettings.ps1'
    $RunPath = './[WindowsUpdateScriptsFolderName]/Set-LocalWindowsUpdateSettings.ps1'

    $ResourceGroupName = '[ResourceGroupName]'
    $StorageAccountName = '[StorageAccountName]'
    $WindowsUpdateScriptsFolderName = '[WindowsUpdateScriptsFolderName]'

    $ScriptName = ($FileUri.Split('/') | Select-Object -Last 1)
    $ContainerName = ($FileUri.Split('/'))[3]

    try
    {
        # Pull Azure environment settings
        $AzureEnvironmentSettings = Get-AzureRmEnvironment -Name '[Environment]'

        # Azure management uri
        $ResourceAppIdURI = $AzureEnvironmentSettings.ActiveDirectoryServiceEndpointResourceId

        # Login uri for Azure AD
        $LoginURI = $AzureEnvironmentSettings.ActiveDirectoryAuthority

        # Get RunAsConnection
        $RunAsConnection = Get-AutomationConnection -Name "AzureRunAsConnection"

        # Get RunAsCertificate
        $Certifcate = Get-AutomationCertificate -Name "AzureRunAsCertificate"

        Add-AzureRmAccount -ServicePrincipal `
        -TenantId $RunAsConnection.TenantId `
        -ApplicationId $RunAsConnection.ApplicationId `
        -CertificateThumbprint $RunAsConnection.CertificateThumbprint `
        -EnvironmentName '[Environment]' -Verbose

        # Get Subscription Id if not provided
        if (!$SubscriptionId)
        {
            $SubscriptionId = $RunAsConnection.SubscriptionId
        }

        # Set up authentication using service principal client certificate
        $Authority = $LoginURI + $RunAsConnection.TenantId
        $AuthContext = [Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext]::new($Authority, $false)
        $ClientCertificate = [Microsoft.IdentityModel.Clients.ActiveDirectory.ClientAssertionCertificate]::new($RunAsConnection.ApplicationId, $Certifcate)
        $AuthResult = $AuthContext.AcquireToken($ResourceAppIdURI, $ClientCertificate)

        # Set up header with authorization token
        $AuthToken = $AuthResult.CreateAuthorizationHeader()
        $RequestHeader = @{
          "Content-Type" = "application/json";
          "Authorization" = "$AuthToken"
        }

        $DownloadLink = InlineScript {
            $StorageAccount = Get-AzureRmStorageAccount -ResourceGroupName $Using:ResourceGroupName -Name $Using:StorageAccountName -ErrorAction Stop
            $StartTime = Get-Date
            $EndTime = $startTime.AddHours(2.0)
            $DownloadLink = New-AzureStorageBlobSASToken -Context $StorageAccount.Context -Container "$Using:ContainerName/$Using:WindowsUpdateScriptsFolderName" -Blob $Using:ScriptName -Permission r -FullUri -StartTime $StartTime -ExpiryTime $EndTime -ErrorAction Stop
            return $DownloadLink
        }

        $TargetVirtualMachines = @()
        foreach ($VirtualMachineName in $VirtualMachineNames)
        {
           $AzureVMResource = (Get-AzureRmResource | Where-Object {($_.ResourceType -eq 'Microsoft.Compute/virtualMachines') -and ($_.Name -eq $VirtualMachineName)})
           $TargetVirtualMachines += $AzureVMResource
        }

        foreach -parallel ($TargetVirtualMachine in $TargetVirtualMachines)
        {
            Write-Output "Checking if $($TargetVirtualMachine.Name) is powered on"
            $PoweredOnAzureRMVirtualMachine = (Get-AzureRMVM -Name $($TargetVirtualMachine.Name) -ResourceGroupName $($TargetVirtualMachine.ResourceGroupName) -Status | Where-Object {$_.Statuses.DisplayStatus -contains "VM running"})
            if ($PoweredOnAzureRMVirtualMachine)
            {
                Write-Output "Checking for old Custom script extensions"

                $CustomScriptExtension = $PoweredOnAzureRMVirtualMachine.Extensions | Where-Object {$_.Type -eq 'Microsoft.Compute.CustomScriptExtension'}
                # If a Custom Script Extension is found, remove it
                if ($CustomScriptExtension)
                {
                    try
                    {
                        Write-Output "Please wait while old deployment jobs are removed. This may take some time..."
                        Write-Output "Removing old Custom Script Extension from $($PoweredOnAzureRMVirtualMachine.Name)"

                        # Remove the discovered Custom Script Extension
                        Remove-AzureRmVMCustomScriptExtension -ResourceGroupName $($PoweredOnAzureRMVirtualMachine.ResourceGroupName) -VMName $($PoweredOnAzureRMVirtualMachine.Name) -Name $CustomScriptExtension.Name -Force -Verbose
                        Write-Output "Custom Script Extension was removed from $($PoweredOnAzureRMVirtualMachine.Name)"
                    }
                    catch
                    {
                        Write-Output "Failed to remove Custom Script Extensions"
                        Write-Output $Error[0].Exception
                    }
                }

                Write-Output "Preparing to deploy new Custom Script Extensions to $($PoweredOnAzureRMVirtualMachine.Name)"

                # Create the RestAPI Uri
                $RestURI = "[ResourceManagerUrl]subscriptions/$SubscriptionID/resourceGroups/$($PoweredOnAzureRMVirtualMachine.ResourceGroupName)/providers/Microsoft.Compute/virtualMachines/$($PoweredOnAzureRMVirtualMachine.Name)/extensions/CustomScriptExtension?api-version=2018-10-01"

                # Create the JSON Body
                $Body = @"
                {
                    "type": "Microsoft.Compute/virtualMachines/extensions",
                    "name": "CustomScriptExtension",
                    "location": "$($TargetVirtualMachine.Location)",
                    "tags": {
                        "displayName": "CustomScriptExtension"
                    },
                    "properties": {
                        "publisher": "Microsoft.Compute",
                        "type": "CustomScriptExtension",
                        "typeHandlerVersion": "1.9",
                        "autoUpgradeMinorVersion": true,
                        "settings": {
                            "fileUris": [
                                "$DownloadLink"
                            ]
                        },
                        "protectedSettings": {
                            "commandToExecute": "powershell -ExecutionPolicy Unrestricted -file $RunPath"
                        }
                    }
                }
"@

                # Send the URI, Body and Authtoken using Invoke-RestMethod
                Write-Output "Deploying Script Extension to $($PoweredOnAzureRMVirtualMachine.Name)"
                $Result = Invoke-RestMethod -Uri $RestURI -Method Put -body $Body -Headers $RequestHeader -ErrorAction Stop
                Write-Output $Result
            }
        }

    }
    catch
    {
        throw $_
    }
}
'@
Add-Content -Path $RunbookFilePath -Value $RunbookFileContent
(Get-Content $RunbookFilePath.FullName).replace('[WindowsUpdateScriptsFolderURL]', $WindowsUpdateScriptsFolderURL) | Set-Content $RunbookFilePath.FullName
(Get-Content $RunbookFilePath.FullName).replace('[WindowsUpdateScriptsFolderName]', $WindowsUpdateScriptsFolderName) | Set-Content $RunbookFilePath.FullName
(Get-Content $RunbookFilePath.FullName).replace('[ResourceGroupName]', $ResourceGroupName) | Set-Content $RunbookFilePath.FullName
(Get-Content $RunbookFilePath.FullName).replace('[StorageAccountName]', $StorageAccountName) | Set-Content $RunbookFilePath.FullName
(Get-Content $RunbookFilePath.FullName).replace('[Environment]', $($Environment.Name)) | Set-Content $RunbookFilePath.FullName
(Get-Content $RunbookFilePath.FullName).replace('[ResourceManagerUrl]', $ResourceManagerUrl) | Set-Content $RunbookFilePath.FullName
try
{
    Write-Output "Importing Runbook $($RunbookFilePath.BaseName)"
    Import-AzureRmAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Path $RunbookFilePath.FullName -Type $RunbookType -Verbose -ErrorAction 'Stop'
    Publish-AzureRmAutomationRunbook -Name $($RunbookFilePath.BaseName) -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Verbose -ErrorAction 'Stop'
}
catch 
{
    Write-Warning $_
    break
}
#endregion

#region Add Start-DeployWindowsUpdateSettingsBySubscription Runbook
$RunbookType = 'PowerShellWorkflow'
$RunbookFilePath = New-Item -Path "$env:TEMP\Start-DeployWindowsUpdateSettingsBySubscription.ps1" -ItemType File -Force
$RunbookFileContent = @'
<#
.SYNOPSIS
    Script to deploy a custom script extension to an Azure Virtual Machine

.DESCRIPTION
    This runbook will deploy Set-LocalWindowsUpdateSettings from a Azure Storage Account to Azure Virtual Machines in specified Subscription.
    This runbook is designed to use Azure Automation and an Automation Account.
    It will deploy the script as a Custom Script Extension.
    You must provide a Subscription Name to start.
    The Automation Account must have permissions to deploy script extensions to the Virtual Machines

.PARAMETER SubscriptionId
    Provide Target Subscription ID
    Example: "14a0628d-1afd-4d05-8183-3d2541882900"

.EXAMPLE
    .\Start-DeployWindowsUpdateSettingsBySubscription.ps1 -SubscriptionId '14a0628d-1afd-4d05-8183-3d2541882900'
#>
Workflow Start-DeployWindowsUpdateSettingsBySubscription
{
    [CmdletBinding()]
    param
    (
        # Provide Target Subscription ID
        # Example: "14a0628d-1afd-4d05-8183-3d2541882900"
        [parameter(Mandatory=$false,HelpMessage='Example: 14a0628d-1afd-4d05-8183-3d2541882900')]
        [String]$SubscriptionId
    )

    $ErrorActionPreference = 'Stop'
    $VerbosePreference = 'Continue'

    $FileUri = '[WindowsUpdateScriptsFolderURL]/Set-LocalWindowsUpdateSettings.ps1'
    $RunPath = './[WindowsUpdateScriptsFolderName]/Set-LocalWindowsUpdateSettings.ps1'

    $ResourceGroupName = '[ResourceGroupName]'
    $StorageAccountName = '[StorageAccountName]'
    $WindowsUpdateScriptsFolderName = '[WindowsUpdateScriptsFolderName]'

    $ScriptName = ($FileUri.Split('/') | Select-Object -Last 1)
    $ContainerName = ($FileUri.Split('/'))[3]

    try
    {
        # Pull Azure environment settings
        $AzureEnvironmentSettings = Get-AzureRmEnvironment -Name '[Environment]'

        # Azure management uri
        $ResourceAppIdURI = $AzureEnvironmentSettings.ActiveDirectoryServiceEndpointResourceId

        # Login uri for Azure AD
        $LoginURI = $AzureEnvironmentSettings.ActiveDirectoryAuthority

        # Get RunAsConnection
        $RunAsConnection = Get-AutomationConnection -Name "AzureRunAsConnection"

        # Get RunAsCertificate
        $Certifcate = Get-AutomationCertificate -Name "AzureRunAsCertificate"

        Add-AzureRmAccount -ServicePrincipal `
        -TenantId $RunAsConnection.TenantId `
        -ApplicationId $RunAsConnection.ApplicationId `
        -CertificateThumbprint $RunAsConnection.CertificateThumbprint `
        -EnvironmentName '[Environment]' -Verbose

        # Get Subscription Id if not provided
        if (!$SubscriptionId)
        {
            $SubscriptionId = $RunAsConnection.SubscriptionId
        }

        # Set up authentication using service principal client certificate
        $Authority = $LoginURI + $RunAsConnection.TenantId
        $AuthContext = [Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext]::new($Authority, $false)
        $ClientCertificate = [Microsoft.IdentityModel.Clients.ActiveDirectory.ClientAssertionCertificate]::new($RunAsConnection.ApplicationId, $Certifcate)
        $AuthResult = $AuthContext.AcquireToken($ResourceAppIdURI, $ClientCertificate)

        # Set up header with authorization token
        $AuthToken = $AuthResult.CreateAuthorizationHeader()
        $RequestHeader = @{
          "Content-Type" = "application/json";
          "Authorization" = "$AuthToken"
        }

        $DownloadLink = InlineScript {
            $StorageAccount = Get-AzureRmStorageAccount -ResourceGroupName $Using:ResourceGroupName -Name $Using:StorageAccountName -ErrorAction Stop
            $StartTime = Get-Date
            $EndTime = $startTime.AddHours(2.0)
            $DownloadLink = New-AzureStorageBlobSASToken -Context $StorageAccount.Context -Container "$Using:ContainerName/$Using:WindowsUpdateScriptsFolderName" -Blob $Using:ScriptName -Permission r -FullUri -StartTime $StartTime -ExpiryTime $EndTime -ErrorAction Stop
            return $DownloadLink
        }

        # Set Working Subscription
        $TargetSubscription = Get-AzureRmSubscription -SubscriptionId $SubscriptionId -Verbose
        $SubscriptionId = $SubscriptionId

        $ResourceGroups = (Get-AzureRmResourceGroup | Where-Object {$_.ResourceId -like "/subscriptions/$SubscriptionId/resourceGroups/*"}).ResourceGroupName

        foreach -parallel ($ResourceGroup in $ResourceGroups)
        {
            Write-Output "Getting all Powered On VMs in ResourceGroup $ResourceGroup"
            $PoweredOnAzureRMVirtualMachines = (Get-AzureRMVM -ResourceGroupName $ResourceGroup -Status | Where-Object {($_.PowerState -eq "VM running") -and ($_.storageprofile.osdisk.ostype -eq 'Windows')})

            Write-Output "Checking for old Custom script extensions"
            foreach -parallel ($PoweredOnAzureRMVirtualMachine in $PoweredOnAzureRMVirtualMachines)
            {
                $CustomScriptExtension = $PoweredOnAzureRMVirtualMachine.Extensions | Where-Object {$_.Type -eq 'Microsoft.Compute.CustomScriptExtension'}
                # If a Custom Script Extension is found, remove it
                if ($CustomScriptExtension)
                {
                    try
                    {
                        Write-Output "Please wait while old deployment jobs are removed. This may take some time..."
                        Write-Output "Removing old Custom Script Extension from $($PoweredOnAzureRMVirtualMachine.Name)"

                        # Remove the discovered Custom Script Extension
                        Remove-AzureRmVMCustomScriptExtension -ResourceGroupName $($PoweredOnAzureRMVirtualMachine.ResourceGroupName) -VMName $($PoweredOnAzureRMVirtualMachine.Name) -Name $CustomScriptExtension.Name -Force -Verbose
                        Write-Output "Custom Script Extension was removed from $($PoweredOnAzureRMVirtualMachine.Name)"
                    }
                    catch
                    {
                        Write-Output "Failed to remove Custom Script Extensions"
                        Write-Output $Error[0].Exception
                    }
                }

                Write-Output "Preparing to deploy new Custom Script Extensions to $($PoweredOnAzureRMVirtualMachine.Name)"

                # Create the RestAPI Uri
                $RestURI = "[ResourceManagerUrl]subscriptions/$SubscriptionID/resourceGroups/$($PoweredOnAzureRMVirtualMachine.ResourceGroupName)/providers/Microsoft.Compute/virtualMachines/$($PoweredOnAzureRMVirtualMachine.Name)/extensions/CustomScriptExtension?api-version=2018-10-01"

                # Create the JSON Body
                $Body = @"
                {
                    "type": "Microsoft.Compute/virtualMachines/extensions",
                    "name": "CustomScriptExtension",
                    "location": "$($PoweredOnAzureRMVirtualMachine.Location)",
                    "tags": {
                        "displayName": "CustomScriptExtension"
                    },
                    "properties": {
                        "publisher": "Microsoft.Compute",
                        "type": "CustomScriptExtension",
                        "typeHandlerVersion": "1.9",
                        "autoUpgradeMinorVersion": true,
                        "settings": {
                            "fileUris": [
                                "$DownloadLink"
                            ]
                        },
                        "protectedSettings": {
                            "commandToExecute": "powershell -ExecutionPolicy Unrestricted -file $RunPath"
                        }
                    }
                }
"@

                # Send the URI, Body and Authtoken using Invoke-RestMethod
                Write-Output "Deploying Script Extension to $($PoweredOnAzureRMVirtualMachine.Name)"
                $Result = Invoke-RestMethod -Uri $RestURI -Method Put -body $Body -Headers $RequestHeader -ErrorAction Stop
                Write-Output $Result

            }
        }
    }
    catch
    {
        throw $_
    }
}
'@
Add-Content -Path $RunbookFilePath -Value $RunbookFileContent
(Get-Content $RunbookFilePath.FullName).replace('[WindowsUpdateScriptsFolderURL]', $WindowsUpdateScriptsFolderURL) | Set-Content $RunbookFilePath.FullName
(Get-Content $RunbookFilePath.FullName).replace('[WindowsUpdateScriptsFolderName]', $WindowsUpdateScriptsFolderName) | Set-Content $RunbookFilePath.FullName
(Get-Content $RunbookFilePath.FullName).replace('[ResourceGroupName]', $ResourceGroupName) | Set-Content $RunbookFilePath.FullName
(Get-Content $RunbookFilePath.FullName).replace('[StorageAccountName]', $StorageAccountName) | Set-Content $RunbookFilePath.FullName
(Get-Content $RunbookFilePath.FullName).replace('[Environment]', $($Environment.Name)) | Set-Content $RunbookFilePath.FullName
(Get-Content $RunbookFilePath.FullName).replace('[ResourceManagerUrl]', $ResourceManagerUrl) | Set-Content $RunbookFilePath.FullName
try
{
    Write-Output "Importing Runbook $($RunbookFilePath.BaseName)"
    Import-AzureRmAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Path $RunbookFilePath.FullName -Type $RunbookType -Verbose -ErrorAction 'Stop'
    Publish-AzureRmAutomationRunbook -Name $($RunbookFilePath.BaseName) -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Verbose -ErrorAction 'Stop'
}
catch 
{
    Write-Warning $_
    break
}
#endregion

#region Add Start-WindowsUpdateDeploymentByResourceGroup Runbook
$RunbookType = 'PowerShellWorkflow'
$RunbookFilePath = New-Item -Path "$env:TEMP\Start-WindowsUpdateDeploymentByResourceGroup.ps1" -ItemType File -Force
$RunbookFileContent = @'
<#
.SYNOPSIS
    Script to deploy a custom script extension to an Azure Virtual Machine

.DESCRIPTION
    This runbook will deploy Invoke-WindowsUpdate.ps1 from a Azure Storage Account to Azure Virtual Machines in specified Resource Groups.
    This runbook is designed to use Azure Automation and an Automation Account.
    It will deploy the script as a Custom Script Extension.
    You must provide Resource Group Name(s) to start.
    The Automation Account must have permissions to deploy script extensions to the Virtual Machines

.PARAMETER ResourceGroups
    Provide Target Resource Group(s) name(s)
    Example:
        For a single ResourceGroup use a JSON format string: ['RG-01']
        For multiple ResourceGroups use a JSON format string: ['RG-01','RG-02','RG-03']

.PARAMETER RestartOption
    Specify if you want to restart the Virtual Machine upon Windows Update installation completion
	"Example: AutoReboot or IgnoreReboot"
	
.PARAMETER ForceOnlineUpdate
	This is a switch that will force the computer to check online for Windows Updates

.PARAMETER SubscriptionId
    Provide Target Subscription ID
    Example: "14a0628d-1afd-4d05-8183-3d2541882900"

.EXAMPLE
    .\Start-WindowsUpdateDeploymentByResourceGroupRunbook.ps1
#>
Workflow Start-WindowsUpdateDeploymentByResourceGroup
{
    [CmdletBinding()]
    param
    (
        # Provide Target Resource Group(s) name(s)
        # Example:
        # For a single ResourceGroup use a JSON format string: ['RG-01']
        # For multiple ResourceGroups use a JSON format string: ['RG-01','RG-02','RG-03']
        [parameter(Mandatory=$true,HelpMessage="'Example: ['RG-01','RG-02','RG-03']'")]
        [String[]]$ResourceGroups,

        # Specify if you want to restart the Virtual Machine upon Windows Update installation completion
	    # Example: AutoReboot or IgnoreReboot"
        [parameter(Mandatory=$true,HelpMessage='Example:')]
        [ValidateSet('IgnoreReboot','AutoReboot')]
        [String]$RestartOption,

        # Provide Target Subscription ID
        # Example: "14a0628d-1afd-4d05-8183-3d2541882900"
        [parameter(Mandatory=$false,HelpMessage='Example: 14a0628d-1afd-4d05-8183-3d2541882900')]
        [String]$SubscriptionId,

        # This is a switch that will force the computer to check online for Windows Updates
        [Switch]$ForceOnlineUpdate
    )

    $ErrorActionPreference = 'Stop'
    $VerbosePreference = 'Continue'

    $FileUri = '[WindowsUpdateScriptsFolderURL]/Invoke-WindowsUpdate.ps1'
    $RunPath = './[WindowsUpdateScriptsFolderName]/Invoke-WindowsUpdate.ps1'

    $ResourceGroupName = '[ResourceGroupName]'
    $StorageAccountName = '[StorageAccountName]'
    $WindowsUpdateScriptsFolderName = '[WindowsUpdateScriptsFolderName]'

    $ScriptName = ($FileUri.Split('/') | Select-Object -Last 1)
    $ContainerName = ($FileUri.Split('/'))[3]

    try
    {
        # Pull Azure environment settings
        $AzureEnvironmentSettings = Get-AzureRmEnvironment -Name '[Environment]'

        # Azure management uri
        $ResourceAppIdURI = $AzureEnvironmentSettings.ActiveDirectoryServiceEndpointResourceId

        # Login uri for Azure AD
        $LoginURI = $AzureEnvironmentSettings.ActiveDirectoryAuthority

        # Get RunAsConnection
        $RunAsConnection = Get-AutomationConnection -Name "AzureRunAsConnection"

        # Get RunAsCertificate
        $Certifcate = Get-AutomationCertificate -Name "AzureRunAsCertificate"

        Add-AzureRmAccount -ServicePrincipal `
        -TenantId $RunAsConnection.TenantId `
        -ApplicationId $RunAsConnection.ApplicationId `
        -CertificateThumbprint $RunAsConnection.CertificateThumbprint `
        -EnvironmentName '[Environment]' -Verbose

        # Get Subscription Id if not provided
        if (!$SubscriptionId)
        {
            $SubscriptionId = $RunAsConnection.SubscriptionId
        }

        # Set up authentication using service principal client certificate
        $Authority = $LoginURI + $RunAsConnection.TenantId
        $AuthContext = [Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext]::new($Authority, $false)
        $ClientCertificate = [Microsoft.IdentityModel.Clients.ActiveDirectory.ClientAssertionCertificate]::new($RunAsConnection.ApplicationId, $Certifcate)
        $AuthResult = $AuthContext.AcquireToken($ResourceAppIdURI, $ClientCertificate)

        # Set up header with authorization token
        $AuthToken = $AuthResult.CreateAuthorizationHeader()
        $RequestHeader = @{
          "Content-Type" = "application/json";
          "Authorization" = "$AuthToken"
        }

        $DownloadLink = InlineScript {
            $StorageAccount = Get-AzureRmStorageAccount -ResourceGroupName $Using:ResourceGroupName -Name $Using:StorageAccountName -ErrorAction Stop
            $StartTime = Get-Date
            $EndTime = $startTime.AddHours(2.0)
            $DownloadLink = New-AzureStorageBlobSASToken -Context $StorageAccount.Context -Container "$Using:ContainerName/$Using:WindowsUpdateScriptsFolderName" -Blob $Using:ScriptName -Permission r -FullUri -StartTime $StartTime -ExpiryTime $EndTime -ErrorAction Stop
            return $DownloadLink
        }

        foreach -parallel ($ResourceGroup in $ResourceGroups)
        {
            Write-Output "Getting all Powered On VMs in ResourceGroup $ResourceGroup"
            $PoweredOnAzureRMVirtualMachines = (Get-AzureRMVM -ResourceGroupName $ResourceGroup -Status | Where-Object {($_.PowerState -eq "VM running") -and ($_.storageprofile.osdisk.ostype -eq 'Windows')})

            Write-Output "Checking for old Custom script extensions"
            foreach -parallel ($PoweredOnAzureRMVirtualMachine in $PoweredOnAzureRMVirtualMachines)
            {
                $CustomScriptExtension = $PoweredOnAzureRMVirtualMachine.Extensions | Where-Object {$_.Type -eq 'Microsoft.Compute.CustomScriptExtension'}
                # If a Custom Script Extension is found, remove it
                if ($CustomScriptExtension)
                {
                    try
                    {
                        Write-Output "Please wait while old deployment jobs are removed. This may take some time..."
                        Write-Output "Removing old Custom Script Extension from $($PoweredOnAzureRMVirtualMachine.Name)"

                        # Remove the discovered Custom Script Extension
                        Remove-AzureRmVMCustomScriptExtension -ResourceGroupName $($PoweredOnAzureRMVirtualMachine.ResourceGroupName) -VMName $($PoweredOnAzureRMVirtualMachine.Name) -Name $CustomScriptExtension.Name -Force -Verbose
                        Write-Output "Custom Script Extension was removed from $($PoweredOnAzureRMVirtualMachine.Name)"
                    }
                    catch
                    {
                        Write-Output "Failed to remove Custom Script Extensions"
                        Write-Output $Error[0].Exception
                    }
                }

                Write-Output "Preparing to deploy new Custom Script Extensions to $($PoweredOnAzureRMVirtualMachine.Name)"

                # Create the RestAPI Uri
                $RestURI = "[ResourceManagerUrl]subscriptions/$SubscriptionID/resourceGroups/$($PoweredOnAzureRMVirtualMachine.ResourceGroupName)/providers/Microsoft.Compute/virtualMachines/$($PoweredOnAzureRMVirtualMachine.Name)/extensions/CustomScriptExtension?api-version=2018-10-01"

                # Create the JSON Body
                if (!($ForceOnlineUpdate))
                {
                    $Body = @"
                    {
                        "type": "Microsoft.Compute/virtualMachines/extensions",
                        "name": "CustomScriptExtension",
                        "location": "$($PoweredOnAzureRMVirtualMachine.Location)",
                        "tags": {
                            "displayName": "CustomScriptExtension"
                        },
                        "properties": {
                            "publisher": "Microsoft.Compute",
                            "type": "CustomScriptExtension",
                            "typeHandlerVersion": "1.9",
                            "autoUpgradeMinorVersion": true,
                            "settings": {
                                "fileUris": [
                                    "$DownloadLink"
                                ]
                            },
                            "protectedSettings": {
                                "commandToExecute": "powershell -ExecutionPolicy Unrestricted -file $RunPath -RestartOption $RestartOption"
                            }
                        }
                    }
"@
                }
                if ($ForceOnlineUpdate)
                {
                    $Body = @"
                    {
                        "type": "Microsoft.Compute/virtualMachines/extensions",
                        "name": "CustomScriptExtension",
                        "location": "$($PoweredOnAzureRMVirtualMachine.Location)",
                        "tags": {
                            "displayName": "CustomScriptExtension"
                        },
                        "properties": {
                            "publisher": "Microsoft.Compute",
                            "type": "CustomScriptExtension",
                            "typeHandlerVersion": "1.9",
                            "autoUpgradeMinorVersion": true,
                            "settings": {
                                "fileUris": [
                                    "$DownloadLink"
                                ]
                            },
                            "protectedSettings": {
                                "commandToExecute": "powershell -ExecutionPolicy Unrestricted -file $RunPath -RestartOption $RestartOption -ForceOnlineUpdate"
                            }
                        }
                    }
"@
                }

                # Send the URI, Body and Authtoken using Invoke-RestMethod
                Write-Output "Deploying Script Extension to $($PoweredOnAzureRMVirtualMachine.Name)"
                $Result = Invoke-RestMethod -Uri $RestURI -Method Put -body $Body -Headers $RequestHeader -ErrorAction Stop
                Write-Output $Result
            }
        }

    }
    catch
    {
        throw $_
    }
}
'@
Add-Content -Path $RunbookFilePath -Value $RunbookFileContent
(Get-Content $RunbookFilePath.FullName).replace('[WindowsUpdateScriptsFolderURL]', $WindowsUpdateScriptsFolderURL) | Set-Content $RunbookFilePath.FullName
(Get-Content $RunbookFilePath.FullName).replace('[WindowsUpdateScriptsFolderName]', $WindowsUpdateScriptsFolderName) | Set-Content $RunbookFilePath.FullName
(Get-Content $RunbookFilePath.FullName).replace('[ResourceGroupName]', $ResourceGroupName) | Set-Content $RunbookFilePath.FullName
(Get-Content $RunbookFilePath.FullName).replace('[StorageAccountName]', $StorageAccountName) | Set-Content $RunbookFilePath.FullName
(Get-Content $RunbookFilePath.FullName).replace('[Environment]', $($Environment.Name)) | Set-Content $RunbookFilePath.FullName
(Get-Content $RunbookFilePath.FullName).replace('[ResourceManagerUrl]', $ResourceManagerUrl) | Set-Content $RunbookFilePath.FullName
try
{
    Write-Output "Importing Runbook $($RunbookFilePath.BaseName)"
    Import-AzureRmAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Path $RunbookFilePath.FullName -Type $RunbookType -Verbose -ErrorAction 'Stop'
    Publish-AzureRmAutomationRunbook -Name $($RunbookFilePath.BaseName) -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Verbose -ErrorAction 'Stop'
}
catch 
{
    Write-Warning $_
    break
}
#endregion

#region Add Start-WindowsUpdateDeploymentBySubscription Runbook
$RunbookType = 'PowerShellWorkflow'
$RunbookFilePath = New-Item -Path "$env:TEMP\Start-WindowsUpdateDeploymentBySubscription.ps1" -ItemType File -Force
$RunbookFileContent = @'
<#
.SYNOPSIS
    Script to deploy a custom script extension to an Azure Virtual Machine

.DESCRIPTION
    This runbook will deploy Invoke-WindowsUpdate.ps1 from a Azure Storage Account to Azure Virtual Machines in specified Subscription.
    This runbook is designed to use Azure Automation and an Automation Account.
    It will deploy the script as a Custom Script Extension.
    You must provide a Subscription Name to start.
    The Automation Account must have permissions to deploy script extensions to the Virtual Machines

.PARAMETER SubscriptionId
    Provide Target Subscription ID
    Example: "14a0628d-1afd-4d05-8183-3d2541882900"

.PARAMETER RestartOption
    Specify if you want to restart the Virtual Machine upon Windows Update installation completion
	"Example: AutoReboot or IgnoreReboot"
	
.PARAMETER ForceOnlineUpdate
	This is a switch that will force the computer to check online for Windows Updates

.EXAMPLE
    .\Start-WindowsUpdateDeploymentBySubscription.ps1
#>
Workflow Start-WindowsUpdateDeploymentBySubscription
{
    [CmdletBinding()]
    param
    (                
        # Specify if you want to restart the Virtual Machine upon Windows Update installation completion
	    # Example: AutoReboot or IgnoreReboot
        [parameter(Mandatory=$true,HelpMessage='Example:')]
        [ValidateSet('IgnoreReboot','AutoReboot')]
        [String]$RestartOption,

        # Provide Target Subscription ID
        # Example: "14a0628d-1afd-4d05-8183-3d2541882900"
        [parameter(Mandatory=$false,HelpMessage='Example: 14a0628d-1afd-4d05-8183-3d2541882900')]
        [String]$SubscriptionId,

        # This is a switch that will force the computer to check online for Windows Updates
        [Switch]$ForceOnlineUpdate
    )

    $ErrorActionPreference = 'Stop'
    $VerbosePreference = 'Continue'

    $FileUri = '[WindowsUpdateScriptsFolderURL]/Invoke-WindowsUpdate.ps1'
    $RunPath = './[WindowsUpdateScriptsFolderName]/Invoke-WindowsUpdate.ps1'

    $ResourceGroupName = '[ResourceGroupName]'
    $StorageAccountName = '[StorageAccountName]'
    $WindowsUpdateScriptsFolderName = '[WindowsUpdateScriptsFolderName]'

    $ScriptName = ($FileUri.Split('/') | Select-Object -Last 1)
    $ContainerName = ($FileUri.Split('/'))[3]

    try
    {
        # Pull Azure environment settings
        $AzureEnvironmentSettings = Get-AzureRmEnvironment -Name '[Environment]'

        # Azure management uri
        $ResourceAppIdURI = $AzureEnvironmentSettings.ActiveDirectoryServiceEndpointResourceId

        # Login uri for Azure AD
        $LoginURI = $AzureEnvironmentSettings.ActiveDirectoryAuthority

        # Get RunAsConnection
        $RunAsConnection = Get-AutomationConnection -Name "AzureRunAsConnection"

        # Get RunAsCertificate
        $Certifcate = Get-AutomationCertificate -Name "AzureRunAsCertificate"

        Add-AzureRmAccount -ServicePrincipal `
        -TenantId $RunAsConnection.TenantId `
        -ApplicationId $RunAsConnection.ApplicationId `
        -CertificateThumbprint $RunAsConnection.CertificateThumbprint `
        -EnvironmentName '[Environment]' -Verbose

        # Get Subscription Id if not provided
        if (!$SubscriptionId)
        {
            $SubscriptionId = $RunAsConnection.SubscriptionId
        }

        # Set up authentication using service principal client certificate
        $Authority = $LoginURI + $RunAsConnection.TenantId
        $AuthContext = [Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext]::new($Authority, $false)
        $ClientCertificate = [Microsoft.IdentityModel.Clients.ActiveDirectory.ClientAssertionCertificate]::new($RunAsConnection.ApplicationId, $Certifcate)
        $AuthResult = $AuthContext.AcquireToken($ResourceAppIdURI, $ClientCertificate)

        # Set up header with authorization token
        $AuthToken = $AuthResult.CreateAuthorizationHeader()
        $RequestHeader = @{
          "Content-Type" = "application/json";
          "Authorization" = "$AuthToken"
        }

        $DownloadLink = InlineScript {
            $StorageAccount = Get-AzureRmStorageAccount -ResourceGroupName $Using:ResourceGroupName -Name $Using:StorageAccountName -ErrorAction Stop
            $StartTime = Get-Date
            $EndTime = $startTime.AddHours(2.0)
            $DownloadLink = New-AzureStorageBlobSASToken -Context $StorageAccount.Context -Container "$Using:ContainerName/$Using:WindowsUpdateScriptsFolderName" -Blob $Using:ScriptName -Permission r -FullUri -StartTime $StartTime -ExpiryTime $EndTime -ErrorAction Stop
            return $DownloadLink
        }

        $ResourceGroups = (Get-AzureRmResourceGroup | Where-Object {$_.ResourceId -like "/subscriptions/$SubscriptionId/resourceGroups/*"}).ResourceGroupName

        foreach -parallel ($ResourceGroup in $ResourceGroups)
        {
            Write-Output "Getting all Powered On VMs in ResourceGroup $ResourceGroup"
            $PoweredOnAzureRMVirtualMachines = (Get-AzureRMVM -ResourceGroupName $ResourceGroup -Status | Where-Object {($_.PowerState -eq "VM running") -and ($_.storageprofile.osdisk.ostype -eq 'Windows')})

            Write-Output "Checking for old Custom script extensions"
            foreach -parallel ($PoweredOnAzureRMVirtualMachine in $PoweredOnAzureRMVirtualMachines)
            {
                $CustomScriptExtension = $PoweredOnAzureRMVirtualMachine.Extensions | Where-Object {$_.Type -eq 'Microsoft.Compute.CustomScriptExtension'}
                # If a Custom Script Extension is found, remove it
                if ($CustomScriptExtension)
                {
                    try
                    {
                        Write-Output "Please wait while old deployment jobs are removed. This may take some time..."
                        Write-Output "Removing old Custom Script Extension from $($PoweredOnAzureRMVirtualMachine.Name)"

                        # Remove the discovered Custom Script Extension
                        Remove-AzureRmVMCustomScriptExtension -ResourceGroupName $($PoweredOnAzureRMVirtualMachine.ResourceGroupName) -VMName $($PoweredOnAzureRMVirtualMachine.Name) -Name $CustomScriptExtension.Name -Force -Verbose
                        Write-Output "Custom Script Extension was removed from $($PoweredOnAzureRMVirtualMachine.Name)"
                    }
                    catch
                    {
                        Write-Output "Failed to remove Custom Script Extensions"
                        Write-Output $Error[0].Exception
                    }
                }

                Write-Output "Preparing to deploy new Custom Script Extensions to $($PoweredOnAzureRMVirtualMachine.Name)"

                # Create the RestAPI Uri
                $RestURI = "[ResourceManagerUrl]subscriptions/$SubscriptionID/resourceGroups/$($PoweredOnAzureRMVirtualMachine.ResourceGroupName)/providers/Microsoft.Compute/virtualMachines/$($PoweredOnAzureRMVirtualMachine.Name)/extensions/CustomScriptExtension?api-version=2018-10-01"

                # Create the JSON Body
                if (!($ForceOnlineUpdate))
                {
                    $Body = @"
                    {
                        "type": "Microsoft.Compute/virtualMachines/extensions",
                        "name": "CustomScriptExtension",
                        "location": "$($PoweredOnAzureRMVirtualMachine.Location)",
                        "tags": {
                            "displayName": "CustomScriptExtension"
                        },
                        "properties": {
                            "publisher": "Microsoft.Compute",
                            "type": "CustomScriptExtension",
                            "typeHandlerVersion": "1.9",
                            "autoUpgradeMinorVersion": true,
                            "settings": {
                                "fileUris": [
                                    "$DownloadLink"
                                ]
                            },
                            "protectedSettings": {
                                "commandToExecute": "powershell -ExecutionPolicy Unrestricted -file $RunPath -RestartOption $RestartOption"
                            }
                        }
                    }
"@
                }
                if ($ForceOnlineUpdate)
                {
                    $Body = @"
                    {
                        "type": "Microsoft.Compute/virtualMachines/extensions",
                        "name": "CustomScriptExtension",
                        "location": "$($PoweredOnAzureRMVirtualMachine.Location)",
                        "tags": {
                            "displayName": "CustomScriptExtension"
                        },
                        "properties": {
                            "publisher": "Microsoft.Compute",
                            "type": "CustomScriptExtension",
                            "typeHandlerVersion": "1.9",
                            "autoUpgradeMinorVersion": true,
                            "settings": {
                                "fileUris": [
                                    "$DownloadLink"
                                ]
                            },
                            "protectedSettings": {
                                "commandToExecute": "powershell -ExecutionPolicy Unrestricted -file $RunPath -RestartOption $RestartOption -ForceOnlineUpdate"
                            }
                        }
                    }
"@
                }

                # Send the URI, Body and Authtoken using Invoke-RestMethod
                Write-Output "Deploying Script Extension to $($PoweredOnAzureRMVirtualMachine.Name)"
                $Result = Invoke-RestMethod -Uri $RestURI -Method Put -body $Body -Headers $RequestHeader -ErrorAction Stop
                Write-Output $Result

            }
        }
    }
    catch
    {
        throw $_
    }
}
'@
Add-Content -Path $RunbookFilePath -Value $RunbookFileContent
(Get-Content $RunbookFilePath.FullName).replace('[WindowsUpdateScriptsFolderURL]', $WindowsUpdateScriptsFolderURL) | Set-Content $RunbookFilePath.FullName
(Get-Content $RunbookFilePath.FullName).replace('[WindowsUpdateScriptsFolderName]', $WindowsUpdateScriptsFolderName) | Set-Content $RunbookFilePath.FullName
(Get-Content $RunbookFilePath.FullName).replace('[ResourceGroupName]', $ResourceGroupName) | Set-Content $RunbookFilePath.FullName
(Get-Content $RunbookFilePath.FullName).replace('[StorageAccountName]', $StorageAccountName) | Set-Content $RunbookFilePath.FullName
(Get-Content $RunbookFilePath.FullName).replace('[Environment]', $($Environment.Name)) | Set-Content $RunbookFilePath.FullName
(Get-Content $RunbookFilePath.FullName).replace('[ResourceManagerUrl]', $ResourceManagerUrl) | Set-Content $RunbookFilePath.FullName
try
{
    Write-Output "Importing Runbook $($RunbookFilePath.BaseName)"
    Import-AzureRmAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Path $RunbookFilePath.FullName -Type $RunbookType -Verbose -ErrorAction 'Stop'
    Publish-AzureRmAutomationRunbook -Name $($RunbookFilePath.BaseName) -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Verbose -ErrorAction 'Stop'
}
catch 
{
    Write-Warning $_
    break
}
#endregion

#region Add Start-WindowsUpdateDeploymentByVMName Runbook
$RunbookType = 'PowerShellWorkflow'
$RunbookFilePath = New-Item -Path "$env:TEMP\Start-WindowsUpdateDeploymentByVMName.ps1" -ItemType File -Force
$RunbookFileContent = @'
<#
.SYNOPSIS
    Script to deploy a custom script extension to an Azure Virtual Machine

.DESCRIPTION
    This runbook will deploy Invoke-WindowsUpdate.ps1 from a Azure Storage Account to Azure Virtual Machines.
    This runbook is designed to use Azure Automation and an Automation Account.
    It will deploy the script as a Custom Script Extension.
    You must provide a Azure Virtual Machine Name(s) to start.
    The Automation Account must have permissions to deploy script extensions to the Virtual Machines 

.PARAMETER VirtualMachineNames
    Provide Target Virtual Machine(s) name(s)
    Example:
        For a single VM use a JSON format string: ['VM-01']
        For multiple VM use a JSON format string: ['VM-01','VM-02','VM-03']

.PARAMETER RestartOption
    Specify if you want to restart the Virtual Machine upon Windows Update installation completion
	"Example: AutoReboot or IgnoreReboot"

.PARAMETER SubscriptionId
    Provide Target Subscription ID
    Example: "14a0628d-1afd-4d05-8183-3d2541882900"
	
.PARAMETER ForceOnlineUpdate
	This is a switch that will force the computer to check online for Windows Updates

.EXAMPLE
    
    .\Start-WindowsUpdateDeploymentByVMName.ps1
#>
Workflow Start-WindowsUpdateDeploymentByVMName
{
    [CmdletBinding()]
    param
    (
        # Provide Target Virtual Machine(s) name(s)
        # Example:
        # For a single VM use a simple string: VM-01
        # For multiple VM use a JSON format string: ['VM-01','VM-02','VM-03']
        [parameter(Mandatory=$true,HelpMessage="'Example: ['VM-01','VM-02','VM-03']'")]
        [String[]]$VirtualMachineNames,

        # Specify if you want to restart the Virtual Machine upon Windows Update installation completion
	    # Example: AutoReboot or IgnoreReboot
        [parameter(Mandatory=$true,HelpMessage='Example:')]
        [ValidateSet('IgnoreReboot','AutoReboot')]
        [String]$RestartOption,

        # Provide Target Subscription ID
        # Example: "14a0628d-1afd-4d05-8183-3d2541882900"
        [parameter(Mandatory=$false,HelpMessage='Example: 14a0628d-1afd-4d05-8183-3d2541882900')]
        [String]$SubscriptionId,

        # This is a switch that will force the computer to check online for Windows Updates
        [Switch]$ForceOnlineUpdate
    )

    $ErrorActionPreference = 'Stop'
    $VerbosePreference = 'Continue'

    $FileUri = '[WindowsUpdateScriptsFolderURL]/Invoke-WindowsUpdate.ps1'
    $RunPath = './[WindowsUpdateScriptsFolderName]/Invoke-WindowsUpdate.ps1'

    $ResourceGroupName = '[ResourceGroupName]'
    $StorageAccountName = '[StorageAccountName]'
    $WindowsUpdateScriptsFolderName = '[WindowsUpdateScriptsFolderName]'

    $ScriptName = ($FileUri.Split('/') | Select-Object -Last 1)
    $ContainerName = ($FileUri.Split('/'))[3]

    try
    {
        # Pull Azure environment settings
        $AzureEnvironmentSettings = Get-AzureRmEnvironment -Name '[Environment]'

        # Azure management uri
        $ResourceAppIdURI = $AzureEnvironmentSettings.ActiveDirectoryServiceEndpointResourceId

        # Login uri for Azure AD
        $LoginURI = $AzureEnvironmentSettings.ActiveDirectoryAuthority

        # Get RunAsConnection
        $RunAsConnection = Get-AutomationConnection -Name "AzureRunAsConnection"

        # Get RunAsCertificate
        $Certifcate = Get-AutomationCertificate -Name "AzureRunAsCertificate"

        Add-AzureRmAccount -ServicePrincipal `
        -TenantId $RunAsConnection.TenantId `
        -ApplicationId $RunAsConnection.ApplicationId `
        -CertificateThumbprint $RunAsConnection.CertificateThumbprint `
        -EnvironmentName '[Environment]' -Verbose

        # Get Subscription Id if not provided
        if (!$SubscriptionId)
        {
            $SubscriptionId = $RunAsConnection.SubscriptionId
        }

        # Set up authentication using service principal client certificate
        $Authority = $LoginURI + $RunAsConnection.TenantId
        $AuthContext = [Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext]::new($Authority, $false)
        $ClientCertificate = [Microsoft.IdentityModel.Clients.ActiveDirectory.ClientAssertionCertificate]::new($RunAsConnection.ApplicationId, $Certifcate)
        $AuthResult = $AuthContext.AcquireToken($ResourceAppIdURI, $ClientCertificate)

        # Set up header with authorization token
        $AuthToken = $AuthResult.CreateAuthorizationHeader()
        $RequestHeader = @{
          "Content-Type" = "application/json";
          "Authorization" = "$AuthToken"
        }

        $DownloadLink = InlineScript {
            $StorageAccount = Get-AzureRmStorageAccount -ResourceGroupName $Using:ResourceGroupName -Name $Using:StorageAccountName -ErrorAction Stop
            $StartTime = Get-Date
            $EndTime = $startTime.AddHours(2.0)
            $DownloadLink = New-AzureStorageBlobSASToken -Context $StorageAccount.Context -Container "$Using:ContainerName/$Using:WindowsUpdateScriptsFolderName" -Blob $Using:ScriptName -Permission r -FullUri -StartTime $StartTime -ExpiryTime $EndTime -ErrorAction Stop
            return $DownloadLink
        }

        $TargetVirtualMachines = @()
        foreach ($VirtualMachineName in $VirtualMachineNames)
        {
           $AzureVMResource = (Get-AzureRmResource | Where-Object {($_.ResourceType -eq 'Microsoft.Compute/virtualMachines') -and ($_.Name -eq $VirtualMachineName)})
           $TargetVirtualMachines += $AzureVMResource
        }

        foreach -parallel ($TargetVirtualMachine in $TargetVirtualMachines)
        {
            Write-Output "Checking if $($TargetVirtualMachine.Name) is powered on"
            $PoweredOnAzureRMVirtualMachine = (Get-AzureRMVM -Name $($TargetVirtualMachine.Name) -ResourceGroupName $($TargetVirtualMachine.ResourceGroupName) -Status | Where-Object {$_.Statuses.DisplayStatus -contains "VM running"})
            if ($PoweredOnAzureRMVirtualMachine)
            {
                Write-Output "Checking for old Custom script extensions"

                $CustomScriptExtension = $PoweredOnAzureRMVirtualMachine.Extensions | Where-Object {$_.Type -eq 'Microsoft.Compute.CustomScriptExtension'}
                # If a Custom Script Extension is found, remove it
                if ($CustomScriptExtension)
                {
                    try
                    {
                        Write-Output "Please wait while old deployment jobs are removed. This may take some time..."
                        Write-Output "Removing old Custom Script Extension from $($PoweredOnAzureRMVirtualMachine.Name)"

                        # Remove the discovered Custom Script Extension
                        Remove-AzureRmVMCustomScriptExtension -ResourceGroupName $($PoweredOnAzureRMVirtualMachine.ResourceGroupName) -VMName $($PoweredOnAzureRMVirtualMachine.Name) -Name $CustomScriptExtension.Name -Force -Verbose
                        Write-Output "Custom Script Extension was removed from $($PoweredOnAzureRMVirtualMachine.Name)"
                    }
                    catch
                    {
                        Write-Output "Failed to remove Custom Script Extensions"
                        Write-Output $Error[0].Exception
                    }
                }

                Write-Output "Preparing to deploy new Custom Script Extensions to $($PoweredOnAzureRMVirtualMachine.Name)"

                # Create the RestAPI Uri
                $RestURI = "[ResourceManagerUrl]subscriptions/$SubscriptionID/resourceGroups/$($PoweredOnAzureRMVirtualMachine.ResourceGroupName)/providers/Microsoft.Compute/virtualMachines/$($PoweredOnAzureRMVirtualMachine.Name)/extensions/CustomScriptExtension?api-version=2018-10-01"

                # Create the JSON Body
                if (!($ForceOnlineUpdate))
                {
                    $Body = @"
                    {
                        "type": "Microsoft.Compute/virtualMachines/extensions",
                        "name": "CustomScriptExtension",
                        "location": "$($TargetVirtualMachine.Location)",
                        "tags": {
                            "displayName": "CustomScriptExtension"
                        },
                        "properties": {
                            "publisher": "Microsoft.Compute",
                            "type": "CustomScriptExtension",
                            "typeHandlerVersion": "1.9",
                            "autoUpgradeMinorVersion": true,
                            "settings": {
                                "fileUris": [
                                    "$DownloadLink"
                                ]
                            },
                            "protectedSettings": {
                                "commandToExecute": "powershell -ExecutionPolicy Unrestricted -file $RunPath -RestartOption $RestartOption"
                            }
                        }
                    }
"@
                }
                if ($ForceOnlineUpdate)
                {
                    $Body = @"
                    {
                        "type": "Microsoft.Compute/virtualMachines/extensions",
                        "name": "CustomScriptExtension",
                        "location": "$($TargetVirtualMachine.Location)",
                        "tags": {
                            "displayName": "CustomScriptExtension"
                        },
                        "properties": {
                            "publisher": "Microsoft.Compute",
                            "type": "CustomScriptExtension",
                            "typeHandlerVersion": "1.9",
                            "autoUpgradeMinorVersion": true,
                            "settings": {
                                "fileUris": [
                                    "$DownloadLink"
                                ]
                            },
                            "protectedSettings": {
                                "commandToExecute": "powershell -ExecutionPolicy Unrestricted -file $RunPath -RestartOption $RestartOption -ForceOnlineUpdate"
                            }
                        }
                    }
"@
                }

                # Send the URI, Body and Authtoken using Invoke-RestMethod
                Write-Output "Deploying Script Extension to $($PoweredOnAzureRMVirtualMachine.Name)"
                $Result = Invoke-RestMethod -Uri $RestURI -Method Put -body $Body -Headers $RequestHeader -ErrorAction Stop
                Write-Output $Result
            }
        }

    }
    catch
    {
        throw $_
    }
}
'@
Add-Content -Path $RunbookFilePath -Value $RunbookFileContent
(Get-Content $RunbookFilePath.FullName).replace('[WindowsUpdateScriptsFolderURL]', $WindowsUpdateScriptsFolderURL) | Set-Content $RunbookFilePath.FullName
(Get-Content $RunbookFilePath.FullName).replace('[WindowsUpdateScriptsFolderName]', $WindowsUpdateScriptsFolderName) | Set-Content $RunbookFilePath.FullName
(Get-Content $RunbookFilePath.FullName).replace('[ResourceGroupName]', $ResourceGroupName) | Set-Content $RunbookFilePath.FullName
(Get-Content $RunbookFilePath.FullName).replace('[StorageAccountName]', $StorageAccountName) | Set-Content $RunbookFilePath.FullName
(Get-Content $RunbookFilePath.FullName).replace('[Environment]', $($Environment.Name)) | Set-Content $RunbookFilePath.FullName
(Get-Content $RunbookFilePath.FullName).replace('[ResourceManagerUrl]', $ResourceManagerUrl) | Set-Content $RunbookFilePath.FullName
try
{
    Write-Output "Importing Runbook $($RunbookFilePath.BaseName)"
    Import-AzureRmAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Path $RunbookFilePath.FullName -Type $RunbookType -Verbose -ErrorAction 'Stop'
    Publish-AzureRmAutomationRunbook -Name $($RunbookFilePath.BaseName) -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Verbose -ErrorAction 'Stop'
}
catch 
{
    Write-Warning $_
    break
}
#endregion

#region Add Start-DeallocatedVMsBasedOnTags Runbook and set an hourly schedule
$RunbookType = 'PowerShellWorkflow'
$RunbookFilePath = New-Item -Path "$env:TEMP\Start-DeallocatedVMsBasedOnTags.ps1" -ItemType File -Force
$RunbookFileContent = @'
<#
.SYNOPSIS
    Power On all deallocated VMs based on tags

.DESCRIPTION
    This script will look for StartUpDays and StartUpTime tags on ResourceGroups & Virtual Machines.
    If the StartUpDays matches the current Day of the week and the StartUpTime is less than or equal to the current time, the VM will be powered on.

.EXAMPLE
  StartUpDays = Monday,Tuesday,Wednesday,Thursday,Friday,Saturday,Sunday , Days you want to shutdown the VMs.
  StartUpTime = 18:00 , Time to shutdown the Azure VM in UTC 24hour format.
  OverrideStartUp = True , Disables automated power on

#>
Workflow Start-DeallocatedVMsBasedOnTags
{
    [CmdletBinding()]
    param
    (
    )

    $ErrorActionPreference = 'Stop'
   
    try
    {
        # Get RunAsConnection
        $RunAsConnection = Get-AutomationConnection -Name "AzureRunAsConnection"

        Add-AzureRmAccount -ServicePrincipal `
        -TenantId $RunAsConnection.TenantId `
        -ApplicationId $RunAsConnection.ApplicationId `
        -CertificateThumbprint $RunAsConnection.CertificateThumbprint `
        -EnvironmentName '[Environment]' -Verbose

        # Get Subscription Id if not provided
        if (!$SubscriptionId)
        {
            $SubscriptionId = $RunAsConnection.SubscriptionId
        }
    }
    catch
    {
        if (!$RunAsConnection)
        {
            $ErrorMessage = "Connection $ConnectionName not found."
            throw $ErrorMessage
        }
        else
        {
            Write-Error -Message $_.Exception
            throw $_.Exception
        }
    }

    # Get Day & Time
    $TimeOfDay = Get-Date -UFormat %R
    $DayOfWeek = (Get-Date).DayOfWeek

    Write-Output "Today is $DayOfWeek and the time is $TimeOfDay"
    
    # Get All Azure Resource Groups
    $AzureRMResourceGroups = Get-AzureRmResourceGroup
    foreach -parallel ($AzureRMResourceGroup in $AzureRMResourceGroups)
    {
        # Get Resource Group Startup Times
        $ResourceGroupStartUpDays = $AzureRMResourceGroup.Tags.StartUpDays
        $ResourceGroupStartUpTime = $AzureRMResourceGroup.Tags.StartUpTime

        If ($ResourceGroupStartUpDays)
        {
            Write-Output "VMs in $($AzureRMResourceGroup.ResourceGroupName) are scheduled to be powered on $ResourceGroupStartUpDays at $ResourceGroupStartUpTime"
            Write-Output "Checking for VM Schedules"
        }

        # Get all VMs in that are Powered off
        $AzureRMVirtualMachines = Get-AzureRMVM -ResourceGroupName $AzureRMResourceGroup.ResourceGroupName -Status | Where-Object {$_.PowerState -eq "VM deallocated"}
        if (!($AzureRMVirtualMachines))
        {
            Write-Output "Resource Group $($AzureRMResourceGroup.ResourceGroupName) does not contain any deallocated VMs."
        }
        else
        {
            # Check each VM for schedules and perform power on
            foreach -parallel ($AzureRMVirtualMachine in $AzureRMVirtualMachines)
            {
                if (($AzureRMVirtualMachine.Tags.keys -contains 'OverrideStartUp') -and ($AzureRMVirtualMachine.Tags.OverrideStartUp -eq 'True'))
                {
                    Write-Output "The VM $($AzureRMVirtualMachine.Name) has a Startup Override. No action will be taken."
                }
                if (($AzureRMVirtualMachine.Tags.keys -contains 'StartUpDays') -and ($AzureRMVirtualMachine.Tags.keys -contains 'StartUpTime'))
                {
                    Write-Output "The VM $($AzureRMVirtualMachine.Name) is scheduled to be started on $($AzureRMVirtualMachine.Tags.StartupDays) at $($AzureRMVirtualMachine.Tags.StartupTime)"
                    if (($AzureRMVirtualMachine.Tags.StartUpDays -like "*$DayOfWeek*") -and ($AzureRMVirtualMachine.Tags.StartUpTime -le $TimeOfDay) -and ($AzureRMVirtualMachine.Tags.OverrideStartUp -ne 'True'))
                    {
                        Write-Output "Powering on $($AzureRMVirtualMachine.Name) based on VM Schedule"
                        Start-AzureRmVM -Name $AzureRMVirtualMachine.Name -ResourceGroupName $AzureRMResourceGroup.ResourceGroupName
                    }
                }
                if (($AzureRMResourceGroup.Tags.StartUpDays -like "*$DayOfWeek*") -and ($AzureRMResourceGroup.Tags.StartUpTime -le $TimeOfDay) -and ($AzureRMVirtualMachine.Tags.OverrideStartUp -ne 'True'))
                {
                    Write-Output "No VM Schedule Tags were found for $($AzureRMVirtualMachine.Name). Using ResourceGroup Power on Settings. $ResourceGroupStartUpDays at $ResourceGroupStartUpTime"
                    Write-Output "Powering on $($AzureRMVirtualMachine.Name) based on ResourceGroup Schedule"
                    Start-AzureRmVM -Name $AzureRMVirtualMachine.Name -ResourceGroupName $AzureRMResourceGroup.ResourceGroupName
                }
            }
        }
    }
}
'@
Add-Content -Path $RunbookFilePath -Value $RunbookFileContent
(Get-Content $RunbookFilePath.FullName).replace('[Environment]', $($Environment.Name)) | Set-Content $RunbookFilePath.FullName
try
{
    Write-Output "Importing Runbook $($RunbookFilePath.BaseName)"
    Import-AzureRmAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Path $RunbookFilePath.FullName -Type $RunbookType -Verbose -ErrorAction 'Stop'
    Publish-AzureRmAutomationRunbook -Name $($RunbookFilePath.BaseName) -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Verbose -ErrorAction 'Stop'
    Register-AzureRmAutomationScheduledRunbook -RunbookName $($RunbookFilePath.BaseName) -ScheduleName $HourlyScheduleName -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Verbose -ErrorAction 'Stop'
}
catch 
{
    Write-Warning $_
    break
}
#endregion

#region Add Stop-RunningVMsBasedOnTags Runbook and set an hourly schedule
$RunbookType = 'PowerShellWorkflow'
$RunbookFilePath = New-Item -Path "$env:TEMP\Stop-RunningVMsBasedOnTags.ps1" -ItemType File -Force
$RunbookFileContent = @'
<#
.SYNOPSIS
    Stop all running VMs based on tags

.DESCRIPTION
    This script will look for ShutdownDays and ShutdownTime tags on ResourceGroups & Virtual Machines.
    If the ShutdownDays matches the current Day of the week and the ShutdownTime is less than or equal to the current time, the VM will be shutdown.

.EXAMPLE
  ShutdownDays = Monday,Tuesday,Wednesday,Thursday,Friday,Saturday,Sunday , Days you want to shutdown the VMs.
  ShutdownTime = 18:00 , Time to shutdown the Azure VM in UTC 24hour format.
  OverrideShutdown = True , Disables automated shutdown

#>
Workflow Stop-RunningVMsBasedOnTags
{
    [CmdletBinding()]
    param
    (
    )

    $ConnectionName = "AzureRunAsConnection"

    try
    {
        # Get the connection "AzureRunAsConnection "
        $servicePrincipalConnection = Get-AutomationConnection -Name $ConnectionName         

        "Logging in to Azure..."
        Add-AzureRmAccount `
            -ServicePrincipal `
            -TenantId $servicePrincipalConnection.TenantId `
            -ApplicationId $servicePrincipalConnection.ApplicationId `
            -CertificateThumbprint $servicePrincipalConnection.CertificateThumbprint `
            -EnvironmentName '[Environment]' -Verbose
    }
    catch
    {
        if (!$servicePrincipalConnection)
        {
            $ErrorMessage = "Connection $ConnectionName not found."
            throw $ErrorMessage
        }
        else
        {
            Write-Error -Message $_.Exception
            throw $_.Exception
        }
    }

    # Get Day & Time
    $TimeOfDay = Get-Date -UFormat %R
    $DayOfWeek = (Get-Date).DayOfWeek

    Write-Output "Today is $DayOfWeek and the time is $TimeOfDay"
    
    # Get All Azure Resource Groups
    $AzureRMResourceGroups = Get-AzureRmResourceGroup
    foreach -parallel ($AzureRMResourceGroup in $AzureRMResourceGroups)
    {
        # Get Resource Group Shutdown Times
        $ResourceGroupShutdownDays = $AzureRMResourceGroup.Tags.ShutdownDays
        $ResourceGroupShutdownTime = $AzureRMResourceGroup.Tags.ShutdownTime

        If ($ResourceGroupShutdownDays)
        {
            Write-Output "VMs in $($AzureRMResourceGroup.ResourceGroupName) are scheduled to be shutdown on $ResourceGroupShutdownDays at $ResourceGroupShutdownTime"
            Write-Output "Checking for VM Schedules"
        }

        # Get all VMs in that are Powered On
        $AzureRMVirtualMachines = Get-AzureRMVM -ResourceGroupName $AzureRMResourceGroup.ResourceGroupName -Status | Where-Object {$_.PowerState -eq "VM running"}
        if (!($AzureRMVirtualMachines))
        {
            Write-Output "Resource Group $($AzureRMResourceGroup.ResourceGroupName) does not contain any running VMs."
        }
        else
        {
            # Check each VM for schedules and perform shutdowns
            foreach -parallel ($AzureRMVirtualMachine in $AzureRMVirtualMachines)
            {
                if (($AzureRMVirtualMachine.Tags.keys -contains 'OverrideShutdown') -and ($AzureRMVirtualMachine.Tags.OverrideShutdown -eq 'True'))
                {
                    Write-Output "The VM $($AzureRMVirtualMachine.Name) has a Shutdown Override. No action will be taken."
                }
                if (($AzureRMVirtualMachine.Tags.keys -contains 'ShutdownDays') -and ($AzureRMVirtualMachine.Tags.keys -contains 'ShutdownTime'))
                {
                    Write-Output "The VM $($AzureRMVirtualMachine.Name) is scheduled to be shutdown on $($AzureRMVirtualMachine.Tags.ShutdownDays) at $($AzureRMVirtualMachine.Tags.ShutdownTime)"
                    if (($AzureRMVirtualMachine.Tags.ShutdownDays -like "*$DayOfWeek*") -and ($AzureRMVirtualMachine.Tags.ShutdownTime -le $TimeOfDay) -and ($AzureRMVirtualMachine.Tags.OverrideShutdown -ne 'True'))
                    {
                        Write-Output "Shutting down $($AzureRMVirtualMachine.Name) based on VM Schedule"
                        Stop-AzureRMVM -Name $AzureRMVirtualMachine.Name -ResourceGroupName $AzureRMResourceGroup.ResourceGroupName -Force
                    }
                }
                if (($AzureRMResourceGroup.Tags.ShutdownDays -like "*$DayOfWeek*") -and ($AzureRMResourceGroup.Tags.ShutdownTime -le $TimeOfDay) -and ($AzureRMVirtualMachine.Tags.OverrideShutdown -ne 'True'))
                {
                    Write-Output "No VM Schedule Tags were found for $($AzureRMVirtualMachine.Name). Using ResourceGroup Shutdown Settings shutdown on $ResourceGroupShutdownDays at $ResourceGroupShutdownTime"
                    Write-Output "Shutting down $($AzureRMVirtualMachine.Name) based on RG Schedule"
                    Stop-AzureRMVM -Name $AzureRMVirtualMachine.Name -ResourceGroupName $AzureRMResourceGroup.ResourceGroupName -Force
                }
            }
        }
    }
}
'@
Add-Content -Path $RunbookFilePath -Value $RunbookFileContent
(Get-Content $RunbookFilePath.FullName).replace('[Environment]', $($Environment.Name)) | Set-Content $RunbookFilePath.FullName
try
{
    Write-Output "Importing Runbook $($RunbookFilePath.BaseName)"
    Import-AzureRmAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Path $RunbookFilePath.FullName -Type $RunbookType -Verbose -ErrorAction 'Stop'
    Publish-AzureRmAutomationRunbook -Name $($RunbookFilePath.BaseName) -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Verbose -ErrorAction 'Stop'
    Register-AzureRmAutomationScheduledRunbook -RunbookName $($RunbookFilePath.BaseName) -ScheduleName $HourlyScheduleName -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Verbose -ErrorAction 'Stop'
}
catch 
{
    Write-Warning $_
    break
}
#endregion

#region Add Get-AzureOrphanedObjects Runbook
$RunbookType = 'PowerShell'
$RunbookFilePath = New-Item -Path "$env:TEMP\Get-AzureOrphanedObjects.ps1" -ItemType File -Force
$RunbookFileContent = @'
<#
.SYNOPSIS
    Script to find Azure Resources that are not in use

.DESCRIPTION
    This script will search your Azure Subscription to find Resources that are not in use.
    It will look for:
        Virtual Machines That Are Powered Off
        Network Security Groups That Are Not In Use
        Network Interfaces That Are Not In Use
        Public IP Addresses That Are Not In Use
        Disks That Are Not Attached To A VM
    At the completion of the script, a download link will be displayed in the output.
    The link is good for 2 hours after the script completes.

.PARAMETER SubscriptionID
    Provide Target Subscription ID
    Example: "aed90f7c-19ff-4b65-a0fb-c0186d3a7265"

.EXAMPLE
    .\Get-AzureOrphanedObjects.ps1 -SubscriptionID 'aed90f7c-19ff-4b65-a0fb-c0186d3a7265'
#>
[CmdletBinding()]
param
(                
    # Provide Target Subscription ID
    # Example: "aed90f7c-19ff-4b65-a0fb-c0186d3a7265"
    [parameter(Mandatory=$false,HelpMessage='Example: aed90f7c-19ff-4b65-a0fb-c0186d3a7265')]
    [String]$SubscriptionID
)

# Set Error Action and Verbose Preference
$VerbosePreference = 'Continue'
$ErrorActionPreference = 'Stop'

# Set Script Variables
$ResourceGroupName = '[ResourceGroupName]'
$StorageAccountName = '[StorageAccountName]'
$OrphanedObjectReportsFolderName = '[OrphanedObjectReportsFolderName]'
$SubscriptionReportsContainerName = '[SubscriptionReportsContainerName]'

try
{
    # Get RunAsConnection
    $RunAsConnection = Get-AutomationConnection -Name "AzureRunAsConnection"

    Add-AzureRmAccount -ServicePrincipal `
    -TenantId $RunAsConnection.TenantId `
    -ApplicationId $RunAsConnection.ApplicationId `
    -CertificateThumbprint $RunAsConnection.CertificateThumbprint `
    -EnvironmentName '[Environment]' -Verbose

    # Get Subscription Id if not provided
    if (!$SubscriptionId)
    {
        $SubscriptionId = $RunAsConnection.SubscriptionId
    }
}
catch
{
    if (!$RunAsConnection)
    {
        $ErrorMessage = "Connection $ConnectionName not found."
        throw $ErrorMessage
    }
    else
    {
        Write-Error -Message $_.Exception
        throw $_.Exception
    }
}

$Subscription = Get-AzureRmSubscription -SubscriptionId $SubscriptionId
Set-AzureRmContext -SubscriptionObject $Subscription  | Out-Null

# Set Counter For Orphaned Objects
[Int]$OrphanedObjectsCount = '0'

# Create Data Table Structure
Write-Verbose 'Creating DataTable Structure'
$DataTable = New-Object System.Data.DataTable
$DataTable.Columns.Add("ResourceType","string") | Out-Null
$DataTable.Columns.Add("ResourceGroupName","string") | Out-Null
$DataTable.Columns.Add("ResourceName","string") | Out-Null
$DataTable.Columns.Add("CreationTime","DateTime") | Out-Null
$DataTable.Columns.Add("VMSize","string") | Out-Null
$DataTable.Columns.Add("VMOperatingSystem","string") | Out-Null
$DataTable.Columns.Add("Subscription","string") | Out-Null

Write-Verbose "Checking Subscription $($Subscription.Name)"

# Get Azure RM Disks That Are Not Managed
Write-Verbose 'Getting Azure RM Disks That Are Not Attached To A VM. Please Wait..'
$AzureRMDisks = Get-AzureRmDisk | Where-Object {$_.ManagedBy -eq $null}
if ($AzureRMDisks.Count -ge '1')
{
    Write-Verbose "I Have Found $($AzureRMDisks.Count) Disks That Are Not Managed."
    foreach ($AzureRMDisk in $AzureRMDisks)
    {
        $NewRow = $DataTable.NewRow() 
        $NewRow.ResourceType = $($AzureRMDisk.Type)
        $NewRow.ResourceGroupName = $($AzureRMDisk.ResourceGroupName)
        $NewRow.ResourceName = $($AzureRMDisk.Name)
        $NewRow.CreationTime = $($AzureRMDisk.TimeCreated)
        $NewRow.Subscription = ($Subscription.Name)
        $DataTable.Rows.Add($NewRow)
        $OrphanedObjectsCount ++
    }
}
else
{
    Write-Verbose 'I Have Not Found Any Disks That Are Not Managed.'
}

# Get Azure RM Public IP Addresses That Are Not In Use
Write-Verbose 'Getting Azure RM Public IP Addresses That Are Not In Use. Please Wait..'
$AzureRMPublicIPAddresses = Get-AzureRmPublicIpAddress | Where-Object {$_.IpConfiguration -eq $null}
if ($AzureRMPublicIPAddresses.Count -ge '1')
{
    Write-Verbose "I Have Found $($AzureRMPublicIPAddresses.Count) Public IP Addresses That Are Not In Use."
    foreach ($AzureRMPublicIPAddress in $AzureRMPublicIPAddresses)
    {
        $NewRow = $DataTable.NewRow() 
        $NewRow.ResourceType = $($AzureRMPublicIPAddress.Type)
        $NewRow.ResourceGroupName = $($AzureRMPublicIPAddress.ResourceGroupName)
        $NewRow.ResourceName = $($AzureRMPublicIPAddress.Name)
        $NewRow.Subscription = ($Subscription.Name)
        $DataTable.Rows.Add($NewRow)
        $OrphanedObjectsCount ++
    }
    
}
else
{
    Write-Verbose 'I Have Not Found Any Unused Public IP Addresses'
}

# Get Azure RM Network Interfaces That Are Not In Use
Write-Verbose 'Getting Azure RM Network Interfaces That Are Not In Use. Please Wait..'
$AzureRMNetworkInterfaces = Get-AzureRmNetworkInterface | Where-Object {$_.VirtualMachine -eq $null}
if ($AzureRMNetworkInterfaces.Count -ge '1')
{
    Write-Verbose "I Have Found $($AzureRMNetworkInterfaces.Count) Network Interfaces That Are Not In Use."
    foreach ($AzureRMNetworkInterface in $AzureRMNetworkInterfaces)
    {
        $NewRow = $DataTable.NewRow() 
        $NewRow.ResourceType = $($AzureRMNetworkInterface.Type)
        $NewRow.ResourceGroupName = $($AzureRMNetworkInterface.ResourceGroupName)
        $NewRow.ResourceName = $($AzureRMNetworkInterface.Name)
        $NewRow.Subscription = ($Subscription.Name)
        $DataTable.Rows.Add($NewRow)
        $OrphanedObjectsCount ++
    }
}
else
{
    Write-Verbose 'I Have Not Found Any Unused Network Interfaces'
}

# Get Azure RM Network Security Groups That Are Not In Use
Write-Verbose 'Getting Azure RM Network Security Groups That Are Not In Use. Please Wait..'
$AzureRMNetworkSecurityGroups = Get-AzureRmNetworkSecurityGroup | Where-Object {$_.subnets.id -eq $null -and $_.networkinterfaces.id -eq $null}
if ($AzureRMNetworkSecurityGroups.Count -ge '1')
{
    Write-Verbose "I Have Found $($AzureRMNetworkSecurityGroups.Count) Network Security Groups That Are Not In Use."
    foreach ($AzureRMNetworkSecurityGroup in $AzureRMNetworkSecurityGroups)
    {
        $NewRow = $DataTable.NewRow()
        $NewRow.ResourceType = $($AzureRMNetworkSecurityGroup.Type)
        $NewRow.ResourceGroupName = $($AzureRMNetworkSecurityGroup.ResourceGroupName)
        $NewRow.ResourceName = $($AzureRMNetworkSecurityGroup.Name)
        $NewRow.Subscription = ($Subscription.Name)
        $DataTable.Rows.Add($NewRow)
        $OrphanedObjectsCount ++
    }
}
else
{
    Write-Verbose 'I Have Not Found Any Unused Network Security Groups.'
}

# Get Azure RM Virtual Machines That Are Powered Off
Write-Verbose 'Getting Azure RM Virtual Machines That Are Powered Off. Please Wait..'
$AzureRMVirtualMachines = Get-AzureRmVM -Status | Where-Object {$_.PowerState -eq "VM deallocated"}
if ($AzureRMVirtualMachines.Count -ge '1')
{
    Write-Verbose "I Have Found $($AzureRMVirtualMachines.Count) Virtual Machines That Are Powered Off." 
    foreach ($AzureRMVirtualMachine in $AzureRMVirtualMachines)
    {
        Write-Verbose "Getting Virtual Machine Information for $($AzureRMVirtualMachine.Name)"
        $AzureRMVMInfo = Get-AzureRmVM -Name $AzureRMVirtualMachine.Name -ResourceGroupName $AzureRMVirtualMachine.ResourceGroupName -DisplayHint Expand
        
        $NewRow = $DataTable.NewRow() 
        $NewRow.ResourceType = $($AzureRMVMInfo.Type)
        $NewRow.ResourceGroupName = $($AzureRMVirtualMachine.ResourceGroupName)
        $NewRow.ResourceName = $($AzureRMVirtualMachine.Name)

        Write-Verbose "Getting Operating System Disk Creation Date Information for $($AzureRMVirtualMachine.Name)"
        $NewRow.CreationTime = (Get-AzureRmDisk -DiskName $($AzureRMVMInfo.StorageProfile.OsDisk.Name) -ResourceGroupName $AzureRMVirtualMachine.ResourceGroupName).TimeCreated
        $NewRow.VMSize = $($AzureRMVMInfo.HardwareProfile.VmSize)
        $NewRow.VMOperatingSystem = $($AzureRMVMInfo.StorageProfile.ImageReference.Sku)
        $NewRow.Subscription = ($Subscription.Name)
        $DataTable.Rows.Add($NewRow)
        $OrphanedObjectsCount ++
    }
}
else
{
    Write-Verbose 'I Have Not Found Any Virtual Machines That Are Powered Off.'
}

if ($OrphanedObjectsCount -ge '1')
{
    Write-Output "I have Found $OrphanedObjectsCount Orphaned Objects."
    # Export the results to CSV file
    $CSVFileName = 'AzureRMOrphanedObjectsReport ' + $(Get-Date -f yyyy-MM-dd) + '.csv'
    $DataTable | Export-Csv "$ENV:Temp\$CSVFileName" -NoTypeInformation -Force

    Write-Verbose "Turning off Storage Account Firewall Temporarily"
    Update-AzureRmStorageAccountNetworkRuleSet -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -DefaultAction Allow -Verbose -ErrorAction 'Stop' | Out-Null

    # Copy File to Azure Storage
    Write-Verbose "Uploading Report to $SubscriptionReportsContainerName\$OrphanedObjectReportsFolderName"
    $StorageAccount = Get-AzureRmStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ErrorAction Stop
    $Containers = Get-AzureStorageContainer -Context $StorageAccount.Context
    if ($SubscriptionReportsContainerName -notin $Containers.Name)
    {
        New-AzureRmStorageContainer -Name $SubscriptionReportsContainerName -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName
    }

    Set-AzureStorageBlobContent -BlobType 'Block' -File "$ENV:Temp\$CSVFileName" -Container $SubscriptionReportsContainerName -Blob "$OrphanedObjectReportsFolderName\$CSVFileName" -Context $StorageAccount.Context -Force | Out-Null
    Write-Verbose "Turning on Storage Account Firewall"
    Update-AzureRmStorageAccountNetworkRuleSet -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -DefaultAction Deny  -WarningAction 'SilentlyContinue' -Verbose -ErrorAction 'Stop' | Out-Null

    # Make file available for download
    Write-Verbose "Generating Download Link"
    $StartTime = Get-Date
    $EndTime = $startTime.AddHours(2.0)
    $DownloadLink = New-AzureStorageBlobSASToken -Context $StorageAccount.Context -Container "$SubscriptionReportsContainerName/$OrphanedObjectReportsFolderName" -Blob $CSVFileName -Permission r -FullUri -StartTime $StartTime -ExpiryTime $EndTime -ErrorAction Stop

    Write-Output "Orphaned Objects Report can be downloaded until $EndTime from the link below."
    Write-Output "$DownloadLink"
}

if ($OrphanedObjectsCount -eq '0')
{
    Write-Output "I Have Found No Orphaned Objects In Your Azure Subscription!"
    Write-Output "You Have Done A Fantastic Job Keeping This Subscription Clean. Keep Up The Good Work!"
}

Write-Verbose 'Script processing complete.'
'@
Add-Content -Path $RunbookFilePath -Value $RunbookFileContent
(Get-Content $RunbookFilePath.FullName).replace('[Environment]', $($Environment.Name)) | Set-Content $RunbookFilePath.FullName
(Get-Content $RunbookFilePath.FullName).replace('[ResourceGroupName]', $ResourceGroupName) | Set-Content $RunbookFilePath.FullName
(Get-Content $RunbookFilePath.FullName).replace('[StorageAccountName]', $StorageAccountName) | Set-Content $RunbookFilePath.FullName
(Get-Content $RunbookFilePath.FullName).replace('[OrphanedObjectReportsFolderName]', $OrphanedObjectReportsFolderName) | Set-Content $RunbookFilePath.FullName
(Get-Content $RunbookFilePath.FullName).replace('[SubscriptionReportsContainerName]', $SubscriptionReportsContainerName) | Set-Content $RunbookFilePath.FullName
try
{
    Write-Output "Importing Runbook $($RunbookFilePath.BaseName)"
    Import-AzureRmAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Path $RunbookFilePath.FullName -Type $RunbookType -Verbose -ErrorAction 'Stop'
    Publish-AzureRmAutomationRunbook -Name $($RunbookFilePath.BaseName) -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Verbose -ErrorAction 'Stop'
}
catch 
{
    Write-Warning $_
    break
}
#endregion

#region Add Update-AutomationAzureModulesForAccount Runbook
$RunbookType = 'PowerShell'
$RunbookFilePath = New-Item -Path "$env:TEMP\Update-AutomationAzureModulesForAccount.ps1" -ItemType File -Force
$RunbookFileContent = @'
<#
Copyright (c) Microsoft Corporation. All rights reserved.
Licensed under the MIT License.
#>

<#
.SYNOPSIS
Update Azure PowerShell modules in an Azure Automation account.

.DESCRIPTION
This Azure Automation runbook updates Azure PowerShell modules imported into an
Azure Automation account with the module versions published to the PowerShell Gallery.

Prerequisite: an Azure Automation account with an Azure Run As account credential.

.PARAMETER ResourceGroupName
The Azure resource group name.

.PARAMETER AutomationAccountName
The Azure Automation account name.

.PARAMETER SimultaneousModuleImportJobCount
(Optional) The maximum number of module import jobs allowed to run concurrently.

.PARAMETER AzureEnvironment
(Optional) Azure environment name.

.PARAMETER Login
(Optional) If $false, do not login to Azure.

.PARAMETER ModuleVersionOverrides
(Optional) Module versions to use instead of the latest on the PowerShell Gallery.
If $null, the currently published latest versions will be used.
If not $null, must contain a JSON-serialized dictionary, for example:
    '{ "AzureRM.Compute": "5.8.0", "AzureRM.Network": "6.10.0" }'
or
    @{ 'AzureRM.Compute'='5.8.0'; 'AzureRM.Network'='6.10.0' } | ConvertTo-Json

.PARAMETER PsGalleryApiUrl
(Optional) PowerShell Gallery API URL.

.LINK
https://docs.microsoft.com/en-us/azure/automation/automation-update-azure-modules
#>

[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseApprovedVerbs", "")]
param
(
    [Parameter(Mandatory = $false)]
    [string] $ResourceGroupName = '[ResourceGroupName]',

    [Parameter(Mandatory = $false)]
    [string] $AutomationAccountName = '[AutomationAccountName]',

    [Parameter(Mandatory = $false)]
    [int] $SimultaneousModuleImportJobCount = 10,

    [Parameter(Mandatory = $false)]
    [string] $AzureEnvironment = '[Environment]',

    [Parameter(Mandatory = $false)]
    [bool] $Login = $true,
    
    [Parameter(Mandatory = $false)]
    [string] $ModuleVersionOverrides = $null,
    
    [Parameter(Mandatory = $false)]
    [string] $PsGalleryApiUrl = 'https://www.powershellgallery.com/api/v2'
)

$ErrorActionPreference = "Continue"

#region Constants

$script:AzureRMProfileModuleName = "AzureRM.Profile"
$script:AzureRMAutomationModuleName = "AzureRM.Automation"
$script:AzureSdkOwnerName = "azure-sdk"

#endregion

#region Functions

function ConvertJsonDictTo-HashTable($JsonString) {
    try{
        $JsonObj = ConvertFrom-Json $JsonString -ErrorAction Stop
    } catch [System.ArgumentException] {
        throw "Unable to deserialize the JSON string for parameter ModuleVersionOverrides: ", $_
    }

    $Result = @{}
    foreach ($Property in $JsonObj.PSObject.Properties) {
        $Result[$Property.Name] = $Property.Value
    }

    $Result
}

# Use the Run As connection to login to Azure
function Login-AzureAutomation {
    try {
        $RunAsConnection = Get-AutomationConnection -Name "AzureRunAsConnection"
        Write-Output "Logging in to Azure ($AzureEnvironment)..."
        Add-AzureRmAccount `
            -ServicePrincipal `
            -TenantId $RunAsConnection.TenantId `
            -ApplicationId $RunAsConnection.ApplicationId `
            -CertificateThumbprint $RunAsConnection.CertificateThumbprint `
            -Environment $AzureEnvironment

        Select-AzureRmSubscription -SubscriptionId $RunAsConnection.SubscriptionID  | Write-Verbose
    } catch {
        if (!$RunAsConnection) {
            Write-Output $servicePrincipalConnection
            Write-Output $_.Exception
            $ErrorMessage = "Connection $connectionName not found."
            throw $ErrorMessage
        }

        throw $_.Exception
    }
}

# Checks the PowerShell Gallery for the latest available version for the module
function Get-ModuleDependencyAndLatestVersion([string] $ModuleName) {

    $ModuleUrlFormat = "$PsGalleryApiUrl/Search()?`$filter={1}&searchTerm=%27{0}%27&targetFramework=%27%27&includePrerelease=false&`$skip=0&`$top=40"
        
    $ForcedModuleVersion = $ModuleVersionOverridesHashTable[$ModuleName]

    $CurrentModuleUrl =
        if ($ForcedModuleVersion) {
            $ModuleUrlFormat -f $ModuleName, "Version%20eq%20'$ForcedModuleVersion'"
        } else {
            $ModuleUrlFormat -f $ModuleName, 'IsLatestVersion'
        }

    $SearchResult = Invoke-RestMethod -Method Get -Uri $CurrentModuleUrl -UseBasicParsing

    if (!$SearchResult) {
        Write-Verbose "Could not find module $ModuleName on PowerShell Gallery. This may be a module you imported from a different location. Ignoring this module"
    } else {
        if ($SearchResult.Length -and $SearchResult.Length -gt 1) {
            $SearchResult = $SearchResult | Where-Object { $_.title.InnerText -eq $ModuleName }
        }

        if (!$SearchResult) {
            Write-Verbose "Could not find module $ModuleName on PowerShell Gallery. This may be a module you imported from a different location. Ignoring this module"
        } else {
            $PackageDetails = Invoke-RestMethod -Method Get -UseBasicParsing -Uri $SearchResult.id

            # Ignore the modules that are not published as part of the Azure SDK
            if ($PackageDetails.entry.properties.Owners -ne $script:AzureSdkOwnerName) {
                Write-Warning "Module : $ModuleName is not part of azure sdk. Ignoring this."
            } else {
                $ModuleVersion = $PackageDetails.entry.properties.version
                $Dependencies = $PackageDetails.entry.properties.dependencies

                @($ModuleVersion, $Dependencies)
            }
        }
    }
}

function Get-ModuleContentUrl($ModuleName) {
    $ModuleContentUrlFormat = "$PsGalleryApiUrl/package/{0}"
    $VersionedModuleContentUrlFormat = "$ModuleContentUrlFormat/{1}"

    $ForcedModuleVersion = $ModuleVersionOverridesHashTable[$ModuleName]
    if ($ForcedModuleVersion) {
        $VersionedModuleContentUrlFormat -f $ModuleName, $ForcedModuleVersion
    } else {
        $ModuleContentUrlFormat -f $ModuleName
    }
}

# Imports the module with given version into Azure Automation
function Import-AutomationModule([string] $ModuleName) {

    $LatestModuleVersionOnGallery = (Get-ModuleDependencyAndLatestVersion $ModuleName)[0]

    $ModuleContentUrl = Get-ModuleContentUrl $ModuleName
    # Find the actual blob storage location of the module
    do {
        $ModuleContentUrl = (Invoke-WebRequest -Uri $ModuleContentUrl -MaximumRedirection 0 -UseBasicParsing -ErrorAction Ignore).Headers.Location 
    } while (!$ModuleContentUrl.Contains(".nupkg"))

    $CurrentModule = Get-AzureRmAutomationModule `
                        -Name $ModuleName `
                        -ResourceGroupName $ResourceGroupName `
                        -AutomationAccountName $AutomationAccountName

    if ($CurrentModule.Version -eq $LatestModuleVersionOnGallery) {
        Write-Output "Module : $ModuleName is already present with version $LatestModuleVersionOnGallery. Skipping Import"
    } else {
        Write-Output "Importing $ModuleName module of version $LatestModuleVersionOnGallery to Automation"

        New-AzureRmAutomationModule `
            -ResourceGroupName $ResourceGroupName `
            -AutomationAccountName $AutomationAccountName `
            -Name $ModuleName `
            -ContentLink $ModuleContentUrl > $null
    }
}

# Parses the dependency got from PowerShell Gallery and returns name and version
function GetModuleNameAndVersionFromPowershellGalleryDependencyFormat([string] $Dependency) {
    if ($Dependency -eq $null) {
        throw "Improper dependency format"
    }

    $Tokens = $Dependency -split":"
    if ($Tokens.Count -ne 3) {
        throw "Improper dependency format"
    }

    $ModuleName = $Tokens[0]
    $ModuleVersion = $Tokens[1].Trim("[","]")

    @($ModuleName, $ModuleVersion)
}

# Validates if the given list of modules has already been added to the module import map
function AreAllModulesAdded([string[]] $ModuleListToAdd) {
    $Result = $true

    foreach ($ModuleToAdd in $ModuleListToAdd) {
        $ModuleAccounted = $false

        # $ModuleToAdd is specified in the following format:
        #       ModuleName:ModuleVersionSpecification:
        # where ModuleVersionSpecification follows the specifiation
        # at https://docs.microsoft.com/en-us/nuget/reference/package-versioning#version-ranges-and-wildcards
        # For example:
        #       AzureRm.profile:[4.0.0]:
        # or
        #       AzureRm.profile:3.0.0:
        # In any case, the dependency version specification is always separated from the module name with
        # the ':' character. The explicit intent of this runbook is to always install the latest module versions,
        # so we want to completely ignore version specifications here.
        $ModuleNameToAdd = $ModuleToAdd -replace '\:.*', ''
            
        foreach($AlreadyIncludedModules in $ModuleImportMapOrder) {
            if ($AlreadyIncludedModules -contains $ModuleNameToAdd) {
                $ModuleAccounted = $true
                break
            }
        }
        
        if (!$ModuleAccounted) {
            $Result = $false
            break
        }
    }

    $Result
}

# Creates a module import map. This is a 2D array of strings so that the first
# element in the array consist of modules with no dependencies.
# The second element only depends on the modules in the first element, the
# third element only dependes on modules in the first and second and so on. 
function Create-ModuleImportMapOrder {
    $ModuleImportMapOrder = $null
    # Get the latest version of the AzureRM.Profile module
    $VersionAndDependencies = Get-ModuleDependencyAndLatestVersion $script:AzureRMProfileModuleName

    $AzureRMProfileEntry = $script:AzureRMProfileModuleName
    $AzureRMProfileEntryArray = ,$AzureRMProfileEntry
    $ModuleImportMapOrder += ,$AzureRMProfileEntryArray

    # Get all the modules in the current automation account
    $CurrentAutomationModuleList = Get-AzureRmAutomationModule `
                                        -ResourceGroupName $ResourceGroupName `
                                        -AutomationAccountName $AutomationAccountName

    do {
        $NextAutomationModuleList = $null
        $CurrentChainVersion = $null
        # Add it to the list if the modules are not available in the same list 
        foreach ($Module in $CurrentAutomationModuleList) {
            $Name = $Module.Name
            Write-Verbose "Checking dependencies for $Name"
            $VersionAndDependencies = Get-ModuleDependencyAndLatestVersion $Module.Name
            if ($null -eq $VersionAndDependencies) {
                continue
            }

            $Dependencies = $VersionAndDependencies[1].Split("|")

            $AzureModuleEntry = $Module.Name

            # If the previous list contains all the dependencies then add it to current list
            if ((-not $Dependencies) -or (AreAllModulesAdded $Dependencies)) {
                Write-Verbose "Adding module $Name to dependency chain"
                $CurrentChainVersion += ,$AzureModuleEntry
            } else {
                # else add it back to the main loop variable list if not already added
                if (!(AreAllModulesAdded $AzureModuleEntry)) {
                    Write-Verbose "Module $Name does not have all dependencies added as yet. Moving module for later import"
                    $NextAutomationModuleList += ,$Module
                }
            }
        }

        $ModuleImportMapOrder += ,$CurrentChainVersion
        $CurrentAutomationModuleList = $NextAutomationModuleList

    } while ($null -ne $CurrentAutomationModuleList)

    $ModuleImportMapOrder
}

# Wait and confirm that all the modules in the list have been imported successfully in Azure Automation
function Wait-AllModulesImported(
            [Collections.Generic.List[string]] $ModuleList,
            [int] $Count) {

    $i = $Count - $SimultaneousModuleImportJobCount
    if ($i -lt 0) { $i = 0 }

    for ( ; $i -lt $Count; $i++) {
        $Module = $ModuleList[$i]

        Write-Output ("Checking import Status for module : {0}" -f $Module)
        while ($true) {
            $AutomationModule = Get-AzureRmAutomationModule `
                                    -Name $Module `
                                    -ResourceGroupName $ResourceGroupName `
                                    -AutomationAccountName $AutomationAccountName

            $IsTerminalProvisioningState = ($AutomationModule.ProvisioningState -eq "Succeeded") -or
                                           ($AutomationModule.ProvisioningState -eq "Failed")

            if ($IsTerminalProvisioningState) {
                break
            }

            Write-Verbose ("Module {0} is getting imported" -f $Module)
            Start-Sleep -Seconds 30
        }

        if ($AutomationModule.ProvisioningState -ne "Succeeded") {
            Write-Error ("Failed to import module : {0}. Status : {1}" -f $Module, $AutomationModule.ProvisioningState)                
        } else {
            Write-Output ("Successfully imported module : {0}" -f $Module)
        }
    }               
}

# Uses the module import map created to import modules. 
# It will only import modules from an element in the array if all the modules
# from the previous element have been added.
function Import-ModulesInAutomationAccordingToDependency([string[][]] $ModuleImportMapOrder) {

    foreach($ModuleList in $ModuleImportMapOrder) {
        $i = 0
        Write-Output "Importing Array of modules : $ModuleList"
        foreach ($Module in $ModuleList) {
            Write-Verbose ("Importing module : {0}" -f $Module)
            Import-AutomationModule -ModuleName $Module
            $i++
            if ($i % $SimultaneousModuleImportJobCount -eq 0) {
                # It takes some time for the modules to start getting imported.
                # Sleep for sometime before making a query to see the status
                Start-Sleep -Seconds 20
                Wait-AllModulesImported $ModuleList $i
            }
        }

        if ($i -lt $SimultaneousModuleImportJobCount) {
            Start-Sleep -Seconds 20
            Wait-AllModulesImported $ModuleList $i
        }
    }
}

function Update-ProfileAndAutomationVersionToLatest {
    # Get the latest azure automation module version 
    $VersionAndDependencies = Get-ModuleDependencyAndLatestVersion $script:AzureRMAutomationModuleName

    # Automation only has dependency on profile
    $ModuleDependencies = GetModuleNameAndVersionFromPowershellGalleryDependencyFormat $VersionAndDependencies[1]
    $ProfileModuleName = $ModuleDependencies[0]

    # Create web client object for downloading data
    $WebClient = New-Object System.Net.WebClient

    # Download AzureRM.Profile to temp location
    $ModuleContentUrl = Get-ModuleContentUrl $ProfileModuleName
    $ProfileURL = (Invoke-WebRequest -Uri $ModuleContentUrl -MaximumRedirection 0 -UseBasicParsing -ErrorAction Ignore).Headers.Location
    $ProfilePath = Join-Path $env:TEMP ($ProfileModuleName + ".zip")
    $WebClient.DownloadFile($ProfileURL, $ProfilePath)

    # Download AzureRM.Automation to temp location
    $ModuleContentUrl = Get-ModuleContentUrl $script:AzureRMAutomationModuleName
    $AutomationURL = (Invoke-WebRequest -Uri $ModuleContentUrl -MaximumRedirection 0 -UseBasicParsing -ErrorAction Ignore).Headers.Location
    $AutomationPath = Join-Path $env:TEMP ($script:AzureRMAutomationModuleName + ".zip")
    $WebClient.DownloadFile($AutomationURL, $AutomationPath)

    # Create folder for unzipping the Module files
    $PathFolderName = New-Guid
    $PathFolder = Join-Path $env:TEMP $PathFolderName

    # Unzip files
    $ProfileUnzipPath = Join-Path $PathFolder $ProfileModuleName
    Expand-Archive -Path $ProfilePath -DestinationPath $ProfileUnzipPath -Force
    $AutomationUnzipPath = Join-Path $PathFolder $script:AzureRMAutomationModuleName
    Expand-Archive -Path $AutomationPath -DestinationPath $AutomationUnzipPath -Force

    # Import modules
    Import-Module (Join-Path $ProfileUnzipPath "AzureRM.Profile.psd1") -Force -Verbose
    Import-Module (Join-Path $AutomationUnzipPath "AzureRM.Automation.psd1") -Force -Verbose
}

#endregion

#region Main body

if ($ModuleVersionOverrides) {
    $ModuleVersionOverridesHashTable = ConvertJsonDictTo-HashTable $ModuleVersionOverrides
} else {
    $ModuleVersionOverridesHashTable = @{}
}

# Import the latest version of the Azure automation and profile version to the local sandbox
Update-ProfileAndAutomationVersionToLatest 

if ($Login) {
    Login-AzureAutomation
}

$ModuleImportMapOrder = Create-ModuleImportMapOrder
Import-ModulesInAutomationAccordingToDependency $ModuleImportMapOrder 

#endregion
'@
Add-Content -Path $RunbookFilePath -Value $RunbookFileContent
(Get-Content $RunbookFilePath.FullName).replace('[ResourceGroupName]', $ResourceGroupName) | Set-Content $RunbookFilePath.FullName
(Get-Content $RunbookFilePath.FullName).replace('[AutomationAccountName]', $AutomationAccountName) | Set-Content $RunbookFilePath.FullName
(Get-Content $RunbookFilePath.FullName).replace('[Environment]', $($Environment.Name)) | Set-Content $RunbookFilePath.FullName
try
{
    Write-Output "Importing Runbook $($RunbookFilePath.BaseName)"
    Import-AzureRmAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Path $RunbookFilePath.FullName -Type $RunbookType -Verbose -ErrorAction 'Stop'
    Publish-AzureRmAutomationRunbook -Name $($RunbookFilePath.BaseName) -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Verbose -ErrorAction 'Stop'
}
catch 
{
    Write-Warning $_
    break
}
#endregion

Write-Output "Creating, Importing, Publishing and Scheduling of Runbooks completed successfully."
#endregion

#region Start Automation Account Module Update
Write-Output "Starting Automation Account Module Update"

# Get Access Token
$TokenCache = $AzureRMAccount.Context.TokenCache
$CachedTokens = $TokenCache.ReadItems() | Where-Object { $_.TenantId -eq $TenantId } | Sort-Object -Property ExpiresOn -Descending
$AccessToken = $CachedTokens | Where-Object {$_.Resource -eq $ResourceUrl} | Select-Object -First 1

$AuthHeader = @{
    'Content-Type'='application/json'
    'Authorization'='Bearer ' + $AccessToken.AccessToken
}

$JobId = [GUID]::NewGuid().ToString()
$URI =  $ResourceManagerUrl + "subscriptions/$SubscriptionID/" + "resourceGroups/$ResourceGroupName/providers/Microsoft.Automation/"` + "automationAccounts/$AutomationAccountName/jobs/$($JobId)?api-version=2015-10-31"

# Runbook and parameters
$Body = @"
    {
        "properties":{
        "runbook":{
            "name":"Update-AutomationAzureModulesForAccount"
        },
        "parameters":{
            "AzureEnvironment":"$($Environment.Name)",
            "ResourceGroupName":"$ResourceGroupName",
            "AutomationAccountName":"$AutomationAccountName"
        }
        }
    }
"@

try
{
    $Response = Invoke-RestMethod -Uri $URI -Method Put -body $body -Headers $AuthHeader -ErrorAction 'Stop'
    Write-Output "Module Update Job submitted successfully. Job Id is $($Response.properties.jobid)"
}
catch
{
    Write-Warning $_
}
#endregion

#region Adding Resource Locks
Write-Output "Adding CanNotDelete Lock to Resources in Resource Group $ResourceGroupName"
New-AzureRmResourceLock -ResourceName $AutomationAccountName -LockName LockResourceGroup -LockLevel CanNotDelete -ResourceGroupName $ResourceGroupName -ResourceType Microsoft.Automation/automationAccounts -Force -Verbose
New-AzureRmResourceLock -ResourceName $KeyVaultName -LockName LockResourceGroup -LockLevel CanNotDelete -ResourceGroupName $ResourceGroupName -ResourceType Microsoft.KeyVault/vaults -Force -Verbose
New-AzureRmResourceLock -ResourceName $StorageAccountName -LockName LockResourceGroup -LockLevel CanNotDelete -ResourceGroupName $ResourceGroupName -ResourceType Microsoft.Storage/storageAccounts -Force -Verbose
#endregion

Write-Output "Subscription Management Solution Deployment Complete"
