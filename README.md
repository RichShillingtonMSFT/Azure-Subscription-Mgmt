# Azure-Subscription-Mgmt
This deploys a complete package of Azure resources to help you manage resources in your Azure Subscription.
The script performs several tasks, including:

* Creates a Resource Group named Subscription-Management-RG
* Creates a Key Vault named KeyVault-{first 13 charachters of your Subscription ID}
* Creates an Azure Automation Account with a RunAs Account
* Creates custom Role Definitions for the Automation Account
* Creates a shared Storage Account named sharedsa{first 13 characters of your Subscription ID without the hyphens}
* Adds Service Endpoints for Key Vault and Storage to all Virtual Networks in the Subscription
* Installs some modules in to the Automation Account
* Creates scripts to enable Windows Update on Virtual Machines and uploads them to the shared Storage Account
* Creates schedules in the Automation Account
* Creates, publishes and schedules several Runbooks in the Automation Account
* Creates Azure Policy Definitions to deploy Azure Disk Encryption to Virtual Machines (They do not get assigned)
* Creates locks for the solution so it will not be deleted by accident

**Install Procedure**

* Run the PowerShell script
* You will be prompted to select your Azure Enviornment. Click the appropriate option and click Ok.
* You will be prompted to Login. Login with an Azure account that can create Service Principals, Custom Role Definitions, Policy Definition and Resources in the Subscription you are targeting.
* If you have more than one Subscription, you will be prompted to select one. Pick the target Subscription from the list and click Ok.
* You will be prompted for a Location for the deployment. All available locations will be displayed. Make your selection and click Ok.
* Now watch as it does it's thing. Thats all you have to do.

---
# Whats in this thing and what does it do?

**Key Vault**

The Key Vault is named KeyVault-{first 13 charachters of your Subscription ID}. 
* By default it will be a Premium SKU.
* The Key Vault will have the firewall enabled.
* Every Virtual Network Subnet in the Subscription except Gateway Subnets will be added to the Firewall rules and the service endpoint for Microsoft.KeyVault is added to the Virtual Networks.
* The script locates the External IP Address of the computer running the deployment and adds it to the Firewall exceptions.
* They Key Vault is set for EnabledForDeployment, EnabledForTemplateDeployment and EnabledForDiskEncryption.

**Storage Account**

The Storage Account is named sharedsa{first 13 characters of your Subscription ID without the hyphens}.
* By default it will be Standard_GRS, StorageV2 and Access Tier Hot.
* The Storage Account will have the firewall enabled.
* Every Virtual Network Subnet in the Subscription except Gateway Subnets will be added to the Firewall rules and the service endpoint for Microsoft.Storage is added to the Virtual Networks.
* Two containers administrationscripts and subscriptionreports are created in the Storage Account.
* The administrationscripts container will have a folder named WindowsUpdateScripts where the code for deploying Windows Updates and Windows Update Settings are stored.
* The subscriptionreports container will have a folder named Reports, where on-demand reports such as Azure Orpahned Objects and Storage Account without VNets are stored.

**Custom Role Definitions**

The scripts creates a few custom role definition to limit the Automation Accounts access to resources.

* Virtual Machine Extension Operator for Subscription {Subscription ID}
  * Can Read, Delete and Write Extensions to virtual machines in the Subscription
  * Assigned actions are:
    * Microsoft.Compute/virtualMachines/extensions/read
    * Microsoft.Compute/virtualMachines/extensions/delete
    * Microsoft.Compute/virtualMachines/extensions/write
    
* Service Endpoint Manager for Subscription {Subscription ID}
  * Can manage Service Endpoints and Endpoint Policies in the Subscription
  * Assigned actions are:
    * Microsoft.Network/serviceEndpointPolicies/delete
    * Microsoft.Network/serviceEndpointPolicies/join/action
    * Microsoft.Network/serviceEndpointPolicies/joinSubnet/action
    * Microsoft.Network/locations/virtualNetworkAvailableEndpointServices/read
    * Microsoft.Network/serviceEndpointPolicies/read
    * Microsoft.Network/serviceEndpointPolicies/serviceEndpointPolicyDefinitions/delete
    * Microsoft.Network/serviceEndpointPolicies/serviceEndpointPolicyDefinitions/read
    * Microsoft.Network/serviceEndpointPolicies/serviceEndpointPolicyDefinitions/write
    * Microsoft.Network/serviceEndpointPolicies/write
    * Microsoft.Network/virtualNetworks/subnets/joinViaServiceEndpoint/action
    * Microsoft.Network/virtualNetworks/write
    
**Automation Account**
 
An Automation Account is created named Subscription-Mgmt-Automation-Account-{first 13 charachters of your Subscription ID}
A RunAs Account named AzureRunAsConnection will be created using a certificate generated using the Key Vault.
 
The Automation Account will be assigned the following permissions:
  * Subscription Reader
    * Built-In Role
    * Scope - Subscription
  * Key Vault Contributor
    * Built-In Role
    * Scope - KeyVault-{first 13 charachters of your Subscription ID}
  * Virtual Machine Contributor
    * Built-In Role
    * Scope - Subscription
  * Virtual Machine Extension Operator for Subscription {Subscription ID}
    * Custom Role
    * Scope - Subscription
  * Service Endpoint Manager for Subscription {Subscription ID}
    * Custom Role
    * Scope - Subscription
    
 **Azure Policy Definitions**
 
Three Azure Policy Definitions are created to deploy Azure Disk Encryption. Windows Virtual Machines support both OS and Data Disk Encryption, however different not all Linux Versions support OS and Data Disk Encryption or any encryption at all. Therefore the policy for Linux Virtual Machines was broke up in to two.

For more information on Supported versions see:

Windows Virtual Machines [Link](https://docs.microsoft.com/en-us/azure/security/azure-security-disk-encryption-prerequisites)

Linux Virtual Machines [Link](https://docs.microsoft.com/en-us/azure/security/azure-security-disk-encryption-faq#bkmk_LinuxOSSupport)

The Policy details are as follows:
  * Azure Disk Encryption Extension to Windows Virtual Machines
    * Policy Action - DeployIfNotExists
    * Policy Location - Subscription
    * Policy Assignment - Not Assigned
  * Azure Disk Encryption Extension to Linux Virtual Machines Data Disks Only
    * Policy Action - DeployIfNotExists
    * Policy Location - Subscription
    * Policy Assignment - Not Assigned
  * Azure Disk Encryption Extension to Linux Virtual Machines OS and Data Disks
    * Policy Action - DeployIfNotExists
    * Policy Location - Subscription
    * Policy Assignment - Not Assigned

These policies can be assigned at or below the scope where it is stored. For more information on Azure Policy including assigning policy see [Link](https://docs.microsoft.com/en-us/azure/governance/policy/overview)


**Automation Runbooks**

There are several Runbooks that get deployed with this solution. Some Runbooks are set with default schedules, while others are not. The following is a list of Runbooks, short usage details and schedules that are linked to them.

  * Invoke-ConfigureAzureDiskEncryption
    * Runbook Type - PowerShell Workflow
    * Schedule - Runs every hour
    * Description
      * This runbook will run Invoke-ConfigureAzureDiskEncryption on VMs that have the OS Volume encrypted, but data disks are not.
      * This will retrieve the Azure Disk Encryption settings from the OS Drive and set ADE on the data drive with the same settings.
    * Usage Example
      * This is configured to run automatically on a schedule against the Subscription where it is deployed.
      * You can choose provide an alternate Subscription ID.
      
  * Add-AllAvailableServiceEndpointsToVirtualNetworks
    * Runbook Type - PowerShell
    * Schedule - Runs once per day
    * Description
      * This runbook will query Azure to get an updated list of available Service Endpoints.
      * It will then find all Virtual Networks and Subnets not name GatewaySubnet and add all Available Service Endpoints to the Virtual Network Subnet Configs.
    * Usage Example
      * This is configured to run automatically on a schedule against the Subscription where it is deployed.
      * You can choose provide an alternate Subscription ID.
      
  * Add-AllSubnetsToKeyVaultFirewall
    * Runbook Type - PowerShell
    * Schedule - Runs once per day
    * Description
      * This script will find all Virtual Networks and ensure that the Service Endpoint for Microsoft.KeyVault is added.
      * It will then update the Key Vault Firewall with the new Subnet(s)
    * Usage Example
      * This is configured to run automatically on a schedule against the Subscription where it is deployed.
      * You can choose provide an alternate Subscription ID.
      
  * Add-AllSubnetsToSharedStorageAccountFirewall
    * Runbook Type - PowerShell
    * Schedule - Runs once per day
    * Description
      * This script will find all Virtual Networks and ensure that the Service Endpoint for Microsoft.Storage is added.
      * It will then update the Storage Account Firewall with the new Subnet(s)
    * Usage Example
      * This is configured to run automatically on a schedule against the Subscription where it is deployed.
      * You can choose provide an alternate Subscription ID.
      
  * Start-DeployWindowsUpdateSettingsByResourceGroup
    * Runbook Type - PowerShell Workflow
    * Schedule - Not Scheduled
    * Description
      * This runbook will deploy Set-LocalWindowsUpdateSettings.ps1 from a Azure Storage Account to Azure Virtual Machines in specified Resource Groups.
      * This runbook is designed to use Azure Automation and an Automation Account.
      * It will deploy the script as a Custom Script Extension.
      * You must provide Resource Group Name(s) to start.
      * The Automation Account must have permissions to deploy script extensions to the Virtual Machines
    * Usage Example
      * For a single ResourceGroup use a JSON format string: ['RG-01']
      * For multiple ResourceGroups use a JSON format string: ['RG-01','RG-02','RG-03']
      
  * Start-DeployWindowsUpdateSettingsByVMName
    * Runbook Type - PowerShell Workflow
    * Schedule - Not Scheduled
    * Description
      * This runbook will deploy Set-LocalWindowsUpdateSettings.ps1 from a Azure Storage Account to Azure Virtual Machines.
      * This runbook is designed to use Azure Automation and an Automation Account.
      * It will deploy the script as a Custom Script Extension.
      * You must provide a Azure Virtual Machine Name(s) to start.
      * The Automation Account must have permissions to deploy script extensions to the Virtual Machines 
    * Usage Example
      * For a single VM use a JSON format string: ['VM-01']
      * For multiple VMs use a JSON format string: ['VM-01','VM-02','VM-03']
      
  * Start-DeployWindowsUpdateSettingsBySubscription
    * Runbook Type - PowerShell Workflow
    * Schedule - Not Scheduled
    * Description
      * This runbook will deploy Set-LocalWindowsUpdateSettings from a Azure Storage Account to Azure Virtual Machines in specified Subscription.
      * This runbook is designed to use Azure Automation and an Automation Account.
      * It will deploy the script as a Custom Script Extension.
      * You must provide a Subscription ID to start.
      * The Automation Account must have permissions to deploy script extensions to the Virtual Machines
    * Usage Example
      * Provide a Subscription ID. If no Subscription ID is provided, the current Subscription will be used.
      
  * Start-WindowsUpdateDeploymentByResourceGroup
    * Runbook Type - PowerShell Workflow
    * Schedule - Not Scheduled
    * Description
      * This runbook will deploy Invoke-WindowsUpdate.ps1 from a Azure Storage Account to Azure Virtual Machines in specified Resource Groups.
      * This runbook is designed to use Azure Automation and an Automation Account.
      * It will deploy the script as a Custom Script Extension.
      * You must provide Resource Group Name(s) to start.
      * The Automation Account must have permissions to deploy script extensions to the Virtual Machines
    * Usage Example
      * For a single ResourceGroup use a JSON format string: ['RG-01']
      * For multiple ResourceGroups use a JSON format string: ['RG-01','RG-02','RG-03']
      * Restart Option - AutoReboot or IgnoreReboot
      * To force the VMs to check for updates online, type true in the ForceOnlineUpdate box.
      
  * Start-WindowsUpdateDeploymentBySubscription
    * Runbook Type - PowerShell Workflow
    * Schedule - Not Scheduled
    * Description
      * This runbook will deploy Invoke-WindowsUpdate.ps1 from a Azure Storage Account to Azure Virtual Machines in specified Subscription.
      * This runbook is designed to use Azure Automation and an Automation Account.
      * It will deploy the script as a Custom Script Extension.
      * You must provide a Subscription Name to start.
      * The Automation Account must have permissions to deploy script extensions to the Virtual Machines
    * Usage Example
      * Provide a Subscription ID. If no Subscription ID is provided, the current Subscription will be used.
      * Restart Option - AutoReboot or IgnoreReboot
      * To force the VMs to check for updates online, type true in the ForceOnlineUpdate box.
      
  * Start-WindowsUpdateDeploymentByVMName
    * Runbook Type - PowerShell Workflow
    * Schedule - Not Scheduled
    * Description
      * This runbook will deploy Invoke-WindowsUpdate.ps1 from a Azure Storage Account to Azure Virtual Machines.
      * This runbook is designed to use Azure Automation and an Automation Account.
      * It will deploy the script as a Custom Script Extension.
      * You must provide a Azure Virtual Machine Name(s) to start.
      * The Automation Account must have permissions to deploy script extensions to the Virtual Machines
    * Usage Example
      * For a single VM use a JSON format string: ['VM-01']
      * For multiple VMs use a JSON format string: ['VM-01','VM-02','VM-03']
      * Restart Option - AutoReboot or IgnoreReboot
      * To force the VMs to check for updates online, type true in the ForceOnlineUpdate box.
      
  * Start-DeallocatedVMsBasedOnTags
    * Runbook Type - PowerShell Workflow
    * Schedule - Runs every hour
    * Description
      * This script will look for StartUpDays and StartUpTime tags on ResourceGroups & Virtual Machines.
      * If the StartUpDays matches the current Day of the week and the StartUpTime is less than or equal to the current time, the VM will be powered on.
    * Usage Example
      * Tag - StartUpDays = Monday,Tuesday,Wednesday,Thursday,Friday,Saturday,Sunday , Days you want to startup the VMs.
      * Tag - StartUpTime = 18:00 , Time to shutdown the Azure VM in UTC 24hour format.
      * Tag - OverrideStartUp = True , Disables automated power on
      
  * Stop-RunningVMsBasedOnTags
    * Runbook Type - PowerShell Workflow
    * Schedule - Runs every hour
    * Description
      * This script will look for ShutdownDays and ShutdownTime tags on ResourceGroups & Virtual Machines.
      * If the ShutdownDays matches the current Day of the week and the ShutdownTime is less than or equal to the current time, the VM will be shutdown.
    * Usage Example
      * Tag - ShutdownDays = Monday,Tuesday,Wednesday,Thursday,Friday,Saturday,Sunday , Days you want to shutdown the VMs.
      * Tag - ShutdownTime = 18:00 , Time to shutdown the Azure VM in UTC 24hour format.
      * Tag - OverrideShutdown = True , Disables automated shutdown

  * Get-AzureOrphanedObjects
    * Runbook Type - PowerShell
    * Schedule - Not Scheduled
    * Description
      * This script will search your Azure Subscription to find Resources that are not in use.
      * It will look for:
        * Virtual Machines That Are Powered Off
        * Network Security Groups That Are Not In Use
        * Network Interfaces That Are Not In Use
        * Public IP Addresses That Are Not In Use
        * Disks That Are Not Attached To A VM
    * Usage Example
      * Start the Runbook from Azure Automation.
      * At the completion of the script, a download link will be displayed in the output.
      * The link is good for 2 hours after the script completes.
      
  * Get-AzureStorageAccountsWithNoVnetsOrServiceEndpoints
    * Runbook Type - PowerShell
    * Schedule - Not Scheduled
    * Description
      * This script will search the Subscription for Storage Accounts.
      * Each Storage Account will be checked for firewal rules.
      * It will examine each rule to look for:
        * Is the rule defined?
        * If the rule is defined, are there Subnets added?
        * If there are Subnets, do the have Service Endpoints for Microsoft.Storage?
      * All Storage Accounts that do not have firewall rules fully configured with Subnets and Service Endpoints will be added to the CSV file.
    * Usage Example
      * Start the Runbook from Azure Automation.
      * At the completion of the script, a download link will be displayed in the output.
      * The link is good for 2 hours after the script completes.
      
  * Update-AutomationAzureModulesForAccount
    * Runbook Type - PowerShell
    * Schedule - Not Scheduled
    * Description
      * This Azure Automation runbook updates Azure PowerShell modules imported into an Azure Automation account with the module versions published to the PowerShell Gallery.
    * Usage Example
      * Start the Runbook from Azure Automation Blade, PowerShell, RestAPI or Azure CLI
      
**Windows Update Scripts**

The Windows Update Runbooks and scripts can be used if you cannot use Update Management or you want to patch your VMs immediately and do not want to wait for WSUS, SCCM or Update Management evaluation cycles. See the *Automation Runbooks* section for details on the Runbooks.
 
There are two scripts that used to deploy Windows Updates and set Windows Update settings on Azure Virtual Machines. These scripts are located in the shared Storage Account that gets created.

  * Invoke-WindowsUpdate.ps1
    * This script was developed to be run as a Custom Script Extension on a Windows Azure Virtual Machine
    * The script will force Windows Update client to check for and install Windows Updates according to the computers Windows Update Settings.
    
  * Set-LocalWindowsUpdateSettings.ps1
    * This script can be used to set the Windows Update Settings for VMs.
    * This is optional and can be used in place of Group Policy for non-domain joined machines.
    * You can use Azure Storage Explorer to download this file to make changes or upload the file after changes are made.
    * See the script for more details on parameters and settings.
