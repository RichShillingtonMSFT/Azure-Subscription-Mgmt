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

**Key Vault**

The Key Vault is named KeyVault-{first 13 charachters of your Subscription ID}. 
* By default it will be a Premium SKU.
* The Key Vault will have the firewall enabled.
* Every Virtual Network Subnet in the Subscription except Gateway Subnets will be added to the Firewall rules and the service endpoint for Microsoft.KeyVault is added to the Virtual Networks.
* They Key Vault is set for EnabledForDeployment, EnabledForTemplateDeployment and EnabledForDiskEncryption

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
