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
---
# Key Vault
The Key Vault is named KeyVault-{first 13 charachters of your Subscription ID}. 
* By default it will be a Premium SKU.
* The Key Vault will have the firewall enabled.
* Every Virtual Network Subnet in the Subscription except Gateway Subnets will be added to the Firewall rules and the service endpoint for Microsoft.KeyVault is added to the Virtual Networks.
* They Key Vault is set for EnabledForDeployment, EnabledForTemplateDeployment and EnabledForDiskEncryption
