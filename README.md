---
services: microsoft-information-protection
platforms: cpp
author: tommoser
level: 300
client: Desktop
service: Microsoft Information Protection
---

# MipSdk-ProtectionApi-Cpp-Sample-Basic

## Summary

This application demonstrates using the MIP SDK Protection API to list available templates, then to encrypt/decrypt a string with that template.

The application demonstrates the following:

- Initializing the `ProtectionProfile`
- Adding the `ProtectionEngine`
- Creating a `ProtectionEngine::Handler`
- Generating a Publishing License (PL)
- Using the PL to generate plaintext from ciphertext
- Using the PL to decrypt ciphertext
  
## Getting Started

### Prerequisites

- Visual Studio 2015 or later with Visual C++ development features installed
- Python 2.7 installed and in the system path

### Sample Setup

> **Project folder** refers to the **MipSdk-ProtectionApi-Cpp-Sample-Basic\MipSdk-ProtectionApi-Cpp-Sample-Basic** directory in the folder where you cloned the repository.

1. From a command prompt, run: **git clone https://github.com/Azure-Samples/MipSdk-ProtectionApi-Cpp-Sample-Basic**
1. Launch the project by double-clicking **MipSdk-ProtectionApi-Cpp-Sample-Basic.sln**
1. When the project starts, set the project type to **x64**
1. Right click the project in Visual Studio and select **Manage NuGet Packages**
1. Browse for *Microsoft.InformationProtection.Protection* and install.
1. In Visual Studio, click the **Build** menu, then click **Build**. The application should compile at this point, but will crash if run.
1. Continue to the steps below to configure the Azure AD App Registration and update the sample code.

### Create an Azure AD App Registration

Authentication against the Azure AD tenant requires creating a native application registration. The client ID created in this step is used in a later step to generate an OAuth2 token.

> Skip this step if you've already created a registration for previous sample. You may continue to use that client ID.

1. Go to https://portal.azure.com and log in as a global admin.
> Your tenant may permit standard users to register applications. If you aren't a global admin, you can attempt these steps, but may need to work with a tenant administrator to have an application registered or be granted access to register applications.
2. Click Azure Active Directory, then **App Registrations** in the menu blade.
3. Click **View all applications**
4. Click **New Applications Registration**
5. For name, enter **MipSdk-Sample-Apps**
6. Set **Application Type** to **Native**
7. For Redirect URI, enter **mipsdk-auth-sample://authorize**
  > Note: This can be anything you'd like, but should be unique in the tenant.
8. Click **Create**

The **Registered app** blade should now be displayed.

1. Click **Settings**
2. Click **Required Permissions**
3. Click **Add**
4. Click **Select an API**
5. Select **Microsoft Rights Management Services** and click **Select**
6. Under **Select Permissions** select **Create and access protected content for users**
7. Click **Select** then **Done**
8. Click **Add**
9. Click **Select an API**
10. In the search box, type **Microsoft Information Protection Sync Service** then select the service and click **Select**
11. Under **Select Permissions** select **Read all unified policies a user has access to.**
12. Click **Select** then **Done**
13. In the **Required Permissions** blade, click **Grant Permissions** and confirm.

### Update Client ID, Username, and Password

1. Open up **main.cpp**.
2. Find line 62 and replace **YOUR CLIENT ID HERE** with the client ID copied from the AAD App Registration.
3. Update the strings for application name and version on line 62.
4. Find line 69 and enter your test username and password.

> Hard coding a username and password isn't recommended. For the scope of this sample, it's an easier way to abstract auth. We'll update this soon, but for now this is a good cross-platform example. 

## Run the Sample

Press F5 to run the sample. The console application will start and after a brief moment displays the labels available for the user.

- Copy a template ID to the clipboard.
- Paste the template in to the input prompt.
- Enter a plaintext string.

The application will obtain a publishing license, use it to encrypt the string, then to decrypt the string.

## Troubleshooting

If the application fails to authenticate, ensure that python.exe is in the system path and that the version is Python 2.7. Alternatively, updated line 61 in auth.cpp to point to the exact path of the executable.


## Resources

- [Microsoft Information Protection Docs](https://aka.ms/mipsdkdocs)
