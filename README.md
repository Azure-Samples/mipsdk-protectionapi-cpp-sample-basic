---
page_type: sample
languages:
- cpp
- python
products:
- azure
description: "This application demonstrates using the MIP SDK Protection API to list available templates, then to encrypt/decrypt a string with that template."
urlFragment: mipsdk-protectionapi-cpp-sample-basic 
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
- Python 2.7 or greater installed and in the system path

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
2. Select Azure Active Directory, then **App Registrations** on the left side menu.
3. Select **New registration**
4. For name, enter **MipSdk-Sample-Apps**
5. Under **Supported account types** set **Accounts in this organizational directory only**
   > Optionally, set this to **Accounts in any organizational directory**.
6. Select **Register**

The **Application registration** screen should now be displaying your new application.

### Add API Permissions 

1. Select **API Permissions**
2. Select **Add a permission**
3. Select **Azure Rights Management Services**
4. Select **Delegated permissions**
5. Check **user_impersonation** and select **Add permissions** at the bottom of the screen.
6. In the **API permissions** menu, select **Grant admin consent for <TENANT NAME>** and confirm.

### Set Redirect URI

1. Select **Authentication**.
2. Select **Add a platform**.
3. Select **Mobile and desktop applications**
4. Select the default native client redirect URI, which should look similar to **https://login.microsoftonline.com/common/oauth2/nativeclient**.
5. Under **Advanced settings** set **Treat as a public client** to **yes**.
   > This is required only for the MIP SDK sample apps using MSAL for Python.
6. Select **configure** and be sure to save and changes if required. 

### Update Client ID, Username, and Password

1. Open up **main.cpp**.
2. Replace **YOUR CLIENT ID HERE** with the client ID copied from the AAD App Registration.
3. Find the tokens for **YOUR USERNAME HERE** and **YOUR PASSWORD HERE** and insert test user credentials. 

> DO NOT hard code a production username and password.

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
