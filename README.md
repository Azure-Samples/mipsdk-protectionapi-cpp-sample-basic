---
page_type: sample
languages:
- cpp
- csharp
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

- Visual Studio 2022 or later with Visual C++ development features installed
- .NET 8 runtime and a .NET 8-compatible SDK installed

### Sample Setup

> **Project folder** refers to the **MipSdk-ProtectionApi-Cpp-Sample-Basic\MipSdk-ProtectionApi-Cpp-Sample-Basic** directory in the folder where you cloned the repository.

1. From a command prompt, run: **git clone https://github.com/Azure-Samples/MipSdk-ProtectionApi-Cpp-Sample-Basic**
1. Launch the project by double-clicking **MipSdk-ProtectionApi-Cpp-Sample-Basic.sln**
1. When the project starts, set the project type to **x64**
1. Right click the project in Visual Studio and select **Manage NuGet Packages**
1. Install *Microsoft.InformationProtection.Protection* **1.18.124** (or latest 1.18.x).
1. In Visual Studio, click the **Build** menu, then click **Build**. The application should compile at this point, but will crash if run.
1. Continue to the steps below to configure the Microsoft Entra ID app registration and update the sample code.

### Create a Microsoft Entra ID App Registration

Authentication against the Microsoft Entra ID tenant requires creating a native application registration. The client ID created in this step is used in a later step to generate an OAuth2 token.

> Skip this step if you've already created a registration for a previous sample. You may continue to use that client ID.

1. Sign in to the [Microsoft Entra admin center](https://entra.microsoft.com) as at least an [Application Developer](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app#prerequisites).
2. Select **Entra ID**, then **App registrations** on the left side menu.
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
4. Add the default native client redirect URI **http://localhost**.
5. Under **Settings** set **Allow public client flows** to **Enabled**.
6. Click **Save**.

### Update Client ID and Username

1. Open up **main.cpp**.
2. Replace **YOUR CLIENT ID HERE** with the client ID copied from the AAD App Registration.
3. Find the token for **YOUR TEST USER ID** and insert a test user identifier. This value is used as the engine identity and as an MSAL login hint.

## Run the Sample

Press F5 to run the sample. The console application will start, then prompt for browser-based sign-in when a cached token is not available.

Authentication runs in-process through `MipAuth.Managed`, a framework-dependent .NET 8 class library using MSAL.NET. The native executable hosts one .NET runtime through the official `nethost`/`hostfxr` APIs and loads `MipAuth.Managed.dll` from the executable directory. A normal solution build copies the managed assembly, runtime configuration, dependency manifest, and managed dependencies beside the native executable.

The authentication component validates the authority and Azure Rights Management resource, normalizes the resource to its `.default` scope, tries a username-matched cached account silently, and falls back to system-browser interactive sign-in. Conditional-access claims from the MIP SDK challenge are forwarded to both MSAL requests.

- Copy a template ID to the clipboard.
- Paste the template in to the input prompt.
- Enter a plaintext string.

The application will obtain a publishing license, use it to encrypt the string, then to decrypt the string.

## Troubleshooting

If the application fails to authenticate, ensure that:
- a supported .NET 8 x64 runtime is installed.
- `MipAuth.Managed.dll`, `MipAuth.Managed.runtimeconfig.json`, and `MipAuth.Managed.deps.json` are beside the built executable.
- the app registration is configured as a public client with the native redirect URI shown above.

To validate the managed code and native host without signing in:

```powershell
dotnet test .\MipAuth.Managed.Tests\MipAuth.Managed.Tests.csproj -c Release
.\x64\Release\mipsdk-protectionapi-cpp-sample-basic.exe --auth-host-smoke
```


## Resources

- [Microsoft Information Protection Docs](https://aka.ms/mipsdkdocs)
