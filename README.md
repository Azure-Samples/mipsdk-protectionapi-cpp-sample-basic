---
page_type: sample
languages:
- cpp
- csharp
products:
- m365
- office-365
description: "This sample application illustrates using the MIP Protection API to list templates, protect a string, and decrypt the protected result."
urlFragment: mipsdk-protectionapi-cpp-sample-basic
---

# mipsdk-protectionapi-cpp-sample-basic

This sample illustrates basic MIP Protection SDK functionality where it:

- Creates a protection profile and engine
- Lists publishing templates for the signed-in user
- Protects an in-memory string
- Decrypts and reads the protected string

## Prerequisites

- Visual Studio 2022 or later with C++ desktop development tools
- .NET 8 runtime
- **x64** build platform (this sample is x64-only)

## Setup

1. Open the solution in Visual Studio and select the **x64** solution platform.
2. Restore NuGet packages and build the solution.
3. In `main.cpp`, replace:
   - `YOUR CLIENT ID` with your app registration client ID
   - `YOUR USER UPN` with a test user UPN

### Microsoft Entra app registration

Create a public client app registration and grant delegated permissions:

- **Azure Rights Management Services** -> `user_impersonation`
- **Microsoft Information Protection Sync Service** -> `UnifiedPolicy.User.Read`

Also configure **Authentication**:

- Add **Mobile and desktop applications**
- Add redirect URI `http://localhost`
- Enable **Allow public client flows**

## Authentication behavior

Authentication runs in-process via the framework-dependent `MipAuth.Managed` .NET 8 component.
The native app hosts .NET using `nethost`/`hostfxr`.

- The auth delegate forwards challenge `resource`, `authority`, and `claims` from the MIP SDK directly to managed auth.
- The managed component normalizes the resource into an MSAL `/.default` scope.
- MSAL attempts silent token acquisition first for the configured username, then uses system-browser interactive sign-in when needed.
- For single-tenant app registrations, `/common` and `/organizations` authorities are normalized to the tenant domain from the username.

## Run

Press **F5** to run the sample. The app will list templates, protect a sample string, and then decrypt it.

For a non-interactive auth-host smoke check:

```powershell
.\x64\Release\mipsdk-protectionapi-cpp-sample-basic.exe --auth-host-smoke
```

## Troubleshooting

If authentication fails, verify:

- .NET 8 runtime is installed
- `MipAuth.Managed.dll`, `.deps.json`, `.runtimeconfig.json`, managed dependencies, and `nethost.dll` are next to the native executable (the build copies these automatically)
- The app registration is configured as a public client with the redirect URI above

## Resources

- [Microsoft Information Protection documentation](https://aka.ms/mipsdkdocs)
