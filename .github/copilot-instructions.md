# Copilot instructions for `mipsdk-protectionapi-cpp-sample-basic`

## Build and test

Run commands from the repository root in a Visual Studio 2022 environment with the .NET 8 SDK/runtime installed.

```powershell
# Restore packages.config and PackageReference dependencies, then build the supported configuration.
& "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\amd64\MSBuild.exe" `
  mipsdk-protectionapi-cpp-sample-basic.sln /restore `
  /p:RestorePackagesConfig=true /p:Configuration=Release /p:Platform=x64 /m /nologo

# Run all managed tests after the solution build.
dotnet test MipAuth.Managed.Tests\MipAuth.Managed.Tests.csproj -c Release --no-build

# Run one xUnit test by fully qualified name.
dotnet test MipAuth.Managed.Tests\MipAuth.Managed.Tests.csproj -c Release --no-build `
  --filter "FullyQualifiedName=MipAuth.Managed.Tests.ValidationTests.NormalizeScopeUsesDefaultScope"

# Exercise native-to-managed hosting without interactive authentication.
.\x64\Release\mipsdk-protectionapi-cpp-sample-basic.exe --auth-host-smoke
```

This repository does not define a dedicated lint command.

## Architecture

- The solution combines a C++17 console application, a framework-dependent `net8.0` authentication component, and xUnit tests for the managed validation layer.
- `main.cpp` drives the sample. `Action` creates the MIP context/profile/engine, lists protection templates, and creates publishing and consumption handlers to encrypt and decrypt strings.
- MIP SDK asynchronous APIs are adapted to synchronous sample flow by passing `std::promise` objects as observer context and waiting on their futures. Keep observer success/failure callbacks paired so failures propagate through `future::get()`.
- `AuthDelegateImpl` forwards every MIP OAuth challenge field--authority, resource, and claims--to `sample::auth::AcquireToken`.
- `auth.cpp` hosts .NET in-process through `nethost`/`hostfxr`. A process-wide `ManagedRuntime` loads `MipAuth.Managed.dll` and its runtime config from the native executable directory and resolves `MipAuth.Managed.EntryPoint.AcquireToken`.
- `MipAuth.Managed` validates the native request, normalizes approved Microsoft Entra authority and Azure Rights Management resource hosts, converts the resource to a `/.default` scope, then uses MSAL cache-first authentication for the exact username before system-browser interactive sign-in.
- Consent is implemented through `ConsentDelegateImpl` and is intentionally non-interactive in this sample (defaults to `Consent::Accept`) so the core protection flow can run without an extra prompt.
- The consent delegate callback is primarily relevant for AD RMS/on-prem service connectivity. Cloud-service calls may still traverse this flow in AD RMS-capable environments; keep this delegate behavior only in apps that need AD RMS support.
- The native project's `CopyManagedAuth` target copies the managed assembly, `.deps.json`, `.runtimeconfig.json`, managed dependencies, and `nethost.dll` beside the x64 executable. Do not replace this with external-process, file, stdout, or console IPC.

## Repository-specific conventions

- Treat x64 as the supported native-host configuration. `auth.cpp` has an x64 `static_assert`, and only x64 project configurations include/link the .NET host files.
- Keep native hosting on the v143 toolset, C++17, MIP Protection SDK `1.18.124`, and `Microsoft.NETCore.App.Host.win-x64` `8.0.29` unless intentionally updating every corresponding `packages.config`, `.vcxproj`, and deployment reference.
- The C++ `AuthRequest` and C# `AuthRequest` are one ABI contract: sequential field order and types, version `1`, native size `120`, UTF-8 pointer/length pairs, and native-owned 64 KiB token/error buffers. Update both definitions and the guards together.
- Preserve the managed entry point as `[UnmanagedCallersOnly]` with the `(IntPtr, int) -> int` component ABI. Return `AuthResult` codes and bounded UTF-8 error text across the boundary; do not let exceptions cross it.
- Keep `AuthResult` values and native expectations aligned. `ValidateManagedHost()` specifically expects the managed `InvalidAuthority` result and `"Invalid authority."` error text.
- Keep authority/resource validation allowlist-based and strict. Generic authentication errors are intentional, and access tokens must never be logged or written to console/files.
- Authentication must remain cache-first for a case-insensitive exact username match, then use the system browser. Forward conditional-access claims to both silent and interactive MSAL requests.
- Managed implementation types are `internal`; tests access them through `InternalsVisibleTo("MipAuth.Managed.Tests")`. Add validation cases to `ValidationTests` when changing accepted authorities, resources, identity rules, or account selection.
- Keep the sample flow template-based and string-based (`ListTemplates`, `ProtectString`, `DecryptString`). Avoid reintroducing file-labeling/sample-policy semantics from other MIP samples.
