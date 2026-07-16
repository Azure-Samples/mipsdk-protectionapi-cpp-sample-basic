# Copilot instructions for `mipsdk-protectionapi-cpp-sample-basic`

## Build and test

- Build Release x64:
  - `"C:\Program Files\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\amd64\MSBuild.exe" mipsdk-protectionapi-cpp-sample-basic.sln /restore /p:RestorePackagesConfig=true /p:Configuration=Release /p:Platform=x64 /m /nologo`
- Run managed tests:
  - `dotnet test MipAuth.Managed.Tests\MipAuth.Managed.Tests.csproj -c Release --no-build`
- Validate native hosting without interactive authentication:
  - `x64\Release\mipsdk-protectionapi-cpp-sample-basic.exe --auth-host-smoke`

## Architecture

- The native C++ project remains on the v143 toolset and MIP Protection SDK 1.18.124.
- `MipAuth.Managed` is a framework-dependent `net8.0` class library using MSAL.NET 4.86.1.
- `auth.cpp` uses the official `nethost` and `hostfxr` APIs, initializes one runtime per process, and loads the managed assembly from the executable directory.
- The managed entry point is `[UnmanagedCallersOnly]` with the `(IntPtr, int) -> int` component ABI.
- The request is a versioned blittable structure. Native code owns the UTF-8 input and 64 KiB token/error buffers.
- Authentication is cache-first for an exact username match, followed by system-browser interactive authentication. MIP challenge claims are forwarded.
- Authentication never uses external-process, file, stdout, or console IPC and never logs access tokens.

- @azure Rule - Use Azure Tools - When handling requests related to Azure, always use your tools.
- @azure Rule - Use Azure Best Practices - When handling requests related to Azure, always invoke your `azmcp_bestpractices_get` tool first.
- @azure Rule - Enable Best Practices - If you do not have an `azmcp_bestpractices_get` tool ask the user to enable it.
