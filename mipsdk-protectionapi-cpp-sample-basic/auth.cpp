/**
*
* Copyright (c) Microsoft Corporation.
* All rights reserved.
*
* This code is licensed under the MIT License.
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files(the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions :
*
* The above copyright notice and this permission notice shall be included in
* all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
* THE SOFTWARE.
*
*/

#include "auth.h"

#include <coreclr_delegates.h>
#include <hostfxr.h>
#include <nethost.h>
#define NOMINMAX
#include <windows.h>

#include <cstdint>
#include <filesystem>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

using std::runtime_error;
using std::string;

namespace {

constexpr uint32_t kRequestVersion = 1;
constexpr int32_t kMinimumBufferSize = 64 * 1024;
constexpr int32_t kInvalidAuthority = 2;

struct AuthRequest {
  uint32_t version;
  uint32_t structSize;

  const char* username;
  int32_t usernameLength;
  int32_t usernameReserved;

  const char* clientId;
  int32_t clientIdLength;
  int32_t clientIdReserved;

  const char* authority;
  int32_t authorityLength;
  int32_t authorityReserved;

  const char* resource;
  int32_t resourceLength;
  int32_t resourceReserved;

  const char* claims;
  int32_t claimsLength;
  int32_t claimsReserved;

  char* tokenBuffer;
  int32_t tokenBufferCapacity;
  int32_t tokenLength;

  char* errorBuffer;
  int32_t errorBufferCapacity;
  int32_t errorLength;
};

static_assert(sizeof(void*) == 8, "The managed authentication host requires x64.");
static_assert(sizeof(AuthRequest) == 120, "The managed authentication ABI layout changed.");

using acquire_token_fn = int(CORECLR_DELEGATE_CALLTYPE*)(void*, int32_t);

std::filesystem::path GetExecutableDirectory() {
  std::vector<wchar_t> buffer(MAX_PATH);
  while (true) {
    DWORD length = GetModuleFileNameW(
        nullptr,
        buffer.data(),
        static_cast<DWORD>(buffer.size()));
    if (length == 0) {
      throw runtime_error("Managed authentication host is unavailable.");
    }
    if (length < buffer.size() - 1) {
      return std::filesystem::path(
          std::wstring(buffer.data(), length)).parent_path();
    }
    if (buffer.size() >= 32768) {
      throw runtime_error("Managed authentication host is unavailable.");
    }
    buffer.resize(buffer.size() * 2);
  }
}

void HOSTFXR_CALLTYPE IgnoreHostError(const char_t*) {
}

class ManagedRuntime final {
 public:
  static ManagedRuntime& Instance() {
    static ManagedRuntime instance;
    return instance;
  }

  acquire_token_fn AcquireToken() const {
    return mAcquireToken;
  }

 private:
  ManagedRuntime() {
    const std::filesystem::path executableDirectory = GetExecutableDirectory();
    const std::filesystem::path assemblyPath =
        executableDirectory / L"MipAuth.Managed.dll";
    const std::filesystem::path runtimeConfigPath =
        executableDirectory / L"MipAuth.Managed.runtimeconfig.json";

    std::vector<wchar_t> hostfxrPath(32768);
    size_t hostfxrPathSize = hostfxrPath.size();
    get_hostfxr_parameters parameters{
        sizeof(get_hostfxr_parameters),
        assemblyPath.c_str(),
        nullptr};
    if (get_hostfxr_path(
            hostfxrPath.data(),
            &hostfxrPathSize,
            &parameters) != 0) {
      throw runtime_error("Managed authentication host is unavailable.");
    }

    mHostfxr = LoadLibraryExW(
        hostfxrPath.data(),
        nullptr,
        LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (mHostfxr == nullptr) {
      throw runtime_error("Managed authentication host is unavailable.");
    }

    auto initialize = reinterpret_cast<hostfxr_initialize_for_runtime_config_fn>(
        GetProcAddress(mHostfxr, "hostfxr_initialize_for_runtime_config"));
    auto getDelegate = reinterpret_cast<hostfxr_get_runtime_delegate_fn>(
        GetProcAddress(mHostfxr, "hostfxr_get_runtime_delegate"));
    auto close = reinterpret_cast<hostfxr_close_fn>(
        GetProcAddress(mHostfxr, "hostfxr_close"));
    auto setErrorWriter = reinterpret_cast<hostfxr_set_error_writer_fn>(
        GetProcAddress(mHostfxr, "hostfxr_set_error_writer"));
    if (initialize == nullptr ||
        getDelegate == nullptr ||
        close == nullptr ||
        setErrorWriter == nullptr) {
      throw runtime_error("Managed authentication host is unavailable.");
    }

    hostfxr_error_writer_fn previousWriter = setErrorWriter(IgnoreHostError);
    hostfxr_handle context = nullptr;
    int32_t result = initialize(runtimeConfigPath.c_str(), nullptr, &context);
    if (result < 0 || context == nullptr) {
      setErrorWriter(previousWriter);
      throw runtime_error("Managed authentication host is unavailable.");
    }

    void* loadAssemblyAddress = nullptr;
    result = getDelegate(
        context,
        hdt_load_assembly_and_get_function_pointer,
        &loadAssemblyAddress);
    close(context);
    if (result < 0 || loadAssemblyAddress == nullptr) {
      setErrorWriter(previousWriter);
      throw runtime_error("Managed authentication host is unavailable.");
    }

    auto loadAssembly =
        reinterpret_cast<load_assembly_and_get_function_pointer_fn>(
            loadAssemblyAddress);
    void* acquireTokenAddress = nullptr;
    result = loadAssembly(
        assemblyPath.c_str(),
        L"MipAuth.Managed.EntryPoint, MipAuth.Managed",
        L"AcquireToken",
        UNMANAGEDCALLERSONLY_METHOD,
        nullptr,
        &acquireTokenAddress);
    setErrorWriter(previousWriter);
    if (result != 0 || acquireTokenAddress == nullptr) {
      throw runtime_error("Managed authentication host is unavailable.");
    }

    mAcquireToken = reinterpret_cast<acquire_token_fn>(acquireTokenAddress);
  }

  ~ManagedRuntime() = default;
  ManagedRuntime(const ManagedRuntime&) = delete;
  ManagedRuntime& operator=(const ManagedRuntime&) = delete;

  HMODULE mHostfxr = nullptr;
  acquire_token_fn mAcquireToken = nullptr;
};

int32_t CheckedLength(const string& value) {
  if (value.size() > static_cast<size_t>(std::numeric_limits<int32_t>::max())) {
    throw runtime_error("Invalid authentication request.");
  }
  return static_cast<int32_t>(value.size());
}

struct InvocationResult {
  int32_t result;
  string token;
  string error;
};

InvocationResult InvokeManaged(
    const string& username,
    const string& clientId,
    const string& resource,
    const string& authority,
    const string& claims) {
  std::vector<char> tokenBuffer(kMinimumBufferSize);
  std::vector<char> errorBuffer(kMinimumBufferSize);

  AuthRequest request{};
  request.version = kRequestVersion;
  request.structSize = sizeof(request);
  request.username = username.data();
  request.usernameLength = CheckedLength(username);
  request.clientId = clientId.data();
  request.clientIdLength = CheckedLength(clientId);
  request.authority = authority.data();
  request.authorityLength = CheckedLength(authority);
  request.resource = resource.data();
  request.resourceLength = CheckedLength(resource);
  request.claims = claims.empty() ? nullptr : claims.data();
  request.claimsLength = CheckedLength(claims);
  request.tokenBuffer = tokenBuffer.data();
  request.tokenBufferCapacity = static_cast<int32_t>(tokenBuffer.size());
  request.errorBuffer = errorBuffer.data();
  request.errorBufferCapacity = static_cast<int32_t>(errorBuffer.size());

  int32_t result = ManagedRuntime::Instance().AcquireToken()(
      &request,
      static_cast<int32_t>(sizeof(request)));

  if (request.tokenLength < 0 ||
      request.tokenLength >= request.tokenBufferCapacity ||
      request.errorLength < 0 ||
      request.errorLength >= request.errorBufferCapacity) {
    throw runtime_error("Managed authentication returned an invalid result.");
  }

  return {
      result,
      string(tokenBuffer.data(), request.tokenLength),
      string(errorBuffer.data(), request.errorLength)};
}

}  // namespace

namespace sample {
namespace auth {

string AcquireToken(
    const string& username,
    const string& clientId,
    const string& resource,
    const string& authority,
    const string& claims) {
  InvocationResult invocation =
      InvokeManaged(username, clientId, resource, authority, claims);
  if (invocation.result != 0 || invocation.token.empty()) {
    const string message = invocation.error.empty()
        ? "Authentication failed."
        : invocation.error;
    throw runtime_error(message);
  }
  return invocation.token;
}

bool ValidateManagedHost() {
  InvocationResult invocation = InvokeManaged(
      "smoke@example.com",
      "11111111-1111-1111-1111-111111111111",
      "https://api.aadrm.com",
      "https://invalid.example/organizations",
      "");
  return invocation.result == kInvalidAuthority &&
      invocation.error == "Invalid authority." &&
      invocation.token.empty();
}

}  // namespace auth
}  // namespace sample
