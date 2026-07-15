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
#include "utils.h"

#include <array>
#include <fstream>
#include <functional>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
#else
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

using std::runtime_error;
using std::string;

namespace {

string TrimOutput(string output) {
  while (!output.empty() && (output.back() == '\r' || output.back() == '\n' || output.back() == ' ' || output.back() == '\t')) {
    output.pop_back();
  }
  return output;
}

#if defined(_WIN32) || defined(_WIN64)
string QuoteWindowsArgument(const string& arg) {
  if (arg.find_first_of(" \t\"") == string::npos) {
    return arg;
  }

  string quoted = "\"";
  size_t backslashCount = 0;
  for (char c : arg) {
    if (c == '\\') {
      ++backslashCount;
    } else if (c == '"') {
      quoted.append(backslashCount * 2 + 1, '\\');
      quoted.push_back('"');
      backslashCount = 0;
    } else {
      quoted.append(backslashCount, '\\');
      backslashCount = 0;
      quoted.push_back(c);
    }
  }

  quoted.append(backslashCount * 2, '\\');
  quoted.push_back('"');
  return quoted;
}

string ExecuteProcess(const std::vector<string>& args) {
  if (args.empty()) {
    throw runtime_error("No process arguments were provided.");
  }

  SECURITY_ATTRIBUTES securityAttributes{};
  securityAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
  securityAttributes.bInheritHandle = TRUE;

  HANDLE readHandle = nullptr;
  HANDLE writeHandle = nullptr;
  if (!CreatePipe(&readHandle, &writeHandle, &securityAttributes, 0)) {
    throw runtime_error("Failed to create process output pipe.");
  }
  if (!SetHandleInformation(readHandle, HANDLE_FLAG_INHERIT, 0)) {
    CloseHandle(readHandle);
    CloseHandle(writeHandle);
    throw runtime_error("Failed to configure process output pipe.");
  }

  STARTUPINFOA startupInfo{};
  startupInfo.cb = sizeof(STARTUPINFOA);
  startupInfo.dwFlags = STARTF_USESTDHANDLES;
  startupInfo.hStdOutput = writeHandle;
  startupInfo.hStdError = writeHandle;
  startupInfo.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

  PROCESS_INFORMATION processInfo{};

  std::ostringstream commandLine;
  for (size_t index = 0; index < args.size(); ++index) {
    if (index != 0) {
      commandLine << ' ';
    }
    commandLine << QuoteWindowsArgument(args[index]);
  }
  string commandLineString = commandLine.str();

  BOOL created = CreateProcessA(
      nullptr,
      &commandLineString[0],
      nullptr,
      nullptr,
      TRUE,
      CREATE_NO_WINDOW,
      nullptr,
      nullptr,
      &startupInfo,
      &processInfo);

  CloseHandle(writeHandle);

  if (!created) {
    CloseHandle(readHandle);
    throw runtime_error("Failed to start auth helper process.");
  }

  std::array<char, 256> buffer{};
  DWORD bytesRead = 0;
  string output;
  while (ReadFile(readHandle, buffer.data(), static_cast<DWORD>(buffer.size()), &bytesRead, nullptr) && bytesRead > 0) {
    output.append(buffer.data(), bytesRead);
  }

  CloseHandle(readHandle);

  WaitForSingleObject(processInfo.hProcess, INFINITE);
  DWORD exitCode = 1;
  GetExitCodeProcess(processInfo.hProcess, &exitCode);
  CloseHandle(processInfo.hProcess);
  CloseHandle(processInfo.hThread);

  if (exitCode != 0) {
    throw runtime_error("Token helper script failed: " + TrimOutput(output));
  }

  return TrimOutput(output);
}
#else
string ExecuteProcess(const std::vector<string>& args) {
  if (args.empty()) {
    throw runtime_error("No process arguments were provided.");
  }

  int pipeFds[2] = {-1, -1};
  if (pipe(pipeFds) != 0) {
    throw runtime_error("Failed to create process output pipe.");
  }

  pid_t pid = fork();
  if (pid < 0) {
    close(pipeFds[0]);
    close(pipeFds[1]);
    throw runtime_error("Failed to start auth helper process.");
  }

  if (pid == 0) {
    dup2(pipeFds[1], STDOUT_FILENO);
    dup2(pipeFds[1], STDERR_FILENO);
    close(pipeFds[0]);
    close(pipeFds[1]);

    std::vector<char*> execArgs;
    execArgs.reserve(args.size() + 1);
    for (const auto& arg : args) {
      execArgs.push_back(const_cast<char*>(arg.c_str()));
    }
    execArgs.push_back(nullptr);
    execvp(execArgs[0], execArgs.data());
    _exit(127);
  }

  close(pipeFds[1]);
  std::array<char, 256> buffer{};
  string output;
  ssize_t count = 0;
  while ((count = read(pipeFds[0], buffer.data(), buffer.size())) > 0) {
    output.append(buffer.data(), static_cast<size_t>(count));
  }
  close(pipeFds[0]);

  int status = 0;
  waitpid(pid, &status, 0);
  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    throw runtime_error("Token helper script failed: " + TrimOutput(output));
  }

  return TrimOutput(output);
}
#endif

} // namespace

namespace sample {
namespace auth {

// Simple, hard coded token example
string AcquireToken() {
  string mToken = "your token here";
  return mToken;
}

// This function implements token acquisition by calling an external Python script.
// Username is used as a login hint for browser-based sign-in.
// Resource and authority are provided by the SDK challenge.
string AcquireToken(
    const string& username,
    const string& clientId,
    const string& resource,
    const string& authority) {
  string authScriptPath;
  if (sample::utils::FileExists("auth.py"))
    authScriptPath = "auth.py";
  else if (sample::utils::FileExists("samples/auth/auth.py"))
    authScriptPath = "samples/auth/auth.py";
  else
    throw runtime_error("Unable to find auth script.");

  std::vector<string> args = {
      "python",
      authScriptPath,
      "-u", username,
      "-a", authority,
      "-r", resource,
      "-c", clientId};

  string result = ExecuteProcess(args);
  if (result.empty())
    throw runtime_error("Failed to acquire token. Ensure Python and MSAL are installed correctly.");

  return result;
}

} // namespace auth
} // namespace sample
