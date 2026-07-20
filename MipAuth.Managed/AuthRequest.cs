/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */

using System.Runtime.InteropServices;

namespace MipAuth.Managed;

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct AuthRequest
{
    internal const uint CurrentVersion = 1;
    internal const int MinimumBufferSize = 64 * 1024;

    internal uint Version;
    internal uint StructSize;

    internal byte* Username;
    internal int UsernameLength;
    internal int UsernameReserved;

    internal byte* ClientId;
    internal int ClientIdLength;
    internal int ClientIdReserved;

    internal byte* Authority;
    internal int AuthorityLength;
    internal int AuthorityReserved;

    internal byte* Resource;
    internal int ResourceLength;
    internal int ResourceReserved;

    internal byte* Claims;
    internal int ClaimsLength;
    internal int ClaimsReserved;

    internal byte* TokenBuffer;
    internal int TokenBufferCapacity;
    internal int TokenLength;

    internal byte* ErrorBuffer;
    internal int ErrorBufferCapacity;
    internal int ErrorLength;
}

internal enum AuthResult
{
    Success = 0,
    InvalidRequest = 1,
    InvalidAuthority = 2,
    InvalidResource = 3,
    InvalidIdentity = 4,
    BufferTooSmall = 5,
    AuthenticationFailed = 6,
    InternalError = 7,
}
