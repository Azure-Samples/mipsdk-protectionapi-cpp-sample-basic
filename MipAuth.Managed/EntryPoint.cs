/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Identity.Client;

namespace MipAuth.Managed;

public static unsafe class EntryPoint
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    [UnmanagedCallersOnly(EntryPoint = "AcquireToken")]
    public static int AcquireToken(IntPtr requestPointer, int requestSize)
    {
        if (requestPointer == IntPtr.Zero ||
            requestSize < sizeof(uint) * 2)
        {
            return (int)AuthResult.InvalidRequest;
        }

        AuthRequest* request = (AuthRequest*)requestPointer;
        if (request->Version != AuthRequest.CurrentVersion ||
            request->StructSize < sizeof(AuthRequest) ||
            requestSize < sizeof(AuthRequest))
        {
            return (int)AuthResult.InvalidRequest;
        }

        request->TokenLength = 0;
        request->ErrorLength = 0;

        if (request->TokenBuffer == null ||
            request->ErrorBuffer == null ||
            request->TokenBufferCapacity < AuthRequest.MinimumBufferSize ||
            request->ErrorBufferCapacity < AuthRequest.MinimumBufferSize)
        {
            return Complete(request, AuthResult.BufferTooSmall, "Authentication buffers are too small.");
        }

        try
        {
            string username = ReadUtf8(request->Username, request->UsernameLength, 1024);
            string clientId = ReadUtf8(request->ClientId, request->ClientIdLength, 64);
            string authorityInput = ReadUtf8(request->Authority, request->AuthorityLength, 2048);
            string resourceInput = ReadUtf8(request->Resource, request->ResourceLength, 2048);
            string? claims = request->ClaimsLength == 0
                ? null
                : ReadUtf8(request->Claims, request->ClaimsLength, AuthRequest.MinimumBufferSize);

            Validation.ValidateIdentity(username, clientId);

            string authority;
            try
            {
                authority = Validation.NormalizeAuthority(authorityInput, username);
            }
            catch (ArgumentException)
            {
                return Complete(request, AuthResult.InvalidAuthority, "Invalid authority.");
            }

            string scope;
            try
            {
                scope = Validation.NormalizeScope(resourceInput);
            }
            catch (ArgumentException)
            {
                return Complete(request, AuthResult.InvalidResource, "Invalid resource.");
            }

            string token = TokenAcquirer.AcquireAsync(
                    username,
                    clientId,
                    authority,
                    scope,
                    claims ?? string.Empty)
                .GetAwaiter()
                .GetResult();

            if (string.IsNullOrEmpty(token))
            {
                return Complete(request, AuthResult.AuthenticationFailed, "Authentication failed.");
            }

            if (!WriteUtf8(request->TokenBuffer, request->TokenBufferCapacity, token, out int tokenLength))
            {
                return Complete(request, AuthResult.BufferTooSmall, "Authentication token is too large.");
            }

            request->TokenLength = tokenLength;
            return (int)AuthResult.Success;
        }
        catch (DecoderFallbackException)
        {
            return Complete(request, AuthResult.InvalidRequest, "Invalid authentication request.");
        }
        catch (ArgumentException)
        {
            return Complete(request, AuthResult.InvalidIdentity, "Invalid authentication request.");
        }
        catch (MsalException)
        {
            return Complete(request, AuthResult.AuthenticationFailed, "Authentication failed.");
        }
        catch
        {
            return Complete(request, AuthResult.InternalError, "Authentication failed.");
        }
    }

    private static string ReadUtf8(byte* pointer, int length, int maximumLength)
    {
        if (pointer == null || length <= 0 || length > maximumLength)
        {
            throw new ArgumentException("Invalid UTF-8 input.");
        }

        string value = StrictUtf8.GetString(new ReadOnlySpan<byte>(pointer, length));
        if (value.Contains('\0'))
        {
            throw new ArgumentException("Invalid UTF-8 input.");
        }

        return value;
    }

    private static bool WriteUtf8(byte* buffer, int capacity, string value, out int bytesWritten)
    {
        bytesWritten = StrictUtf8.GetByteCount(value);
        if (bytesWritten >= capacity)
        {
            bytesWritten = 0;
            return false;
        }

        StrictUtf8.GetBytes(value, new Span<byte>(buffer, capacity));
        buffer[bytesWritten] = 0;
        return true;
    }

    private static int Complete(AuthRequest* request, AuthResult result, string error)
    {
        request->TokenLength = 0;
        if (request->ErrorBuffer != null &&
            request->ErrorBufferCapacity > 0 &&
            WriteUtf8(request->ErrorBuffer, request->ErrorBufferCapacity, error, out int errorLength))
        {
            request->ErrorLength = errorLength;
        }

        return (int)result;
    }
}
