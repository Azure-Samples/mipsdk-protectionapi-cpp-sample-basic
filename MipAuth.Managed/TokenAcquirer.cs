/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */

using System.Collections.Concurrent;
using Microsoft.Identity.Client;

namespace MipAuth.Managed;

internal static class TokenAcquirer
{
    private static readonly ConcurrentDictionary<string, IPublicClientApplication> Applications =
        new(StringComparer.Ordinal);

    internal static async Task<string?> AcquireAsync(
        string username,
        string clientId,
        string authority,
        string scope,
        string? claims)
    {
        string normalizedAuthority = NormalizeAuthorityForMsal(authority, username);
        string cacheKey = $"{clientId}\n{normalizedAuthority}";
        IPublicClientApplication application = Applications.GetOrAdd(
            cacheKey,
            _ => PublicClientApplicationBuilder
                .Create(clientId)
                .WithAuthority(normalizedAuthority)
                .WithDefaultRedirectUri()
                .Build());

        IEnumerable<IAccount> accounts = await application.GetAccountsAsync().ConfigureAwait(false);

        foreach (IAccount account in FindUsernameMatches(accounts, username))
        {
            try
            {
                AcquireTokenSilentParameterBuilder silent =
                    application.AcquireTokenSilent([scope], account);
                if (!string.IsNullOrEmpty(claims))
                {
                    silent = silent.WithClaims(claims);
                }

                AuthenticationResult result = await silent.ExecuteAsync().ConfigureAwait(false);
                if (!string.IsNullOrEmpty(result.AccessToken))
                {
                    return result.AccessToken;
                }
            }
            catch (MsalUiRequiredException)
            {
            }
        }

        AcquireTokenInteractiveParameterBuilder interactive =
            application.AcquireTokenInteractive([scope])
                .WithLoginHint(username)
                .WithUseEmbeddedWebView(false);
        if (!string.IsNullOrEmpty(claims))
        {
            interactive = interactive.WithClaims(claims);
        }

        AuthenticationResult interactiveResult =
            await interactive.ExecuteAsync().ConfigureAwait(false);
        return string.IsNullOrEmpty(interactiveResult.AccessToken)
            ? null
            : interactiveResult.AccessToken;
    }

    internal static IEnumerable<IAccount> FindUsernameMatches(
        IEnumerable<IAccount> accounts,
        string username) =>
        accounts.Where(
            account => string.Equals(
                account.Username,
                username,
                StringComparison.OrdinalIgnoreCase));

    internal static string NormalizeAuthorityForMsal(string authority, string username)
    {
        if (!Uri.TryCreate(authority, UriKind.Absolute, out Uri? uri))
        {
            return authority;
        }

        string path = uri.AbsolutePath.Trim('/');
        if (!path.Equals("common", StringComparison.OrdinalIgnoreCase) &&
            !path.Equals("organizations", StringComparison.OrdinalIgnoreCase))
        {
            return authority.TrimEnd('/');
        }

        string tenant = GetTenantDomain(username);
        return $"https://{uri.IdnHost.ToLowerInvariant()}/{tenant}";
    }

    private static string GetTenantDomain(string username)
    {
        int separator = username.LastIndexOf('@');
        string domain = separator > 0 && separator < username.Length - 1
            ? username[(separator + 1)..].ToLowerInvariant()
            : string.Empty;
        if (!IsValidDnsHost(domain))
        {
            throw new ArgumentException("Username must contain a valid tenant domain.");
        }

        return domain;
    }

    private static bool IsValidDnsHost(string host)
    {
        if (host.Length is 0 or > 253 || host.Any(character => character > 0x7f))
        {
            return false;
        }

        foreach (string label in host.Split('.'))
        {
            if (label.Length is 0 or > 63 ||
                !char.IsAsciiLetterOrDigit(label[0]) ||
                !char.IsAsciiLetterOrDigit(label[^1]) ||
                label.Any(character =>
                    !char.IsAsciiLetterOrDigit(character) && character != '-'))
            {
                return false;
            }
        }

        return true;
    }
}
