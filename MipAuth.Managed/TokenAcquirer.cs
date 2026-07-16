/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */

using System.Collections.Concurrent;
using Microsoft.Identity.Client;

namespace MipAuth.Managed;

internal static class TokenAcquirer
{
    private readonly record struct ApplicationKey(string ClientId, string Authority);

    private static readonly ConcurrentDictionary<ApplicationKey, Lazy<IPublicClientApplication>> Applications = new();

    internal static async Task<string?> AcquireAsync(
        string username,
        string clientId,
        string authority,
        string scope,
        string? claims)
    {
        var key = new ApplicationKey(clientId, authority);
        IPublicClientApplication application = Applications.GetOrAdd(
            key,
            static value => new Lazy<IPublicClientApplication>(
                () => PublicClientApplicationBuilder
                    .Create(value.ClientId)
                    .WithAuthority(value.Authority)
                    .WithDefaultRedirectUri()
                    .Build(),
                LazyThreadSafetyMode.ExecutionAndPublication)).Value;

        IEnumerable<IAccount> accounts;
        try
        {
            accounts = await application.GetAccountsAsync().ConfigureAwait(false);
        }
        catch (MsalException)
        {
            accounts = [];
        }

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
            catch (MsalException)
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
}
