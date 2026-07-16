/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */

using System.Text.RegularExpressions;

namespace MipAuth.Managed;

internal static partial class Validation
{
    private static readonly IReadOnlyDictionary<string, string> AuthorityHosts =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["login.microsoftonline.com"] = "login.microsoftonline.com",
            ["login.microsoftonline.us"] = "login.microsoftonline.us",
            ["login.partner.microsoftonline.cn"] = "login.partner.microsoftonline.cn",
            ["login.windows.net"] = "login.microsoftonline.com",
        };

    private static readonly HashSet<string> ResourceHosts =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "aadrm.com",
            "aadrm.us",
            "aadrm.cn",
            "api.aadrm.com",
            "api.aadrm.us",
            "api.aadrm.cn",
        };

    [GeneratedRegex(@"^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$", RegexOptions.CultureInvariant)]
    private static partial Regex TenantPattern();

    internal static string NormalizeAuthority(string authority, string username)
    {
        if (!TryCreateStrictHttpsUri(authority, out Uri uri) ||
            !AuthorityHosts.TryGetValue(uri.IdnHost, out string? normalizedHost))
        {
            throw new ArgumentException("Invalid authority.", nameof(authority));
        }

        string path = GetRawPath(authority);
        if (path.EndsWith('/'))
        {
            path = path[..^1];
        }

        if (path.Length < 2 || path.IndexOf('/', 1) >= 0)
        {
            throw new ArgumentException("Invalid authority.", nameof(authority));
        }

        string tenant = path[1..];
        if (!TenantPattern().IsMatch(tenant))
        {
            throw new ArgumentException("Invalid authority.", nameof(authority));
        }

        if (tenant.Equals("common", StringComparison.OrdinalIgnoreCase) ||
            tenant.Equals("organizations", StringComparison.OrdinalIgnoreCase))
        {
            tenant = GetTenantDomain(username);
        }

        return $"https://{normalizedHost}/{tenant}";
    }

    internal static string NormalizeScope(string resource)
    {
        if (!TryCreateStrictHttpsUri(resource, out Uri uri) ||
            !ResourceHosts.Contains(uri.IdnHost) ||
            GetRawPath(resource) is not ("" or "/"))
        {
            throw new ArgumentException("Invalid resource.", nameof(resource));
        }

        return $"https://{uri.IdnHost.ToLowerInvariant()}/.default";
    }

    internal static void ValidateIdentity(string username, string clientId)
    {
        if (string.IsNullOrWhiteSpace(username) ||
            username.Length > 320 ||
            username.Any(char.IsWhiteSpace) ||
            username.Contains('\0') ||
            !Guid.TryParseExact(clientId, "D", out _))
        {
            throw new ArgumentException("Invalid identity.");
        }
    }

    private static bool TryCreateStrictHttpsUri(string value, out Uri uri)
    {
        uri = null!;
        int authorityStart = value.IndexOf("://", StringComparison.OrdinalIgnoreCase);
        authorityStart = authorityStart < 0 ? -1 : authorityStart + 3;
        int authorityEnd = authorityStart < 0
            ? -1
            : value.IndexOfAny(['/', '?', '#'], authorityStart);
        string rawAuthority = authorityStart < 0
            ? string.Empty
            : value[authorityStart..(authorityEnd < 0 ? value.Length : authorityEnd)];

        if (string.IsNullOrEmpty(value) ||
            value.Length > 2048 ||
            value.Any(char.IsWhiteSpace) ||
            value.Contains('\0') ||
            !Uri.TryCreate(value, UriKind.Absolute, out Uri? candidate) ||
            !candidate.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ||
            !string.IsNullOrEmpty(candidate.UserInfo) ||
            !string.IsNullOrEmpty(candidate.Query) ||
            !string.IsNullOrEmpty(candidate.Fragment) ||
            !rawAuthority.Equals(candidate.IdnHost, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        uri = candidate;
        return true;
    }

    private static string GetRawPath(string value)
    {
        int authorityStart = value.IndexOf("://", StringComparison.OrdinalIgnoreCase) + 3;
        int pathStart = value.IndexOf('/', authorityStart);
        return pathStart < 0 ? string.Empty : value[pathStart..];
    }

    private static string GetTenantDomain(string username)
    {
        int separator = username.LastIndexOf('@');
        string domain = separator > 0 && separator < username.Length - 1
            ? username[(separator + 1)..].ToLowerInvariant()
            : string.Empty;
        if (domain.Length is 0 or > 253 ||
            domain.Any(character => character > 0x7f) ||
            domain.Split('.').Any(label =>
                label.Length is 0 or > 63 ||
                !char.IsAsciiLetterOrDigit(label[0]) ||
                !char.IsAsciiLetterOrDigit(label[^1]) ||
                label.Any(character =>
                    !char.IsAsciiLetterOrDigit(character) && character != '-')))
        {
            throw new ArgumentException("Invalid identity.");
        }

        return domain;
    }
}
