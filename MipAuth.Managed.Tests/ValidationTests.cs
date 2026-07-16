/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */

using Microsoft.Identity.Client;
using Xunit;

namespace MipAuth.Managed.Tests;

public sealed class ValidationTests
{
    [Theory]
    [InlineData("https://login.microsoftonline.com/common", "user@contoso.com", "https://login.microsoftonline.com/contoso.com")]
    [InlineData("https://login.windows.net/contoso.onmicrosoft.com/", "user@ignored.example", "https://login.microsoftonline.com/contoso.onmicrosoft.com")]
    [InlineData("https://login.microsoftonline.us/organizations", "user@contoso.us", "https://login.microsoftonline.us/contoso.us")]
    [InlineData("https://login.partner.microsoftonline.cn/11111111-1111-1111-1111-111111111111", "user@ignored.example", "https://login.partner.microsoftonline.cn/11111111-1111-1111-1111-111111111111")]
    public void NormalizeAuthorityAcceptsSupportedAuthorities(
        string input,
        string username,
        string expected)
    {
        Assert.Equal(expected, Validation.NormalizeAuthority(input, username));
    }

    [Theory]
    [InlineData("http://login.microsoftonline.com/common")]
    [InlineData("https://evil.example/common")]
    [InlineData("https://login.microsoftonline.com:443/common")]
    [InlineData("https://login.microsoftonline.com/common/extra")]
    [InlineData("https://login.microsoftonline.com/common//")]
    [InlineData("https://login.microsoftonline.com/common?prompt=login")]
    [InlineData("https://user@login.microsoftonline.com/common")]
    public void NormalizeAuthorityRejectsUntrustedAuthorities(string input)
    {
        Assert.Throws<ArgumentException>(() =>
            Validation.NormalizeAuthority(input, "user@contoso.com"));
    }

    [Theory]
    [InlineData("user")]
    [InlineData("user@bad..example")]
    [InlineData("user@-bad.example")]
    public void NormalizeAuthorityRejectsInvalidDerivedTenant(string username)
    {
        Assert.Throws<ArgumentException>(() =>
            Validation.NormalizeAuthority(
                "https://login.microsoftonline.com/common",
                username));
    }

    [Theory]
    [InlineData("https://aadrm.com", "https://aadrm.com/.default")]
    [InlineData("https://aadrm.us/", "https://aadrm.us/.default")]
    [InlineData("https://aadrm.cn", "https://aadrm.cn/.default")]
    [InlineData("https://api.aadrm.com", "https://api.aadrm.com/.default")]
    [InlineData("https://api.aadrm.us/", "https://api.aadrm.us/.default")]
    [InlineData("https://api.aadrm.cn", "https://api.aadrm.cn/.default")]
    public void NormalizeScopeUsesDefaultScope(string input, string expected)
    {
        Assert.Equal(expected, Validation.NormalizeScope(input));
    }

    [Theory]
    [InlineData("http://api.aadrm.com")]
    [InlineData("https://api.aadrm.com:443")]
    [InlineData("https://api.aadrm.com/path")]
    [InlineData("https://api.aadrm.com/./")]
    [InlineData("https://api.aadrm.com?x=1")]
    [InlineData("https://evil.aadrm.com")]
    [InlineData("https://example.com")]
    public void NormalizeScopeRejectsUntrustedResources(string input)
    {
        Assert.Throws<ArgumentException>(() => Validation.NormalizeScope(input));
    }

    [Fact]
    public void ValidateIdentityRequiresGuidClientIdAndUsername()
    {
        Validation.ValidateIdentity("user@contoso.com", "11111111-1111-1111-1111-111111111111");

        Assert.Throws<ArgumentException>(() => Validation.ValidateIdentity("user name", "11111111-1111-1111-1111-111111111111"));
        Assert.Throws<ArgumentException>(() => Validation.ValidateIdentity("user@contoso.com", "not-a-guid"));
    }

    [Fact]
    public void AccountSelectionMatchesOnlyRequestedUsername()
    {
        IAccount[] accounts =
        [
            new TestAccount("other@contoso.com"),
            new TestAccount("USER@CONTOSO.COM"),
        ];

        IAccount match = Assert.Single(TokenAcquirer.FindUsernameMatches(accounts, "user@contoso.com"));
        Assert.Equal("USER@CONTOSO.COM", match.Username);
    }

    private sealed class TestAccount(string username) : IAccount
    {
        public string Username { get; } = username;
        public string Environment => "login.microsoftonline.com";
        public AccountId HomeAccountId { get; } = new("id", "tenant", "id.tenant");
    }
}
