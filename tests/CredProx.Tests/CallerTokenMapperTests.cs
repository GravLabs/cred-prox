using System.Security.Cryptography;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M39 outcome B: the principal-to-caller mapping layer. The mapper reads the client id
/// from the configured claim names, matches it (case-insensitively) against every
/// caller's declared token client ids, and yields a caller identity whose key id names
/// the token (uti, then jti) — never any token material. No client claim, no listed
/// client or an unlisted client maps to nothing: a valid token from an unknown app is
/// not a caller.
/// </summary>
public sealed class CallerTokenMapperTests
{
    private static string Hash() =>
        "sha256:" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("unused"))).ToLowerInvariant();

    private static CallerRegistryProvider Registry(params (string Caller, string[]? TokenClients)[] callers)
    {
        var entries = new Dictionary<string, string?>();
        foreach (var (caller, tokenClients) in callers)
        {
            if (tokenClients is { Length: > 0 })
            {
                // Token-only callers declare no key at all; keyed callers keep their key.
                if (tokenClients is not null)
                {
                    for (var i = 0; i < tokenClients.Length; i++)
                    {
                        entries[$"CredProx:Callers:{caller}:TokenClientIds:{i}"] = tokenClients[i];
                    }
                }
            }
            else
            {
                entries[$"CredProx:Callers:{caller}:Keys:0:KeyId"] = "k1";
                entries[$"CredProx:Callers:{caller}:Keys:0:KeyHash"] = Hash();
            }
        }

        var config = new ConfigurationBuilder().AddInMemoryCollection(entries).Build();
        return new CallerRegistryProvider(
            new CallerBinder(config, new SecretAccessorFactory(new ConfigurationSecretSource(config))),
            new ConfigurationSecretSource(config),
            NullLogger<CallerRegistryProvider>.Instance);
    }

    private static DefaultCallerTokenMapper Mapper(
        CallerRegistryProvider provider,
        CallerTokenOptions? options = null) =>
        new(provider, options ?? new CallerTokenOptions());

    private static ClaimsPrincipal Principal(params (string Type, string Value)[] claims) =>
        new(new ClaimsIdentity(claims.Select(c => new Claim(c.Type, c.Value)), authenticationType: "test"));

    [Fact]
    public void ListedClient_MapsToCallerWithTokenKeyId()
    {
        var mapper = Mapper(Registry(("agent-1", ["client-abc"])));
        var mapping = mapper.MapToken(Principal(("azp", "client-abc"), ("uti", "tid-9")));

        Assert.NotNull(mapping);
        Assert.Equal("agent-1", mapping!.Identity.CallerId);
        Assert.Equal("token:tid-9", mapping.Identity.KeyId);
        Assert.Empty(mapping.Scopes);
    }

    [Fact]
    public void MappedRoleClaimType_PopulatesScopes_WhenConfigured()
    {
        // M39 fold F3: the caller-token scheme maps nothing, so the long role claim type
        // appears only from an issuer that names it directly or a host that turns inbound
        // mapping back on — met by configuration, not by shipping the URIs as defaults.
        var mapper = Mapper(
            Registry(("agent-1", ["client-abc"])),
            new CallerTokenOptions
            {
                ScopeClaimNames = ["roles", "scp", "http://schemas.microsoft.com/ws/2008/06/identity/claims/role"],
            });
        var mapping = mapper.MapToken(Principal(
            ("azp", "client-abc"),
            ("http://schemas.microsoft.com/ws/2008/06/identity/claims/role", "reports-read")));

        Assert.Equal("reports-read", Assert.Single(mapping!.Scopes));
    }

    [Fact]
    public void ListedClient_IdentityCarriesTheMatchedClientId()
    {
        // M39 outcome C (ADR-0004 audit): the client id the token was issued to rides
        // on the identity so audit can record it — the token itself never does.
        var mapper = Mapper(Registry(("agent-1", ["client-abc"])));
        var mapping = mapper.MapToken(Principal(("appid", "Client-ABC"), ("uti", "tid-1")));

        Assert.Equal("Client-ABC", mapping!.Identity.ClientId);
    }

    [Fact]
    public void UnlistedClient_MapsToNull()
    {
        var mapper = Mapper(Registry(("agent-1", ["client-abc"])));
        Assert.Null(mapper.MapToken(Principal(("azp", "client-OTHER"), ("uti", "t1"))));
    }

    [Fact]
    public void NoClientClaim_MapsToNull()
    {
        var mapper = Mapper(Registry(("agent-1", ["client-abc"])));
        Assert.Null(mapper.MapToken(Principal(("uti", "t1"))));
    }

    [Fact]
    public void EmptyClientClaim_MapsToNull()
    {
        var mapper = Mapper(Registry(("agent-1", ["client-abc"])));
        Assert.Null(mapper.MapToken(Principal(("azp", ""), ("uti", "t1"))));
    }

    [Fact]
    public void AzpBeatsAppid()
    {
        // azp is listed first: it wins; the appid value is never consulted.
        var mapper = Mapper(Registry(("agent-1", ["from-azp"]), ("agent-2", ["from-appid"])));
        var mapping = mapper.MapToken(Principal(("azp", "from-azp"), ("appid", "from-appid")));
        Assert.Equal("agent-1", mapping!.Identity.CallerId);
    }

    [Fact]
    public void AppidUsedWhenNoAzp()
    {
        var mapper = Mapper(Registry(("agent-1", ["v1-client"])));
        Assert.Equal("agent-1", mapper.MapToken(Principal(("appid", "v1-client")))!.Identity.CallerId);
    }

    [Fact]
    public void UtiBeatsJti_JtiThenUnknown()
    {
        var mapper = Mapper(Registry(("agent-1", ["c1"])));
        Assert.Equal("token:u", mapper.MapToken(Principal(("azp", "c1"), ("uti", "u"), ("jti", "j")))!.Identity.KeyId);
        Assert.Equal("token:j", mapper.MapToken(Principal(("azp", "c1"), ("jti", "j")))!.Identity.KeyId);
        Assert.Equal("token:unknown", mapper.MapToken(Principal(("azp", "c1")))!.Identity.KeyId);
    }

    [Fact]
    public void MatchingIsCaseInsensitive()
    {
        var mapper = Mapper(Registry(("agent-1", ["Client-Abc"])));
        Assert.NotNull(mapper.MapToken(Principal(("azp", "client-ABC"))));
    }

    [Fact]
    public void RolesBeatScp_AllValuesOfFirstPresentClaim()
    {
        var mapper = Mapper(Registry(("agent-1", ["c1"])));
        var mapping = mapper.MapToken(Principal(
            ("azp", "c1"),
            ("roles", "read"),
            ("roles", "write"),
            ("scp", "ignored")));
        Assert.True(mapping!.Scopes.SetEquals(["read", "write"]));
    }

    [Fact]
    public void ScpUsedWhenNoRoles()
    {
        var mapper = Mapper(Registry(("agent-1", ["c1"])));
        var mapping = mapper.MapToken(Principal(("azp", "c1"), ("scp", "api://x/access_as_user")));
        Assert.True(mapping!.Scopes.SetEquals(["api://x/access_as_user"]));
    }

    [Fact]
    public void CustomClaimNames_AreHonoured()
    {
        var mapper = Mapper(
            Registry(("agent-1", ["c1"])),
            new CallerTokenOptions { ClientClaimNames = ["cid"], ScopeClaimNames = ["permissions"] });
        var mapping = mapper.MapToken(Principal(("cid", "c1"), ("permissions", "p1"), ("azp", "nope")));
        Assert.Equal("agent-1", mapping!.Identity.CallerId);
        Assert.True(mapping.Scopes.SetEquals(["p1"]));
    }

    [Fact]
    public void TokenOnlyCaller_IsMatchable()
    {
        var provider = Registry(("token-only", ["c1"]));
        // The definition bound with zero keys — the token clients are its credential.
        Assert.True(provider.Current.TryGet("token-only", out var definition));
        Assert.Empty(definition!.Keys);
        Assert.Equal("token-only", Mapper(provider).MapToken(Principal(("azp", "c1")))!.Identity.CallerId);
    }

    [Fact]
    public void MultipleCallers_FirstMatchWinsAcrossRegistry()
    {
        var mapper = Mapper(Registry(("agent-1", ["one"]), ("agent-2", ["two"])));
        Assert.Equal("agent-2", mapper.MapToken(Principal(("azp", "two")))!.Identity.CallerId);
    }
}
