using System.Security.Claims;
using CredProx.Abstractions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// Executes the Abstractions members through their public shape. The M49 package split moved
/// these types out of the core assembly, where internal callers used to run them as part of
/// core behavior; behavior tests elsewhere still exercise the same code paths through them,
/// but nothing inside the new assembly's coverage scope runs them any more. These pins
/// execute the factories, guards, defaults and data holders directly.
/// </summary>
public class AbstractionsMemberTests
{
    private static CallerIdentity Identity() => new("acme", "key-1");

    private sealed class PassThrough : DelegatingHandler
    {
    }

    // Implements only the two required members, so Order and the context overload run their
    // interface defaults.
    private sealed class PlainPipelineFeature : IPipelineFeature
    {
        private readonly PassThrough _handler = new();

        public Stage Stage => Stage.Pipeline;

        public DelegatingHandler CreateHandler(DelegatingHandler innerHandler) => _handler;
    }

    // Implements only ApplyAsync, so Stage runs its interface default.
    private sealed class MinimalResponseFeature : IResponseFeature
    {
        public ValueTask ApplyAsync(HttpContext context, CancellationToken cancellationToken) =>
            ValueTask.CompletedTask;
    }

    [Fact]
    public void CallerAuthentication_NoCredential_IsSharedAndCarriesNothing()
    {
        var first = CallerAuthenticationResult.NoCredential();

        Assert.Same(first, CallerAuthenticationResult.NoCredential());
        Assert.Equal(CallerAuthenticationOutcome.NoCredential, first.Outcome);
        Assert.Null(first.Identity);
        Assert.Null(first.Scopes);
        Assert.Null(first.PresentedCredentialHeader);
        Assert.Null(first.Principal);
    }

    [Fact]
    public void CallerAuthentication_Refused_CarriesNoCredentialData()
    {
        var result = CallerAuthenticationResult.Refused();

        Assert.Equal(CallerAuthenticationOutcome.Refused, result.Outcome);
        Assert.Null(result.Identity);
        Assert.Null(result.Scopes);
        Assert.Null(result.PresentedCredentialHeader);
        Assert.Null(result.Principal);
    }

    [Fact]
    public void CallerAuthentication_Authenticated_IdentityOnly()
    {
        var result = CallerAuthenticationResult.Authenticated(Identity());

        Assert.Equal(CallerAuthenticationOutcome.Authenticated, result.Outcome);
        Assert.Equal(Identity(), result.Identity);
        Assert.Null(result.Scopes);
        Assert.Null(result.PresentedCredentialHeader);
        Assert.Null(result.Principal);
    }

    [Fact]
    public void CallerAuthentication_Authenticated_CarriesScopesHeaderAndPrincipal()
    {
        var scopes = new HashSet<string> { "read" };
        var principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "user-1")]));

        var result = CallerAuthenticationResult.Authenticated(
            Identity(), scopes, "X-Caller-Key", principal);

        Assert.Same(scopes, result.Scopes);
        Assert.Equal("X-Caller-Key", result.PresentedCredentialHeader);
        Assert.Same(principal, result.Principal);
    }

    [Fact]
    public void CallerAuthentication_Authenticated_NullIdentity_Throws()
    {
        var error = Assert.Throws<ArgumentNullException>(
            () => CallerAuthenticationResult.Authenticated(null!));

        Assert.Equal("identity", error.ParamName);
    }

    [Theory]
    [InlineData("")]
    [InlineData("caller key")]
    [InlineData("caller\tkey")]
    [InlineData("caller@key")]
    public void CallerAuthentication_Authenticated_MalformedHeader_Throws(string header)
    {
        var error = Assert.Throws<ArgumentException>(
            () => CallerAuthenticationResult.Authenticated(Identity(), null, header));

        Assert.Equal("presentedCredentialHeader", error.ParamName);
    }

    [Theory]
    [InlineData("ETag")]
    [InlineData("X-API-Key")]
    [InlineData("A!#$%&'*+-.^_`|~9z")]
    public void CallerAuthentication_Authenticated_AcceptsTokenCharacters(string header)
    {
        var result = CallerAuthenticationResult.Authenticated(Identity(), null, header);

        Assert.Equal(header, result.PresentedCredentialHeader);
    }

    [Fact]
    public void CallerIdentity_ClaimTypes_AreStable()
    {
        Assert.Equal("credprox.caller", CallerIdentity.CallerClaimType);
        Assert.Equal("credprox.keyid", CallerIdentity.KeyIdClaimType);
        Assert.Equal("credprox.clientid", CallerIdentity.ClientIdClaimType);
    }

    [Fact]
    public void CallerIdentity_FromPrincipal_Null_ReturnsNull()
    {
        Assert.Null(CallerIdentity.FromPrincipal(null));
    }

    [Theory]
    [InlineData(false, false, false)]
    [InlineData(true, false, false)]
    [InlineData(true, true, false)]
    [InlineData(true, true, true)]
    public void CallerIdentity_FromPrincipal_ReadsExactlyThePresentClaims(
        bool withCaller, bool withKeyId, bool withClientId)
    {
        var claims = new List<Claim>();
        if (withCaller)
        {
            claims.Add(new Claim(CallerIdentity.CallerClaimType, "acme"));
        }

        if (withKeyId)
        {
            claims.Add(new Claim(CallerIdentity.KeyIdClaimType, "key-1"));
        }

        if (withClientId)
        {
            claims.Add(new Claim(CallerIdentity.ClientIdClaimType, "client-1"));
        }

        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims));
        var identity = CallerIdentity.FromPrincipal(principal);

        if (!withCaller)
        {
            Assert.Null(identity);
            return;
        }

        Assert.NotNull(identity);
        Assert.Equal("acme", identity.CallerId);
        Assert.Equal(withKeyId ? "key-1" : string.Empty, identity.KeyId);
        Assert.Equal(withClientId ? "client-1" : null, identity.ClientId);
    }

    [Fact]
    public void CallerIdentity_FromPrincipal_EmptyCallerClaim_ReturnsNull()
    {
        var principal = new ClaimsPrincipal(
            new ClaimsIdentity([new Claim(CallerIdentity.CallerClaimType, string.Empty)]));

        Assert.Null(CallerIdentity.FromPrincipal(principal));
    }

    // Construction behind a void call so the guard's ArgumentException (not the exception
    // under construction) is what reaches the assert.
    private static void ThrowConsent(string? authorizeUrl) =>
        _ = new ConsentRequiredException(authorizeUrl!, "message");

    private static void ThrowInbound(string? reason) =>
        _ = new InboundTokenRejectedException(reason!, "message");

    [Fact]
    public void ConsentRequired_CarriesUrlAndMessage()
    {
        var error = new ConsentRequiredException("https://idp.example/authorize", "no consent");

        Assert.Equal("https://idp.example/authorize", error.AuthorizeUrl);
        Assert.Equal("no consent", error.Message);
        Assert.IsAssignableFrom<InvalidOperationException>(error);
    }

    [Fact]
    public void ConsentRequired_RejectsEmptyAuthorizeUrl()
    {
        var error = Assert.Throws<ArgumentException>(() => ThrowConsent(string.Empty));

        Assert.Equal("authorizeUrl", error.ParamName);
    }

    [Fact]
    public void ConsentRequired_RejectsNullAuthorizeUrl()
    {
        var error = Assert.Throws<ArgumentNullException>(() => ThrowConsent(null));

        Assert.Equal("authorizeUrl", error.ParamName);
    }

    [Fact]
    public void InboundTokenRejected_CarriesReasonAndMessage()
    {
        var error = new InboundTokenRejectedException("signature", "aud check passed, sig did not");

        Assert.Equal("signature", error.Reason);
        Assert.Equal("aud check passed, sig did not", error.Message);
        Assert.IsAssignableFrom<InvalidOperationException>(error);
    }

    [Fact]
    public void InboundTokenRejected_RejectsEmptyReason()
    {
        var error = Assert.Throws<ArgumentException>(() => ThrowInbound(string.Empty));

        Assert.Equal("reason", error.ParamName);
    }

    [Fact]
    public void InboundTokenRejected_RejectsNullReason()
    {
        var error = Assert.Throws<ArgumentNullException>(() => ThrowInbound(null));

        Assert.Equal("reason", error.ParamName);
    }

    [Fact]
    public void HealthResult_RoundTripsWithValueEquality()
    {
        var result = new CredProxHealthResult(CredProxHealthSeverity.Degraded, "certificate expires soon");

        Assert.Equal(CredProxHealthSeverity.Degraded, result.Severity);
        Assert.Equal("certificate expires soon", result.Description);
        Assert.Equal(
            new CredProxHealthResult(CredProxHealthSeverity.Degraded, "certificate expires soon"),
            result);
    }

    [Fact]
    public void PipelineFeatureContext_RoundTripsWithValueEquality()
    {
        var context = new PipelineFeatureContext("cluster-a");

        Assert.Equal("cluster-a", context.ClusterId);
        Assert.Equal(new PipelineFeatureContext("cluster-a"), context);
    }

    [Fact]
    public void CallerKeyMatch_RoundTripsWithValueEquality()
    {
        var match = new CallerKeyMatch(Identity());

        Assert.Equal(Identity(), match.Identity);
        Assert.Equal(new CallerKeyMatch(Identity()), match);
    }

    [Fact]
    public void CallerRegistryEntry_KeepsIdAndLiveSection()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string, string?> { ["CredProx:Callers:acme:Audience"] = "vendor" }).Build();
        var section = configuration.GetSection("CredProx:Callers:acme");

        var entry = new CallerRegistryEntry("acme", section);

        Assert.Equal("acme", entry.CallerId);
        Assert.Same(section, entry.Configuration);
        Assert.Equal("vendor", entry.Configuration["Audience"]);
    }

    [Fact]
    public void PipelineFeature_OrderDefaultsToZero()
    {
        IPipelineFeature feature = new PlainPipelineFeature();

        Assert.Equal(0, feature.Order);
    }

    [Fact]
    public void PipelineFeature_ContextOverloadFallsBackToThePlainOverload()
    {
        IPipelineFeature feature = new PlainPipelineFeature();
        var inner = new PassThrough();

        Assert.Same(
            feature.CreateHandler(inner),
            feature.CreateHandler(inner, new PipelineFeatureContext("cluster-a")));
    }

    [Fact]
    public void ResponseFeature_StageDefaultsToShapeResponse()
    {
        IResponseFeature feature = new MinimalResponseFeature();

        Assert.Equal(Stage.ShapeResponse, feature.Stage);
    }
}
