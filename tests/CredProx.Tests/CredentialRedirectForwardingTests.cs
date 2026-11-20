using System.Net;
using CredProx.Abstractions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// A host-supplied primary handler that performs the redirect itself over its own inner
/// client never mutates the caller's <see cref="HttpRequestMessage"/> — which was the
/// guard's only signal. The acceptance rule (the decision recorded 14:21Z on row
/// 1c0ffce3) is about where the
/// response CLAIMS to have ended: a response stamped with an effective request URI other
/// than the configured endpoint (scheme, host, port, path) is refused — that is the R-1
/// attack shape; a response that carries no stamp at all is accepted on that basis alone,
/// because every shipped transport stamps its responses and refusing absence would
/// break host test suites on a patch release; the 3xx refusal applies regardless.
/// Shape adapted from the adversarial Gd probe of the M45 security work.
/// </summary>
public sealed class CredentialRedirectForwardingTests : IAsyncLifetime
{
    private readonly List<string> _evilHits = [];
    private IHost _idp = null!;
    private IHost _evil = null!;
    private int _idpPort;
    private int _evilPort;

    public Task InitializeAsync()
    {
        _evil = Start(ctx =>
        {
            lock (_evilHits)
            {
                _evilHits.Add($"{ctx.Request.Method} {ctx.Request.Path}");
            }

            ctx.Response.ContentType = "application/json";
            return ctx.Response.WriteAsync(
                """{"access_token":"EVIL-TOKEN","expires_in":3600,"token_type":"Bearer"}""");
        });
        _evilPort = ReadPort(_evil);

        _idp = Start(async ctx =>
        {
            var path = ctx.Request.Path.Value ?? string.Empty;
            if (path.StartsWith("/cc-302", StringComparison.Ordinal))
            {
                ctx.Response.StatusCode = 302;
                ctx.Response.Headers.Location = $"http://127.0.0.1:{_evilPort}/token-target";
                return;
            }

            if (path.StartsWith("/cc-ok", StringComparison.Ordinal))
            {
                ctx.Response.ContentType = "application/json";
                await ctx.Response.WriteAsync(
                    """{"access_token":"GOOD-TOKEN","expires_in":3600,"token_type":"Bearer"}""");
            }
            else
            {
                ctx.Response.StatusCode = 404;
            }
        });
        _idpPort = ReadPort(_idp);
        return Task.CompletedTask;
    }

    public async Task DisposeAsync()
    {
        await _evil.StopAsync();
        _evil.Dispose();
        await _idp.StopAsync();
        _idp.Dispose();
    }

    private static IHost Start(RequestDelegate handler)
    {
        var host = new HostBuilder()
            .ConfigureWebHost(web =>
            {
                web.UseKestrel(o => o.Listen(IPAddress.Loopback, 0));
                web.ConfigureLogging(l => l.ClearProviders());
                web.Configure(app => app.Run(handler));
            })
            .Start();
        return host;
    }

    private static int ReadPort(IHost host) => new Uri(host.Services.GetRequiredService<IServer>()
        .Features.Get<IServerAddressesFeature>()!.Addresses.First()).Port;

    private string Idp(string path) => $"http://127.0.0.1:{_idpPort}{path}";

    /// <summary>The shipped named-client registrations with a host-supplied primary handler —
    /// exactly the injection the Gd probe used: everything CredProx wires stays, only the
    /// transport underneath is the host's.</summary>
    private static IHttpClientFactory TokenFactoryWithPrimary(Func<HttpMessageHandler> primary)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddCredProxOAuth();
        services.AddHttpClient(CredProxHttpClientNames.TokenClient)
            .ConfigurePrimaryHttpMessageHandler(primary);
        return services.BuildServiceProvider().GetRequiredService<IHttpClientFactory>();
    }

    private static InMemoryTokenCache Cache() =>
        new(Options.Create(new TokenCacheOptions()), TimeProvider.System);

    private async Task<string> MintAsync(string endpointPath)
    {
        var provider = new OAuthClientCredentialsProvider(
            Cache(), TokenFactoryWithPrimary(static () => new ForwardingHandler()), TimeProvider.System);
        var token = await provider.GetCredentialAsync(
            new OAuthClientCredentialsOptions
            {
                TokenEndpoint = Idp(endpointPath),
                ClientId = "cid",
                ClientSecret = "csec",
            },
            TestSecrets.AccessorFor([]),
            new CredentialRequestContext { CredentialName = "probe", Partition = "p1" },
            default);
        return token;
    }

    // ---- the evasion: a forward-to-evil mint must be a refusal ----

    [Fact]
    public async Task ForwardingPrimaryHandler_EvadingVia302_Refused_NoEvilToken()
    {
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => MintAsync("/cc-302"));
        Assert.Contains("redirect", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("EVIL", ex.Message, StringComparison.Ordinal);
    }

    // ---- the control: the same handler, no redirect in play, still mints ----

    [Fact]
    public async Task ForwardingPrimaryHandler_Direct200_StillMints()
    {
        lock (_evilHits)
        {
            _evilHits.Clear();
        }

        Assert.Equal("GOOD-TOKEN", await MintAsync("/cc-ok"));
        lock (_evilHits)
        {
            Assert.Empty(_evilHits);
        }
    }

    // ---- the acceptance rule, at the unit ------------------------------
    //
    // The guard exists as one internal copy per package assembly (core, OAuth,
    // LoginExchange) with the same namespace, so the name is ambiguous from a test
    // project that references all three; these units reach the OAuth copy — the one
    // the OAuth mint path compiles against — through its own assembly.

    private static readonly System.Reflection.MethodInfo EndsElsewhereMethod =
        typeof(OAuthClientCredentialsProvider).Assembly
            .GetType("CredProx.CredProxRedirectGuard", throwOnError: true)!
            .GetMethod("EndsElsewhere", System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic)!;

    private static bool EndsElsewhere(HttpResponseMessage response, Uri configured) =>
        (bool)EndsElsewhereMethod.Invoke(null, [response, configured])!;

    [Fact]
    public void ResponseFromSameAddress_DifferentQuery_CountsAsEndedAtEndpoint()
    {
        var response = EndedAt("http://127.0.0.1:9/t?x=1");
        Assert.False(EndsElsewhere(response, new Uri("http://127.0.0.1:9/t")));
    }

    [Fact]
    public void ResponseFromDifferentPath_CountsAsElsewhere()
    {
        var response = EndedAt("http://127.0.0.1:9/other");
        Assert.True(EndsElsewhere(response, new Uri("http://127.0.0.1:9/t")));
    }

    [Fact]
    public void ResponseFromDifferentPort_CountsAsElsewhere()
    {
        var response = EndedAt("http://127.0.0.1:10/t");
        Assert.True(EndsElsewhere(response, new Uri("http://127.0.0.1:9/t")));
    }

    [Fact]
    public void ResponseFromDifferentHost_CountsAsElsewhere()
    {
        var response = EndedAt("http://localhost:9/t");
        Assert.True(EndsElsewhere(response, new Uri("http://127.0.0.1:9/t")));
    }

    [Fact]
    public void ResponseWithoutRequestMessage_IsAcceptedOnThatBasisAlone()
    {
        // The 14:21Z decision on row 1c0ffce3: absence is not refusal. The shipped transports always stamp;
        // refusing null would break host stubs on a PATCH. The 3xx refusal is a separate
        // term and still applies.
        var response = new HttpResponseMessage(HttpStatusCode.OK);
        Assert.False(EndsElsewhere(response, new Uri("http://127.0.0.1:9/t")));
    }

    [Fact]
    public async Task UnstampedPrimaryHandler_Direct200_StillMints()
    {
        // The mint-level shape of the same decision: a host transport that hand-builds its
        // 200 without a stamp must not lose the mint on a patch upgrade.
        var provider = new OAuthClientCredentialsProvider(
            Cache(), TokenFactoryWithPrimary(static () => new UnstampedHandler()), TimeProvider.System);
        var token = await provider.GetCredentialAsync(
            new OAuthClientCredentialsOptions
            {
                TokenEndpoint = Idp("/cc-ok"),
                ClientId = "cid",
                ClientSecret = "csec",
            },
            TestSecrets.AccessorFor([]),
            new CredentialRequestContext { CredentialName = "probe", Partition = "p1" },
            default);
        Assert.Equal("STUB-TOKEN", token);
    }

    /// <summary>The common host shape (and every hand-written test stub): a built
    /// response declaring no effective request URI.</summary>
    private sealed class UnstampedHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    """{"access_token":"STUB-TOKEN","expires_in":3600,"token_type":"Bearer"}""",
                    System.Text.Encoding.UTF8,
                    "application/json"),
            });
    }

    private static HttpResponseMessage EndedAt(string finalUri) =>
        new(HttpStatusCode.OK) { RequestMessage = new HttpRequestMessage(HttpMethod.Post, finalUri) };

    /// <summary>A plausible host-supplied transport (proxy/relay style): it performs any
    /// redirect itself over an inner client, so the caller's HttpRequestMessage is never
    /// mutated — the shape the guard's URI-change signal cannot see.</summary>
    private sealed class ForwardingHandler : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            using var inner = new HttpClient(new SocketsHttpHandler { AllowAutoRedirect = false });
            var outbound = await CloneAsync(request, request.RequestUri!);
            var response = await inner.SendAsync(outbound, cancellationToken);

            for (var hop = 0; hop < 5; hop++)
            {
                if ((int)response.StatusCode is not (>= 300 and < 400) || response.Headers.Location is not { } location)
                {
                    break;
                }

                var next = location.IsAbsoluteUri ? location : new Uri(outbound.RequestUri!, location);
                var method = (int)response.StatusCode is 302 or 303 ? HttpMethod.Get : outbound.Method;
                response.Dispose();
                var nextRequest = await CloneAsync(outbound, next);
                nextRequest.Method = method;
                outbound = nextRequest;
                response = await inner.SendAsync(outbound, cancellationToken);
            }

            return response;
        }

        private static async Task<HttpRequestMessage> CloneAsync(HttpRequestMessage source, Uri uri)
        {
            var clone = new HttpRequestMessage(source.Method, uri);
            foreach (var header in source.Headers)
            {
                clone.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }

            if (source.Content is { } content)
            {
                var bytes = await content.ReadAsByteArrayAsync();
                var copy = new ByteArrayContent(bytes);
                foreach (var header in content.Headers)
                {
                    copy.Headers.TryAddWithoutValidation(header.Key, header.Value);
                }

                clone.Content = copy;
            }

            return clone;
        }
    }
}
