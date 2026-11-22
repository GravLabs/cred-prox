using System.Text;
using Xunit;

namespace CredProx.LiveTests;

// The AiGateway vendor's machine-local contract, proven offline against planted
// files in the temp directory (same shape as the GitHubApp contract cells): a
// missing file names ANTHROPIC_API_KEY, a loose mode names the actual octal, a
// well-formed 600 file round-trips, and a wrong-shape value is a problem that
// names the variable and the expectation but never the value. These cells use the
// path override and never touch the real ~/.config/credprox-live.
[Trait("Layer", "Offline")]
public sealed class AiGatewayEnvContractTests : IDisposable
{
    private readonly string _tempPath = Path.Combine(
        Path.GetTempPath(),
        $"credprox-live-aigateway-{Guid.NewGuid():N}.env");

    public void Dispose()
    {
        try
        {
            File.Delete(_tempPath);
        }
        catch (IOException)
        {
            // scratch file; the temp dir clears it
        }
    }

    [Fact]
    public void FileGate_NamesTheVariable_ModeAndRoundTrip()
    {
        var absent = LiveEnv.Probe(AiGatewayEnv.Vendor, AiGatewayEnv.RequiredKeys, _tempPath + ".absent");
        Assert.False(absent.Available);
        Assert.Contains("does not exist", absent.SkipReason, StringComparison.Ordinal);
        Assert.Contains("~/.config/credprox-live/live.env", absent.SkipReason, StringComparison.Ordinal);
        Assert.Contains("ANTHROPIC_API_KEY", absent.SkipReason, StringComparison.Ordinal);

        File.WriteAllLines(_tempPath, new[] { "ANTHROPIC_API_KEY=" + AiGatewayFixture.StubApiKey });
        File.SetUnixFileMode(
            _tempPath,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead); // 644
        var loose = LiveEnv.Probe(AiGatewayEnv.Vendor, AiGatewayEnv.RequiredKeys, _tempPath);
        Assert.False(loose.Available);
        Assert.Contains("mode 644, must be exactly 600", string.Join("; ", loose.Problems), StringComparison.Ordinal);

        var missing = Path.Combine(Path.GetTempPath(), $"credprox-live-aigateway-missing-{Guid.NewGuid():N}.env");
        File.WriteAllLines(missing, new[] { "# no keys here" });
        File.SetUnixFileMode(missing, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        var noKey = LiveEnv.Probe(AiGatewayEnv.Vendor, AiGatewayEnv.RequiredKeys, missing);
        Assert.False(noKey.Available);
        Assert.Contains("missing variables: ANTHROPIC_API_KEY", string.Join("; ", noKey.Problems), StringComparison.Ordinal);
        File.Delete(missing);

        File.SetUnixFileMode(_tempPath, UnixFileMode.UserRead | UnixFileMode.UserWrite); // 600
        var probe = LiveEnv.Probe(AiGatewayEnv.Vendor, AiGatewayEnv.RequiredKeys, _tempPath);
        Assert.True(probe.Available, string.Join("; ", probe.Problems));
        Assert.Equal(AiGatewayFixture.StubApiKey, probe.Values["ANTHROPIC_API_KEY"]);
    }

    [Fact]
    public void ValueProblems_NameBadShapesWithoutEchoingValues()
    {
        var shortKey = AiGatewayEnv.ValueProblems(new Dictionary<string, string>
        {
            ["ANTHROPIC_API_KEY"] = "sk-ant-tiny",
        });
        Assert.Single(shortKey);
        Assert.Contains("ANTHROPIC_API_KEY", shortKey[0], StringComparison.Ordinal);
        Assert.DoesNotContain("sk-ant-tiny", shortKey[0], StringComparison.Ordinal);

        var wrongPrefix = AiGatewayEnv.ValueProblems(new Dictionary<string, string>
        {
            ["ANTHROPIC_API_KEY"] = "Bearer-something-else-entirely-0123456789",
        });
        Assert.Single(wrongPrefix);
        Assert.DoesNotContain("Bearer-something", wrongPrefix[0], StringComparison.Ordinal);

        var good = AiGatewayEnv.ValueProblems(new Dictionary<string, string>
        {
            ["ANTHROPIC_API_KEY"] = AiGatewayFixture.StubApiKey,
        });
        Assert.Empty(good);
    }
}

// The standing offline proof for the AiGateway live cell, against the sample's own
// stand-in (the same two repoint keys the shipped Development override uses) with a
// planted sk-ant-shaped fake provider key. It shows the forwarded call carries the
// provider key to the vendor while the CALLER sees it redacted, and — the claim the
// live cell cannot count — that refusals happen before the vendor is touched: the
// stand-in's /__calls counter does not move for an unknown caller key or an
// operation outside the caller's allow-list.
[Collection("AiGateway")]
[Trait("Layer", "Offline")]
public sealed class AiGatewayStandInTests
{
    private readonly AiGatewayFixture _fixture;

    public AiGatewayStandInTests(AiGatewayFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task ProviderKeyReachesVendor_RedactsAtCaller_RefusalsNeverReachVendor()
    {
        await _fixture.StartStubAsync();

        var chatCaller = "offline-chat-" + Guid.NewGuid().ToString("N");
        var getOnlyCaller = "offline-getonly-" + Guid.NewGuid().ToString("N");
        var secrets = new List<string> { AiGatewayFixture.StubApiKey };
        var env = new Dictionary<string, string>
        {
            // the shipped Development override, as env — same two keys
            ["CredProx__Destinations__ai__Template"] = AiGatewayFixture.StubUrl,
            ["ReverseProxy__Clusters__ai__Destinations__ai__Address"] = AiGatewayFixture.StubUrl + "/",
            ["CredProx__Secrets__ai-provider-key"] = AiGatewayFixture.StubApiKey,
            // a bare Urls env key overrides the shipped appsettings Urls; measured:
            // ASPNETCORE_URLS does not (host stayed on 5088 with 5090 in the env)
            ["Urls"] = AiGatewayFixture.OfflineHostUrl,
            // caller allowed exactly this POST
            ["CredProx__Callers__offline-chat__Keys__0__KeyId"] = "offline-chat-key",
            ["CredProx__Callers__offline-chat__Keys__0__KeyHash"] = AiGatewayFixture.CallerKeyConfig(chatCaller),
            ["CredProx__Callers__offline-chat__Operations__0__Route"] = "ai",
            ["CredProx__Callers__offline-chat__Operations__0__Methods__0"] = "POST",
            ["CredProx__Callers__offline-chat__Operations__0__Paths__0"] = "/ai/v1/chat/**",
            // caller allowed only GET — its POST must die at CredProx
            ["CredProx__Callers__offline-getonly__Keys__0__KeyId"] = "offline-getonly-key",
            ["CredProx__Callers__offline-getonly__Keys__0__KeyHash"] = AiGatewayFixture.CallerKeyConfig(getOnlyCaller),
            ["CredProx__Callers__offline-getonly__Operations__0__Route"] = "ai",
            ["CredProx__Callers__offline-getonly__Operations__0__Methods__0"] = "GET",
            ["CredProx__Callers__offline-getonly__Operations__0__Paths__0"] = "/ai/v1/chat/**",
        };

        // cleanup belongs to the fixture (see the GitHubApp precedent)
        var host = _fixture.StartHost(env, secrets, AiGatewayFixture.OfflineHostPort);
        {
            await _fixture.WaitForHostAsync(host, AiGatewayFixture.OfflineHostUrl);
            using var client = new HttpClient { BaseAddress = new Uri(AiGatewayFixture.OfflineHostUrl) };

            var callsBefore = StubCalls();

            // forwarded call: 200 from the stand-in; the caller sees the provider
            // key only in redacted form even though the stand-in echoes it
            var post = new HttpRequestMessage(HttpMethod.Post, "/ai/v1/chat/completions");
            post.Headers.Add("X-CredProx-Key", chatCaller);
            post.Content = new StringContent("{\"model\":\"m\"}", Encoding.UTF8, "application/json");
            var served = await client.SendAsync(post);
            var servedBody = await served.Content.ReadAsStringAsync();
            Assert.True(
                (int)served.StatusCode == 200,
                $"the stand-in answered {(int)served.StatusCode}: " +
                SecretLeakScanner.Sanitize(servedBody, secrets));
            Assert.Contains("Bearer [redacted]", servedBody, StringComparison.Ordinal);
            Assert.DoesNotContain(AiGatewayFixture.StubApiKey, servedBody, StringComparison.Ordinal);

            // unknown caller key: CredProx's own problem document, vendor untouched
            var wrong = new HttpRequestMessage(HttpMethod.Post, "/ai/v1/chat/completions");
            wrong.Headers.Add("X-CredProx-Key", chatCaller + "-wrong");
            wrong.Content = new StringContent("{\"model\":\"m\"}", Encoding.UTF8, "application/json");
            var rejected = await client.SendAsync(wrong);
            var rejectedBody = await rejected.Content.ReadAsStringAsync();
            Assert.True(
                (int)rejected.StatusCode == 401,
                $"unknown caller key answered {(int)rejected.StatusCode}: " +
                SecretLeakScanner.Sanitize(rejectedBody, secrets));
            Assert.Contains(
                "application/problem+json",
                rejected.Content.Headers.ContentType?.ToString() ?? string.Empty,
                StringComparison.Ordinal);

            // operation outside the allow-list: GET-only caller posts — refused locally
            var disallowed = new HttpRequestMessage(HttpMethod.Post, "/ai/v1/chat/completions");
            disallowed.Headers.Add("X-CredProx-Key", getOnlyCaller);
            disallowed.Content = new StringContent("{\"model\":\"m\"}", Encoding.UTF8, "application/json");
            var forbidden = await client.SendAsync(disallowed);
            var forbiddenBody = await forbidden.Content.ReadAsStringAsync();
            Assert.True(
                (int)forbidden.StatusCode == 403,
                $"disallowed operation answered {(int)forbidden.StatusCode}: " +
                SecretLeakScanner.Sanitize(forbiddenBody, secrets));
            Assert.Contains(
                "application/problem+json",
                forbidden.Content.Headers.ContentType?.ToString() ?? string.Empty,
                StringComparison.Ordinal);

            // the differential the live run cannot count: exactly one vendor hit —
            // both refusals died before the vendor was touched
            var callsAfter = StubCalls();
            Assert.Equal(callsBefore + 1, callsAfter);

            var log = host.Stdout + host.Stderr;
            Assert.Empty(SecretLeakScanner.FindLeaks(log, secrets));
        }
    }

    private int StubCalls() =>
        int.Parse(_fixture.Stub.GetStringAsync("/__calls").GetAwaiter().GetResult());
}
