using Xunit;
using Xunit.Abstractions;

namespace CredProx.LiveTests;

// The M46 unit-1 proof against the real GitHub: the shipped sample host, launched
// with only the machine-local credential env, mints the app JWT, exchanges it once
// for an installation token, forwards a read-only API call GitHub answers 200, and
// serves a second call from the cache without a second exchange. The exchange count
// comes from CredProx's own meter, observed by the startup-hook witness inside the
// host process; no test double stands anywhere on the vendor path.
[Collection("GitHubApp")]
[Trait("Layer", "Live")]
public sealed class GitHubAppLiveTests
{
    private readonly GitHubAppFixture _fixture;
    private readonly ITestOutputHelper _output;

    public GitHubAppLiveTests(GitHubAppFixture fixture, ITestOutputHelper output)
    {
        _fixture = fixture;
        _output = output;
    }

    [GitHubAppLiveFact]
    public async Task GitHubApp_ExchangesOnceForwardsTwiceAndCachesAgainstGitHub()
    {
        var probe = GitHubAppEnv.Probe();
        Assert.True(probe.Available, probe.SkipReason);
        var shapeProblems = GitHubAppEnv.ValueProblems(probe.Values);
        Assert.True(shapeProblems.Count == 0, string.Join("; ", shapeProblems));

        var witnessFile = Path.Combine(Path.GetTempPath(), $"credprox-live-witness-{Guid.NewGuid():N}.log");
        var privateKeyPem = GitHubAppEnv.PrivateKeyPem(probe.Values);
        var secrets = new List<string> { privateKeyPem, probe.Values["PRIVATE_KEY_BASE64"] };
        var env = new Dictionary<string, string>
        {
            ["CredProx__Credentials__github-app__Issuer"] = probe.Values["APP_ID"],
            ["CredProx__Credentials__github-app__TokenEndpoint"] =
                GitHubAppEnv.TokenEndpointFor(probe.Values["INSTALLATION_ID"]),
            ["CredProx__Secrets__github-app-signing-key"] = privateKeyPem,
            ["DOTNET_STARTUP_HOOKS"] = LiveHosts.WitnessDllPath(),
            [LiveWitnessPathVariable] = witnessFile,
        };

        var host = _fixture.StartHost(env, secrets);
        try
        {
            await _fixture.WaitForHostAsync(host);
            // A real caller sends a User-Agent (curl does, and GitHub 403s a request
            // without one at its edge); CredProx forwards it untouched.
            using var client = new HttpClient { BaseAddress = new Uri(GitHubAppFixture.HostUrl) };
            client.DefaultRequestHeaders.UserAgent.ParseAdd("curl/8.5.0");
            using var first = await client.GetAsync("/github/installation/repositories");
            using var second = await client.GetAsync("/github/installation/repositories");

            var log = host.Stdout + host.Stderr;
            var leaks = SecretLeakScanner.FindLeaks(log, secrets);

            Assert.True(
                (int)first.StatusCode == 200,
                $"GitHub answered the first forwarded call with {(int)first.StatusCode}; sanitized host output:\n" +
                SecretLeakScanner.Sanitize(log, secrets));
            Assert.True(
                (int)second.StatusCode == 200,
                $"GitHub answered the second forwarded call with {(int)second.StatusCode}; sanitized host output:\n" +
                SecretLeakScanner.Sanitize(log, secrets));
            var server = first.Headers.TryGetValues("Server", out var values) ? string.Join(",", values) : "";
            Assert.Contains("github", server, StringComparison.OrdinalIgnoreCase);

            var counts = await LiveHosts.ReadWitnessStableAsync(witnessFile);
            Assert.Equal(1, counts.Miss);
            Assert.Equal(1, counts.FetchSuccess);
            Assert.Equal(0, counts.FetchFailure);
            Assert.True(counts.Hit >= 1, $"the second call showed no cache hit (witness: miss {counts.Miss}, hit {counts.Hit})");

            Assert.Empty(leaks);

            // Numbers only — no ids, tokens, or repository names — for the runner's PASS line.
            _output.WriteLine(
                $"OBSERVED exchanges={counts.Miss} fetch_success={counts.FetchSuccess} " +
                $"cache_hits={counts.Hit} forwarded_calls=2 statuses=200,200");
        }
        finally
        {
            TryDelete(witnessFile);
        }
    }

    private const string LiveWitnessPathVariable = "CREDPROX_LIVE_WITNESS_FILE";

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (IOException)
        {
            // scratch file; the temp dir clears it
        }
    }
}
