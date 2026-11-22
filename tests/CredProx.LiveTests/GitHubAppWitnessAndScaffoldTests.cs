using Xunit;

namespace CredProx.LiveTests;

// The standing offline proofs for the live scaffold — these run with no secrets and
// no network beyond localhost, and they are the reason a live PASS can be trusted:
// the witness cell shows the startup-hook meter listener counts exactly one exchange
// and one cache hit for two forwarded calls (against the GitHub stand-in, with the
// sample repointed exactly as the offline smokes repoint it), and the scanner cell
// shows the leak check bites on planted fake secret material and cleans it up.
[Collection("GitHubApp")]
[Trait("Layer", "Offline")]
public sealed class GitHubAppWitnessAndScaffoldTests
{
    private readonly GitHubAppFixture _fixture;

    public GitHubAppWitnessAndScaffoldTests(GitHubAppFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task Witness_CountsExactlyOneExchangeAgainstStandIn()
    {
        var (privatePem, publicPem) = _fixture.GenerateSigningPair();
        await _fixture.StartStubAsync(publicPem);

        var witnessFile = Path.Combine(Path.GetTempPath(), $"credprox-live-witness-{Guid.NewGuid():N}.log");
        var secrets = new List<string> { privatePem, GitHubAppFixture.StubInstallationToken };
        var env = new Dictionary<string, string>
        {
            // the same three repoint keys the offline smokes use, plus the signing secret
            ["CredProx__Destinations__github__Template"] = GitHubAppFixture.StubUrl,
            ["CredProx__Credentials__github-app__TokenEndpoint"] =
                GitHubAppFixture.StubUrl + "/app/installations/789012/access_tokens",
            ["ReverseProxy__Clusters__github__Destinations__github__Address"] =
                GitHubAppFixture.StubUrl + "/",
            ["CredProx__Secrets__github-app-signing-key"] = privatePem,
            ["DOTNET_STARTUP_HOOKS"] = LiveHosts.WitnessDllPath(),
            ["CREDPROX_LIVE_WITNESS_FILE"] = witnessFile,
        };

        var host = _fixture.StartHost(env, secrets);
        try
        {
            await _fixture.WaitForHostAsync(host);
            using var client = new HttpClient { BaseAddress = new Uri(GitHubAppFixture.HostUrl) };
            using var first = await client.GetAsync("/github/repos/octocat/hello-world");
            using var second = await client.GetAsync("/github/repos/octocat/hello-world");
            Assert.True((int)first.StatusCode == 200, "first forwarded call: " + (int)first.StatusCode);
            Assert.True((int)second.StatusCode == 200, "second forwarded call: " + (int)second.StatusCode);

            var counts = await LiveHosts.ReadWitnessStableAsync(witnessFile);
            Assert.Equal(1, counts.Miss);
            Assert.Equal(1, counts.FetchSuccess);
            Assert.Equal(0, counts.FetchFailure);
            Assert.True(counts.Hit >= 1, $"no cache hit observed (miss {counts.Miss}, hit {counts.Hit})");

            // differential check: the stand-in itself saw exactly one token exchange
            var stubCalls = int.Parse(await _fixture.Stub.GetStringAsync("/__calls"));
            Assert.Equal(1, stubCalls);

            var log = host.Stdout + host.Stderr;
            Assert.Empty(SecretLeakScanner.FindLeaks(log, secrets));
        }
        finally
        {
            TryDelete(witnessFile);
        }
    }

    [Fact]
    public void Scanner_BitesOnPlantedFakeMaterial()
    {
        // all planted values are fakes written into this cell; they are not secrets
        var fakePem = string.Join(
            '\n',
            "-----BEGIN PRIVATE KEY-----",
            "RkFLRVBBVkVBTE5PQVJFQUxLRVk=" + "RkFLRVBBVkVBTE5PQVJFQUxLRVk=",
            "-----END PRIVATE KEY-----");
        var fakeToken = "ghs_" + new string('A', 12) + new string('B', 12);
        var fakeJwt = "eyJhbGciOiJub25lIn0"
            + ".eyJmYWtlIjp0cnVlfQ"
            + "." + new string('C', 10) + new string('D', 10) + new string('E', 10);
        var fakeApiKey = "sk-ant-" + new string('A', 12) + new string('B', 12);
        var text =
            "fail: host refused the request [1] with key " + fakePem + "\n" +
            "warn: retried with " + fakeToken + " after expiry\n" +
            "info: assertion header " + fakeJwt + " sent upstream\n" +
            "info: provider auth " + fakeApiKey + " sent upstream\n" +
            "info: forwarded GET /repos/octocat/hello-world answered 200\n";

        var secrets = new[] { fakePem };
        var leaks = SecretLeakScanner.FindLeaks(text, secrets);
        Assert.Equal(
            new[]
            {
                "loaded secret material appears in captured output",
                "a GitHub token shape appears in captured output",
                "an Anthropic API key shape appears in captured output",
                "a JWT shape appears in captured output",
            },
            leaks);

        var sanitized = SecretLeakScanner.Sanitize(text, secrets);
        Assert.DoesNotContain(fakePem, sanitized, StringComparison.Ordinal);
        Assert.DoesNotContain(fakeToken, sanitized, StringComparison.Ordinal);
        Assert.DoesNotContain(fakeJwt, sanitized, StringComparison.Ordinal);
        Assert.DoesNotContain(fakeApiKey, sanitized, StringComparison.Ordinal);
        Assert.DoesNotContain("ghs_", sanitized, StringComparison.Ordinal);
        Assert.DoesNotContain("sk-ant-", sanitized, StringComparison.Ordinal);
        Assert.DoesNotContain("eyJ", sanitized, StringComparison.Ordinal);
        Assert.Empty(SecretLeakScanner.FindLeaks(sanitized, secrets));

        // every documented prefix bites: an OAuth access token is caught even alone
        Assert.Equal(
            new[] { "a GitHub token shape appears in captured output" },
            SecretLeakScanner.FindLeaks(
                "warn: reauth used gho_" + new string('A', 24) + " instead\n",
                secrets));

        // and so is a lone Anthropic API key
        Assert.Equal(
            new[] { "an Anthropic API key shape appears in captured output" },
            SecretLeakScanner.FindLeaks(
                "warn: provider auth was sk-ant-" + new string('C', 24) + " after all\n",
                secrets));

        // negative control: honest log lines produce no hits
        Assert.Empty(SecretLeakScanner.FindLeaks(
            "info: forwarded GET /repos/octocat/hello-world answered 200\n",
            secrets));
    }

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

// The machine-local secret contract itself, proven offline against planted files in
// a private temp directory: every failure mode is a loud problem that names what is
// missing (central file, mode with its actual octal, or each variable), and a
// well-formed mode-600 file round-trips its values. Vendor isolation is proven
// here too: each vendor's probe sees ONLY its own variables, a file holding just
// some vendors' variables is normal, and a stale per-vendor file is named once and
// said to be ignored — never read. These cells use the path override and never
// touch the real ~/.config/credprox-live, which is the owner's territory.
[Trait("Layer", "Offline")]
public sealed class LiveEnvContractTests : IDisposable
{
    // The central file and a stale sibling need a directory of their own:
    private readonly string _tempDir = Path.Combine(
        Path.GetTempPath(),
        $"credprox-live-contract-{Guid.NewGuid():N}");

    private readonly string _central;

    private static readonly IReadOnlyList<string> Keys = ["APP_ID", "INSTALLATION_ID", "PRIVATE_KEY_BASE64"];

    // concatenation shape on purpose: the source never carries a literal that
    // matches this project's own Anthropic-key scan pattern, while the runtime
    // value stays a well-formed fake:
    private const string FakeApiKey = "sk-ant-" + "fakecontractkey000000000000";
    private const string FakeTenant = "00000000-0000-0000-0000-000000000000";

    public LiveEnvContractTests()
    {
        Directory.CreateDirectory(_tempDir);
        _central = Path.Combine(_tempDir, "live.env");
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_tempDir, recursive: true);
        }
        catch (IOException)
        {
            // scratch dir; the temp dir clears it
        }
    }

    [Fact]
    public void MissingFile_NamesEveryRequiredVariableAndTheCentralPath()
    {
        var probe = LiveEnv.Probe(GitHubAppEnv.Vendor, Keys, Path.Combine(_tempDir, "absent.env"));
        Assert.False(probe.Available);
        Assert.Contains("does not exist", probe.SkipReason, StringComparison.Ordinal);
        Assert.Contains("~/.config/credprox-live/live.env", probe.SkipReason, StringComparison.Ordinal);
        Assert.Contains("APP_ID", probe.SkipReason, StringComparison.Ordinal);
        Assert.Contains("INSTALLATION_ID", probe.SkipReason, StringComparison.Ordinal);
        Assert.Contains("PRIVATE_KEY_BASE64", probe.SkipReason, StringComparison.Ordinal);
    }

    [Fact]
    public void LooseMode_RefusesNamingTheActualOctal()
    {
        WriteEnv(UnixFileMode.UserRead | UnixFileMode.UserWrite
            | UnixFileMode.GroupRead | UnixFileMode.OtherRead); // 644
        var probe = LiveEnv.Probe(GitHubAppEnv.Vendor, Keys, _central);
        Assert.False(probe.Available);
        Assert.Contains("mode 644, must be exactly 600", string.Join("; ", probe.Problems), StringComparison.Ordinal);
    }

    [Fact]
    public void Mode600_RoundTripsValues()
    {
        WriteEnv(UnixFileMode.UserRead | UnixFileMode.UserWrite); // 600
        var probe = LiveEnv.Probe(GitHubAppEnv.Vendor, Keys, _central);
        Assert.True(probe.Available, string.Join("; ", probe.Problems));
        Assert.Equal("123456", probe.Values["APP_ID"]);
        Assert.Equal("789012", probe.Values["INSTALLATION_ID"]);
    }

    [Fact]
    public void CentralFile_EveryVendorSeesOnlyItsOwnVariables()
    {
        // one file, every vendor's variables; a githubapp run must not see
        // ANTHROPIC_API_KEY (the isolation cell the row names):
        WriteFullCentralFile();
        var github = LiveEnv.Probe(GitHubAppEnv.Vendor, GitHubAppEnv.RequiredKeys, _central);
        Assert.True(github.Available, string.Join("; ", github.Problems));
        Assert.Equal(3, github.Values.Count);
        Assert.False(github.Values.ContainsKey("ANTHROPIC_API_KEY"));
        Assert.False(github.Values.ContainsKey("TENANT_ID"));
        var githubValues = string.Join(";", github.Values.Select(kv => kv.Key + "=" + kv.Value));
        Assert.DoesNotContain(FakeApiKey, githubValues, StringComparison.Ordinal);
        Assert.DoesNotContain(FakeTenant, githubValues, StringComparison.Ordinal);

        var aigateway = LiveEnv.Probe(AiGatewayEnv.Vendor, AiGatewayEnv.RequiredKeys, _central);
        Assert.True(aigateway.Available, string.Join("; ", aigateway.Problems));
        Assert.Equal(new[] { "ANTHROPIC_API_KEY" }, aigateway.Values.Keys.ToArray());
        Assert.Equal(FakeApiKey, aigateway.Values["ANTHROPIC_API_KEY"]);

        var graph = LiveEnv.Probe(GraphEnv.Vendor, GraphEnv.RequiredKeys, _central);
        Assert.True(graph.Available, string.Join("; ", graph.Problems));
        Assert.Equal(new[] { "TENANT_ID" }, graph.Values.Keys.ToArray());
    }

    [Fact]
    public void PartialFile_IsNormal_VendorsWithTheirVariablesStillRun()
    {
        File.WriteAllLines(_central, new[] { "TENANT_ID=" + FakeTenant });
        File.SetUnixFileMode(_central, UnixFileMode.UserRead | UnixFileMode.UserWrite); // 600
        var graph = LiveEnv.Probe(GraphEnv.Vendor, GraphEnv.RequiredKeys, _central);
        Assert.True(graph.Available, string.Join("; ", graph.Problems));
        var github = LiveEnv.Probe(GitHubAppEnv.Vendor, GitHubAppEnv.RequiredKeys, _central);
        Assert.False(github.Available);
        Assert.Contains("missing variables: APP_ID, INSTALLATION_ID, PRIVATE_KEY_BASE64",
            string.Join("; ", github.Problems), StringComparison.Ordinal);
    }

    [Fact]
    public void StalePerVendorFile_IsNamedAsIgnored_NeverRead()
    {
        WriteFullCentralFile();
        var stale = Path.Combine(_tempDir, "githubapp.env");
        File.WriteAllLines(stale, new[] { "APP_ID=999999", "INSTALLATION_ID=999999", "PRIVATE_KEY_BASE64=stale" });
        File.SetUnixFileMode(stale, UnixFileMode.UserRead | UnixFileMode.UserWrite); // 600
        var probe = LiveEnv.Probe(GitHubAppEnv.Vendor, GitHubAppEnv.RequiredKeys, _central);
        Assert.True(probe.Available, string.Join("; ", probe.Problems));
        Assert.Equal("123456", probe.Values["APP_ID"]); // the central value, not the stale one
        var note = Assert.Single(probe.Notices);
        Assert.Contains("githubapp.env", note, StringComparison.Ordinal);
        Assert.Contains("IGNORED", note, StringComparison.Ordinal);
        Assert.DoesNotContain("999999", note, StringComparison.Ordinal); // named, never its content
    }

    [Fact]
    public void ValueProblems_NameBadShapesWithoutEchoingValues()
    {
        var notDigits = GitHubAppEnv.ValueProblems(new Dictionary<string, string>
        {
            ["APP_ID"] = "app-1",
            ["INSTALLATION_ID"] = "12a",
        });
        Assert.Contains(notDigits, p => p.StartsWith("APP_ID", StringComparison.Ordinal));
        Assert.Contains(notDigits, p => p.StartsWith("INSTALLATION_ID", StringComparison.Ordinal));
        Assert.DoesNotContain("app-1", string.Join("; ", notDigits), StringComparison.Ordinal);

        var notBase64 = GitHubAppEnv.ValueProblems(new Dictionary<string, string>
        {
            ["PRIVATE_KEY_BASE64"] = "not base64 at all!",
        });
        Assert.Single(notBase64);
        Assert.Contains("is not base64", notBase64[0], StringComparison.Ordinal);

        var wrongPayload = GitHubAppEnv.ValueProblems(new Dictionary<string, string>
        {
            ["PRIVATE_KEY_BASE64"] = Convert.ToBase64String(
                System.Text.Encoding.UTF8.GetBytes("just some text, not a key")),
        });
        Assert.Single(wrongPayload);
        Assert.Contains("does not decode to a private key PEM", wrongPayload[0], StringComparison.Ordinal);

        var goodPem = "-----BEGIN PRIVATE KEY-----\nRkFLRQ==\n-----END PRIVATE KEY-----";
        var good = GitHubAppEnv.ValueProblems(new Dictionary<string, string>
        {
            ["APP_ID"] = "123456",
            ["INSTALLATION_ID"] = "789012",
            ["PRIVATE_KEY_BASE64"] = Convert.ToBase64String(
                System.Text.Encoding.UTF8.GetBytes(goodPem)),
        });
        Assert.Empty(good);
        Assert.Equal(goodPem, GitHubAppEnv.PrivateKeyPem(new Dictionary<string, string>
        {
            ["PRIVATE_KEY_BASE64"] = Convert.ToBase64String(
                System.Text.Encoding.UTF8.GetBytes(goodPem)),
        }), StringComparer.Ordinal);
    }

    private void WriteEnv(UnixFileMode mode)
    {
        File.WriteAllLines(_central, new[]
        {
            "# planted by the env-contract cell; fakes only",
            "APP_ID=123456",
            "INSTALLATION_ID=789012",
            "PRIVATE_KEY_BASE64=" + Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(
                "-----BEGIN PRIVATE KEY-----\nRkFLRQ==\n-----END PRIVATE KEY-----")),
        });
        File.SetUnixFileMode(_central, mode);
    }

    // every vendor's variables in the one central file, fake values only:
    private void WriteFullCentralFile()
    {
        WriteEnv(UnixFileMode.UserRead | UnixFileMode.UserWrite); // 600
        File.AppendAllLines(_central, new[]
        {
            "ANTHROPIC_API_KEY=" + FakeApiKey,
            "TENANT_ID=" + FakeTenant,
        });
    }
}
