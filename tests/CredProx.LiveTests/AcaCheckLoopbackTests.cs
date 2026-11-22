using System.Diagnostics;
using System.Text;
using Xunit;

namespace CredProx.LiveTests;

// The acacheck mode of tools/aca-live-harness, run against the SHIPPED
// samples/AzureContainerApps host and its shipped StubApi on loopback — the
// offline twin of the in-cluster verify job (M46 unit 3). Same ports the sample
// ships (5097/8098, pinned by its appsettings; this class is the only LiveTests
// owner of them). The keys are the sample's own shipped demo constants; nothing
// here is a real credential, and no Azure resource is touched: the job-in-
// cluster identity path is the live leg, this class proves the probe's check
// logic and its output contract that scripts/live-m46-aca.sh verify counts.
[Trait("Layer", "Offline")]
public sealed class AcaCheckLoopbackTests : IAsyncLifetime
{
    private const string HostUrl = "http://localhost:5097";
    private const string DemoCallerKey = "credprox-e17-aca-demo-key";
    private const string DemoVendorKey = "credprox-aca-demo-vendor-key-never-real";

    private string _sampleBin = "";
    private string _stubBin = "";
    private string _harnessBin = "";
    private Process? _stub;
    private Process? _host;

    public async Task InitializeAsync()
    {
        (_sampleBin, _stubBin, _harnessBin) = LocateBins();

        _stub = StartDotnet(_stubBin, "StubApi.dll", []);
        await WaitUntilAsync(
            async () =>
            {
                try
                {
                    using var probe = new HttpClient();
                    var ok = await probe.GetAsync("http://localhost:8098/__last-auth");
                    return ok.IsSuccessStatusCode;
                }
                catch (HttpRequestException)
                {
                    return false; // still warming
                }
            },
            "the vendor stand-in never served its port");

        _host = StartDotnet(_sampleBin, "AzureContainerApps.dll", []);
        await WaitUntilAsync(
            async () =>
            {
                try
                {
                    using var probe = new HttpClient();
                    await probe.GetAsync(HostUrl + "/health");
                    return true; // any answer means the port is up
                }
                catch (HttpRequestException)
                {
                    return false; // still warming
                }
            },
            "the AzureContainerApps host never served its port");
    }

    public async Task DisposeAsync()
    {
        foreach (var process in new[] { _host, _stub })
        {
            if (process is null)
            {
                continue;
            }

            try
            {
                process.Kill(entireProcessTree: true);
                await process.WaitForExitAsync();
            }
            catch (InvalidOperationException)
            {
                // already gone
            }

            process.Dispose();
        }
    }

    [Fact]
    public async Task FullChain_AllThreeChecksPass()
    {
        var run = await RunHarness(new() { ["CREDPROX_SMOKE_CALLER_KEY"] = DemoCallerKey, ["CREDPROX_SMOKE_VENDOR_KEY"] = DemoVendorKey });
        Assert.True(run.Exit == 0, $"acacheck must exit 0: exit={run.Exit}\nout={run.Out}\nerr={run.Err}");
        Assert.Contains("acacheck UTC ", run.Out, StringComparison.Ordinal); // wall-clock anchor line
        Assert.Contains("build unstamped", run.Out, StringComparison.Ordinal); // no DEPLOY_IMAGE_DIGEST here
        Assert.Contains("C1 PASS health unauthenticated", run.Out, StringComparison.Ordinal);
        Assert.Contains("C2 PASS caller-key call reaches the vendor, scrubbed for the caller", run.Out, StringComparison.Ordinal);
        Assert.Contains("C3 PASS no caller key refused 401", run.Out, StringComparison.Ordinal);
        Assert.Contains("ACACHECK OK", run.Out, StringComparison.Ordinal);
    }

    [Fact]
    public async Task WrongCallerKey_C2FailsAsRefusal_TheGoodKeyIsNeverEchoed()
    {
        var run = await RunHarness(new()
        {
            ["CREDPROX_SMOKE_CALLER_KEY"] = "credproxt-wrong-key-for-the-refusal-cell",
            ["CREDPROX_SMOKE_VENDOR_KEY"] = DemoVendorKey,
        });
        Assert.Equal(1, run.Exit);
        Assert.Contains("C2 FAIL caller-key call reaches the vendor", run.Out, StringComparison.Ordinal);
        Assert.Contains("status=401", run.Out, StringComparison.Ordinal);
        Assert.Contains("ACACHECK FAILED", run.Out, StringComparison.Ordinal);
        // C1/C3 are key-independent and still pass - the failure is exactly C2
        Assert.Contains("C1 PASS", run.Out, StringComparison.Ordinal);
        Assert.Contains("C3 PASS", run.Out, StringComparison.Ordinal);
        Assert.DoesNotContain(DemoCallerKey, run.Out + run.Err, StringComparison.Ordinal);
    }

    [Fact]
    public async Task VendorKeyAbsent_SaysSoOnStderr_AndStillPasses()
    {
        // the raw vendor key is OPTIONAL for the probe: without it C2 asserts
        // the scrubbed shape only - out loud on stderr, never silently
        var run = await RunHarness(new() { ["CREDPROX_SMOKE_CALLER_KEY"] = DemoCallerKey });
        Assert.True(run.Exit == 0, $"absent vendor key must not fail the probe: exit={run.Exit}\nerr={run.Err}");
        Assert.Contains(
            "warn: vendor key value not available to this probe",
            run.Err,
            StringComparison.Ordinal);
        Assert.Contains("C2 PASS", run.Out, StringComparison.Ordinal);
        Assert.Contains("ACACHECK OK", run.Out, StringComparison.Ordinal);
    }

    private sealed record HarnessRun(int Exit, string Out, string Err);

    private async Task<HarnessRun> RunHarness(Dictionary<string, string> env)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "dotnet",
            WorkingDirectory = _harnessBin,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        psi.ArgumentList.Add("exec");
        psi.ArgumentList.Add(Path.Combine(_harnessBin, "AcaLiveHarness.dll"));
        psi.ArgumentList.Add("--mode");
        psi.ArgumentList.Add("acacheck");
        psi.ArgumentList.Add("--proxy");
        psi.ArgumentList.Add(HostUrl);
        // start from a clean key/identity slate: the probe must see exactly the
        // inputs this cell names, nothing inherited
        foreach (var key in new[]
        {
            "CREDPROX_SMOKE_CALLER_KEY",
            "CREDPROX_SMOKE_VENDOR_KEY",
            "CredProx__Secrets__caller-key",
            "CredProx__Secrets__acme-vendor-key",
            "KeyVault__Uri",
            "MANAGED_IDENTITY_CLIENT_ID",
            "DEPLOY_IMAGE_DIGEST",
        })
        {
            psi.Environment.Remove(key);
        }

        foreach (var (key, value) in env)
        {
            psi.Environment[key] = value;
        }

        using var process = Process.Start(psi) ?? throw new InvalidOperationException("the harness did not start");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        Assert.True(process.WaitForExit(120_000), "the harness did not exit within 120 s");
        return new HarnessRun(process.ExitCode, stdout.Result, stderr.Result);
    }

    private static async Task WaitUntilAsync(Func<Task<bool>> probe, string failure, int seconds = 90)
    {
        for (var attempt = 0; attempt < seconds; attempt++)
        {
            if (await probe())
            {
                return;
            }

            await Task.Delay(1000);
        }

        throw new InvalidOperationException(failure);
    }

    private static Process StartDotnet(string bin, string dll, Dictionary<string, string> env)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "dotnet",
            WorkingDirectory = bin, // content root: the host must find its appsettings.json
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        psi.ArgumentList.Add("exec");
        psi.ArgumentList.Add(Path.Combine(bin, dll));
        foreach (var (key, value) in env)
        {
            psi.Environment[key] = value;
        }

        return Process.Start(psi) ?? throw new InvalidOperationException($"could not start {dll}");
    }

    private static (string SampleBin, string StubBin, string HarnessBin) LocateBins()
    {
        var own = AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar);
        var parts = own.Split(Path.DirectorySeparatorChar);
        var binIndex = Array.IndexOf(parts, "bin");
        if (binIndex < 3)
        {
            throw new InvalidOperationException($"unexpected test assembly location '{own}'");
        }

        var repoRoot = string.Join(Path.DirectorySeparatorChar, parts[..(binIndex - 2)]);
        var configuration = parts[binIndex + 1];
        var sampleBin = Path.Combine(repoRoot, "samples", "AzureContainerApps", "bin", configuration, "net10.0");
        var stubBin = Path.Combine(repoRoot, "samples", "AzureContainerApps", "StubApi", "bin", configuration, "net10.0");
        var harnessBin = Path.Combine(repoRoot, "tools", "aca-live-harness", "bin", configuration, "net10.0");
        foreach (var (dir, dll) in new[]
        {
            (sampleBin, "AzureContainerApps.dll"),
            (stubBin, "StubApi.dll"),
            (harnessBin, "AcaLiveHarness.dll"),
        })
        {
            if (!File.Exists(Path.Combine(dir, dll)))
            {
                throw new InvalidOperationException($"no built {dll} at '{dir}' - the ProjectReference did not build it");
            }
        }

        return (sampleBin, stubBin, harnessBin);
    }
}
