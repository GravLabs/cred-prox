using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using Xunit;

namespace CredProx.SampleSmokes;

// Deliberately breaks TokenExchangeFixture's init — the cell the failed batteries
// need to stay impossible: when init cannot finish, nothing may survive it holding
// a port. This class sits OUTSIDE the TokenExchange collection so the working cells
// never depend on the sabotage; collection-parallelism is off (xunit.runner.json),
// so the held port cannot race them.
public sealed class TokenExchangeTeardownTests
{
    [Fact]
    [Trait("Sample", "TokenExchange")]
    public async Task AFailedInitLeavesNothingBehind()
    {
        var port = new Uri(TokenExchangeFixture.ApiUrl).Port;
        var holder = new TcpListener(IPAddress.Loopback, port);
        holder.Start();
        try
        {
            var fixture = new TokenExchangeFixture();
            var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.InitializeAsync());
            Assert.Contains($"port {port}", ex.Message);
        }
        finally
        {
            holder.Stop();
        }

        var left = await RunDockerAsync("ps", "-a", "--filter", "name=tokenexchange", "--format", "{{.Names}}");
        Assert.Equal("", left);
    }

    [Fact]
    [Trait("Sample", "TokenExchange")]
    public async Task AFailureAfterComposeUpLeavesNothingBehind()
    {
        // The cell that pins the init cleanup itself. The held-port cell above fails
        // at the preflight, before any resource exists; this one lets compose finish
        // and kills the proxy host instead — it binds TEST-NET-1, an address no host
        // can take — so init fails while the keycloak and api containers are alive.
        // If the cleanup on the failed-init path ever disappears, the container and
        // port checks below are what go red (the leak is exactly what they inspect).
        var fixture = new TokenExchangeFixture { ProxyBindUrl = "http://192.0.2.1:5092" };
        await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.InitializeAsync());

        var left = await RunDockerAsync("ps", "-a", "--filter", "name=tokenexchange", "--format", "{{.Names}}");
        Assert.Equal("", left);
        SmokePorts.EnsureFreeFor("TokenExchange");
    }

    private static async Task<string> RunDockerAsync(params string[] args)
    {
        var psi = new ProcessStartInfo("docker")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var arg in args)
        {
            psi.ArgumentList.Add(arg);
        }

        using var proc = Process.Start(psi) ?? throw new InvalidOperationException("docker not runnable");
        var output = (await proc.StandardOutput.ReadToEndAsync()).Trim();
        await proc.WaitForExitAsync();
        return output;
    }
}
