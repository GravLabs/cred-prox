using System.Text.Json;
using Xunit;
namespace CredProx.Tests;
/// <summary>
/// The soak host consumes CredProx from the local feed exactly like a real host, and from
/// 0.15 (ADR-0007) each credential <c>Type</c> ships either in the core — armed by the
/// entry <c>AddCredProx(configuration)</c> — or in <c>CredProx.Identity</c>, armed by the
/// chained <c>AddIdentity()</c>: a host config that names a type without the package
/// reference and its arming call fails the host at startup validation — the
/// <c>CredentialBinder</c> unknown-type hint carries the package name. The harness carried
/// OAuthClientCredentials and LoginExchange past the 0.12 split without either, and CI
/// built the host without starting it, so nothing caught it. This pin keeps the soak
/// config, the host's package references and its setup calls from drifting apart again:
/// for every credential type the soak config names, the owning package must be referenced
/// and its arming call must be present. The same rule covers caller admission: a config
/// that declares <c>CredProx:Callers</c> obligates the entry call — caller keys ride the
/// core from 0.15 — without which the startup guard refuses to boot the host (ADR-0005),
/// and a CI that builds but never starts the host would not notice.
/// </summary>
public sealed class SoakHostCredentialPackagePinTests
{
    // The type-to-package authority is the unknown-Type hint switch in
    // src/CredProx/Credentials/CredentialBinder.cs; this map mirrors it for the host side.
    private static readonly Dictionary<string, (string Package, string AddCall)> TypeOwners = new(StringComparer.Ordinal)
    {
        ["StaticKey"] = ("CredProx", "AddCredProx"),
        ["Hmac"] = ("CredProx", "AddCredProx"),
        ["LoginExchange"] = ("CredProx", "AddCredProx"),
        ["OAuthClientCredentials"] = ("CredProx.Identity", "AddIdentity"),
        ["TokenExchange"] = ("CredProx.Identity", "AddIdentity"),
        ["JwtAssertion"] = ("CredProx.Identity", "AddIdentity"),
    };

    public static TheoryData<string> CredentialTypesNamedByTheSoakConfig()
    {
        var path = Path.Combine(RepoRoot(), "tools", "m33-soak", "SoakHost", "appsettings.json");
        using var doc = JsonDocument.Parse(File.ReadAllText(path));
        var data = new TheoryData<string>();
        foreach (var type in doc.RootElement.GetProperty("CredProx").GetProperty("Credentials").EnumerateObject()
                     .Select(c => c.Value.GetProperty("Type").GetString())
                     .Distinct(StringComparer.Ordinal))
        {
            Assert.False(string.IsNullOrEmpty(type), "a credential in the soak config has no Type");
            data.Add(type!);
        }
        return data;
    }

    [Theory]
    [MemberData(nameof(CredentialTypesNamedByTheSoakConfig))]
    public void EverySoakCredentialType_ShipsWithItsPackageAndRegistration(string credentialType)
    {
        Assert.True(TypeOwners.TryGetValue(credentialType, out var owner),
            $"the soak config names unknown credential Type '{credentialType}'; extend this pin's map to match the CredentialBinder hints");
        var root = RepoRoot();
        var csproj = File.ReadAllText(Path.Combine(root, "tools", "m33-soak", "SoakHost", "SoakHost.csproj"));
        var program = File.ReadAllText(Path.Combine(root, "tools", "m33-soak", "SoakHost", "Program.cs"));
        Assert.Contains($"Include=\"{owner.Package}\"", csproj);
        Assert.Contains(owner.AddCall + "(", program);
    }

    [Fact]
    public void CallerConfigOnTheSoakHost_ShipsItsPackageAndRegistration()
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(
            Path.Combine(RepoRoot(), "tools", "m33-soak", "SoakHost", "appsettings.json")));
        var hasCallers = doc.RootElement.GetProperty("CredProx").TryGetProperty("Callers", out var callers)
                         && callers.ValueKind == JsonValueKind.Object
                         && callers.EnumerateObject().Any();
        Assert.True(hasCallers,
            "SoakHost appsettings.json carries no CredProx:Callers section - the package-pin checks below would pass vacuously; the soak host admits callers on purpose.");

        var root = RepoRoot();
        var csproj = File.ReadAllText(Path.Combine(root, "tools", "m33-soak", "SoakHost", "SoakHost.csproj"));
        var program = File.ReadAllText(Path.Combine(root, "tools", "m33-soak", "SoakHost", "Program.cs"));
        Assert.Contains("Include=\"CredProx\"", csproj);
        Assert.Contains("AddCredProx(", program);
    }

    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "docs", "credprox-plan.md")))
        {
            dir = dir.Parent;
        }
        Assert.NotNull(dir);
        return dir!.FullName;
    }
}
