using System.Security.Cryptography.X509Certificates;
using CredProx;
using CredProx.Abstractions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// <c>CredProx:Connections</c> startup binding and certificate rotation (§3.3, §5.2
/// "Connections"): the certificate loads at startup (a wrong password fails startup,
/// naming the connection but never the password), a rotated secret value bumps the
/// version stamp the client factory compares, and a broken rotation keeps serving the
/// previous certificate.
/// </summary>
public sealed class ConnectionBinderTests
{
    private readonly X509Certificate2 _first = TestCertificates.CreateSelfSigned("conn-first");
    private readonly X509Certificate2 _second = TestCertificates.CreateSelfSigned("conn-second");

    private static (IConfiguration Config, ReloadableMemoryConfigurationProvider Reloadable) ConfigWith(
        Dictionary<string, string?> entries)
    {
        var source = new ReloadableMemoryConfigurationSource(entries);
        var config = new ConfigurationBuilder().Add(source).Build();
        return (config, (ReloadableMemoryConfigurationProvider)config.Providers.OfType<ReloadableMemoryConfigurationProvider>().Single());
    }

    private static ConnectionRegistry Bind(IConfiguration config) =>
        new ConnectionBinder(
            config,
            new SecretAccessorFactory(new ConfigurationSecretSource(config)),
            NullLoggerFactory.Instance)
            .Bind();

    private Dictionary<string, string?> PfxConnection(string password = "p@ss") => new()
    {
        ["CredProx:Connections:contoso:ClientCertificate"] = "secret:contoso-cert",
        ["CredProx:Connections:contoso:ClientCertificatePassword"] = "secret:contoso-pw",
        ["CredProx:Secrets:contoso-cert"] = TestCertificates.PfxBase64(_first, password),
        ["CredProx:Secrets:contoso-pw"] = password,
    };

    [Fact]
    public void ValidConnection_LoadsAtStartup()
    {
        var (config, _) = ConfigWith(PfxConnection());

        var registry = Bind(config);

        var connection = registry.Get("contoso");
        Assert.Equal(_first.Thumbprint, connection.Certificate.Thumbprint);
        Assert.Equal(1, connection.Version);
        Assert.Equal("secret:contoso-cert", connection.CertificateReference);
    }

    [Fact]
    public void MissingClientCertificate_FailsStartup()
    {
        var (config, _) = ConfigWith(new Dictionary<string, string?>
        {
            ["CredProx:Connections:contoso:ClientCertificatePassword"] = "secret:pw",
        });

        var error = Assert.Throws<OptionsValidationException>(() => Bind(config));
        Assert.Contains("contoso", error.Message);
        Assert.Contains("no ClientCertificate", error.Message);
    }

    [Fact]
    public void UnresolvableCertificateSecret_FailsStartupNamingTheReference()
    {
        var (config, _) = ConfigWith(new Dictionary<string, string?>
        {
            ["CredProx:Connections:contoso:ClientCertificate"] = "secret:nowhere",
        });

        var error = Assert.Throws<OptionsValidationException>(() => Bind(config));
        Assert.Contains("contoso", error.Message);
        Assert.Contains("nowhere", error.Message);
    }

    [Fact]
    public void WrongPassword_FailsStartupWithoutEchoingIt()
    {
        var (config, _) = ConfigWith(new Dictionary<string, string?>
        {
            ["CredProx:Connections:contoso:ClientCertificate"] = "secret:contoso-cert",
            ["CredProx:Connections:contoso:ClientCertificatePassword"] = "secret:contoso-pw",
            ["CredProx:Secrets:contoso-cert"] = TestCertificates.PfxBase64(_first, "real-p@ss"),
            ["CredProx:Secrets:contoso-pw"] = "wrong-p@ss",
        });

        var error = Assert.Throws<OptionsValidationException>(() => Bind(config));
        Assert.Contains("contoso", error.Message);
        Assert.DoesNotContain("wrong-p@ss", error.Message);
        Assert.DoesNotContain("real-p@ss", error.Message);
    }

    [Fact]
    public void RotatedSecretValue_ReloadsCertificateAndBumpsVersion()
    {
        var (config, reloadable) = ConfigWith(PfxConnection(password: "p@ss"));
        var connection = Bind(config).Get("contoso");

        reloadable.Set("CredProx:Secrets:contoso-cert", TestCertificates.PfxBase64(_second, "p@ss"));
        reloadable.Reload();
        connection.Refresh();

        Assert.Equal(2, connection.Version);
        Assert.Equal(_second.Thumbprint, connection.Certificate.Thumbprint);
    }

    [Fact]
    public void UnchangedSecretValue_RefreshKeepsVersion()
    {
        var (config, reloadable) = ConfigWith(PfxConnection());
        var connection = Bind(config).Get("contoso");

        reloadable.Reload();
        connection.Refresh();

        Assert.Equal(1, connection.Version);
    }

    [Fact]
    public void BrokenRotatedValue_KeepsServingThePreviousCertificate()
    {
        var (config, reloadable) = ConfigWith(PfxConnection());
        var connection = Bind(config).Get("contoso");

        reloadable.Set("CredProx:Secrets:contoso-cert", "not-certificate-material");
        reloadable.Reload();
        connection.Refresh();

        Assert.Equal(1, connection.Version);
        Assert.Equal(_first.Thumbprint, connection.Certificate.Thumbprint);
    }

    [Fact]
    public void UnknownConnectionName_FailsWithMessage()
    {
        var (config, _) = ConfigWith(PfxConnection());

        var registry = Bind(config);
        Assert.False(registry.TryGet("other", out _));
        Assert.Throws<InvalidOperationException>(() => registry.Get("other"));
    }
}
