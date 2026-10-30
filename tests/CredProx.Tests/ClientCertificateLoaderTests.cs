using System.Security.Cryptography.X509Certificates;
using CredProx;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// <see cref="ClientCertificateLoader"/> (§3.2 <c>"ClientCertificate": "secret:..."</c>):
/// base64 PFX and PEM bundles load, encrypted keys need the right password, and every
/// failure names the reference and the failure kind — never the value, the password or
/// key material (§5.2 "Connections").
/// </summary>
public sealed class ClientCertificateLoaderTests
{
    [Fact]
    public void PfxBase64_Loads()
    {
        using var source = TestCertificates.CreateSelfSigned("loader-pfx");

        using var loaded = ClientCertificateLoader.Load(
            TestCertificates.PfxBase64(source), null, "contoso-cert");

        Assert.True(loaded.HasPrivateKey);
        Assert.Equal(source.Thumbprint, loaded.Thumbprint);
    }

    [Fact]
    public void PasswordProtectedPfx_LoadsWithPassword()
    {
        using var source = TestCertificates.CreateSelfSigned("loader-pfx-pw");

        using var loaded = ClientCertificateLoader.Load(
            TestCertificates.PfxBase64(source, "p@ss"), "p@ss", "contoso-cert");

        Assert.Equal(source.Thumbprint, loaded.Thumbprint);
    }

    [Fact]
    public void PlainPemBundle_Loads()
    {
        using var source = TestCertificates.CreateSelfSigned("loader-pem");

        using var loaded = ClientCertificateLoader.Load(
            TestCertificates.PemBundle(source), null, "contoso-cert");

        Assert.True(loaded.HasPrivateKey);
        Assert.Equal(source.Thumbprint, loaded.Thumbprint);
    }

    [Fact]
    public void EncryptedPemKey_LoadsWithPassword()
    {
        using var source = TestCertificates.CreateSelfSigned("loader-pem-pw");

        using var loaded = ClientCertificateLoader.Load(
            TestCertificates.EncryptedPemBundle(source, "p@ss"), "p@ss", "contoso-cert");

        Assert.Equal(source.Thumbprint, loaded.Thumbprint);
    }

    [Fact]
    public void EncryptedPemKey_WrongPassword_Fails()
    {
        using var source = TestCertificates.CreateSelfSigned("loader-pem-bad");
        var bundle = TestCertificates.EncryptedPemBundle(source, "right-p@ss");

        var error = Assert.Throws<InvalidOperationException>(() =>
            ClientCertificateLoader.Load(bundle, "wrong-p@ss", "contoso-cert"));

        Assert.Contains("contoso-cert", error.Message);
        Assert.DoesNotContain("wrong-p@ss", error.Message);
        Assert.DoesNotContain("right-p@ss", error.Message);
    }

    [Fact]
    public void EncryptedPemKey_NoPassword_FailsNamingTheReference()
    {
        using var source = TestCertificates.CreateSelfSigned("loader-pem-nopw");
        var bundle = TestCertificates.EncryptedPemBundle(source, "p@ss");

        var error = Assert.Throws<InvalidOperationException>(() =>
            ClientCertificateLoader.Load(bundle, null, "contoso-cert"));

        Assert.Contains("contoso-cert", error.Message);
    }

    [Fact]
    public void CertificateWithoutPrivateKey_Fails()
    {
        using var source = TestCertificates.CreateSelfSigned("loader-pub-only");
        var publicOnly = X509Certificate2.CreateFromPem(source.ExportCertificatePem());
        Assert.False(publicOnly.HasPrivateKey);

        var error = Assert.Throws<InvalidOperationException>(() =>
            ClientCertificateLoader.Load(
                Convert.ToBase64String(publicOnly.Export(X509ContentType.Pfx)), null, "contoso-cert"));

        Assert.Contains("contoso-cert", error.Message);
    }

    [Fact]
    public void GarbageValue_FailsWithoutEchoingIt()
    {
        var secretValue = "MII-super-secret-not-a-pfx";

        var error = Assert.Throws<InvalidOperationException>(() =>
            ClientCertificateLoader.Load(secretValue, null, "contoso-cert"));

        Assert.Contains("contoso-cert", error.Message);
        Assert.DoesNotContain(secretValue, error.Message);
    }
}
