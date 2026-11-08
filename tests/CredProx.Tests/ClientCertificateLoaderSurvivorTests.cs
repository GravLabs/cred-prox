using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CredProx;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M31 mutation triage of <see cref="ClientCertificateLoader"/>: the raw-value guard, the
/// inner failure kind and diagnosis text (the wrapper names only the kind), chain
/// re-encoding between certificate blocks, the private-key block selection, and the
/// encrypted-key password paths.
/// </summary>
public sealed class ClientCertificateLoaderSurvivorTests
{
    [Fact]
    public void Load_NullRawValue_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => ClientCertificateLoader.Load(null!, null, "ref"));
    }

    [Fact]
    public void Load_CertificateWithoutPrivateKey_NamesTheKindAndCarriesTheDiagnosis()
    {
        // Public-only PFX: the PFX path is the one that yields a loadable certificate
        // without a key (a PEM bundle without a key block fails earlier, at parsing).
        using var selfSigned = TestCertificates.CreateSelfSigned("loader-triage-keyless");
        using var publicOnly = X509Certificate2.CreateFromPem(selfSigned.ExportCertificatePem());
        var keylessPfx = Convert.ToBase64String(publicOnly.Export(X509ContentType.Pfx));

        var ex = Assert.Throws<InvalidOperationException>(
            () => ClientCertificateLoader.Load(keylessPfx, null, "triage-ref"));

        Assert.Equal("The client certificate 'triage-ref' cannot be loaded (FormatException).", ex.Message);
        var inner = Assert.IsType<FormatException>(ex.InnerException);
        Assert.Equal("The certificate has no private key.", inner.Message);
    }

    [Fact]
    public void Load_TwoCertificateBlocks_PlusKey_ReEncodesTheChain()
    {
        // The separator between certificate blocks is load-bearing: dropped, the blocks
        // concatenate into one unparseable label body.
        using var selfSigned = TestCertificates.CreateSelfSigned("loader-triage-chain");
        var bundle = selfSigned.ExportCertificatePem() + "\n"
            + selfSigned.ExportCertificatePem() + "\n"
            + selfSigned.GetRSAPrivateKey()!.ExportPkcs8PrivateKeyPem();

        using var certificate = ClientCertificateLoader.Load(bundle, null, "chain-ref");
        Assert.True(certificate.HasPrivateKey);
    }

    [Fact]
    public void Load_PublicKeyBlockBeforePrivateKey_SelectsThePrivateKeyBlock()
    {
        // A public key must never be mistaken for the key block (label tail match, first
        // key block wins): the key stays null until a *PRIVATE KEY label arrives.
        using var selfSigned = TestCertificates.CreateSelfSigned("loader-triage-pubpriv");
        var bundle = selfSigned.ExportCertificatePem() + "\n"
            + selfSigned.GetRSAPublicKey()!.ExportSubjectPublicKeyInfoPem() + "\n"
            + selfSigned.GetRSAPrivateKey()!.ExportPkcs8PrivateKeyPem();

        using var certificate = ClientCertificateLoader.Load(bundle, null, "pub-priv-ref");
        Assert.True(certificate.HasPrivateKey);
    }

    [Fact]
    public void Load_EncryptedKeyWithoutPassword_ReportsTheMissingPasswordDiagnosis()
    {
        using var selfSigned = TestCertificates.CreateSelfSigned("loader-triage-enc");
        var bundle = TestCertificates.EncryptedPemBundle(selfSigned, "triage-password");

        var ex = Assert.Throws<InvalidOperationException>(
            () => ClientCertificateLoader.Load(bundle, password: null, "enc-ref"));

        Assert.Equal("The client certificate 'enc-ref' cannot be loaded (FormatException).", ex.Message);
        var inner = Assert.IsType<FormatException>(ex.InnerException);
        Assert.Equal("The private key is encrypted but no password is configured.", inner.Message);
    }

    [Fact]
    public void Load_EncryptedKeyWithPassword_DecryptsAndLoads()
    {
        using var selfSigned = TestCertificates.CreateSelfSigned("loader-triage-encok");
        var bundle = TestCertificates.EncryptedPemBundle(selfSigned, "triage-password");

        using var certificate = ClientCertificateLoader.Load(bundle, "triage-password", "enc-ok-ref");
        Assert.True(certificate.HasPrivateKey);
    }

    [Fact]
    public void Load_GarbageBase64_NamesKindNeverValue()
    {
        var secretish = Convert.ToBase64String("hunter2-hunter2"u8.ToArray());

        var ex = Assert.Throws<InvalidOperationException>(
            () => ClientCertificateLoader.Load(secretish, null, "junk-ref"));

        Assert.Equal(
            $"The client certificate 'junk-ref' cannot be loaded ({ex.InnerException!.GetType().Name}).",
            ex.Message);
        Assert.DoesNotContain("hunter2", ex.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void Load_CertPlusPublicKeyWithoutPrivateKey_FailsAsNoPrivateKeyNotKeyMismatch()
    {
        // The selector must never accept a PUBLIC KEY block as the key: it would then
        // die as "key does not match the certificate" (CryptographicException) and hide
        // the operator's actual problem — no private key configured at all.
        using var selfSigned = TestCertificates.CreateSelfSigned("loader-triage-keyabsent");
        var bundle = selfSigned.ExportCertificatePem() + "\n"
            + selfSigned.GetRSAPublicKey()!.ExportSubjectPublicKeyInfoPem() + "\n";

        var ex = Assert.Throws<InvalidOperationException>(
            () => ClientCertificateLoader.Load(bundle, null, "key-absent-ref"));

        Assert.Equal("The client certificate 'key-absent-ref' cannot be loaded (FormatException).", ex.Message);
        var inner = Assert.IsType<FormatException>(ex.InnerException);
        Assert.Equal("The PEM bundle contains no private key.", inner.Message);
    }

    [Fact]
    public void Load_PrivateKeyOnlyBundle_StatesNoCertificate()
    {
        // The two bundle diagnoses are distinct operator problems; dropping the
        // certificate check would fall through to the missing-key message (or worse,
        // a key-parse crash) and blame the wrong thing.
        using var selfSigned = TestCertificates.CreateSelfSigned("loader-triage-nocert");
        var keyOnly = selfSigned.GetRSAPrivateKey()!.ExportPkcs8PrivateKeyPem();

        var ex = Assert.Throws<InvalidOperationException>(
            () => ClientCertificateLoader.Load(keyOnly, null, "no-cert-ref"));

        Assert.Equal("The client certificate 'no-cert-ref' cannot be loaded (FormatException).", ex.Message);
        var inner = Assert.IsType<FormatException>(ex.InnerException);
        Assert.Equal("The PEM bundle contains no certificate.", inner.Message);
    }

    [Fact]
    public void Load_EncryptedEcdsaKeyWithPassword_DecryptsThroughTheEcdsaFallback()
    {
        // The RSA import of an encrypted EC-PKCS8 block raises CryptographicException;
        // the fallback re-reads it as EC and re-emits the key under its plain label —
        // relabelling it anything else (or nothing) breaks the CreateFromPem pair.
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=loader-triage-ec", ecdsa, HashAlgorithmName.SHA256);
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(2));
        var encrypted = ecdsa.ExportEncryptedPkcs8PrivateKey(
            "ec-password",
            new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 100_000));
        var bundle = cert.ExportCertificatePem()
            + "\n"
            + PemEncoding.WriteString("ENCRYPTED PRIVATE KEY", encrypted);

        using var loaded = ClientCertificateLoader.Load(bundle, "ec-password", "ec-enc-ref");
        Assert.True(loaded.HasPrivateKey);
    }
}
