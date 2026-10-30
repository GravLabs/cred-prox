using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CredProx.E2ETests;

/// <summary>
/// Throwaway PKI for the nginx mTLS test (plan §5.2 Connections row): a CA, a server
/// certificate for <c>localhost</c>, and two client certificates whose subjects nginx echoes
/// back so rotation is verified from the server's side. All material lives in the test's
/// temp directory and dies with it.
/// </summary>
internal static class E2ECertificates
{
    internal sealed record TestPki(
        string CaCertificatePem,
        string ServerCertificatePem,
        string ServerPrivateKeyPem,
        string ServerCertificateThumbprint,
        string ClientAlphaBundlePem,
        string ClientBetaBundlePem);

    public static TestPki Create()
    {
        var notBefore = DateTimeOffset.UtcNow.AddDays(-1);
        var notAfter = DateTimeOffset.UtcNow.AddDays(2);

        using var caKey = RSA.Create(2048);
        var caRequest = new CertificateRequest(
            "CN=CredProx E2E CA", caKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        caRequest.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, critical: true));
        using var ca = caRequest.CreateSelfSigned(notBefore, notAfter);

        var (serverCert, serverKeyPem) = CreateLeaf(ca, "localhost", Oids.ServerAuth, ["localhost"], notBefore, notAfter);
        var (alphaCert, alphaKeyPem) = CreateLeaf(ca, "client-alpha", Oids.ClientAuth, null, notBefore, notAfter);
        var (betaCert, betaKeyPem) = CreateLeaf(ca, "client-beta", Oids.ClientAuth, null, notBefore, notAfter);

        return new TestPki(
            ca.ExportCertificatePem(),
            serverCert.ExportCertificatePem(),
            serverKeyPem,
            serverCert.Thumbprint,
            Bundle(alphaCert, alphaKeyPem),
            Bundle(betaCert, betaKeyPem));
    }

    private static class Oids
    {
        public static readonly Oid ServerAuth = new("1.3.6.1.5.5.7.3.1");

        public static readonly Oid ClientAuth = new("1.3.6.1.5.5.7.3.2");
    }

    private static (X509Certificate2 Certificate, string PrivateKeyPem) CreateLeaf(
        X509Certificate2 ca,
        string commonName,
        Oid enhancedKeyUsage,
        string[]? dnsNames,
        DateTimeOffset notBefore,
        DateTimeOffset notAfter)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(
            $"CN={commonName}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, critical: true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { enhancedKeyUsage }, critical: false));

        if (dnsNames is not null)
        {
            var san = new SubjectAlternativeNameBuilder();
            foreach (var dnsName in dnsNames)
            {
                san.AddDnsName(dnsName);
            }

            request.CertificateExtensions.Add(san.Build());
        }

        // A positive, unique serial per leaf (leading byte below 0x80).
        var serialNumber = new byte[9];
        serialNumber[0] = 0x01;
        RandomNumberGenerator.Fill(serialNumber.AsSpan(1));

        // The self-signed CA already carries its private key; it signs the leaf directly.
        var certificate = request.Create(ca, notBefore, notAfter, serialNumber);
        return (certificate, key.ExportPkcs8PrivateKeyPem());
    }

    // The PEM bundle shape CredProx's connection loader accepts: certificate blocks and a
    // PKCS#8 private key block.
    private static string Bundle(X509Certificate2 certificate, string privateKeyPem) =>
        certificate.ExportCertificatePem() + "\n" + privateKeyPem;
}
