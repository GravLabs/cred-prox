using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using CredProx;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Model;
using Yarp.ReverseProxy.Transforms;

namespace CredProx.Tests;

/// <summary>
/// Builds a real <see cref="HttpContext"/> carrying the two features the M4 request
/// features read: the <see cref="CredProxRequestState"/> the core transform publishes and
/// a stub <see cref="IReverseProxyFeature"/> whose route/cluster configs carry the
/// <c>CredProx.*</c> metadata — so features run against the same shapes YARP gives them.
/// </summary>
internal static class M4Contexts
{
    public static DefaultHttpContext Create(
        out HttpRequestMessage proxyRequest,
        Dictionary<string, string>? routeMetadata = null,
        Dictionary<string, string>? clusterMetadata = null)
    {
        var context = new DefaultHttpContext();
        context.Request.Method = "GET";
        context.Request.Scheme = "http";
        context.Request.Host = new HostString("caller");
        context.Request.Path = "/api";

        var route = new RouteModel(
            new RouteConfig { RouteId = "route-1", Metadata = routeMetadata },
            cluster: null,
            HttpTransformer.Default);
        var cluster = new ClusterModel(
            new ClusterConfig { ClusterId = "cluster-1", Metadata = clusterMetadata },
            new HttpMessageInvoker(new SocketsHttpHandler()));
        context.Features.Set<IReverseProxyFeature>(new StubReverseProxyFeature(route, cluster));

        proxyRequest = new HttpRequestMessage(HttpMethod.Get, "http://upstream/api");
        context.Features.Set(new CredProxRequestState(context, proxyRequest));

        // Response body must be captured, not dropped, so abort assertions can read the
        // problem document.
        context.Response.Body = new MemoryStream();
        return context;
    }

    public static string ResponseBody(HttpContext context)
    {
        context.Response.Body.Position = 0;
        return new StreamReader(context.Response.Body, Encoding.UTF8).ReadToEnd();
    }

    private sealed class StubReverseProxyFeature(RouteModel route, ClusterModel cluster) : IReverseProxyFeature
    {
        public RouteModel Route { get; } = route;

        public ClusterModel Cluster { get; } = cluster;

        public IReadOnlyList<DestinationState> AllDestinations { get; } = [];

        public IReadOnlyList<DestinationState> AvailableDestinations { get; set; } = [];

        public DestinationState? ProxiedDestination { get; set; }
    }
}

/// <summary>
/// In-memory certificate material for the connection tests: a self-signed RSA certificate
/// exported as base64 PFX (optionally password-protected), a plain PEM bundle, or a PEM
/// bundle whose key is an encrypted PKCS#8.
/// </summary>
internal static class TestCertificates
{
    public static X509Certificate2 CreateSelfSigned(string commonName)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            $"CN={commonName}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(365));
    }

    public static string PfxBase64(X509Certificate2 certificate, string? password = null) =>
        Convert.ToBase64String(certificate.Export(X509ContentType.Pfx, password));

    // ExportCertificatePem/ExportPkcs8PrivateKeyPem emit no trailing newline; PEM blocks
    // must be newline-separated or the footer of one runs into the header of the next.
    public static string PemBundle(X509Certificate2 certificate) =>
        certificate.ExportCertificatePem() + "\n" + certificate.GetRSAPrivateKey()!.ExportPkcs8PrivateKeyPem();

    public static string EncryptedPemBundle(X509Certificate2 certificate, string password)
    {
        using var rsa = certificate.GetRSAPrivateKey()!;
        var encrypted = rsa.ExportEncryptedPkcs8PrivateKey(
            password,
            new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 100_000));
        return certificate.ExportCertificatePem()
            + "\n"
            + PemEncoding.WriteString("ENCRYPTED PRIVATE KEY", encrypted);
    }
}

internal static class TestConfig
{
    /// <summary>An in-memory configuration root over the given raw keys.</summary>
    public static IConfiguration Root(params (string Key, string? Value)[] entries) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(entries.ToDictionary(e => e.Key, e => e.Value))
            .Build();
}

internal static class TestProviders
{
    /// <summary>A reload-aware destination provider bound over the given config root.</summary>
    public static DestinationRegistryProvider Destinations(IConfiguration config) => new(
        new DestinationBinder(config, [new HeaderPartitionSourceFactory()]),
        new ConfigurationSecretSource(config),
        Microsoft.Extensions.Logging.Abstractions.NullLogger<DestinationRegistryProvider>.Instance);
}

/// <summary>
/// Captures every log line a host writes — formatted message, plus the exception text on
/// its own line when one is attached — so tests can assert on warnings and errors.
/// </summary>
internal sealed class CapturingLoggerProvider(List<string?> logs) : ILoggerProvider
{
    public ILogger CreateLogger(string categoryName) => new CapturingLogger(logs);

    public void Dispose()
    {
    }

    private sealed class CapturingLogger(List<string?> logs) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            logs.Add(formatter(state, exception));
            if (exception is not null)
            {
                logs.Add(exception.ToString());
            }
        }
    }
}
