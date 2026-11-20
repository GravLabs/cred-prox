using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using Azure.Core;
using CredProx;
using CredProx.Abstractions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;
using Yarp.ReverseProxy.Configuration;

namespace CredProx.Tests;

/// <summary>
/// M48 guard for the class of break a public-API rename leaves in <c>tools/</c>: the
/// SoakHost and aca-live-harness credential configs are taken through the real
/// fail-closed startup path — the same registration set each host runs and the same
/// <see cref="CredProxStartupValidator"/> pass <see cref="VendorSnippetValidationTests"/>
/// drives for docs/vendors snippets. A renamed or misspelled config key therefore fails
/// the battery, not the release soak (which was how the LoginExchange
/// Lifetime rename would have surfaced). Secret values the hosts take from Key Vault at
/// runtime are stood in per shape exactly as the vendor-snippet gate does; names are the
/// file's own.
/// </summary>
public sealed class ToolsConfigBindingGuardTests
{
    /// <summary>
    /// STRONG arm (SoakHost): every credential bag binds AND the full startup-validation
    /// pass runs. Caller <c>KeyHash</c> placeholders and empty secret names stand in for
    /// runtime material (Key Vault) with valid shapes, exactly as the vendor-snippet gate
    /// stands in PEM for docs pages.
    /// </summary>
    [Fact]
    public void SoakHostConfig_BindsAndPassesStartupValidation()
    {
        var config = Load(Path.Combine("tools", "m33-soak", "SoakHost", "appsettings.json"));

        using var provider = Register(config, useLoginExchange: true);
        provider.GetRequiredService<CredentialRegistryProvider>();
        StartValidator(provider, config);
    }

    /// <summary>
    /// BINDER arm (aca-live-harness): unknown-key rejection at the credential binder via
    /// registry activation, NOT full startup validation — the shipped file declares no
    /// <c>CredProx:Callers</c> section at all (its caller keys arrive from Key Vault at
    /// runtime), so the startup validator refuses it with its no-caller rule ("Caller
    /// authentication is registered but no caller is configured") before the credential
    /// key-rename class is even reachable. The TokenCredential is a never-acquired stub:
    /// binding its bag must not ask it for a token (the stub is the pin).
    /// </summary>
    [Fact]
    public void AcaLiveHarnessConfig_CredentialBags_BindThroughFailClosedRegistration()
    {
        var config = Load(Path.Combine("tools", "aca-live-harness", "appsettings.json"));

        using var provider = Register(config, useLoginExchange: false);
        provider.GetRequiredService<CredentialRegistryProvider>();
    }

    /// <summary>
    /// Guard-loaded probe: the exact regression class this file exists for — a credential
    /// bag carrying a key the options type no longer defines must be refused loudly, with
    /// the unknown key named, not silently ignored.
    /// </summary>
    [Fact]
    public void SoakHostConfig_WithStaleRenamedKey_FailsStartupNamingTheKey()
    {
        var config = new ConfigurationBuilder()
            .AddJsonFile(RepoFile(Path.Combine("tools", "m33-soak", "SoakHost", "appsettings.json")))
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                // The pre-rename spelling of the login-exchange lifetime knob.
                ["CredProx:Credentials:login-acme:Lifetime"] = "00:02:00",
            })
            .Build();

        var ex = Assert.ThrowsAny<OptionsValidationException>(() =>
        {
            using var provider = Register(OverlaySecrets(config), useLoginExchange: true);
            provider.GetRequiredService<CredentialRegistryProvider>();
        });
        Assert.Contains("'Lifetime'", ex.Message, StringComparison.Ordinal);
    }

    // ---- the real startup path, per host ----

    private static ServiceProvider Register(IConfiguration config, bool useLoginExchange)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        if (useLoginExchange)
        {
            // Mirrors tools/m33-soak/SoakHost/Program.cs registrations.
            services.AddCredProxTokenCache();
            services.AddCredProxConfigurationSecrets(config);
            services.AddCredProxCallerAuthentication(config);
            services.AddCredProxBuiltInCredentials();
            services.AddCredProxOAuth();
            services.AddCredProxLoginExchange();
            services.AddCredProxCredentials(config);
            services.AddCredProxThrottling(config);
            services.AddCredProxResilience(config);
            services.AddReverseProxy()
                .LoadFromConfig(config.GetSection("ReverseProxy"))
                .AddCredProx(config);
        }
        else
        {
            // Mirrors tools/aca-live-harness/Program.cs registrations; the TokenCredential
            // is a never-acquired stub — startup validation must not ask it for a token.
            services.AddCredProxAzureTokenCredential(new NeverAcquiredTokenCredential());
            services.AddCredProxTokenCache();
            services.AddCredProxConfigurationSecrets(config);
            services.AddCredProxBuiltInCredentials();
            services.AddCredProxOAuth();
            services.AddCredProxHmac();
            services.AddCredProxCredentials(config);
            services.AddCredProxCallerAuthentication(config);
            services.AddReverseProxy()
                .LoadFromConfig(config.GetSection("ReverseProxy"))
                .AddCredProx(config);
        }

        return services.BuildServiceProvider();
    }

    private static void StartValidator(ServiceProvider provider, IConfiguration config)
    {
        var validator = new CredProxStartupValidator(
            provider,
            provider.GetServices<IProxyConfigProvider>(),
            config,
            provider.GetRequiredService<SecretReferenceValidator>(),
            provider.GetServices<IPresetSource>(),
            NullLogger<CredProxStartupValidator>.Instance);

        validator.StartAsync(default).GetAwaiter().GetResult();
    }

    // ---- config loading with the vendor-gate secret stand-ins ----

    private static IConfiguration Load(string relativePath) =>
        OverlaySecrets(new ConfigurationBuilder()
            .AddJsonFile(RepoFile(relativePath))
            .Build());

    private static IConfiguration OverlaySecrets(IConfiguration config)
    {
        config = OverlayCallerKeyHashes(config);
        // Key Vault supplies the real values at runtime; the gate stands in per shape,
        // exactly as the vendor-snippet rule (certificate- and key-shaped names get real
        // generated material so the binders that load material still bind).
        var overlays = new Dictionary<string, string?>();
        foreach (var section in config.GetSection("CredProx:Secrets").GetChildren())
        {
            if (section.Value is not (null or ""))
            {
                continue;
            }

            overlays["CredProx:Secrets:" + section.Key] = section.Key.Contains("signing", StringComparison.OrdinalIgnoreCase)
                ? PrivateKeyPem()
                : section.Key.Contains("cert", StringComparison.OrdinalIgnoreCase) && !section.Key.Contains("password", StringComparison.OrdinalIgnoreCase)
                    ? PemBundle()
                    : "tools-guard-test-secret-value";
        }

        return overlays.Count == 0 ? config : new ConfigurationBuilder().AddConfiguration(config)
            .AddInMemoryCollection(overlays)
            .Build();
    }

    /// <summary>
    /// Soak config ships placeholder KeyHashes (KEYHASH_A, ...); the harness supplies real
    /// ones from Key Vault at runtime. Stand in a deterministic, shape-valid hash so the
    /// caller-side startup checks see material, not the placeholder.
    /// </summary>
    private static IConfiguration OverlayCallerKeyHashes(IConfiguration config)
    {
        var overlays = new Dictionary<string, string?>();
        foreach (var caller in config.GetSection("CredProx:Callers").GetChildren())
        {
            foreach (var key in caller.GetSection("Keys").GetChildren())
            {
                var hash = key["KeyHash"];
                if (hash is null || KeyHashPattern.IsMatch(hash))
                {
                    continue;
                }

                var path = $"CredProx:Callers:{caller.Key}:Keys:{key.Key}:KeyHash";
                overlays[path] = "sha256:" + Convert.ToHexString(
                    SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(path))).ToLowerInvariant();
            }
        }

        return overlays.Count == 0 ? config : new ConfigurationBuilder().AddConfiguration(config)
            .AddInMemoryCollection(overlays)
            .Build();
    }

    private static readonly Regex KeyHashPattern = new(@"^sha256:[0-9a-fA-F]{64}$", RegexOptions.Compiled);

    private static string RepoFile(string relativePath)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "docs", "credprox-plan.md")))
        {
            dir = dir.Parent;
        }

        Assert.NotNull(dir);
        return Path.Combine(dir!.FullName, relativePath);
    }

    private static string PrivateKeyPem()
    {
        using var rsa = RSA.Create(2048);
        return rsa.ExportPkcs8PrivateKeyPem();
    }

    private static string PemBundle()
    {
        using var rsa = RSA.Create(2048);
        using var certificate = new CertificateRequest(
                "CN=tools-guard-test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        return certificate.ExportCertificatePem() + "\n" + certificate.GetRSAPrivateKey()!.ExportPkcs8PrivateKeyPem();
    }

    /// <summary>
    /// Registration material only: any attempt to mint a token from it is a bug in the
    /// startup path, and says so.
    /// </summary>
    private sealed class NeverAcquiredTokenCredential : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("startup validation must not acquire a token");

        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("startup validation must not acquire a token");
    }
}
