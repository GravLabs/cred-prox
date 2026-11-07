using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.RegularExpressions;
using CredProx;
using CredProx.Abstractions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;
using Yarp.ReverseProxy.Configuration;

namespace CredProx.Tests;

/// <summary>
/// M28 (§8.6, vendor config snippets): every <c>json credprox-snippet</c> block in
/// docs/vendors/*.md is extracted and taken through the REAL fail-closed startup path —
/// unknown-key rejection at registration (M14a/M16/M17) plus the full
/// <see cref="CredProxStartupValidator"/> pass (registry binds, secret-reference
/// resolution, route-metadata cross-checks). A snippet with a wrong or misspelled key
/// therefore fails CI, not the adopter's first deploy.
/// </summary>
/// <remarks>
/// The two negative probes here are the milestone's required "deliberately broken
/// snippet" demo, pinned so the gate stays loaded: an unknown key must refuse
/// registration, and a dangling credential reference must refuse startup validation.
/// Placeholders <c>&lt;like-this&gt;</c> substitute to syntactically valid values, and
/// empty <c>CredProx:Secrets</c> values (pages list names, never values) substitute to
/// a syntactically valid stand-in — certificate- and key-shaped names get a real
/// generated PEM so the binders that load material still bind.
/// </remarks>
public sealed class VendorSnippetValidationTests
{
    private const string SnippetFence = "```json credprox-snippet";

    private static readonly Regex BlockPattern = new(
        Regex.Escape(SnippetFence) + @"\r?\n(?<json>.*?)\r?\n```", RegexOptions.Singleline | RegexOptions.Compiled);

    private static readonly Regex PlaceholderPattern = new(
        @"<([A-Za-z0-9_.\-]+)>", RegexOptions.Compiled);

    private static readonly string[] ExpectedPages =
    [
        "adp.md", "github-apps.md", "graph.md", "salesforce.md", "servicenow.md", "spotify.md", "workday.md",
    ];

    // ---- roster + extraction ----

    [Fact]
    public void VendorFolder_HasExactlyTheRosteredPages_EachWithOneSnippet()
    {
        var pages = Directory.GetFiles(VendorsDir(), "*.md")
            .Where(p => !string.Equals(Path.GetFileName(p), "README.md", StringComparison.OrdinalIgnoreCase))
            .Select(Path.GetFileName)
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(ExpectedPages, pages);

        foreach (var page in pages)
        {
            Assert.Single(BlockPattern.Matches(File.ReadAllText(Path.Combine(VendorsDir(), page!))).Cast<Match>());
        }
    }

    // ---- the happy path: every snippet survives the real startup gate ----

    [Theory]
    [MemberData(nameof(VendorPages))]
    public async Task Snippet_BindsAndPassesStartupValidation(string page)
    {
        var entries = ExtractEntries(page);
        var config = Build(entries);

        using var provider = Register(config);
        await StartValidatorAsync(provider, config);
    }

    // ---- negative probe 1: a misspelled key inside a snippet must fail CI ----

    [Theory]
    [MemberData(nameof(VendorPages))]
    public void Snippet_WithMisspelledKey_FailsRegistration(string page)
    {
        var entries = ExtractEntries(page);
        entries["CredProx:InboundKeyHeaderr"] = "X-API-Key"; // the exact class of typo the M17 walker refuses
        var config = Build(entries);

        var ex = Assert.Throws<OptionsValidationException>(() => Register(config));
        Assert.Contains("'InboundKeyHeaderr'", ex.Message);
    }

    // ---- negative probe 2: a dangling credential reference must fail validation ----

    [Theory]
    [MemberData(nameof(VendorPages))]
    public async Task Snippet_WithDanglingCredentialReference_FailsStartupValidation(string page)
    {
        var entries = ExtractEntries(page);
        var rewritten = 0;
        foreach (var key in entries.Keys.ToList())
        {
            if (Regex.IsMatch(key, @"^ReverseProxy:Routes:[^:]+:Metadata:CredProx\.Credential$"))
            {
                entries[key] = "ghost-ref";
                rewritten++;
            }
        }

        Assert.True(rewritten > 0, $"no route credential metadata found in {page}");
        var config = Build(entries);

        using var provider = Register(config);
        var ex = await Assert.ThrowsAsync<OptionsValidationException>(
            () => StartValidatorAsync(provider, config));
        Assert.Contains("ghost-ref", ex.Message);
    }

    // ---- the real startup path ----

    /// <summary>The registration half: this is where unknown-key refusal happens.</summary>
    private static ServiceProvider Register(IConfiguration config)
    {
        // Same registration set a sample host runs (samples/Spotify/Program.cs:27-34),
        // minus the web host: cache, config secrets, built-in credential types, the
        // config-bound credential registry, then the YARP + CredProx feature.
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddCredProxTokenCache();
        services.AddCredProxConfigurationSecrets(config);
        services.AddCredProxBuiltInCredentials();
        services.AddCredProxCredentials(config);
        services.AddReverseProxy().LoadFromConfig(config.GetSection("ReverseProxy")).AddCredProx(config);
        return services.BuildServiceProvider();
    }

    private static async Task StartValidatorAsync(ServiceProvider provider, IConfiguration config)
    {
        // The same validator the host starts via AddCredProx's AddHostedService, driven
        // directly the way CredProxStartupValidatorTests drives it — real providers, real
        // registries, no stubs: the snippet config is the system under test.
        var validator = new CredProxStartupValidator(
            provider,
            provider.GetServices<IProxyConfigProvider>(),
            config,
            provider.GetRequiredService<SecretReferenceValidator>(),
            provider.GetServices<IPresetSource>(),
            NullLogger<CredProxStartupValidator>.Instance);

        await validator.StartAsync(default);
    }

    // ---- extraction + placeholder substitution ----

    public static TheoryData<string> VendorPages()
    {
        var data = new TheoryData<string>();
        foreach (var name in ExpectedPages)
        {
            data.Add(Path.Combine(VendorsDir(), name));
        }

        return data;
    }

    private static Dictionary<string, string?> ExtractEntries(string pagePath)
    {
        var block = Assert.Single(BlockPattern.Matches(File.ReadAllText(pagePath)).Cast<Match>());

        var entries = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        using var document = JsonDocument.Parse(
            block.Groups["json"].Value,
            new JsonDocumentOptions { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true });
        Flatten("", document.RootElement, entries);

        // <placeholders> substitute to syntactically valid, host-safe tokens; the docs'
        // own rule is that real tenant values only ever appear as placeholders.
        foreach (var key in entries.Keys.ToList())
        {
            if (entries[key] is string value)
            {
                entries[key] = PlaceholderPattern.Replace(value, m => m.Groups[1].Value);
            }
        }

        // Secrets: pages name the references and leave values empty; stand in per shape.
        foreach (var key in entries.Keys.ToList())
        {
            if (!key.StartsWith("CredProx:Secrets:", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (entries[key] is not (null or ""))
            {
                continue; // a page that ever ships a literal secret fails the scrub gate, not this one
            }

            entries[key] = key.Contains("signing", StringComparison.OrdinalIgnoreCase)
                ? PrivateKeyPem()
                : key.Contains("cert", StringComparison.OrdinalIgnoreCase)
                    ? PemBundle()
                    : "snippet-test-secret-value";
        }

        return entries;
    }

    private static IConfiguration Build(Dictionary<string, string?> entries) =>
        new ConfigurationBuilder().AddInMemoryCollection(entries).Build();

    private static void Flatten(string prefix, JsonElement element, Dictionary<string, string?> entries)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var property in element.EnumerateObject())
                {
                    Flatten(prefix.Length == 0 ? property.Name : prefix + ":" + property.Name, property.Value, entries);
                }

                break;

            case JsonValueKind.Array:
                var index = 0;
                foreach (var item in element.EnumerateArray())
                {
                    Flatten($"{prefix}:{index}", item, entries);
                    index++;
                }

                break;

            case JsonValueKind.Null:
                entries[prefix] = null;
                break;

            default:
                entries[prefix] = element.GetRawText().Trim('"');
                break;
        }
    }

    // ---- repo navigation ----

    private static string VendorsDir()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "docs", "credprox-plan.md")))
        {
            dir = dir.Parent;
        }

        Assert.NotNull(dir);
        return Path.Combine(dir!.FullName, "docs", "vendors");
    }

    // ---- syntactically valid stand-ins for key/cert secrets ----

    private static string PrivateKeyPem()
    {
        using var rsa = RSA.Create(2048);
        return rsa.ExportPkcs8PrivateKeyPem();
    }

    private static string PemBundle()
    {
        using var rsa = RSA.Create(2048);
        using var certificate = new CertificateRequest(
                "CN=snippet-test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        return certificate.ExportCertificatePem() + "\n" + certificate.GetRSAPrivateKey()!.ExportPkcs8PrivateKeyPem();
    }
}
