using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.Extensions.AspNetCore.Configuration.Secrets;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using CredProx;
using Microsoft.Extensions.Primitives;

// M29 R2.3 (plan: docs/azure-live-test-plan.md §Round 2): the round-2 host, ONE image,
// three modes.
//
//   --mode proxy         the CredProx forwarder. Credential material is NEVER in config
//                        values or env: with KeyVault__Uri set, the stock Azure Key Vault
//                        configuration provider (the shipped MicrosoftGraph pattern:
//                        AddAzureKeyVault + AddCredProxConfigurationSecrets) feeds the
//                        secret:jwt-signing-key / secret:hmac-key / secret:mtls-client-cert
//                        (+ password) references declared in appsettings.json. The identity
//                        is the Container App's user-assigned managed identity via
//                        DefaultAzureCredential under ACA's env contract. Routes: /arm/*
//                        (TokenCredential -> ARM, the first real managed-identity egress),
//                        /jwt/*, /hmac/*, /mtls/* -> the counterparty. Every route demands
//                        a caller key (AddCredProxCallerAuthentication); the caller
//                        registry arrives as environment config and stores only the
//                        SHA-256 HASH of the key value - the registry itself is not
//                        secret material.
//   --mode counterparty  the three verifiers we run (same bar as the shipped GitHubApp
//                        --smoke stub, the HmacSigning verifier and the NginxMTls E2E):
//                        verifies the RS256 client assertion against the PINNED PUBLIC
//                        KEY, recomputes the HMAC canonical string independently, and
//                        requires + chain-verifies the mTLS client certificate against
//                        the PINNED CA. Public pinning material (jwt public key, CA cert)
//                        and its own server PFX come from the same vault via the same
//                        provider.
//   --mode battery       no listener. Probes the proxy through its INTERNAL ingress FQDN
//                        and prints one machine-readable line per plan phase
//                        ("P5 PASS ..."/"P5 FAIL ...") - driven non-interactively as a
//                        Container Apps Job by scripts/live-azure-smoke.sh (G2: no TTY,
//                        no public listener). The caller key value it presents is read
//                        from the vault as a secret.
//
//   --mode reloadproof  offline proof that the vault provider reloads a RUNNING process:
//                        the real provider 1.3.2 + a real SecretClient + its real polling
//                        loop poll a loopback Key-Vault REST stub (tools/keyvault-stub.py)
//                        through a transport swapped at SecretClientOptions.Transport -
//                        the vault URI keeps its real https vault form, only the pipeline
//                        endpoint moves. Rewrite the stub's file while the mode runs: the
//                        reload token fires and the value changes without a restart.
//                        Proves the MECHANISM (the vendor default ReloadInterval is null =
//                        NO polling; the samples set 30s explicitly); live Azure-side
//                        timing is the P10 witness's job, not claimed here. Exit-coded:
//                        RELOAD PROOF OK / RELOAD PROOF FAILED.
//
//   --smoke (with --mode proxy) full in-process offline proof: counterparty + proxy +
//   battery checks in one process with generated material - no vault, no Azure. Proves
//   the verifier logic and the CredProx wiring (JWT exchange -> pinned verification,
//   HMAC canonical string, mTLS client-cert chain + CN echo, caller-key 401). Smoke P5
//   runs against an in-proc ARM stub: route + caller-auth + forwarding, NOT the managed
//   identity - the MI path is proven only by the live battery (P5).
//
// Not claimed anywhere in this file: Keycloak never verifies a client assertion; the
// vault custodies and delivers key material and performs no crypto operation (no HSM
// claim); the pinned verifiers prove signature CORRECTNESS, not vendor trust.

var mode = ReadSwitch(args, "--mode", "proxy");

// BUILD-IDENTITY WITNESS (live finding 2026-11-06): re-pushing an UNCHANGED image tag
// leaves the Container App template byte-identical, so `update` creates no new revision
// and the running pods keep serving the PREVIOUS build - a green deploy can silently test
// stale code. The deploy script stamps the tag's CURRENT ACR digest into
// DEPLOY_IMAGE_DIGEST (a config change -> forced new revision -> fresh pull), and every
// process echoes it here so the runtime logs themselves prove which build ran. A digest
// is a content hash (public artifact identifier) - never secret material.
Console.Error.WriteLine($"build: {Environment.GetEnvironmentVariable("DEPLOY_IMAGE_DIGEST") ?? "<unset>"}");

return mode switch
{
    "proxy" when args.Contains("--smoke") => await SmokeRunner.RunAsync(),
    "proxy" => await ProxyRunner.RunAsync(),
    "counterparty" => await CounterpartyRunner.RunAsync(),
    "battery" => await BatteryRunner.RunAsync(args),
    "reloadproof" => await ReloadProofRunner.RunAsync(),
    _ => Fail($"unknown --mode '{mode}' (expected proxy | counterparty | battery | reloadproof)"),
};

static int Fail(string message)
{
    Console.Error.WriteLine($"error: {message}");
    return 1;
}

static string ReadSwitch(string[] args, string name, string defaultValue)
{
    var value = defaultValue;
    for (var i = 0; i < args.Length - 1; i++)
    {
        if (string.Equals(args[i], name, StringComparison.Ordinal))
        {
            value = args[i + 1];
        }
    }

    return value;
}

internal static class SubjectString
{
    // X500 DistinguishedName rendering embeds CRLF continuations on multi-RDN subjects -
    // keep asserts and echoes on a single line.
    public static string SquashLines(this string value) =>
        value.Replace("\r", string.Empty, StringComparison.Ordinal)
             .Replace("\n", string.Empty, StringComparison.Ordinal);
}

internal static class Wire
{
    // Shared constants between proxy config, counterparty verifier and battery asserts -
    // one place, so the smoke pass and the live pass assert the same things.
    public const string JwtIssuer = "credprox-m29";
    public const string JwtAudience = "http://credprox-m29-counterparty";
    public const string ClientCertCn = "CN=credprox-m29-client";
    public const string CallerKeyHeader = "X-CredProx-Key";

    // Plan phases. P9's host-side half (the declared-env read-back against the ARM
    // resource) is done by scripts/live-azure-smoke.sh - in-cluster the battery proves
    // the 401 edge. phase "jwtprobe" runs only the JWT check (P10 rotation witnesses).
    public static async Task<int> RunChecksAsync(HttpClient client, string proxyBase, string callerKey, string phase)
    {
        var failed = 0;
        failed += await CheckAsync("P5", phase == "all", () => ArmAsync(client, proxyBase, callerKey));
        failed += await CheckAsync("P6", phase is "all" or "jwtprobe", () => JwtAsync(client, proxyBase, callerKey));
        failed += await CheckAsync("P7", phase == "all", () => HmacAsync(client, proxyBase, callerKey));
        failed += await CheckAsync("P8", phase == "all", () => MtlsAsync(client, proxyBase, callerKey));
        failed += await CheckAsync("P9", phase == "all", () => NoKeyRejectedAsync(client, proxyBase));
        return failed == 0 ? 0 : 1;
    }

    private static async Task<int> CheckAsync(string name, bool run, Func<Task<string?>> probe)
    {
        if (!run)
        {
            return 0;
        }

        try
        {
            var detail = await probe();
            if (detail is null)
            {
                Console.WriteLine($"{name} PASS");
                return 0;
            }

            Console.WriteLine($"{name} FAIL {detail}");
            return 1;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"{name} FAIL exception {ex.GetType().Name}: {Truncate(ex.Message)}");
            return 1;
        }
    }

    private static async Task<string?> ArmAsync(HttpClient client, string baseUrl, string callerKey)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, $"{baseUrl}/arm/subscriptions?api-version=2022-12-01");
        request.Headers.TryAddWithoutValidation(CallerKeyHeader, callerKey);
        var response = await client.SendAsync(request);
        var body = await response.Content.ReadAsStringAsync();
        return response.IsSuccessStatusCode && body.Contains("subscriptionId", StringComparison.OrdinalIgnoreCase)
            ? null
            : $"status={(int)response.StatusCode} body={Truncate(body)}";
    }

    private static async Task<string?> JwtAsync(HttpClient client, string baseUrl, string callerKey)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, $"{baseUrl}/jwt/echo");
        request.Headers.TryAddWithoutValidation(CallerKeyHeader, callerKey);
        var response = await client.SendAsync(request);
        var body = await response.Content.ReadAsStringAsync();
        return response.IsSuccessStatusCode
            && body.Contains("assertion-verified", StringComparison.Ordinal)
            && body.Contains("aud-ok", StringComparison.Ordinal)
            ? null
            : $"status={(int)response.StatusCode} body={Truncate(body)}";
    }

    private static async Task<string?> HmacAsync(HttpClient client, string baseUrl, string callerKey)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/hmac/verify")
        {
            Content = new StringContent("""{"order":29}""", Encoding.UTF8, "application/json"),
        };
        request.Headers.TryAddWithoutValidation(CallerKeyHeader, callerKey);
        var response = await client.SendAsync(request);
        var body = await response.Content.ReadAsStringAsync();
        return response.IsSuccessStatusCode && body.Contains("signature valid", StringComparison.Ordinal)
            ? null
            : $"status={(int)response.StatusCode} body={Truncate(body)}";
    }

    private static async Task<string?> MtlsAsync(HttpClient client, string baseUrl, string callerKey)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, $"{baseUrl}/mtls/echo");
        request.Headers.TryAddWithoutValidation(CallerKeyHeader, callerKey);
        var response = await client.SendAsync(request);
        var body = await response.Content.ReadAsStringAsync();
        return response.IsSuccessStatusCode
            && body.Contains("mtls-verified", StringComparison.Ordinal)
            && body.Contains(ClientCertCn, StringComparison.Ordinal)
            ? null
            : $"status={(int)response.StatusCode} body={Truncate(body)}";
    }

    private static async Task<string?> NoKeyRejectedAsync(HttpClient client, string baseUrl)
    {
        var response = await client.GetAsync($"{baseUrl}/arm/subscriptions?api-version=2022-12-01");
        return (int)response.StatusCode == 401 ? null : $"status={(int)response.StatusCode} (expected 401)";
    }

    public static string Truncate(string value, int max = 180) =>
        value.Length <= max ? value : value[..max] + "...";
}

internal static class ProxyRunner
{
    public static async Task<int> RunAsync()
    {
        var app = CreateApp(smoke: false);
        await app.RunAsync();
        return 0;
    }

    public static WebApplication CreateApp(bool smoke)
    {
        var builder = WebApplication.CreateBuilder();
        if (smoke)
        {
            SmokeMaterial.ApplyProxyOverrides(builder.Configuration);
        }

        // The shipped MicrosoftGraph pattern: with a vault URI configured the standard
        // provider plugs in, so vault secrets CredProx--Secrets--<name> answer the
        // secret:<name> references in appsettings.json. Default builder order stands
        // (appsettings -> env -> command line); the vault provider appends last. The
        // caller-hash env vars the deploy script sets use distinct keys
        // (CredProx__Callers__*) that no vault secret shadows.
        // ReloadInterval is set EXPLICITLY (M29 F2): the vendor default is null = the
        // provider never polls, so a long-running proxy would keep serving the
        // pre-rotation key forever and the live P10 rotation witness could never fire.
        // 30s cadence; the P10 probe windows (20s apart) bound the pickup latency.
        var keyVaultUri = builder.Configuration["KeyVault:Uri"];
        if (!string.IsNullOrEmpty(keyVaultUri))
        {
            builder.Configuration.AddAzureKeyVault(new Uri(keyVaultUri), RuntimeIdentity.Credential(),
                new AzureKeyVaultConfigurationOptions { ReloadInterval = TimeSpan.FromSeconds(30) });
        }

        // The TokenCredential TYPE is registered by the AzureKeyVault package's helper
        // (samples/MicrosoftGraph identity variant, Program.cs:21) - the built-in set
        // alone does not know it. Smoke runs with no Azure environment, so the arm
        // credential is a fixed-token stub there: it still exercises provider attach ->
        // Bearer header -> forwarding, but the managed identity is proven ONLY by the
        // live battery (P5).
        builder.Services.AddCredProxAzureTokenCredential(
            smoke ? new SmokeTokenCredential() : RuntimeIdentity.Credential());
        builder.Services.AddCredProxTokenCache();
        builder.Services.AddCredProxConfigurationSecrets(builder.Configuration);
        builder.Services.AddCredProxBuiltInCredentials();
        builder.Services.AddCredProxCredentials(builder.Configuration);
        builder.Services.AddCredProxCallerAuthentication(builder.Configuration);
        builder.Services.AddRouting();
        builder.Services.AddReverseProxy()
            .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
            .AddCredProx(builder.Configuration);

        if (smoke)
        {
            builder.WebHost.UseUrls(SmokeMaterial.ProxyUrl);
        }

        var app = builder.Build();
        app.MapReverseProxy();
        return app;
    }
}

internal static class CounterpartyRunner
{
    public static async Task<int> RunAsync()
    {
        var app = CreateApp(smoke: false, httpPort: 8082, httpsPort: 8443);
        await app.RunAsync();
        return 0;
    }

    public static WebApplication CreateApp(bool smoke, int httpPort, int httpsPort)
    {
        var builder = WebApplication.CreateBuilder();
        if (smoke)
        {
            SmokeMaterial.ApplyCounterpartyOverrides(builder.Configuration);
        }

        // Same explicit ReloadInterval as the proxy (vendor default: no polling). The
        // jwt-public pin P10 relies on is NOT rotated during the phase, so this reload
        // never heals a wrong-key refusal mid-phase - the witness stays sound.
        var keyVaultUri = builder.Configuration["KeyVault:Uri"];
        if (!string.IsNullOrEmpty(keyVaultUri))
        {
            builder.Configuration.AddAzureKeyVault(new Uri(keyVaultUri), RuntimeIdentity.Credential(),
                new AzureKeyVaultConfigurationOptions { ReloadInterval = TimeSpan.FromSeconds(30) });
        }

        // Public pinning material + the counterparty's own server certificate (SAN
        // localhost, issued by the test CA, so the proxy's DEFAULT chain validation
        // accepts it once the entrypoint has installed the CA cert - public material -
        // into the container trust store). No CredProx services here: this is a vendor
        // stand-in, deliberately sharing no code path with the product it verifies.
        // TEST MATERIAL lives under CredProxTest:, NOT CredProx: - the shipped
        // CredProx config validator (live finding 2026-11-06) rejects every
        // foreign key inside the CredProx section at proxy startup, and the
        // vault provider feeds ALL vault secrets into every host's config.
        // Nothing that is not a bindable CredProx option may live under
        // CredProx-- in the vault (live crash: proxy CrashLoopBackOff on
        // 'caller-key-hash'/'jwt-public'/'mtls-ca*' as unknown keys).
        var jwtPublicPem = builder.Configuration["CredProxTest:jwt-public"];
        var caPem = builder.Configuration["CredProxTest:mtls-ca"];
        var serverPfx = builder.Configuration["CredProx:Secrets:cp-server-cert"];
        var serverPfxPassword = builder.Configuration["CredProx:Secrets:cp-server-cert-password"];
        var hmacKey = builder.Configuration["CredProx:Secrets:hmac-key"];
        if (string.IsNullOrEmpty(jwtPublicPem) || string.IsNullOrEmpty(caPem)
            || string.IsNullOrEmpty(serverPfx) || string.IsNullOrEmpty(hmacKey))
        {
            throw new InvalidOperationException(
                "counterparty needs CredProxTest:jwt-public, CredProxTest:mtls-ca, " +
                "CredProx:Secrets:cp-server-cert(+password) and CredProx:Secrets:hmac-key " +
                "- from the vault via KeyVault__Uri (live) or --smoke material (offline).");
        }

        var jwtRsa = RSA.Create();
        jwtRsa.ImportFromPem(jwtPublicPem);
        // Stub token lifetime (ruling B, 2026-11-06): CONFIGURABLE because the
        // P10 live rotation witness is gated by the proxy's EXCHANGED-TOKEN refresh point
        // (lifetime x RefreshFraction 0.8), not by the vault reload interval - at 59 min
        // the wrong key is never refused inside any sane witness window. Live deploy sets
        // 2 minutes (CredProxTest__stub-token-minutes); default 59 keeps the offline smoke
        // and every un-set deployment exactly as before.
        var stubTokenMinutes = int.TryParse(builder.Configuration["CredProxTest:stub-token-minutes"], out var stm) && stm > 0
            ? stm
            : 59;
        var ca = X509Certificate2.CreateFromPem(caPem);
        var serverCertificate = X509CertificateLoader.LoadPkcs12(Convert.FromBase64String(serverPfx), serverPfxPassword);

        builder.WebHost.ConfigureKestrel(options =>
        {
            // Explicit Listen replaces ASPNETCORE_URLS for this container (the app yaml
            // sets no URLS for the counterparty - the ports live here).
            options.ListenAnyIP(httpPort);
            options.ListenAnyIP(httpsPort, listen => listen.UseHttps(https =>
            {
                https.ServerCertificate = serverCertificate;
                // Allow + verify ourselves against the pinned test CA: the CA is in no
                // OS trust store on THIS container, and the pinned chain is the point
                // of the check (same posture as the NginxMTls E2E's ssl_verify_client).
                https.ClientCertificateMode = Microsoft.AspNetCore.Server.Kestrel.Https.ClientCertificateMode.AllowCertificate;
                https.ClientCertificateValidation = (clientCertificate, _, _) =>
                    clientCertificate is not null && VerifyAgainstPinnedCa(clientCertificate, ca);
            }));
        });

        var app = builder.Build();

        // The installation-token shape of the shipped GitHubApp stub, verified with an
        // independent RS256 check against the pinned public key (signature + iss/aud/exp/
        // jti) exactly the way GitHub's own verifier works against the App's key.
        app.MapPost("/app/token", async (HttpContext context) =>
        {
            var header = context.Request.Headers.Authorization.ToString();
            var jwt = header.StartsWith("Bearer ", StringComparison.Ordinal) ? header["Bearer ".Length..] : "";
            var parts = jwt.Split('.');
            if (jwt.Length == 0 || parts.Length != 3 || !VerifyJwt(jwtRsa, parts))
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await context.Response.WriteAsync("""{"message":"JWT verification failed"}""");
                return;
            }

            context.Response.StatusCode = StatusCodes.Status201Created;
            await context.Response.WriteAsync(
                $$"""{"token":"cpm29-stub-token","expires_at":"{{DateTime.UtcNow.AddMinutes(stubTokenMinutes):yyyy-MM-ddTHH:mm:ssZ}}"}""");
        });

        app.Map("/jwt/echo", (HttpContext context) => context.Response.WriteAsync(
            $"assertion-verified; aud-ok; authorization={Wire.Truncate(context.Request.Headers.Authorization.ToString(), 60)}"));

        // Independent HMAC verifier - same documented layout as the HmacSigning sample
        // (METHOD \n PATH \n UNIX-SECONDS \n sha256-hex(body), HMAC-SHA256 lowercase
        // hex), sharing no code with CredProx: exactly how a real vendor's verifier is.
        app.Map("/hmac/verify", async (HttpContext context) =>
        {
            using var reader = new StreamReader(context.Request.Body, Encoding.UTF8);
            var body = await reader.ReadToEndAsync();
            var signature = context.Request.Headers["X-Signature"].ToString();
            var timestamp = context.Request.Headers["X-Timestamp"].ToString();
            var canonical = string.Join('\n',
                context.Request.Method,
                context.Request.Path,
                timestamp,
                Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(body))).ToLowerInvariant());
            var expected = Convert.ToHexString(HMACSHA256.HashData(
                Encoding.UTF8.GetBytes(hmacKey), Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
            var ok = signature.Length == expected.Length && CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(signature), Encoding.UTF8.GetBytes(expected));
            context.Response.StatusCode = ok ? StatusCodes.Status200OK : StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsync(ok ? "signature valid" : "signature invalid");
        });

        // mTLS proof: the callback above already refused anything that does not chain to
        // the pinned CA; arriving here WITH the test CN certificate is the pass condition
        // the battery asserts.
        app.Map("/mtls/echo", (HttpContext context) =>
        {
            var clientCertificate = context.Connection.ClientCertificate;
            if (clientCertificate is null)
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                return context.Response.WriteAsync("no-client-certificate");
            }

            return context.Response.WriteAsync(
                $"mtls-verified; subject={clientCertificate.Subject.SquashLines()}");
        });

        // ARM stand-in so --smoke exercises /arm/* end to end (route + caller auth +
        // forwarding). Maps the STRIPPED path because the /arm route removes the /arm
        // prefix - the live ARM endpoint expects /subscriptions too. The live battery
        // never reaches this route: live /arm goes to management.azure.com with the
        // managed identity.
        app.Map("/subscriptions", (HttpContext context) => context.Response.WriteAsync(
            """{"value":[{"subscriptionId":"counterparty-stub","tenantId":"counterparty-stub"}]}"""));

        return app;
    }

    private static bool VerifyAgainstPinnedCa(X509Certificate2 clientCertificate, X509Certificate2 ca)
    {
        if (!clientCertificate.Subject.SquashLines()
                .Contains(Wire.ClientCertCn, StringComparison.Ordinal))
        {
            return false;
        }

        // Pinned trust = CustomRootTrust with the CA in the CustomTrustStore (live
        // finding 2026-11-06, P8): ExtraStore is a chain-building AUXILIARY pool, NOT
        // a trust anchor - on Linux the build stops at the self-signed pinned CA with
        // UntrustedRoot and every client cert is refused. The offline smoke only ever
        // passed because --smoke installs its test CA into the OS trust store, which
        // OS-default trust then found; the counterparty container has no such install
        // (CREDPROX_TEST_CA_PEM_B64 is the PROXY's server-chain trust). With
        // CustomRootTrust the OS store is excluded entirely - which makes this check
        // genuinely pin in BOTH modes, and the thumbprint gate below still holds.
        using var chainBuilder = new X509Chain
        {
            ChainPolicy =
            {
                TrustMode = X509ChainTrustMode.CustomRootTrust,
                RevocationMode = X509RevocationMode.NoCheck,
                VerificationFlags = X509VerificationFlags.NoFlag,
                CustomTrustStore = { ca },
            },
        };
        if (!chainBuilder.Build(clientCertificate))
        {
            return false;
        }

        // The chain must TERMINATE at the pinned CA, not merely pass some OS validation.
        return chainBuilder.ChainElements[^1].Certificate.Thumbprint == ca.Thumbprint;
    }

    private static bool VerifyJwt(RSA publicKey, string[] parts)
    {
        try
        {
            var signingInput = Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]);
            var signature = Convert.FromBase64String(Pad(parts[2]));
            if (!publicKey.VerifyData(signingInput, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
            {
                return false;
            }

            var payloadJson = Encoding.UTF8.GetString(Convert.FromBase64String(Pad(parts[1])));
            using var payload = JsonDocument.Parse(payloadJson);
            var root = payload.RootElement;
            return root.GetProperty("iss").GetString() == Wire.JwtIssuer
                && root.GetProperty("aud").GetString() == Wire.JwtAudience
                && root.GetProperty("exp").GetInt64() > DateTimeOffset.UtcNow.ToUnixTimeSeconds()
                && !string.IsNullOrEmpty(root.GetProperty("jti").GetString());
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException or JsonException or InvalidOperationException)
        {
            return false;
        }

        static string Pad(string base64Url) =>
            base64Url.Replace('-', '+').Replace('_', '/') + new string('=', (4 - base64Url.Length % 4) % 4);
    }
}

// The one runtime identity factory for every Azure call this sample makes.
// WHY THIS EXISTS (live wire evidence, M29 eastus 2026-11-06): with a workload that
// has TWO user-assigned identities attached, the Container Apps identity proxy only
// answers token requests that NAME one - and the App Service/ACA probe path of
// Azure.Identity (1.13.1, captured against a local stub with the ACA env contract)
// puts MANAGED_IDENTITY_CLIENT_ID in NO request: only the explicit
// DefaultAzureCredentialOptions.ManagedIdentityClientId reaches the wire
// (…&client_id=<value>). The unfiltered request -> MIC 400 "Unable to load the
// proper Managed Identity" -> swallowed by DefaultAzureCredential's chain -> an
// empty vault config (the 1.3.2 provider on this stack does NOT surface the
// failure). So the client id from the env hint MUST be threaded through options.
// Outside ACA (no IDENTITY_ENDPOINT) ClientId stays null when the env var is
// unset: identical behavior to a bare DefaultAzureCredential.
internal static class RuntimeIdentity
{
    public static TokenCredential Credential() => new DefaultAzureCredential(
        new DefaultAzureCredentialOptions
        {
            ManagedIdentityClientId = Environment.GetEnvironmentVariable("MANAGED_IDENTITY_CLIENT_ID"),
        });
}

internal static class BatteryRunner
{
    public static async Task<int> RunAsync(string[] args)
    {
        var proxyBase = ReadSwitch(args, "--proxy", "");
        var phase = ReadSwitch(args, "--phase", "all");
        if (string.IsNullOrEmpty(proxyBase))
        {
            return BatteryFail("battery needs --proxy https://<internal-ingress-fqdn>");
        }

        // Wall-clock anchor (live run 2026-11-06: the smoke logs carried no timestamps, so
        // a refusal/recovery window could only be timed from Azure execution metadata).
        // One line naming the UTC start, the build (DEPLOY_IMAGE_DIGEST stamp; offline runs
        // have none) and the phase - every P-line below inherits this anchor.
        Console.WriteLine($"battery UTC {DateTime.UtcNow:yyyy-MM-ddTHH:mm:ssZ} phase {phase} build " +
            (Environment.GetEnvironmentVariable("DEPLOY_IMAGE_DIGEST") is { Length: > 0 } stamp ? stamp : "unstamped"));

        var configurationBuilder = new ConfigurationBuilder().AddEnvironmentVariables();
        // LOOKUP FORM MATTERS: AddEnvironmentVariables normalizes "__" in env NAMES to
        // the config ":" separator, so the env var KeyVault__Uri is ONLY reachable as
        // "KeyVault:Uri" - a lookup under the raw double-underscore name returns null
        // SILENTLY (live root cause 2026-11-06: the vault provider was never attached
        // on the battery path, and every vault failure upstream looked like a missing
        // key). The proxy/counterparty paths already read the colon form.
        var keyVaultUri = configurationBuilder.Build()["KeyVault:Uri"];
        if (!string.IsNullOrEmpty(keyVaultUri))
        {
            // Cadence set so all sample sites agree; the job itself is short-lived.
            configurationBuilder.AddAzureKeyVault(new Uri(keyVaultUri), RuntimeIdentity.Credential(),
                new AzureKeyVaultConfigurationOptions { ReloadInterval = TimeSpan.FromSeconds(30) });
        }

        var configuration = configurationBuilder.Build();
        var callerKey = configuration["CredProx:Secrets:caller-key"] ?? configuration["CREDPROX_SMOKE_CALLER_KEY"];
        if (string.IsNullOrEmpty(callerKey) && !string.IsNullOrEmpty(keyVaultUri))
        {
            // NEVER report "no key" silently: a config provider whose first vault load
            // failed can present an EMPTY config without any exception on the runtime
            // stack this image ships on (live finding 2026-11-06 - it masked the real
            // identity failure for two smoke runs). Probe the vault directly and report
            // what the vault/identity actually said. Exception messages carry status +
            // vault URL, never secret values; nothing sensitive is printed.
            try
            {
                var direct = new SecretClient(new Uri(keyVaultUri), RuntimeIdentity.Credential())
                    .GetSecret("CredProx--Secrets--caller-key");
                callerKey = direct.Value.Value;
                Console.Error.WriteLine("warn: vault config provider delivered no keys (first-load failure " +
                    "swallowed by the provider); direct vault fetch succeeded - identity and vault are OK");
            }
            catch (Exception ex)
            {
                return BatteryFail($"vault fetch of CredProx--Secrets--caller-key failed: " +
                    $"{ex.GetType().Name}: {ex.Message}");
            }
        }

        if (string.IsNullOrEmpty(callerKey))
        {
            return BatteryFail("battery needs the caller key: vault secret CredProx--Secrets--caller-key " +
                "(KeyVault__Uri + managed identity) or CREDPROX_SMOKE_CALLER_KEY (smoke).");
        }

        // Strict TLS: the ACA internal ingress serves a Microsoft-issued certificate; a
        // chain failure would be a real finding, not something to paper over.
        using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(60) };
        var exit = await Wire.RunChecksAsync(client, proxyBase.TrimEnd('/'), callerKey, phase);
        Console.WriteLine(exit == 0 ? "BATTERY OK" : "BATTERY FAILED");
        return exit;
    }

    private static int BatteryFail(string message)
    {
        Console.Error.WriteLine($"error: {message}");
        return 1;
    }

    private static string ReadSwitch(string[] args, string name, string defaultValue)
    {
        var value = defaultValue;
        for (var i = 0; i < args.Length - 1; i++)
        {
            if (string.Equals(args[i], name, StringComparison.Ordinal))
            {
                value = args[i + 1];
            }
        }

        return value;
    }
}

internal static class SmokeRunner
{
    // Offline proof of the verifier logic + CredProx wiring, one process:
    // generated material -> counterparty app -> proxy app -> battery checks -> stop.
    public static async Task<int> RunAsync()
    {
        SmokeMaterial.Generate();
        // The proxy uses DEFAULT chain validation against the outbound counterparty
        // certificate (that is the live posture too); in the live container the
        // entrypoint installs the CA from the public CREDPROX_TEST_CA_PEM_B64 env
        // var. Smoke installs the same PUBLIC CA into the OS trust store for the run
        // (root inside the sample container; an honest failure anywhere else).
        if (RunTrustStoreInstall(SmokeMaterial.CaPem!) != 0)
        {
            Console.Error.WriteLine("SMOKE FAILED: cannot install the test CA into the OS trust store (update-ca-certificates).");
            Console.Error.WriteLine("Run the smoke inside the sample image: docker run --rm <image> --mode proxy --smoke");
            RemoveSmokeCa();
            return 1;
        }

        var counterparty = CounterpartyRunner.CreateApp(smoke: true, httpPort: 9182, httpsPort: 9183);
        var proxy = ProxyRunner.CreateApp(smoke: true);
        try
        {
            await counterparty.StartAsync();
            await proxy.StartAsync();
            using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(60) };
            Console.WriteLine("SMOKE: proxy + counterparty up (generated material, no vault, no Azure).");
            Console.WriteLine("SMOKE: P5 here targets the in-proc ARM stub - route/caller-auth/forwarding only, NOT the managed identity.");
            var exit = await Wire.RunChecksAsync(client, SmokeMaterial.ProxyUrl, SmokeMaterial.CallerKeyValue!, phase: "all");
            Console.WriteLine(exit == 0
                ? "SMOKE OK: JWT pinned-verify, HMAC independent verify, mTLS pinned chain + CN echo, caller-key 401."
                : "SMOKE FAILED: see the FAIL lines above.");
            return exit;
        }
        finally
        {
            await proxy.StopAsync();
            await counterparty.StopAsync();
            RemoveSmokeCa();
        }
    }

    private const string SmokeCaPath = "/usr/local/share/ca-certificates/credprox-m29-smoke-ca.crt";

    // Same trust-store mechanism the container entrypoint uses (update-ca-certificates);
    // 0 on success. Requires root - true inside the sample container.
    private static int RunTrustStoreInstall(string caPem)
    {
        try
        {
            File.WriteAllText(SmokeCaPath, caPem);
            using var process = Process.Start(new ProcessStartInfo("update-ca-certificates")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            });
            if (process is null)
            {
                return 1;
            }

            process.WaitForExit(30_000);
            return process.HasExited ? process.ExitCode : 1;
        }
        catch (Exception)
        {
            return 1;
        }
    }

    private static void RemoveSmokeCa()
    {
        try
        {
            if (File.Exists(SmokeCaPath))
            {
                File.Delete(SmokeCaPath);
                using var process = Process.Start(new ProcessStartInfo("update-ca-certificates")
                {
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                });
                process?.WaitForExit(30_000);
            }
        }
        catch (Exception)
        {
            // The container is ephemeral; cleanup failure is noise, not a verdict.
        }
    }
}

internal sealed class SmokeMaterial
{
    public static RSA? JwtKey;
    public static string? JwtPublicPem;
    public static string? HmacKey;
    public static string? CallerKeyValue;
    public static string? CallerKeyHash;
    public static X509Certificate2? CaPublic;
    public static string? CaPem;
    public static string? ClientPfxBase64;
    public static string? ClientPfxPassword;
    public static string? ServerPfxBase64;
    public static string? ServerPfxPassword;
    public const string ProxyUrl = "http://127.0.0.1:9181";

    // Positive 128-bit serial (high bit cleared), as certificate profiles expect.
    private static byte[] NewSerial()
    {
        var serial = RandomNumberGenerator.GetBytes(16);
        serial[0] &= 0x7f;
        if (serial[0] == 0)
        {
            serial[0] = 0x7f;
        }

        return serial;
    }

    public static void Generate()
    {
        JwtKey = RSA.Create(2048);
        JwtPublicPem = JwtKey.ExportSubjectPublicKeyInfoPem();
        HmacKey = "credprox-m29-smoke-hmac-key";
        CallerKeyValue = "credprox-m29-smoke-caller-key";
        CallerKeyHash = "sha256:" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(CallerKeyValue))).ToLowerInvariant();

        var notBefore = DateTimeOffset.UtcNow.AddMinutes(-5);
        var notAfter = DateTimeOffset.UtcNow.AddHours(4);

        var caKey = RSA.Create(2048);
        var caRequest = new CertificateRequest("CN=credprox-m29-smoke-ca", caKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        caRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        var caCert = caRequest.CreateSelfSigned(notBefore, notAfter);
        CaPublic = caCert;
        CaPem = caCert.ExportCertificatePem();

        var serverKey = RSA.Create(2048);
        var serverRequest = new CertificateRequest("CN=credprox-m29-counterparty", serverKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("localhost");
        san.AddIpAddress(System.Net.IPAddress.Loopback);
        serverRequest.CertificateExtensions.Add(san.Build());
        serverRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        var serverCert = serverRequest
            .Create(caCert, notBefore, notAfter, NewSerial())
            .CopyWithPrivateKey(serverKey);
        ServerPfxBase64 = Convert.ToBase64String(serverCert.Export(X509ContentType.Pfx, "smoke-server-pw"));
        ServerPfxPassword = "smoke-server-pw";

        var clientKey = RSA.Create(2048);
        var clientRequest = new CertificateRequest(Wire.ClientCertCn, clientKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        clientRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        clientRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, false));
        var clientCert = clientRequest
            .Create(caCert, notBefore, notAfter, NewSerial())
            .CopyWithPrivateKey(clientKey);
        ClientPfxBase64 = Convert.ToBase64String(clientCert.Export(X509ContentType.Pfx, "smoke-client-pw"));
        ClientPfxPassword = "smoke-client-pw";
    }

    public static void ApplyProxyOverrides(IConfigurationManager configuration) =>
        configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["CredProx:Secrets:jwt-signing-key"] = JwtKey!.ExportRSAPrivateKeyPem(),
            ["CredProx:Secrets:hmac-key"] = HmacKey,
            ["CredProx:Secrets:mtls-client-cert"] = ClientPfxBase64,
            ["CredProx:Secrets:mtls-client-cert-password"] = ClientPfxPassword,
            ["CredProx:Callers:smoke:Keys:0:KeyId"] = "smoke-key-1",
            ["CredProx:Callers:smoke:Keys:0:KeyHash"] = CallerKeyHash,
            ["CredProx:Credentials:jwt:TokenEndpoint"] = "http://127.0.0.1:9182/app/token",
            // The CredProx destination TEMPLATE is the authoritative egress prefix: the
            // CredProx transform overwrites YARP's cluster Address per request
            // (CredProxTransformProvider.cs:117). Smoke retargets BOTH - kept
            // consistent, exactly as the live config keeps them consistent.
            ["CredProx:Destinations:arm:Template"] = "http://127.0.0.1:9182",
            ["CredProx:Destinations:cp:Template"] = "http://127.0.0.1:9182",
            ["CredProx:Destinations:cpmtls:Template"] = "https://127.0.0.1:9183",
            ["ReverseProxy:Clusters:arm:Destinations:arm:Address"] = "http://127.0.0.1:9182/",
            ["ReverseProxy:Clusters:cp:Destinations:cp:Address"] = "http://127.0.0.1:9182/",
            ["ReverseProxy:Clusters:cpmtls:Destinations:cp:Address"] = "https://127.0.0.1:9183/",
        });

    public static void ApplyCounterpartyOverrides(IConfigurationManager configuration) =>
        configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["CredProxTest:jwt-public"] = JwtPublicPem,
            ["CredProxTest:mtls-ca"] = CaPem,
            ["CredProx:Secrets:cp-server-cert"] = ServerPfxBase64,
            ["CredProx:Secrets:cp-server-cert-password"] = ServerPfxPassword,
            ["CredProx:Secrets:hmac-key"] = HmacKey,
        });
}

// Offline smoke stand-in for the managed identity: returns a fixed token, never mints
// from Azure. This is explicitly NOT the MI path - see the smoke banner and README
// honesty notes; the live battery P5 is what proves the managed identity.
internal sealed class SmokeTokenCredential : TokenCredential
{
    public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
        => new(new AccessToken("smoke-stub-token", DateTimeOffset.UtcNow.AddHours(1)));

    public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken)
        => new("smoke-stub-token", DateTimeOffset.UtcNow.AddHours(1));
}

// --mode reloadproof (see the mode table in the header). Everything on the vault path is
// the real shipped thing - provider, SecretClient, polling loop, REST shapes - except the
// HTTP endpoint: only ClientOptions.Transport is swapped, so the requests reach the loopback stub
// (tools/keyvault-stub.py) while the vault URI keeps its real https vault form. A plain
// file or in-memory config source would not exercise the provider's polling and does not
// count (M29 verdict, pinned 2026-11-06).
internal static class ReloadProofRunner
{
    public static async Task<int> RunAsync()
    {
        var proofSeconds = int.TryParse(Environment.GetEnvironmentVariable("CREDPROX_PROOF_SECONDS"), out var p) ? p : 90;
        var reloadSeconds = int.TryParse(Environment.GetEnvironmentVariable("CREDPROX_RELOAD_SECONDS"), out var r) ? r : 5;
        var vaultUri = Environment.GetEnvironmentVariable("KeyVault__Uri") ?? "https://credprox-m29-stub.vault.azure.net/";
        const string Key = "CredProx:Secrets:proof";

        // SecretClientOptions (Azure.Core ClientOptions) Transport is the supported swap
        // point (Azure.Core >= 1.40 exposes the settable Transport; the older protected
        // CreateTransport override was removed). Swapping ONLY the transport leaves the
        // provider, the SecretClient REST calls and the polling loop exactly as shipped.
        var client = new SecretClient(new Uri(vaultUri), new SmokeTokenCredential(), new SecretClientOptions
        {
            Transport = new StubEndpointTransport(
                new HttpClientTransport(),
                Environment.GetEnvironmentVariable("CREDPROX_STUB_BASE") ?? "http://127.0.0.1:18300")
        });
        var configuration = new ConfigurationBuilder()
            .AddEnvironmentVariables()
            .AddAzureKeyVault(client, new AzureKeyVaultConfigurationOptions
            {
                ReloadInterval = TimeSpan.FromSeconds(reloadSeconds)
            })
            .Build();

        var baseline = configuration[Key] ?? "<absent>";
        Console.WriteLine($"[reloadproof {Stamp()}] baseline {Key} = {baseline} (poll every {reloadSeconds}s, witness {proofSeconds}s)");
        if (baseline == "<absent>")
        {
            Console.Error.WriteLine("error: seed the stub data dir with CredProx--Secrets--proof.txt before starting");
            return 1;
        }

        var reloads = 0;
        ChangeToken.OnChange(configuration.GetReloadToken, () =>
        {
            var value = configuration[Key] ?? "<absent>";
            Interlocked.Increment(ref reloads);
            Console.WriteLine($"[reloadproof {Stamp()}] RELOAD TOKEN FIRED; {Key} = {value}");
        });

        var deadline = DateTimeOffset.UtcNow.AddSeconds(proofSeconds);
        while (DateTimeOffset.UtcNow < deadline)
        {
            await Task.Delay(2000);
        }

        var final = configuration[Key] ?? "<absent>";
        var ok = Volatile.Read(ref reloads) > 0 && final != baseline;
        Console.WriteLine($"[reloadproof {Stamp()}] final {Key} = {final}; reload tokens fired = {reloads}");
        Console.WriteLine(ok ? "RELOAD PROOF OK" : "RELOAD PROOF FAILED");
        return ok ? 0 : 1;
    }

    private static string Stamp() => DateTimeOffset.Now.ToString("HH:mm:ss");
}

// Rewrites scheme/host/port to the loopback stub and carries the original vault host in
// X-Stub-Vault-Host so the stub answers with secret ids on the REAL vault host - the ids
// must parse against the vault URI the SecretClient was built with.
internal sealed class StubEndpointTransport : HttpPipelineTransport
{
    private readonly HttpPipelineTransport _inner;
    private readonly Uri _stubBase;

    public StubEndpointTransport(HttpPipelineTransport inner, string stubBase)
    {
        _inner = inner;
        _stubBase = new Uri(stubBase, UriKind.Absolute);
    }

    public override Request CreateRequest() => _inner.CreateRequest();

    public override void Process(HttpMessage message)
    {
        Rewrite(message);
        _inner.Process(message);
    }

    public override ValueTask ProcessAsync(HttpMessage message)
    {
        Rewrite(message);
        return _inner.ProcessAsync(message);
    }

    private void Rewrite(HttpMessage message)
    {
        var uri = message.Request.Uri;
        if (!string.IsNullOrEmpty(uri.Host))
        {
            message.Request.Headers.SetValue("X-Stub-Vault-Host", uri.Host);
        }
        uri.Scheme = _stubBase.Scheme;
        uri.Host = _stubBase.Host;
        uri.Port = _stubBase.Port;
    }
}
