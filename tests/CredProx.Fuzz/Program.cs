using System.Buffers;
using System.Net.Http;
using System.Text;
using CredProx;
using Microsoft.Extensions.Configuration;

using SharpFuzz;

// M31 Phase B harness (plan 5.4): six targets, one per process, selected by argv:
//   pathpatterns (default) | headerattach | scrub | sse | configkeys | parsers
// Each target is an invariant probe over a pure-or-cheap entry point; a crash means
// either an unexpected exception type or a broken post-condition (InvariantViolation).
// Documented validation rejections (ArgumentException/FormatException from the BCL
// header/query validators and the library's own guards) are swallowed on purpose —
// refusing malformed input is the contract, not a finding.
var canary = args.Contains("canary", StringComparer.Ordinal);
var target = args.FirstOrDefault(a => !a.Equals("canary", StringComparison.Ordinal)) ?? "pathpatterns";

switch (target)
{
    case "pathpatterns":
        Fuzzer.OutOfProcess.Run(path => PathGate(path, canary));
        break;
    case "headerattach":
        Fuzzer.OutOfProcess.Run(HeaderAttach);
        break;
    case "scrub":
        Fuzzer.OutOfProcess.Run(Scrub);
        break;
    case "sse":
        Fuzzer.OutOfProcess.Run(Sse);
        break;
    case "configkeys":
        Fuzzer.OutOfProcess.Run(ConfigKeys);
        break;
    case "parsers":
        Fuzzer.OutOfProcess.Run(Parsers);
        break;
    default:
        throw new ArgumentException($"unknown fuzz target: {target}");
}

// The path gate: a dot segment must never be admitted, whatever encoding tricks
// arrive. (Phase A invariant, unchanged.)
static void PathGate(string path, bool canary)
{
    var admitted = PathPatterns.IsSafePath(path, path)
        && PathPatterns.Matches(path, "/allowed/*");

    if (!admitted)
    {
        return;
    }

    if (canary)
    {
        if (path == "/allowed/x")
        {
            throw new InvalidOperationException("canary: seeded invariant violation");
        }

        return;
    }

    // Exact dot segments only (P-3 triage): the contract refuses the segments '.' and
    // '..', not every string containing two dots — RFC 3986 resolves only whole dot
    // segments, and '/allowed/a..' is a legal literal filename. The first oracle used
    // Contains("..") and crashed on that legal shape.
    foreach (var segment in path.Split('/', StringSplitOptions.RemoveEmptyEntries))
    {
        if (segment is "." or "..")
        {
            throw new InvariantViolation("admitted path contains a dot segment: " + path);
        }
    }
}

// Credential placement: an accepted (location, name, value) must attach exactly once,
// must never smuggle control characters, a cookie must stay a single pair, and a query
// value must never break its parameter boundary. Divergence between the public
// IsValidCookieName check and what Apply actually accepts is itself the finding.
static void HeaderAttach(string input)
{
    try
    {
        var lines = input.Split('\n');
        var location = lines.Length > 0 && int.TryParse(lines[0], out var l) && l is >= 0 and <= 2
            ? (CredentialLocation)l
            : CredentialLocation.Header;
        var name = lines.Length > 1 ? lines[1] : "X-Api-Key";
        var value = lines.Length > 2 ? string.Join("\n", lines.Skip(2)) : "v";

        var request = new HttpRequestMessage(HttpMethod.Get, "http://vendor.example/api");
        var cookieNameOk = CredentialAttacher.IsValidCookieName(name);
        // Mirrors Apply's contract: non-empty value (P-4 — an empty value attaches nothing
        // for BCL-known names) plus the ASCII/CTL safety rules.
        var cookieValueOk = value.Length > 0
            && value.All(static c => c is not (';' or '\r' or '\n' or '\0') && c < 0x7f);

        try
        {
            CredentialAttacher.Apply(request, location, name, value);
        }
        catch (Exception ex) when (ex is ArgumentException or FormatException)
        {
            if (location == CredentialLocation.Cookie && cookieNameOk && cookieValueOk)
            {
                throw new InvariantViolation(
                    $"Apply rejected a cookie IsValidCookieName+value rules accept: name='{name}' value='{value}'");
            }

            return;
        }

        switch (location)
        {
            case CredentialLocation.Header:
                var values = request.Headers.GetValues(name).ToList();
                if (values.Count != 1 || values[0] != value)
                {
                    throw new InvariantViolation($"header not attached exactly once verbatim: {values.Count} values");
                }

                break;

            case CredentialLocation.Cookie:
                var cookies = request.Headers.GetValues("Cookie").ToList();
                if (cookies.Count != 1)
                {
                    throw new InvariantViolation($"more than one Cookie header: {cookies.Count}");
                }

                if (cookies[0] != name + "=" + value || cookies[0].Contains(';'))
                {
                    throw new InvariantViolation($"cookie pair broken: '{cookies[0]}'");
                }

                break;

            case CredentialLocation.Query:
                var uri = request.RequestUri!;
                if (uri.Fragment.Length > 0)
                {
                    throw new InvariantViolation($"query value escaped the parameter boundary (fragment set): {uri}");
                }

                if (uri.Query.Contains('\r') || uri.Query.Contains('\n'))
                {
                    throw new InvariantViolation($"raw control char in query: {uri.Query}");
                }

                var matches = uri.Query.TrimStart('?')
                    .Split('&', StringSplitOptions.RemoveEmptyEntries)
                    .Select(static pair => pair.Split('=', 2))
                    .Where(kv => kv.Length == 2 && Uri.UnescapeDataString(kv[0]) == name)
                    .ToList();
                if (matches.Count != 1 || Uri.UnescapeDataString(matches[0][1]) != value)
                {
                    throw new InvariantViolation($"query parameter not attached exactly once verbatim ({matches.Count})");
                }

                break;
        }
    }
    catch (Exception ex) when (ex is ArgumentException or FormatException or UriFormatException)
    {
        // documented validation rejects
    }
}

// Final-batch scrubbing: a registered secret never survives a batch that covers the
// whole pending buffer, and a body with no match passes through byte-identical.
static void Scrub(string input)
{
    var bytes = Encoding.UTF8.GetBytes(input);
    var patterns = Probe.Patterns;
    var pool = ArrayPool<byte>.Shared;
    var (batch, length, consumed) = SecretScrubber.ScrubBatch(bytes, bytes.Length, patterns, SecretScrubber.Replacement, pool);
    var emitted = batch.AsSpan(0, length);

    if (consumed != bytes.Length)
    {
        throw new InvariantViolation($"final batch consumed {consumed} of {bytes.Length}");
    }

    foreach (var secret in Probe.Secrets)
    {
        if (Probe.ContainsSequence(emitted, Encoding.UTF8.GetBytes(secret)))
        {
            throw new InvariantViolation($"secret survived final scrub: {secret}");
        }
    }

    // A replacement needs a full registered pattern in the buffer; if no secret is
    // present in the input at all, the emitted bytes must be the input bytes.
    var hadMatch = Probe.Secrets.Any(secret => Probe.ContainsSequence(bytes, Encoding.UTF8.GetBytes(secret)));
    if (!hadMatch && !emitted.SequenceEqual(bytes))
    {
        pool.Return(batch, clearArray: true);
        throw new InvariantViolation("no-match body not byte-identical");
    }

    pool.Return(batch, clearArray: true);
}

// SSE scrubbing: per-event scrubbing may let a secret split across an event boundary
// survive (documented residue) — but the surviving bytes stay split by the delimiter,
// so a CONTIGUOUS secret must never appear in the output at any framing.
static void Sse(string input)
{
    if (input.Length > 600_000)
    {
        return; // keep the target away from buffer-cap stress; framing tests cover that
    }

    var bytes = Encoding.UTF8.GetBytes(input);
    using var inner = new MemoryStream(bytes);
    using var scrubbing = new EventScrubbingStream(inner, Probe.Secrets);
    using var output = new MemoryStream();
    scrubbing.CopyTo(output);
    var written = output.ToArray().AsSpan();

    foreach (var secret in Probe.Secrets)
    {
        if (Probe.ContainsSequence(written, Encoding.UTF8.GetBytes(secret)))
        {
            throw new InvariantViolation($"contiguous secret in SSE output: {secret}");
        }
    }
}

// Config key validation: an unknown key must be reported (never silently dropped),
// reports must be deterministic, and an error message must never echo a secret value.
static void ConfigKeys(string input)
{
    var key = input.Replace('\0', '?');
    var data = new Dictionary<string, string?>
    {
        ["CredProx:destinations:" + key] = Probe.SecretValue,
    };

    // The in-memory provider's dictionary is case-insensitive: adding a fixed
    // 'Allowed' row alongside a fuzzed key that differs from it only in case throws
    // ArgumentException at Build() — a provider-level reject the catch below swallows,
    // leaving the seed with zero instrumented edges (afl reports that as 'No
    // instrumentation detected'). Skip the fixed row for those keys; the validator
    // still sees the fuzzed key and reports it against the accepted set.
    if (!string.Equals(key, "Allowed", StringComparison.OrdinalIgnoreCase))
    {
        data["CredProx:destinations:Allowed"] = "1";
    }

    List<string> Validate()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(data).Build();
        var section = configuration.GetSection("CredProx:destinations");
        var errors = new List<string>();
        ConfigKeyValidator.RejectUnknownKeys(
            section,
            new Dictionary<string, Type?> { ["Allowed"] = null },
            "destination 'probe'",
            "CredProx:destinations",
            errors);
        return errors;
    }

    try
    {
        var first = Validate();
        var second = Validate();
        if (!first.SequenceEqual(second, StringComparer.Ordinal))
        {
            throw new InvariantViolation("config validation is nondeterministic");
        }

        foreach (var error in first)
        {
            if (error.Contains(Probe.SecretValue, StringComparison.Ordinal))
            {
                throw new InvariantViolation("validation error echoes a secret value");
            }
        }

        var known = string.Equals(key, "Allowed", StringComparison.OrdinalIgnoreCase);
        if (!known && key.Length > 0 && first.Count == 0)
        {
            throw new InvariantViolation($"unknown key silently accepted: '{key}'");
        }
    }
    catch (Exception ex) when (ex is ArgumentException or FormatException)
    {
        // provider-level rejects on malformed keys
    }
}

// Small parsers: HMAC component parsing, the header-newline defence behind the
// canonical string, and media-type classification.
static void Parsers(string input)
{
    try
    {
        // component token parsing: deterministic, and "header:" alone never parses
        if (HmacSigner.TryParseComponent(input, out var kind, out var argument))
        {
            if (!HmacSigner.TryParseComponent(input, out var kind2, out var argument2)
                || kind2 != kind || argument2 != argument)
            {
                throw new InvariantViolation("TryParseComponent nondeterministic");
            }

            if (kind == HmacComponentKind.Header && argument.Length == 0)
            {
                throw new InvariantViolation("header component accepted with empty argument");
            }
        }

        // canonical-string separator injection: two header layouts are distinct
        // documents; they may only canonicalize identically if a value smuggled the
        // separator — which the BCL header validator must make unconstructable.
        var parts = input.Split('\u0001', 2);
        var v1 = parts[0];
        var v2 = parts.Length > 1 ? parts[1] : string.Empty;
        var options = new HmacOptions { Separator = "\n" };
        var components = new[] { (HmacComponentKind.Header, "X-A"), (HmacComponentKind.Header, "X-B") };
        var now = DateTimeOffset.UnixEpoch;
        var body = Array.Empty<byte>();

        var legit = new HttpRequestMessage(HttpMethod.Post, "http://vendor.example/api");
        var smuggled = new HttpRequestMessage(HttpMethod.Post, "http://vendor.example/api");
        try
        {
            legit.Headers.Add("X-A", v1);
            legit.Headers.Add("X-B", v2.Length == 0 ? string.Empty : "\n" + v2);
            smuggled.Headers.Add("X-A", v1.Length == 0 ? string.Empty : v1 + "\n");
            smuggled.Headers.Add("X-B", v2);
        }
        catch (Exception ex) when (ex is ArgumentException or FormatException)
        {
            return; // newline refused: the defence holds, nothing to compare
        }

        var legitCanonical = HmacSigner.BuildCanonicalString(components, legit, body, options, now);
        var smuggledCanonical = HmacSigner.BuildCanonicalString(components, smuggled, body, options, now);
        if (legitCanonical == smuggledCanonical)
        {
            // Only a collision between genuinely distinct documents is a finding. When a
            // value is empty the ternaries above collapse both requests to the same header
            // set (empty is valid for the BCL validator and carries no separator), and an
            // identical-document 'collision' is an oracle artefact, not library behaviour.
            var legitPair = (
                string.Join(",", legit.Headers.GetValues("X-A")),
                string.Join(",", legit.Headers.GetValues("X-B")));
            var smuggledPair = (
                string.Join(",", smuggled.Headers.GetValues("X-A")),
                string.Join(",", smuggled.Headers.GetValues("X-B")));
            if (legitPair != smuggledPair)
            {
                throw new InvariantViolation($"separator smuggled through a header value: '{v1}' / '{v2}'");
            }
        }

        // media-type classification: must never throw on a parsed value, and must be
        // deterministic
        if (System.Net.Http.Headers.MediaTypeHeaderValue.TryParse(input, out var mediaType))
        {
            var first = (ResponseBodies.IsEventStream(mediaType), ResponseBodies.IsTextLike(mediaType), ResponseBodies.IsCharsetUtf8OrAscii(mediaType));
            var again = (ResponseBodies.IsEventStream(mediaType), ResponseBodies.IsTextLike(mediaType), ResponseBodies.IsCharsetUtf8OrAscii(mediaType));
            if (first != again)
            {
                throw new InvariantViolation("media classification nondeterministic");
            }
        }
    }
    catch (Exception ex) when (ex is ArgumentException or FormatException)
    {
        // documented validation rejects
    }
}

internal static class Probe
{
    public static readonly string[] Secrets = ["s3cr3t-value", "tok-abc"];

    public static readonly byte[][] Patterns = SecretScrubber.CompilePatterns(Secrets);

    public const string SecretValue = "SECRETVALUE-DO-NOT-ECHO";

    public static bool ContainsSequence(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle) =>
        haystack.IndexOf(needle) >= 0;
}

internal sealed class InvariantViolation : Exception
{
    public InvariantViolation(string message)
        : base(message)
    {
    }
}
