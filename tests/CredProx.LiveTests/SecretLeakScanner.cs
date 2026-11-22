using System.Text.RegularExpressions;

namespace CredProx.LiveTests;

// The no-leak discipline for live runs (plan M46): nothing secret may surface in a
// host log or in test output. Every value the scaffold loads (the private key PEM and
// its base64 form, or a provider API key) is matched verbatim, plus the vendor
// token, API-key and JWT shapes, so a
// leak is caught even when it is not one of the loaded strings. FindLeaks never
// quotes what it found — hit descriptions name the kind, never the content — and
// Sanitize is what failure paths must run over any text before echoing it.
public static partial class SecretLeakScanner
{
    // GitHub OAuth/App token shapes: ghs_, gho_, ghu_, ghp_, ghr_.
    [GeneratedRegex(@"\bgh[opsru]_[A-Za-z0-9]{20,}\b")]
    private static partial Regex GitHubTokenShape();

    // Anthropic API keys: the sk-ant- prefix followed by at least 20 key characters
    // (alphanumerics, dashes, underscores).
    [GeneratedRegex(@"\bsk-ant-[A-Za-z0-9_-]{20,}\b")]
    private static partial Regex AnthropicKeyShape();

    // A JWT is three dot-separated base64url segments with the standard JSON header
    // prefix; none of its parts should ever appear in a host log.
    [GeneratedRegex(@"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")]
    private static partial Regex JwtShape();

    public static IReadOnlyList<string> FindLeaks(string text, IReadOnlyCollection<string> secretValues)
    {
        var hits = new List<string>();
        if (secretValues.Any(value => value.Length > 0 && text.Contains(value, StringComparison.Ordinal)))
        {
            hits.Add("loaded secret material appears in captured output");
        }

        if (GitHubTokenShape().IsMatch(text))
        {
            hits.Add("a GitHub token shape appears in captured output");
        }

        if (AnthropicKeyShape().IsMatch(text))
        {
            hits.Add("an Anthropic API key shape appears in captured output");
        }

        if (JwtShape().IsMatch(text))
        {
            hits.Add("a JWT shape appears in captured output");
        }

        return hits;
    }

    public static string Sanitize(string text, IReadOnlyCollection<string> secretValues)
    {
        foreach (var value in secretValues.Where(value => value.Length > 0))
        {
            text = text.Replace(value, "[redacted]", StringComparison.Ordinal);
        }

        text = GitHubTokenShape().Replace(text, "[redacted]");
        text = AnthropicKeyShape().Replace(text, "[redacted]");
        text = JwtShape().Replace(text, "[redacted]");
        return text;
    }
}
