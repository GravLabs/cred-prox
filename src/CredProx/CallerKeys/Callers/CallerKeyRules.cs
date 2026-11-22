using System.Globalization;
using CredProx.Abstractions;
using Microsoft.Extensions.Configuration;

namespace CredProx;

/// <summary>
/// This package's caller-key rules, contributed to the core's registry validation: every
/// key must carry a <c>KeyId</c> unique within its caller and a <c>KeyHash</c> that is a
/// <c>sha256:&lt;64 hex&gt;</c> value or a <c>secret:</c> reference, and an
/// <c>ExpiresAt</c> that parses as a date-time. These rules check the declaration's shape
/// only — a <c>secret:</c> reference is accepted unseen here, and its value is resolved
/// exactly once per bind by <see cref="CallerKeyTableContributor"/>, the package's sole
/// secret resolver; a reference that cannot be resolved refuses the bind there. A caller
/// needs at least one authentication path — a declaration-valid key here, or the token
/// client ids the CredProx.CallerTokens add-on reads. Unknown keys under a <c>Keys</c>
/// entry fail closed (M14a): a typo would otherwise leave a key half-configured. The core
/// runs these rules at host start AND on every live configuration change, so a live edit
/// into a refused shape never takes effect — the previous registry keeps serving. Errors
/// name the caller and the key id — never a key value or hash.
/// </summary>
internal sealed class CallerKeyRules : ICallerRegistryValidator
{
    // The secret-reference prefix is the published configuration contract (it appears in
    // 0.11.0 documentation and must keep working); the core's SecretReferences constant
    // is internal, so the package states the same literal.
    private const string SecretReferencePrefix = "secret:";

    private static readonly HashSet<string> KeyEntryKeys =
        new(StringComparer.OrdinalIgnoreCase) { "KeyId", "KeyHash", "ExpiresAt" };

    public IReadOnlyList<string> Validate(IReadOnlyList<CallerRegistryEntry> callers)
    {
        var errors = new List<string>();

        foreach (var caller in callers)
        {
            var callerId = caller.CallerId;
            var keysSection = caller.Configuration.GetSection("Keys");
            var callerKeyErrors = 0;
            var before = errors.Count;

            // Fail closed on a typo one level under each Keys entry (M14a), exactly as the
            // core binder did while it read keys: an unknown field is ignored, which would
            // silently weaken the caller's credential.
            foreach (var entry in keysSection.GetChildren())
            {
                foreach (var child in entry.GetChildren())
                {
                    if (!KeyEntryKeys.Contains(child.Key))
                    {
                        AddUnknownKeyError(errors, callerId, $"Keys:{entry.Key}:{child.Key}");
                    }
                }
            }

            var keyIds = new HashSet<string>(StringComparer.Ordinal);
            var usableKeys = 0;

            foreach (var keySection in keysSection.GetChildren())
            {
                var keyId = keySection["KeyId"];
                if (string.IsNullOrWhiteSpace(keyId))
                {
                    errors.Add($"The caller '{callerId}' has a key with no KeyId.");
                    continue;
                }

                if (!keyIds.Add(keyId))
                {
                    errors.Add($"The caller '{callerId}' declares the KeyId '{keyId}' twice.");
                    continue;
                }

                var hashDeclaration = keySection["KeyHash"];
                if (string.IsNullOrWhiteSpace(hashDeclaration))
                {
                    errors.Add($"The caller '{callerId}' key '{keyId}' has no KeyHash.");
                    continue;
                }

                if (!ValidateHashDeclaration(hashDeclaration, callerId, keyId, errors))
                {
                    continue;
                }

                DateTimeOffset? expiresAt = null;
                var expiry = keySection["ExpiresAt"];
                if (!string.IsNullOrWhiteSpace(expiry))
                {
                    if (!DateTimeOffset.TryParse(expiry, CultureInfo.InvariantCulture, DateTimeStyles.None, out var parsed))
                    {
                        errors.Add($"The caller '{callerId}' key '{keyId}' has an ExpiresAt that is not a date-time.");
                        continue;
                    }

                    expiresAt = parsed;
                }

                usableKeys++;
            }

            callerKeyErrors = errors.Count - before;

            // A caller needs at least one authentication path: a usable key, or the token
            // client ids the CredProx.CallerTokens add-on reads from configuration. The
            // core accepts the TokenClientIds key (a 0.11.0 config must bind) but reads no
            // values; this package owns the keys half of the alternative. Only say it when
            // nothing else already named the caller's key trouble.
            var tokenPathConfigured = caller.Configuration.GetSection("TokenClientIds").GetChildren().Any();
            if (usableKeys == 0 && !tokenPathConfigured && callerKeyErrors == 0)
            {
                errors.Add($"The caller '{callerId}' declares no usable key under Keys and declares no TokenClientIds.");
            }
        }

        return errors;
    }

    private static void AddUnknownKeyError(List<string> errors, string callerId, string path)
    {
        var known = string.Join(", ", KeyEntryKeys.Order(StringComparer.Ordinal));
        errors.Add(
            $"The caller '{callerId}' declares the unknown configuration key '{path}' under 'CredProx:Callers'. "
            + $"Known keys at that level: {known}. An unknown key is ignored by the binder, which would "
            + "silently weaken the caller's allow-list — fix the spelling or remove the key.");
    }

    // Shape-only, by design: a literal must parse as sha256:<hex> here, and a
    // secret: reference is accepted unseen — its value lives outside configuration, so
    // validating it would resolve the secret a second time per bind. The table
    // contributor is the sole resolver: it refuses the bind when a reference cannot
    // resolve or resolves to something that is not a hash.
    private static bool ValidateHashDeclaration(
        string declaration,
        string callerId,
        string keyId,
        List<string> errors)
    {
        if (declaration.StartsWith(SecretReferencePrefix, StringComparison.Ordinal))
        {
            if (declaration.Length == SecretReferencePrefix.Length)
            {
                errors.Add($"The caller '{callerId}' key '{keyId}' has an empty secret reference as its KeyHash.");
                return false;
            }

            return true;
        }

        if (!TryParseHash(declaration, out _))
        {
            errors.Add($"The caller '{callerId}' key '{keyId}' has a KeyHash that is not 'sha256:<64 hex digits>'.");
            return false;
        }

        return true;
    }

    /// <summary>
    /// Parses <c>sha256:&lt;hex&gt;</c> (case-insensitive hex). The hash — never the key —
    /// is what configuration stores.
    /// </summary>
    internal static bool TryParseHash(string value, out byte[] hash)
    {
        hash = [];
        const string prefix = "sha256:";
        if (!value.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) || value.Length != prefix.Length + 64)
        {
            return false;
        }

        var hex = value[prefix.Length..];
        var bytes = new byte[32];
        for (var i = 0; i < 32; i++)
        {
            if (!byte.TryParse(hex.AsSpan(i * 2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var b))
            {
                return false;
            }

            bytes[i] = b;
        }

        hash = bytes;
        return true;
    }
}
