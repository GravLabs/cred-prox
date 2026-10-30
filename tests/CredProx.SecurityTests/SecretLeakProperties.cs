using CredProx;
using FsCheck;
using FsCheck.Xunit;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace CredProx.SecurityTests;

/// <summary>
/// §5.2 "Validation" / §3.2 as a property: a failing client-certificate load names the
/// reference and the failure kind — the secret value never appears in the startup failure,
/// whatever the value was.
/// </summary>
public sealed class SecretLeakProperties
{
    [Property(MaxTest = 200)]
    public void ConnectionLoadFailure_NamesTheReferenceNeverTheValue(NonNull<string> generated)
    {
        // The prefix guarantees the value is never loadable certificate material, so the
        // load always fails — the question is only what the failure says.
        var secretValue = "not-a-cert-" + generated.Get;
        if (secretValue.Contains("-----BEGIN", StringComparison.Ordinal))
        {
            return; // would take the PEM path; still fails, but keep the shape deterministic
        }

        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["CredProx:Connections:contoso:ClientCertificate"] = "secret:contoso-cert",
                ["CredProx:Secrets:contoso-cert"] = secretValue,
            })
            .Build();

        var error = Assert.Throws<OptionsValidationException>(() =>
            new ConnectionBinder(
                config,
                new SecretAccessorFactory(new ConfigurationSecretSource(config)),
                NullLoggerFactory.Instance).Bind());

        Assert.Contains("contoso", error.Message); // names the connection and the reference
        Assert.DoesNotContain(secretValue, error.Message);

        // The value itself, independent of the prefix, must not be quoted either.
        if (generated.Get.Length >= 12)
        {
            Assert.DoesNotContain(generated.Get, error.Message);
        }
    }
}
