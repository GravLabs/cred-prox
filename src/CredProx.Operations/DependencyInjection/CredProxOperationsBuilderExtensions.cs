using System.Diagnostics.CodeAnalysis;
using CredProx;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// The operations package's one chained call (ADR-0007): <c>.AddOperations()</c> replaces
/// the three separate setup calls of 0.14. Each leg switches on from its own
/// <c>CredProx</c> section — writing the config is the setup, the same rule the core's
/// own features follow.
/// </summary>
[Experimental("CREDPROX001")]
public static class CredProxOperationsBuilderExtensions
{
    /// <summary>
    /// Turns on the configured operations legs: throttling from
    /// <c>CredProx:Throttling</c>, resilience from <c>CredProx:Resilience</c>, and health
    /// probes from <c>CredProx:Health</c>. A section that is absent registers nothing for
    /// that leg; a section that is configured without this call refuses startup naming the
    /// package and this method.
    /// </summary>
    /// <param name="builder">The CredProx builder from <c>AddCredProx(configuration)</c>.</param>
    /// <returns>The same <paramref name="builder"/>, for chaining.</returns>
    public static CredProxBuilder AddOperations(this CredProxBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        var configuration = builder.Configuration;

        if (configuration.GetSection("CredProx:Throttling").GetChildren().Any())
        {
            builder.Services.AddCredProxThrottling(configuration);
        }

        if (configuration.GetSection("CredProx:Resilience").GetChildren().Any())
        {
            builder.Services.AddCredProxResilience(configuration);
        }

        if (configuration.GetSection("CredProx:Health").GetChildren().Any())
        {
            builder.Services.AddCredProxHealthProbes(configuration);
        }

        return builder;
    }
}
