using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace CredProx;

/// <summary>
/// The handle the <see cref="CredProxServiceCollectionExtensions.AddCredProx(IServiceCollection, IConfiguration)"/>
/// entry hands back (ADR-0007 item 5). The host passes its configuration once, at the
/// entry; every add-on package then adds one chained call to this builder
/// (<c>.AddIdentity()</c>, <c>.AddOperations()</c>, <c>.AddAzure(credential)</c>), and
/// plugin authors extend it through the <c>With*</c> seams. The builder carries the two
/// things every chained call needs — the service collection and the one configuration
/// pass — and nothing else.
/// </summary>
[Experimental("CREDPROX001")]
public sealed class CredProxBuilder
{
    /// <summary>
    /// Creates the builder. Hosts get this from <c>AddCredProx(configuration)</c>; there is
    /// no reason to construct it directly.
    /// </summary>
    /// <param name="services">The host's service collection.</param>
    /// <param name="configuration">The configuration pass the entry received.</param>
    public CredProxBuilder(IServiceCollection services, IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);
        Services = services;
        Configuration = configuration;
    }

    /// <summary>The host's service collection, as the entry received it.</summary>
    public IServiceCollection Services { get; }

    /// <summary>
    /// The one configuration pass, as the entry received it. Chained calls read their
    /// feature sections from it — a host never passes configuration twice.
    /// </summary>
    public IConfiguration Configuration { get; }
}
