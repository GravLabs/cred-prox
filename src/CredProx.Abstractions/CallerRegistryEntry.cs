using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Configuration;

namespace CredProx.Abstractions;

/// <summary>
/// One configured caller, handed to every <see cref="ICallerRegistryValidator"/> as part
/// of the complete registry view: the id as configured, plus the live
/// <c>CredProx:Callers:&lt;id&gt;</c> configuration section. A feature package reads the
/// keys its own add-on owns and ignores the rest — the core never learns what they mean.
/// </summary>
/// <remarks>
/// The section is live, not a snapshot: on a rebind it carries the configuration being
/// validated right now, so a rule sees exactly what the drift introduced.
/// </remarks>
/// <param name="CallerId">The caller id — the section key under <c>CredProx:Callers</c>.</param>
/// <param name="Configuration">The caller's live configuration section.</param>
[Experimental("CREDPROX001")]
public sealed record CallerRegistryEntry(string CallerId, IConfigurationSection Configuration);
