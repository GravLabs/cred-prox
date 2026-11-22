using System.Diagnostics.CodeAnalysis;

namespace CredProx.Abstractions;

/// <summary>
/// Contributes rules about the caller registry that a feature package owns and the core
/// must not learn. The core runs every registered validator over the complete set of
/// configured callers once at host start and again on every live configuration rebind.
/// Errors refuse the registry: at startup the host fails to start with an
/// <c>OptionsValidationException</c> carrying the errors; on a live rebind the previous
/// registry keeps serving and the reason is logged. That rebind guarantee is the point —
/// a check that ran only at registration could never see a configuration that drifted
/// into a refused shape after the host had started.
/// </summary>
/// <remarks>
/// <para>
/// Register through <c>WithCallerRegistryValidator&lt;TValidator&gt;()</c> (or the
/// plain singleton registration). A validator is a pure function of the current
/// configuration: no side effects, nothing cached, no assumption about which other
/// validators ran. Cross-caller rules — one client id claimed by two callers — are why
/// every entry arrives in a single call.
/// </para>
/// <para>
/// A validator that throws instead of returning errors is treated as a refused registry,
/// with the same consequences on either path.
/// </para>
/// </remarks>
[Experimental("CREDPROX001")]
public interface ICallerRegistryValidator
{
    /// <summary>
    /// Validates the complete registry view, in configuration order.
    /// </summary>
    /// <param name="callers">
    /// Every configured caller — one entry per <c>CredProx:Callers:&lt;id&gt;</c> section.
    /// </param>
    /// <returns>The validation errors, naming the caller and the key path; empty means the registry passes.</returns>
    IReadOnlyList<string> Validate(IReadOnlyList<CallerRegistryEntry> callers);
}
