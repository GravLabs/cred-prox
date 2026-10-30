using System.Diagnostics.CodeAnalysis;

namespace CredProx;

/// <summary>
/// Implemented by credential options that declare where their value is attached to the
/// outbound request. The credential binder turns this into the attach step the request
/// feature applies (see <c>docs/credprox-plan.md</c> §3.1).
/// </summary>
[Experimental("CREDPROX001")]
public interface IHasAttachment
{
    /// <summary>Header, query or cookie placement.</summary>
    CredentialLocation Location { get; }

    /// <summary>The header, query parameter, or cookie name.</summary>
    string Name { get; }

    /// <summary>
    /// A literal prefix written before the value inside the header/parameter
    /// (for example <c>"Bearer "</c>); <see langword="null"/> or empty attaches the raw value.
    /// </summary>
    string? Prefix { get; }
}
