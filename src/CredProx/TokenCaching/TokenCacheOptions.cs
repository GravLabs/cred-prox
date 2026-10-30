using System.Diagnostics.CodeAnalysis;

namespace CredProx;

/// <summary>
/// Options for <see cref="InMemoryTokenCache"/> (see <c>docs/credprox-plan.md</c> §3.3).
/// </summary>
[Experimental("CREDPROX001")]
public sealed class TokenCacheOptions
{
    private double _refreshFraction = 0.8;
    private TimeSpan _skew = TimeSpan.FromSeconds(30);
    private TimeSpan _negativeCacheTtl = TimeSpan.FromSeconds(5);

    /// <summary>
    /// The fraction of a token's lifetime after which it is refreshed early, counting from
    /// when the fetch started. The default is <c>0.8</c>: refresh at 80% of lifetime.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">
    /// The value is not in <c>(0, 1]</c>.
    /// </exception>
    public double RefreshFraction
    {
        get => _refreshFraction;
        set
        {
            if (value <= 0.0 || value > 1.0)
            {
                throw new ArgumentOutOfRangeException(nameof(value), value, "RefreshFraction must be in (0, 1].");
            }

            _refreshFraction = value;
        }
    }

    /// <summary>
    /// How long before the reported expiry a token stops being served, so a token is never
    /// used after the vendor already considers it dead. A token is served while
    /// <c>now &lt; min(started + lifetime × RefreshFraction, ExpiresAt − Skew)</c>.
    /// The default is 30 seconds.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is negative.</exception>
    public TimeSpan Skew
    {
        get => _skew;
        set
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(value, TimeSpan.Zero);
            _skew = value;
        }
    }

    /// <summary>
    /// How long a failed fetch is remembered before a new fetch is attempted. Failures are
    /// cached only for this duration — never for the token lifetime — so a transient vendor
    /// outage does not turn into a sustained one. The default is 5 seconds.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is negative.</exception>
    public TimeSpan NegativeCacheTtl
    {
        get => _negativeCacheTtl;
        set
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(value, TimeSpan.Zero);
            _negativeCacheTtl = value;
        }
    }
}
