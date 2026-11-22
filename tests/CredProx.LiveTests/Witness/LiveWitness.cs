using System.Diagnostics.Metrics;

// A DOTNET_STARTUP_HOOKS assembly: the .NET runtime calls Initialize() when the host process
// starts, before its entry point runs. This observer attaches a MeterListener to the
// library's own "CredProx" meter and appends one token-cache observation per line to
// the file named by CREDPROX_LIVE_WITNESS_FILE:
//
//   miss          a token acquisition was needed and started (one per exchange)
//   hit           a cached token was served without touching the vendor
//   fetch-success a vendor token fetch completed successfully
//   fetch-failure a vendor token fetch failed
//
// It observes meters only: it never proxies, mutates, or logs request data, and it
// records no values — the counts carry no secret. When CREDPROX_LIVE_WITNESS_FILE is
// unset it installs nothing, so a stray load of this assembly is inert.
// The runtime enters a startup-hook assembly through this global name; the
// path,TypeName spelling is not parsed, so the entry type is fixed here.
public static class StartupHook
{
    public const string FilePathVariable = "CREDPROX_LIVE_WITNESS_FILE";

    public static void Initialize()
    {
        var path = Environment.GetEnvironmentVariable(FilePathVariable);
        if (string.IsNullOrEmpty(path))
        {
            return;
        }

        var gate = new object();
        var listener = new MeterListener
        {
            InstrumentPublished = (instrument, listener) =>
            {
                if (instrument.Meter.Name != "CredProx")
                {
                    return;
                }

                if (instrument.Name is "credprox.token.cache" or "credprox.token.fetches")
                {
                    listener.EnableMeasurementEvents(instrument);
                }
            },
        };
        listener.SetMeasurementEventCallback<long>((instrument, measurement, tags, state) =>
        {
            var kind = Classify(instrument.Name, tags);
            if (kind is null)
            {
                return;
            }

            lock (gate)
            {
                File.AppendAllText(path, kind + Environment.NewLine);
            }
        });
        listener.Start();
    }

    private static string? Classify(string? instrumentName, ReadOnlySpan<KeyValuePair<string, object?>> tags)
    {
        string? result = null;
        string? outcome = null;
        foreach (var tag in tags)
        {
            if (tag.Key == "result")
            {
                result = tag.Value as string;
            }
            else if (tag.Key == "outcome")
            {
                outcome = tag.Value as string;
            }
        }

        return instrumentName switch
        {
            "credprox.token.cache" when result is "hit" or "miss" => result,
            "credprox.token.fetches" when outcome is "success" or "failure" => "fetch-" + outcome,
            _ => null,
        };
    }
}
