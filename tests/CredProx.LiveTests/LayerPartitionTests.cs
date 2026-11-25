using System.Reflection;
using Xunit;

namespace CredProx.LiveTests;

// The closed partition: every Fact and Theory in THIS assembly — this cell
// included — carries exactly one Layer trait, valued Offline or Live. The two
// Layer filters are the only sanctioned ways to run this project and an
// unfiltered run is ruled out by the lead, so a cell without exactly one label
// is dead bytes no leg ever executes. The reflection lives inside the assembly
// because an outside pin can pass by reflecting a stale assembly list, and the
// pin cell itself carries Layer=Offline because an unlabelled pin could only
// ever run under the forbidden unfiltered command.
//
// The cell SET is reflected from the assembly; the Layer VALUE is read from the
// source text of the declaring file (the attribute block attached to the method
// plus the block attached to its class). Measured reason, 2026-11-24: the pinned
// xunit materialises the trait attribute instance but keeps its data outside any
// readable field or property, so a metadata read of the value is not available
// to reflection here — the filter works because the runner reads traits through
// its own pipeline. Source text is the honest surface this pin can read: the
// attribute blocks are one attribute per line, which the parser relies on.
[Trait("Layer", "Offline")]
public sealed class LayerPartitionTests
{
    [Fact]
    public void EveryFactAndTheory_CarriesExactlyOneLayerTrait_OfflineOrLive()
    {
        var offenders = new List<string>();
        var cells = 0;
        var offline = 0;
        var live = 0;
        var projectDir = Path.Combine(RepoRoot(), "tests", "CredProx.LiveTests");
        var sourceByFile = new Dictionary<string, string[]>();

        foreach (var type in typeof(LayerPartitionTests).Assembly.GetTypes())
        {
            string[]? typeLines = null;
            var typeBlocks = new List<string>();
            var classDeclIndex = -1;
            var classScopeEnd = -1;
            foreach (var method in type.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly))
            {
                // FactAttribute covers TheoryAttribute and every live-attribute subclass.
                if (!method.GetCustomAttributes(inherit: true).Any(a => a is FactAttribute))
                {
                    continue;
                }

                cells++;
                if (typeLines is null)
                {
                    typeLines = LocateSource(projectDir, sourceByFile, type.Name).Lines;
                    classDeclIndex = ClassDeclIndex(typeLines, type.Name);
                    classScopeEnd = ClassScopeEnd(typeLines, classDeclIndex);
                    typeBlocks = AttributeBlocksAbove(typeLines, classDeclIndex);
                }

                // The method block is located INSIDE this class's source range,
                // never by first match in the file: two classes in one file may
                // declare same-named fact methods, and a file-wide search would
                // hand the second class's cell the first one's trait (measured
                // 2026-11-24, reviewer demo). No declaration in scope is itself
                // an offender, not a silent pass.
                var methodDeclIndex = MethodDeclIndex(typeLines, method.Name, classDeclIndex, classScopeEnd);
                if (methodDeclIndex < 0)
                {
                    offenders.Add($"{type.Name}.{method.Name} declaration not found inside the {type.Name} class range in source");
                    continue;
                }

                var methodBlocks = AttributeBlocksAbove(typeLines, methodDeclIndex);
                var layerValues = typeBlocks.Concat(methodBlocks)
                    .Where(b => b.Contains("Trait(\"Layer\"", StringComparison.Ordinal))
                    .Select(b => b.Contains("Trait(\"Layer\", \"Offline\")", StringComparison.Ordinal) ? "Offline"
                        : b.Contains("Trait(\"Layer\", \"Live\")", StringComparison.Ordinal) ? "Live"
                        : "unknown")
                    .ToList();

                if (layerValues.Count != 1)
                {
                    offenders.Add($"{type.Name}.{method.Name} matched {layerValues.Count} Layer trait lines in source");
                }
                else if (layerValues[0] == "Offline")
                {
                    offline++;
                }
                else if (layerValues[0] == "Live")
                {
                    live++;
                }
                else
                {
                    offenders.Add($"{type.Name}.{method.Name} Layer value not Offline/Live");
                }
            }
        }

        Assert.True(cells > 100, $"reflection saw only {cells} cells - the assembly shape changed");
        Assert.True(offenders.Count == 0, string.Join("; ", offenders.Take(10)));
        Assert.Equal(cells, offline + live);
    }

    // The file declaring the test type: convention here is one class per name,
    // the type's own name is unique across the project's .cs files.
    private static (string File, string[] Lines) LocateSource(
        string projectDir,
        Dictionary<string, string[]> cache,
        string typeName)
    {
        foreach (var file in Directory.GetFiles(projectDir, "*.cs"))
        {
            if (!cache.TryGetValue(file, out var lines))
            {
                lines = File.ReadAllLines(file);
                cache[file] = lines;
            }

            if (lines.Any(l => IsClassDeclFor(l.TrimStart(), typeName)))
            {
                return (file, lines);
            }
        }

        throw new InvalidOperationException($"no source file declares {typeName} - the pin's file convention broke");
    }

    // The contiguous attribute block directly above the declaration line at
    // declIndex: immediately-preceding attribute lines count (the project's
    // convention is one attribute per line); anything else ends the walk.
    private static List<string> AttributeBlocksAbove(string[] lines, int declIndex)
    {
        var blocks = new List<string>();
        for (var j = declIndex - 1; j >= 0; j--)
        {
            var above = lines[j].Trim();
            if (above.StartsWith("[", StringComparison.Ordinal))
            {
                blocks.Add(above);
                continue;
            }

            break;
        }

        return blocks;
    }

    private static bool IsClassDeclFor(string trimmedLine, string typeName) =>
        trimmedLine.StartsWith("public sealed class " + typeName, StringComparison.Ordinal)
        || trimmedLine.StartsWith("public class " + typeName, StringComparison.Ordinal);

    private static int ClassDeclIndex(string[] lines, string typeName)
    {
        for (var i = 0; i < lines.Length; i++)
        {
            if (IsClassDeclFor(lines[i].TrimStart(), typeName))
            {
                return i;
            }
        }

        throw new InvalidOperationException($"source has no declaration of {typeName} - the pin's file convention broke");
    }

    // A class's source range ends where the next class declaration in the same
    // file starts, or at end of file; method blocks are scoped inside it so a
    // same-named method in a later class can never borrow the first one's
    // attribute block.
    private static int ClassScopeEnd(string[] lines, int classDeclIndex)
    {
        for (var i = classDeclIndex + 1; i < lines.Length; i++)
        {
            var trimmed = lines[i].TrimStart();
            if (trimmed.StartsWith("public ", StringComparison.Ordinal) && trimmed.Contains("class ", StringComparison.Ordinal))
            {
                return i;
            }
        }

        return lines.Length;
    }

    private static int MethodDeclIndex(string[] lines, string methodName, int from, int to)
    {
        for (var i = from + 1; i < to; i++)
        {
            var trimmed = lines[i].TrimStart();
            if (trimmed.StartsWith("public ", StringComparison.Ordinal) && lines[i].Contains(methodName + "(", StringComparison.Ordinal))
            {
                return i;
            }
        }

        return -1;
    }

    private static string RepoRoot()
    {
        var parts = AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar)
            .Split(Path.DirectorySeparatorChar);
        var binIndex = Array.IndexOf(parts, "bin");
        Assert.True(binIndex >= 3, $"unexpected test assembly location '{AppContext.BaseDirectory}'");
        return string.Join(Path.DirectorySeparatorChar, parts[..(binIndex - 2)]);
    }
}
