using System.Text.Json.Nodes;
using TokenVault.Core;

namespace TokenVault.Launcher;

public static class JavaLocator
{
    // Explicit path wins; otherwise the runtime the official launcher installed for this version, then common JDKs.
    public static string? Find(Configuration c)
    {
        if (!string.IsNullOrWhiteSpace(c.JavaPath)) return File.Exists(Configuration.Expand(c.JavaPath)) ? Configuration.Expand(c.JavaPath) : null;
        return Candidates(c).FirstOrDefault(File.Exists);
    }

    private static IEnumerable<string> Candidates(Configuration c)
    {
        string root = Configuration.Expand(c.MinecraftDirectory);
        string? component = null;
        try
        {
            string manifest = Path.Combine(root, "versions", c.MinecraftVersion, c.MinecraftVersion + ".json");
            if (File.Exists(manifest)) component = JsonNode.Parse(File.ReadAllText(manifest))?["javaVersion"]?["component"]?.GetValue<string>();
        }
        catch (Exception ex) when (ex is IOException or System.Text.Json.JsonException or InvalidOperationException) { }
        if (component is not null && component.All(ch => char.IsAsciiLetterOrDigit(ch) || ch is '-' or '_' or '.'))
        {
            string store = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Packages", "Microsoft.4297127D64EC6_8wekyb3d8bbwe", "LocalCache", "Local", "runtime");
            foreach (string runtime in new[] { Path.Combine(root, "runtime"), store })
                yield return Path.Combine(runtime, component, "windows-x64", component, "bin", "java.exe");
        }
        foreach (string programs in new[] { Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles) })
        foreach (string vendor in new[] { "Eclipse Adoptium", "Java", "Microsoft", "Zulu", "Amazon Corretto" })
        {
            string parent = Path.Combine(programs, vendor);
            if (!Directory.Exists(parent)) continue;
            foreach (string jdk in Directory.EnumerateDirectories(parent).Where(d => Path.GetFileName(d).Contains("25", StringComparison.Ordinal)).Order())
                yield return Path.Combine(jdk, "bin", "java.exe");
        }
    }

    public static string Home(string javaExe) => Path.GetDirectoryName(Path.GetDirectoryName(Path.GetFullPath(javaExe)))!;
    public static bool IsJdk(string javaExe) => File.Exists(Path.Combine(Path.GetDirectoryName(javaExe)!, "javac.exe"));
}
