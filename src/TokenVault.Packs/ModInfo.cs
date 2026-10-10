using System.IO.Compression;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace TokenVault.Packs;

// Display info for an installed mod, read from its fabric.mod.json. Mod files are sandbox-writable, so this is
// treated as untrusted input: bounded reads, no code, no images, plain strings only.
public sealed record ModInfo(string Name, string? Version, string File, long Size)
{
    public static ModInfo Read(string path)
    {
        var info = new FileInfo(path);
        string name = Path.GetFileNameWithoutExtension(path);
        if ((info.Attributes & FileAttributes.ReparsePoint) != 0) return new(name, null, info.Name, 0);
        try
        {
            using var zip = ZipFile.OpenRead(path);
            if (zip.GetEntry("fabric.mod.json") is { Length: < 512 * 1024 } entry)
            {
                using var stream = entry.Open();
                using var json = JsonDocument.Parse(stream, new JsonDocumentOptions { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip });
                var root = json.RootElement;
                string? Field(string key) => root.TryGetProperty(key, out var v) && v.ValueKind == JsonValueKind.String ? Clean(v.GetString()) : null;
                return new(Field("name") ?? Field("id") ?? name, Field("version"), info.Name, info.Length);
            }
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or JsonException or UnauthorizedAccessException) { }
        return new(name, null, info.Name, info.Length);
    }

    private static string? Clean(string? s)
    {
        if (string.IsNullOrWhiteSpace(s)) return null;
        s = new string(s.Where(c => !char.IsControl(c)).ToArray()).Trim();
        return s.Length > 80 ? s[..80] : s;
    }

    // What a folder of loose mods was made for: the loader most of them declare and the Minecraft version they most
    // often name. Null when the mods don't say (or disagree on the loader). Untrusted input, bounded like Read.
    public static (string? Minecraft, string Loader)? Detect(string modsDirectory)
    {
        if (!Directory.Exists(modsDirectory)) return null;
        var loaders = new Dictionary<string, int>();
        var versions = new Dictionary<string, int>();
        foreach (string jar in Directory.EnumerateFiles(modsDirectory, "*.jar").Take(500))
        {
            try
            {
                if ((System.IO.File.GetAttributes(jar) & FileAttributes.ReparsePoint) != 0) continue;
                using var zip = ZipFile.OpenRead(jar);
                string? loader = null, text = null;
                foreach (var (entry, name) in new[] { ("fabric.mod.json", "fabric"), ("quilt.mod.json", "quilt"),
                             ("META-INF/neoforge.mods.toml", "neoforge"), ("META-INF/mods.toml", "forge") })
                    if (zip.GetEntry(entry) is { Length: < 512 * 1024 } found)
                    {
                        using var reader = new StreamReader(found.Open());
                        text = reader.ReadToEnd(); loader = name; break;
                    }
                if (loader is null || text is null) continue;
                loaders[loader] = loaders.GetValueOrDefault(loader) + 1;
                // fabric/quilt: "minecraft": "~1.20.1" / ">=1.21 <1.22"; forge: modId="minecraft" versionRange="[1.20.1,1.21)"
                var match = loader is "fabric" or "quilt"
                    ? Regex.Match(text, "\"minecraft\"\\s*:\\s*\\[?\\s*\"[^0-9\"]*(\\d+\\.\\d+(?:\\.\\d+)?)", RegexOptions.None, TimeSpan.FromSeconds(1))
                    : Regex.Match(text, "modId\\s*=\\s*\"minecraft\"[^\\[]*?versionRange\\s*=\\s*\"[\\[(]?(\\d+\\.\\d+(?:\\.\\d+)?)", RegexOptions.None, TimeSpan.FromSeconds(1));
                if (match.Success) versions[match.Groups[1].Value] = versions.GetValueOrDefault(match.Groups[1].Value) + 1;
            }
            catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or RegexMatchTimeoutException) { }
        }
        if (loaders.Count == 0) return null;
        var top = loaders.OrderByDescending(p => p.Value).ToList();
        if (top.Count > 1 && top[1].Value * 4 > top[0].Value) return null; // mixed loaders: don't guess
        string? minecraft = versions.Count == 0 ? null : versions.OrderByDescending(p => p.Value).First().Key;
        return (minecraft, top[0].Key);
    }

    public static IReadOnlyList<ModInfo> List(string modsDirectory)
    {
        if (!Directory.Exists(modsDirectory)) return [];
        return Directory.EnumerateFiles(modsDirectory, "*.jar").Take(2000).Select(Read)
            .OrderBy(m => m.Name, StringComparer.OrdinalIgnoreCase).ToList();
    }
}
