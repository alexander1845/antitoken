using System.IO.Compression;
using System.Text.Json;

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

    public static IReadOnlyList<ModInfo> List(string modsDirectory)
    {
        if (!Directory.Exists(modsDirectory)) return [];
        return Directory.EnumerateFiles(modsDirectory, "*.jar").Take(2000).Select(Read)
            .OrderBy(m => m.Name, StringComparer.OrdinalIgnoreCase).ToList();
    }
}
