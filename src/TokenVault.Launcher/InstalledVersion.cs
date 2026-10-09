using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using TokenVault.Core;

namespace TokenVault.Launcher;

// ReadDirectories: the parts of the game install the sandbox needs to read (never an install root itself).
public sealed record GameLaunch(string MainClass, List<string> JvmArguments, List<string> GameArguments, string ClassPath,
    List<string> ReadDirectories, int Protocol);

// Turns an installed version (vanilla, Fabric, Quilt, Forge, NeoForge; Minecraft 1.8 and later) into a command line,
// the way the official launcher reads version JSON files. Versions are looked up in Token Vault's own install first and
// then in the loader's folder (Forge/NeoForge), so vanilla files always come from the install Token Vault verified.
public static class InstalledVersion
{
    public static GameLaunch Resolve(Configuration c, SessionDescriptor session, string natives)
    {
        string root = Configuration.Expand(c.MinecraftDirectory);
        string? loaderRoot = c.LoaderDirectory is { Length: > 0 } l ? Configuration.Expand(l) : null;
        string[] roots = loaderRoot is null ? [root] : [root, loaderRoot];
        string game = Configuration.Expand(c.GameDirectory);
        var chain = new List<JsonObject>();
        var versionDirectories = new List<string>();
        var seen = new HashSet<string>();
        string? id = c.Profile;
        while (id is not null)
        {
            if (id.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 || id is "." or ".." || id.Contains('/') || id.Contains('\\') || !seen.Add(id))
                throw new InvalidDataException("Invalid version inheritance.");
            string? file = roots.Select(r => Path.Combine(r, "versions", id, id + ".json")).FirstOrDefault(File.Exists)
                ?? throw new UserVisibleException($"Version {id} is not installed yet. Press Play again to install it.");
            versionDirectories.Add(Path.GetDirectoryName(file)!);
            var node = JsonNode.Parse(File.ReadAllText(file))!.AsObject();
            chain.Add(node); id = node["inheritsFrom"]?.GetValue<string>();
        }
        chain.Reverse(); // base (vanilla) first, loader last
        string baseId = chain[0]["id"]!.GetValue<string>();
        if (baseId != c.MinecraftVersion) throw new InvalidDataException($"This instance expects Minecraft {c.MinecraftVersion}, but the installed profile is {baseId}.");
        string main = Enumerable.Reverse(chain).Select(n => n["mainClass"]?.GetValue<string>()).FirstOrDefault(m => !string.IsNullOrEmpty(m))
            ?? throw new InvalidDataException("The installed profile has no main class.");

        var libraries = new Dictionary<string, JsonObject>();
        foreach (var manifest in chain)
        foreach (var node in manifest["libraries"]?.AsArray() ?? [])
        {
            var lib = node!.AsObject();
            if (!Allowed(lib["rules"])) continue;
            string name = lib["name"]!.GetValue<string>();
            string[] parts = name.Split(':');
            libraries[parts[0] + ":" + parts[1] + (parts.Length > 3 ? ":" + parts[3] : "")] = lib; // later (loader) entries win
        }
        var paths = new List<string>();
        foreach (var lib in libraries.Values)
        {
            string name = lib["name"]!.GetValue<string>();
            if (lib["natives"]?["windows"] is JsonNode native)
            {
                string classifier = native.GetValue<string>().Replace("${arch}", "64", StringComparison.Ordinal);
                if (lib["downloads"]?["classifiers"]?[classifier]?["path"]?.GetValue<string>() is { } nativePath)
                    ExtractNatives(Library(roots, nativePath), natives);
                if (lib["downloads"]?["artifact"] is null) continue; // natives-only entry (old LWJGL 2)
            }
            string relative = lib["downloads"]?["artifact"]?["path"]?.GetValue<string>() ?? MavenPath(name);
            string path = Library(roots, relative);
            if (name.StartsWith("com.mojang:authlib:", StringComparison.Ordinal))
            {
                // Must be exactly the build Mojang lists for this version.
                string? expected = lib["downloads"]?["artifact"]?["sha1"]?.GetValue<string>();
                using var stream = File.OpenRead(path);
                if (expected is null || !Convert.ToHexString(SHA1.HashData(stream)).Equals(expected, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("Authlib doesn't match Mojang's published checksum. Launch refused.");
            }
            if (!paths.Contains(path, StringComparer.OrdinalIgnoreCase)) paths.Add(path);
        }
        string client = Path.Combine(root, "versions", baseId, baseId + ".jar");
        if (!File.Exists(client)) throw new FileNotFoundException("Minecraft client JAR missing.", client);
        int protocol = Protocol(client, baseId);
        paths.Add(client);

        string cp = string.Join(Path.PathSeparator, paths);
        string assetsRoot = Path.Combine(root, "assets");
        string assets = chain[0]["assetIndex"]?["id"]?.GetValue<string>() ?? chain[0]["assets"]?.GetValue<string>() ?? "legacy";
        var replacements = new Dictionary<string, string>
        {
            ["natives_directory"] = natives, ["launcher_name"] = "TokenVault", ["launcher_version"] = "1.0",
            ["classpath"] = cp, ["classpath_separator"] = Path.PathSeparator.ToString(),
            ["library_directory"] = Path.Combine(loaderRoot ?? root, "libraries"),
            ["auth_player_name"] = session.Profile.Name, ["version_name"] = c.Profile, ["game_directory"] = game,
            ["assets_root"] = assetsRoot, ["game_assets"] = assetsRoot, ["assets_index_name"] = assets,
            ["auth_uuid"] = session.Profile.Id, ["auth_access_token"] = session.FakeToken, ["auth_session"] = session.FakeToken,
            ["user_type"] = "msa", ["version_type"] = "release", ["user_properties"] = "{}",
            ["clientid"] = c.ClientId.Length > 0 ? c.ClientId : "0", ["auth_xuid"] = "0"
        };
        string Expand(string text) => Regex.Replace(text, @"\$\{([^}]+)\}", m => replacements.TryGetValue(m.Groups[1].Value, out var value)
            ? value : throw new InvalidDataException("Unsupported launcher placeholder: " + m.Groups[1].Value));

        List<string> jvm, args;
        // Before 1.13, versions use one "minecraftArguments" string (the most specific one wins) and default JVM arguments.
        if (Enumerable.Reverse(chain).Select(n => n["minecraftArguments"]?.GetValue<string>()).FirstOrDefault(a => a is not null) is { } legacy &&
            !chain.Any(n => n["arguments"]?["game"] is not null))
        {
            jvm = ["-Djava.library.path=" + natives, "-cp", cp];
            args = legacy.Split(' ', StringSplitOptions.RemoveEmptyEntries).Select(Expand).ToList();
        }
        else
        {
            jvm = chain.SelectMany(x => Arguments(x["arguments"]?["jvm"])).Select(Expand).ToList();
            args = chain.SelectMany(x => Arguments(x["arguments"]?["game"])).Select(Expand).ToList();
            if (!jvm.Contains("-cp")) { jvm.Add("-cp"); jvm.Add(cp); }
            if (!jvm.Any(a => a.StartsWith("-Djava.library.path=", StringComparison.Ordinal))) jvm.Insert(0, "-Djava.library.path=" + natives);
        }
        var read = new List<string> { Path.Combine(root, "libraries"), assetsRoot };
        if (loaderRoot is not null) read.Add(Path.Combine(loaderRoot, "libraries"));
        read.AddRange(versionDirectories);
        return new(main, jvm, args, cp, read.Distinct(StringComparer.OrdinalIgnoreCase).ToList(), protocol);
    }

    // Network protocol of the client: from the JAR's version.json (1.14+), else the published numbers for older releases.
    public static int Protocol(string clientJar, string versionId)
    {
        using (var zip = ZipFile.OpenRead(clientJar))
            if (zip.GetEntry("version.json") is { } entry)
            {
                using var reader = new StreamReader(entry.Open());
                if (JsonNode.Parse(reader.ReadToEnd())?["protocol_version"]?.GetValue<int>() is int p) return p;
            }
        return LegacyProtocol(versionId) ?? throw new UserVisibleException($"Minecraft {versionId} is older than Token Vault supports (1.8 and later).");
    }

    public static int? LegacyProtocol(string versionId) => versionId switch
    {
        _ when versionId.StartsWith("1.8", StringComparison.Ordinal) && (versionId.Length == 3 || versionId[3] == '.') => 47,
        "1.9" => 107, "1.9.1" => 108, "1.9.2" => 109, "1.9.3" or "1.9.4" => 110,
        "1.10" or "1.10.1" or "1.10.2" => 210, "1.11" => 315, "1.11.1" or "1.11.2" => 316,
        "1.12" => 335, "1.12.1" => 338, "1.12.2" => 340, "1.13" => 393, "1.13.1" => 401, "1.13.2" => 404,
        _ => null
    };

    private static string Library(string[] roots, string relative)
    {
        foreach (string r in roots)
        {
            string path = Under(r, "libraries/" + relative);
            if (File.Exists(path)) return path;
        }
        throw new UserVisibleException("A game library is missing: " + relative + ". Press Play again to reinstall.");
    }

    public static bool Allowed(JsonNode? rules)
    {
        if (rules is null) return true;
        bool allowed = false;
        foreach (var rule in rules.AsArray())
        {
            bool match = true;
            if (rule!["os"] is JsonObject os)
            {
                if (os["name"] is JsonNode name && name.GetValue<string>() != "windows") match = false;
                if (os["arch"] is JsonNode arch && arch.GetValue<string>() is not ("x86_64" or "amd64")) match = false;
                if (os["version"] is JsonNode ver && !Regex.IsMatch(Environment.OSVersion.Version.ToString(), ver.GetValue<string>(), RegexOptions.None, TimeSpan.FromMilliseconds(100))) match = false;
            }
            if (rule["features"] is JsonObject features && features.Any(f => f.Value!.GetValue<bool>())) match = false;
            if (match) allowed = rule["action"]!.GetValue<string>() == "allow";
        }
        return allowed;
    }

    private static IEnumerable<string> Arguments(JsonNode? arguments)
    {
        if (arguments is null) yield break;
        foreach (var argument in arguments.AsArray())
        {
            if (argument is JsonValue v) { yield return v.GetValue<string>(); continue; }
            if (!Allowed(argument!["rules"])) continue;
            if (argument["value"] is JsonArray array) foreach (var item in array) yield return item!.GetValue<string>();
            else yield return argument["value"]!.GetValue<string>();
        }
    }

    // group:artifact:version[:classifier][@extension]
    public static string MavenPath(string name)
    {
        string extension = "jar";
        int at = name.IndexOf('@');
        if (at >= 0) { extension = name[(at + 1)..]; name = name[..at]; }
        string[] p = name.Split(':');
        if (p.Length is < 3 or > 4 || !Regex.IsMatch(extension, "^[A-Za-z0-9]{1,10}$")) throw new InvalidDataException("Invalid Maven coordinate.");
        return $"{p[0].Replace('.', '/')}/{p[1]}/{p[2]}/{p[1]}-{p[2]}{(p.Length == 4 ? "-" + p[3] : "")}.{extension}";
    }

    private static string Under(string root, string relative)
    {
        string path = Path.GetFullPath(Path.Combine(root, relative));
        if (!SandboxPolicy.IsWithin(path, root)) throw new InvalidDataException("Path escapes Minecraft directory.");
        return path;
    }

    private static void ExtractNatives(string jar, string directory)
    {
        using var zip = ZipFile.OpenRead(jar);
        foreach (var entry in zip.Entries.Where(e => e.Name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)))
            entry.ExtractToFile(Path.Combine(directory, entry.Name), overwrite: true);
    }
}
