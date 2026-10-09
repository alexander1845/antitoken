using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using TokenVault.Core;

namespace TokenVault.Launcher;

public sealed record FabricLaunch(string MainClass, List<string> JvmArguments, List<string> GameArguments, string ClassPath);

public static class InstalledFabric
{
    public const string AuthlibSha1 = "54895b4e25e8b9b4cbbbe25f24eccf2b71b1ac2b";
    public static FabricLaunch Resolve(Configuration c, SessionDescriptor session, string natives)
    {
        string root = Configuration.Expand(c.MinecraftDirectory);
        string game = Configuration.Expand(c.GameDirectory);
        if (!Directory.Exists(Configuration.Expand(c.ModsDirectory))) throw new DirectoryNotFoundException("Mods directory not found.");
        var chain = new List<JsonObject>();
        var seen = new HashSet<string>();
        string? id = c.FabricProfile;
        while (id is not null)
        {
            if (id.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 || id is "." or ".." || id.Contains('/') || id.Contains('\\') || !seen.Add(id))
                throw new InvalidDataException("Invalid version inheritance.");
            string file = Path.Combine(root, "versions", id, id + ".json");
            if (!File.Exists(file)) throw new FileNotFoundException("Install this Minecraft/Fabric version in the normal launcher first.", file);
            var node = JsonNode.Parse(File.ReadAllText(file))!.AsObject();
            chain.Add(node); id = node["inheritsFrom"]?.GetValue<string>();
        }
        chain.Reverse();
        if (chain[0]["id"]?.GetValue<string>() != "26.1.2" || chain[0]["javaVersion"]?["majorVersion"]?.GetValue<int>() != 25)
            throw new InvalidDataException("Installed profile is not Minecraft 26.1.2 / Java 25.");
        string main = chain.Last()["mainClass"]?.GetValue<string>() ?? "";
        if (main != "net.fabricmc.loader.impl.launch.knot.KnotClient") throw new InvalidDataException("Expected Fabric KnotClient.");
        var libraries = new Dictionary<string, JsonObject>();
        foreach (var manifest in chain)
        foreach (var node in manifest["libraries"]!.AsArray())
        {
            var lib = node!.AsObject();
            if (!Allowed(lib["rules"])) continue;
            string name = lib["name"]!.GetValue<string>();
            string[] parts = name.Split(':');
            libraries[parts[0] + ":" + parts[1] + (parts.Length > 3 ? ":" + parts[3] : "")] = lib;
        }
        if (!libraries.Values.Any(l => l["name"]!.GetValue<string>() == "net.fabricmc:fabric-loader:" + c.FabricVersion))
            throw new InvalidDataException("Configured Fabric version does not match the installed profile.");
        var paths = new List<string>();
        bool verifiedAuthlib = false;
        foreach (var lib in libraries.Values)
        {
            string name = lib["name"]!.GetValue<string>();
            string relative = lib["downloads"]?["artifact"]?["path"]?.GetValue<string>() ?? MavenPath(name);
            string path = Under(root, "libraries/" + relative);
            if (!File.Exists(path)) throw new FileNotFoundException("Missing installed library; launch the normal profile once first.", path);
            paths.Add(path);
            if (name.StartsWith("com.mojang:authlib:", StringComparison.Ordinal))
            {
                using var stream = File.OpenRead(path);
                if (name != "com.mojang:authlib:7.0.63" || Convert.ToHexString(SHA1.HashData(stream)).ToLowerInvariant() != AuthlibSha1)
                    throw new InvalidDataException("Unverified Authlib version or content. Launch refused.");
                verifiedAuthlib = true;
            }
            if (lib["natives"]?["windows"] is JsonNode native)
            {
                string classifier = native.GetValue<string>().Replace("${arch}", "64", StringComparison.Ordinal);
                string nativePath = lib["downloads"]!["classifiers"]![classifier]!["path"]!.GetValue<string>();
                ExtractNatives(Under(root, "libraries/" + nativePath), natives);
            }
        }
        if (!verifiedAuthlib) throw new InvalidDataException("Authlib missing.");
        string client = Path.Combine(root, "versions", "26.1.2", "26.1.2.jar");
        if (!File.Exists(client)) throw new FileNotFoundException("Minecraft client JAR missing.", client);
        using (var zip = ZipFile.OpenRead(client))
        using (var reader = new StreamReader(zip.GetEntry("version.json")!.Open()))
        {
            var version = JsonNode.Parse(reader.ReadToEnd())!;
            if (version["id"]!.GetValue<string>() != "26.1.2" || version["protocol_version"]!.GetValue<int>() != 775)
                throw new InvalidDataException("Client protocol mismatch.");
        }
        paths.Add(client);
        string cp = string.Join(Path.PathSeparator, paths);
        string assets = chain[0]["assetIndex"]!["id"]!.GetValue<string>();
        var replacements = new Dictionary<string, string>
        {
            ["natives_directory"] = natives, ["launcher_name"] = "TokenVault", ["launcher_version"] = "0.1.0",
            ["classpath"] = cp, ["classpath_separator"] = Path.PathSeparator.ToString(), ["library_directory"] = Path.Combine(root, "libraries"),
            ["auth_player_name"] = session.Profile.Name, ["version_name"] = c.FabricProfile, ["game_directory"] = game,
            ["assets_root"] = Path.Combine(root, "assets"), ["assets_index_name"] = assets, ["auth_uuid"] = session.Profile.Id,
            ["auth_access_token"] = session.FakeToken, ["user_type"] = "msa", ["version_type"] = "release",
            ["clientid"] = c.ClientId, ["auth_xuid"] = "0", ["user_properties"] = "{}"
        };
        string Expand(string text) => Regex.Replace(text, @"\$\{([^}]+)\}", m => replacements.TryGetValue(m.Groups[1].Value, out var value)
            ? value : throw new InvalidDataException("Unsupported launcher placeholder: " + m.Groups[1].Value));
        var jvm = chain.SelectMany(x => Arguments(x["arguments"]?["jvm"])).Select(Expand).ToList();
        var args = chain.SelectMany(x => Arguments(x["arguments"]?["game"])).Select(Expand).ToList();
        if (!jvm.Contains("-cp")) { jvm.Add("-cp"); jvm.Add(cp); }
        args.AddRange(["--quickPlayMultiplayer", $"127.0.0.1:{session.GamePort}"]);
        return new(main, jvm, args, cp);
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

    private static string MavenPath(string name)
    {
        string[] p = name.Split(':');
        if (p.Length is < 3 or > 4) throw new InvalidDataException("Invalid Maven coordinate.");
        return $"{p[0].Replace('.', '/')}/{p[1]}/{p[2]}/{p[1]}-{p[2]}{(p.Length == 4 ? "-" + p[3] : "")}.jar";
    }

    private static string Under(string root, string relative)
    {
        string path = Path.GetFullPath(Path.Combine(root, relative));
        if (!path.StartsWith(Path.TrimEndingDirectorySeparator(root) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Path escapes Minecraft directory.");
        return path;
    }

    private static void ExtractNatives(string jar, string directory)
    {
        using var zip = ZipFile.OpenRead(jar);
        foreach (var entry in zip.Entries.Where(e => e.Name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)))
            entry.ExtractToFile(Path.Combine(directory, entry.Name), overwrite: true);
    }
}
