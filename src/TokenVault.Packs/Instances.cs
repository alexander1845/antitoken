using System.Text.Json;
using System.Text.Json.Serialization;
using TokenVault.Core;

namespace TokenVault.Packs;

// A file a pack lists that could not be downloaded automatically (some CurseForge authors block third-party
// downloads). The player downloads it from the page and drops it into the mods folder.
public sealed record MissingFile(string Name, string Page);

// Metadata lives in Token Vault's private data folder, never inside the (sandbox-writable) game folder,
// so a mod cannot change what Token Vault believes about an instance.
public sealed class Instance
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string Name { get; set; } = "Minecraft";
    public string Source { get; set; } = "New";
    public string MinecraftVersion { get; set; } = Configuration.DefaultVersion;
    public string Loader { get; set; } = "fabric";   // vanilla | fabric | quilt | forge | neoforge
    public string? LoaderVersion { get; set; }       // null: newest stable, pinned on first install
    public List<MissingFile> Missing { get; set; } = [];
    public DateTimeOffset Created { get; set; } = DateTimeOffset.UtcNow;

    [JsonIgnore] public string Directory => Path.Combine(AppPaths.InstanceRoot, Id);
    [JsonIgnore] public string ModsDirectory => Path.Combine(Directory, "mods");

    public int CountMods()
    {
        try { return System.IO.Directory.Exists(ModsDirectory) ? System.IO.Directory.EnumerateFiles(ModsDirectory, "*.jar").Count() : 0; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return 0; }
    }

    // Launch settings for this instance on top of the player's settings (before and after installation).
    public Configuration Apply(Configuration settings, TokenVault.Launcher.InstalledProfile? installed = null)
    {
        var c = settings.Clone();
        c.MinecraftVersion = MinecraftVersion;
        c.Loader = Loader;
        c.GameDirectory = Directory;
        c.ModsDirectory = ModsDirectory;
        if (installed is not null) { c.Profile = installed.Profile; c.LoaderDirectory = installed.LoaderDirectory; }
        return c;
    }

    public string Describe() => $"Minecraft {MinecraftVersion} · {TokenVault.Launcher.GameInstaller.LoaderName(Loader)}" +
        (Loader == "vanilla" ? "" : " " + (LoaderVersion ?? "(newest)"));
}

public static class InstanceStore
{
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

    public static List<Instance> Load()
    {
        List<Instance> list = [];
        try
        {
            if (File.Exists(AppPaths.Instances))
                list = JsonSerializer.Deserialize<List<Instance>>(File.ReadAllText(AppPaths.Instances)) ?? [];
        }
        catch (JsonException) { }
        list.RemoveAll(i => !Guid.TryParseExact(i.Id, "N", out _) || i.Name is null || i.Missing is null ||
            !Configuration.IsVersionId(i.MinecraftVersion ?? "") || !TokenVault.Launcher.GameInstaller.Loaders.Contains(i.Loader));
        if (list.Count == 0) list.Add(new Instance { Name = "Fabric " + Configuration.DefaultVersion, Source = "New" });
        return list;
    }

    public static void Save(IEnumerable<Instance> instances)
    {
        string temp = AppPaths.Instances + ".new";
        File.WriteAllText(temp, JsonSerializer.Serialize(instances.ToList(), Json));
        File.Move(temp, AppPaths.Instances, overwrite: true);
    }

    // Creates the game folder fresh. A folder the vault creates has never been reachable by the sandbox.
    public static void CreateFolder(Instance instance)
    {
        System.IO.Directory.CreateDirectory(AppPaths.InstanceRoot);
        System.IO.Directory.CreateDirectory(instance.Directory);
        System.IO.Directory.CreateDirectory(instance.ModsDirectory);
    }

    // Removes an instance folder. .NET deletes links themselves rather than following them.
    public static void DeleteFolder(Instance instance)
    {
        if (System.IO.Directory.Exists(instance.Directory)) System.IO.Directory.Delete(instance.Directory, recursive: true);
    }
}
