using TokenVault.Core;

namespace TokenVault.Launcher;

// Decides which folders the game sandbox may be given. A grant on a folder exposes everything below it,
// so a folder is refused if it is (or contains) a place that holds credentials or Token Vault itself.
public static class SandboxPolicy
{
    public static IEnumerable<string> ProtectedDirectories(Configuration c) => new[]
    {
        Configuration.Expand(c.MinecraftDirectory), // official launcher sign-in files live in the root
        AppPaths.Data,
        AppContext.BaseDirectory,
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
    }.Where(p => p.Length > 0).Select(Normalize);

    public static void CheckRead(Configuration c, string directory)
    {
        string g = Normalize(directory);
        if (Path.GetPathRoot(g) is { } root && Normalize(root) == g)
            throw new UserVisibleException("Refusing to give the game sandbox a whole drive: " + g);
        foreach (string p in ProtectedDirectories(c))
            if (Same(p, g) || IsWithin(p, g))
                throw new UserVisibleException($"Refusing to give the game sandbox access to {g}: it contains {p}, " +
                    "which holds sign-in data or Token Vault itself. Choose a dedicated folder.");
        if (IsWithin(g, AppPaths.Data) || IsWithin(g, AppContext.BaseDirectory))
            throw new UserVisibleException("Game folders must not be inside Token Vault's own folders: " + g);
    }

    // Writable folders additionally must not overlap anything the sandbox only reads (shared with the
    // official launcher) so a mod cannot plant files that run outside the sandbox later.
    public static void CheckWrite(Configuration c, string directory, IEnumerable<string> readOnly)
    {
        CheckRead(c, directory);
        string g = Normalize(directory);
        if (IsWithin(g, Configuration.Expand(c.MinecraftDirectory)))
            throw new UserVisibleException($"The instance folder {g} is inside the shared Minecraft folder. Use a separate folder.");
        foreach (string r in readOnly.Select(Normalize))
            if (Same(r, g) || IsWithin(r, g) || IsWithin(g, r))
                throw new UserVisibleException($"The instance/mods folder {g} overlaps the shared Minecraft install ({r}). Use a separate instance folder.");
    }

    public static string Normalize(string path) => Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
    public static bool Same(string a, string b) => string.Equals(Normalize(a), Normalize(b), StringComparison.OrdinalIgnoreCase);
    public static bool IsWithin(string child, string parent) =>
        Normalize(child).StartsWith(Normalize(parent) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
}
