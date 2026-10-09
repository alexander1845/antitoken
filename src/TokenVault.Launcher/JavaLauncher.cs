using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using TokenVault.Core;

namespace TokenVault.Launcher;

[SupportedOSPlatform("windows")]
public static class JavaLauncher
{
    public static async Task<int> LaunchAsync(Configuration c, SessionDescriptor session, GameSandbox sandbox, Action<string> log, CancellationToken ct)
    {
        if (session.MinecraftVersion != c.MinecraftVersion || session.ExpiresAt <= DateTimeOffset.UtcNow ||
            session.HttpsPort != c.HttpsPort || session.GamePort != c.GamePort)
            throw new InvalidDataException("Vault descriptor does not match configuration or has expired.");
        string java = JavaLocator.Find(c) ?? throw new UserVisibleException(
            "Java 25 was not found. Start Minecraft 26.1.2 once in the official launcher (it installs Java), or choose java.exe in Settings.");
        string javaVersion = await CaptureAsync(java, ["-version"], ct);
        if (!Regex.IsMatch(javaVersion, "version \"25(?:[.\"])", RegexOptions.CultureInvariant))
            throw new UserVisibleException("Minecraft 26.1.2 needs Java 25; the selected java.exe is a different version.");
        log("Java: " + java);

        string game = Configuration.Expand(c.GameDirectory), mods = Configuration.Expand(c.ModsDirectory), javaHome = JavaLocator.Home(java);
        bool modsInsideGame = SandboxPolicy.Same(mods, game) || SandboxPolicy.IsWithin(mods, game);
        Directory.CreateDirectory(game);
        if (modsInsideGame) Directory.CreateDirectory(mods);
        string run = Path.Combine(AppPaths.Run, Guid.NewGuid().ToString("N"));
        string natives = Path.Combine(run, "natives"), temp = Path.Combine(run, "tmp");
        Directory.CreateDirectory(natives); Directory.CreateDirectory(temp);
        try
        {
            var installed = InstalledFabric.Resolve(c, session, natives);
            string skins = Path.Combine(Configuration.Expand(c.MinecraftDirectory), "assets", "skins");
            // Every folder is checked before any permission changes, so a bad setting changes nothing.
            var readOnly = installed.ReadDirectories.Append(javaHome).ToList();
            foreach (string directory in readOnly) SandboxPolicy.CheckRead(c, directory);
            SandboxPolicy.CheckWrite(c, game, readOnly);
            if (!modsInsideGame) SandboxPolicy.CheckRead(c, mods);
            SandboxPolicy.CheckRead(c, skins);

            // Files Token Vault writes go into a fresh folder BEFORE the sandbox can write there.
            string trust = Path.Combine(run, "vault.jks");
            await File.WriteAllBytesAsync(trust, JavaTrustStore.Create(
                [("tokenvault-loopback", Convert.FromBase64String(session.CertificateDer)), .. JavaTrustStore.WindowsRoots()],
                DateTimeOffset.UtcNow), ct);
            string probe = Path.Combine(run, "AuthlibProbe.java");
            File.Copy(Path.Combine(AppContext.BaseDirectory, "AuthlibProbe.java"), probe);

            log("Sharing only the needed folders with the sandbox…");
            foreach (string directory in readOnly) sandbox.GrantRead(directory);
            if (!modsInsideGame) sandbox.GrantRead(mods);
            Directory.CreateDirectory(skins);
            sandbox.GrantWrite(skins); // skin cache only; holds downloaded PNGs
            sandbox.GrantWrite(game);
            sandbox.GrantWrite(run);

            var properties = Properties(session, trust, temp, game);
            var environment = SandboxEnvironment(temp);
            if (JavaLocator.IsJdk(java))
            {
                log("Checking Authlib redirection inside the sandbox…");
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
                timeout.CancelAfter(TimeSpan.FromSeconds(90));
                int result;
                using (var check = sandbox.Start(java, [.. properties, "--class-path", installed.ClassPath, probe,
                           $"https://127.0.0.1:{session.HttpsPort}", session.FakeToken], run, environment, allowClipboard: false))
                {
                    try { result = await check.WaitForExitAsync(timeout.Token); }
                    catch (OperationCanceledException) when (!ct.IsCancellationRequested) { result = -1; }
                }
                if (result != 0)
                    throw new UserVisibleException("The sandboxed Authlib check failed, so the game was not started. " +
                        "Check that sandbox networking is allowed and that Minecraft 26.1.2 + Fabric are installed correctly.");
            }
            else log("Authlib check skipped (this Java has no compiler). The vault still refuses everything outside its allowlist.");

            var arguments = new List<string>(installed.JvmArguments);
            arguments.AddRange(properties);
            arguments.Add("-Xmx" + c.MemoryMb + "M");
            arguments.Add("-Dfabric.modsFolder=" + mods);
            arguments.Add(installed.MainClass);
            arguments.AddRange(installed.GameArguments);
            // No command-line logging, @argfiles, token files, or real-token environment inheritance.
            log($"Starting Minecraft {c.MinecraftVersion} with Fabric in the sandbox{(c.AllowClipboard ? "" : " (clipboard blocked)")}.");
            using var process = sandbox.Start(java, arguments, game, environment, c.AllowClipboard);
            return await process.WaitForExitAsync(ct); // Dispose kills the whole job, including on cancel.
        }
        finally
        {
            DeleteRun(run);
        }
    }

    public static List<string> Properties(SessionDescriptor s, string trust, string temp, string game) =>
    ["-Dminecraft.api.env=custom", $"-Dminecraft.api.session.host=https://127.0.0.1:{s.HttpsPort}/session",
        $"-Dminecraft.api.services.host=https://127.0.0.1:{s.HttpsPort}/services",
        $"-Dminecraft.api.profiles.host=https://127.0.0.1:{s.HttpsPort}/profiles",
        "-Djavax.net.ssl.trustStore=" + trust, "-Djavax.net.ssl.trustStoreType=JKS", "-Djavax.net.ssl.trustStorePassword=" + JavaTrustStore.Password,
        // Keep every write inside sandbox-writable folders.
        "-XX:-UsePerfData", "-Djava.io.tmpdir=" + temp, "-Djna.tmpdir=" + temp,
        "-Dorg.lwjgl.system.SharedLibraryExtractPath=" + temp, "-Duser.home=" + game];

    // Removes per-launch folders. The sandbox could write into them, but .NET deletes links themselves rather than
    // following them, so planted junctions cannot redirect this delete elsewhere.
    public static void DeleteRun(string run)
    {
        try { if (Directory.Exists(run)) Directory.Delete(run, recursive: true); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }

    public static void CleanStaleRuns()
    {
        if (Directory.Exists(AppPaths.Run)) foreach (string run in Directory.EnumerateDirectories(AppPaths.Run)) DeleteRun(run);
    }

    private static readonly HashSet<string> Inherited = new(StringComparer.OrdinalIgnoreCase)
    {
        "SystemRoot", "WINDIR", "SystemDrive", "PATH", "PATHEXT", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "PROGRAMDATA",
        "ProgramFiles", "ProgramFiles(x86)", "CommonProgramFiles", "PROCESSOR_ARCHITECTURE", "NUMBER_OF_PROCESSORS", "USERNAME", "USERDOMAIN"
    };

    private static Dictionary<string, string> SandboxEnvironment(string temp)
    {
        var environment = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (System.Collections.DictionaryEntry entry in Environment.GetEnvironmentVariables())
            if (entry.Key is string key && Inherited.Contains(key) && entry.Value is string value) environment[key] = value;
        environment["TEMP"] = temp; environment["TMP"] = temp;
        return environment;
    }

    // Unsandboxed, but only ever runs `java -version` (no game or mod code).
    private static async Task<string> CaptureAsync(string executable, IEnumerable<string> args, CancellationToken ct)
    {
        var info = new ProcessStartInfo(executable) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var key in info.Environment.Keys.ToArray()) if (!Inherited.Contains(key) && key is not ("TEMP" or "TMP")) info.Environment.Remove(key);
        foreach (var arg in args) info.ArgumentList.Add(arg);
        using var process = Process.Start(info) ?? throw new InvalidOperationException("Failed to start Java.");
        Task<string> stdout = process.StandardOutput.ReadToEndAsync(ct), stderr = process.StandardError.ReadToEndAsync(ct);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromSeconds(60));
        try { await process.WaitForExitAsync(timeout.Token); }
        finally { if (!process.HasExited) process.Kill(entireProcessTree: true); }
        string result = await stdout + await stderr;
        if (process.ExitCode != 0) throw new UserVisibleException("The selected java.exe did not run. Choose a working Java 25.");
        return result;
    }
}
