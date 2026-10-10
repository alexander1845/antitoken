using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using TokenVault.Core;

namespace TokenVault.Launcher;

[SupportedOSPlatform("windows")]
public static class JavaLauncher
{
    // started: called with the game process once it runs (Token Vault uses it to recognise the game's connections).
    public static async Task<int> LaunchAsync(Configuration c, SessionDescriptor session, GameSandbox sandbox, Action<string> log, CancellationToken ct,
        Action<SandboxedProcess>? started = null)
    {
        if (session.MinecraftVersion != c.MinecraftVersion || session.ExpiresAt <= DateTimeOffset.UtcNow || session.HttpsPort != c.HttpsPort)
            throw new InvalidDataException("Vault descriptor does not match configuration or has expired.");
        // Java is never executed outside the sandbox: the runtime Token Vault installed matches the version's JSON.
        string java = JavaLocator.Find(c) ?? throw new UserVisibleException("Java isn't installed yet. Press Play again to install it.");
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
            var installed = InstalledVersion.Resolve(c, session, natives);
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
            // The self-check needs a JDK (Mojang's runtime has no compiler) and AuthlibProbe.java next to TokenVault.exe.
            // It is a compatibility check only (the game holds a fake token either way), so without them the game still starts.
            bool modernAuthlib = installed.ClassPath.Split(Path.PathSeparator)
                .Any(path => Regex.IsMatch(Path.GetFileName(path), @"^authlib-([4-9]|\d{2,})\.", RegexOptions.CultureInvariant)); // 1.19.3+
            string probeSource = Path.Combine(AppContext.BaseDirectory, "AuthlibProbe.java"), probe = Path.Combine(run, "AuthlibProbe.java");
            bool selfCheck = JavaLocator.IsJdk(java) && modernAuthlib;
            if (selfCheck && File.Exists(probeSource)) File.Copy(probeSource, probe);
            else if (selfCheck) { selfCheck = false; log("Skipping the sign-in self-check: AuthlibProbe.java isn't next to TokenVault.exe."); }

            log("Sharing only the needed folders with the sandbox…");
            // The Forge/NeoForge folder is shared by every instance on that loader version. It was writable only while its
            // installer ran; builds before 1.1 left it writable, which would let a mod in one instance alter all of them.
            if (c.LoaderDirectory.Length > 0)
            {
                string loader = Configuration.Expand(c.LoaderDirectory);
                GameSandbox.RequireNoLinks(loader);
                sandbox.RevokeWrite(loader);
            }
            foreach (string directory in readOnly) sandbox.GrantRead(directory);
            if (!modsInsideGame) sandbox.GrantRead(mods);
            Directory.CreateDirectory(skins);
            // Skin cache only; holds downloaded PNGs. Not needed to play, so a failure here doesn't stop the launch.
            try { sandbox.GrantWrite(skins); }
            catch (Exception ex) when (ex is UserVisibleException or UnauthorizedAccessException or IOException)
            { log("Skin cache unavailable (" + ex.Message + "). The game still starts."); }
            // The server list points the game at Token Vault's local brokers. No sandboxed process is running
            // now (each game's job is gone), so nothing can race this write.
            ServersFile.Write(Path.Combine(game, "servers.dat"), session.Servers);
            // Captures the JVM's console output. Created before the sandbox can write the folder; read back only
            // through this handle, so the sandbox can't redirect what Token Vault reads.
            using var output = new FileStream(Path.Combine(run, "output.log"), FileMode.CreateNew, FileAccess.ReadWrite, FileShare.ReadWrite);
            sandbox.GrantWrite(game);
            sandbox.GrantWrite(run);

            var properties = Properties(session, trust, temp, game);
            var environment = SandboxEnvironment(temp);
            if (selfCheck)
            {
                log("Checking Authlib redirection inside the sandbox…");
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
                timeout.CancelAfter(TimeSpan.FromSeconds(90));
                int result;
                using (var check = sandbox.Start(java, [.. properties, "--class-path", installed.ClassPath, probe,
                           $"https://127.0.0.1:{session.HttpsPort}", session.FakeToken], run, environment, allowClipboard: false, output.SafeFileHandle))
                {
                    try { result = await check.WaitForExitAsync(timeout.Token); }
                    catch (OperationCanceledException) when (!ct.IsCancellationRequested) { result = -1; }
                }
                if (result != 0)
                {
                    // Compatibility only (the game holds a fake token either way): report it and still start the game.
                    string tail = Tail(output);
                    foreach (string line in tail.Split('\n', StringSplitOptions.RemoveEmptyEntries).TakeLast(12)) log("  " + line);
                    log($"Warning: the sign-in self-check failed ({ExitText(result)}: {LastLine(tail) ?? "no output"}). Chat signing may not work.");
                }
                else log("Self-check passed: the game talks only to Token Vault for sign-in.");
                output.SetLength(0);
            }

            var arguments = new List<string>(installed.JvmArguments);
            arguments.AddRange(properties);
            arguments.Add("-Xmx" + c.MemoryMb + "M");
            arguments.Add(installed.MainClass);
            arguments.AddRange(installed.GameArguments);
            // No command-line logging, @argfiles, token files, or real-token environment inheritance.
            log($"Starting Minecraft {c.MinecraftVersion} ({GameInstaller.LoaderName(c.Loader)}) in the sandbox{(c.AllowClipboard ? "" : ", clipboard blocked")}.");
            using var process = sandbox.Start(java, arguments, game, environment, c.AllowClipboard, output.SafeFileHandle);
            started?.Invoke(process);
            int code = await process.WaitForExitAsync(ct); // Dispose kills the whole job, including on cancel.
            if (code != 0)
                foreach (string line in Tail(output).Split('\n', StringSplitOptions.RemoveEmptyEntries).TakeLast(20)) log("  " + line);
            return code;
        }
        finally
        {
            DeleteRun(run);
        }
    }

    // Untrusted text from the sandbox: last 32 KB, control characters removed, for display only.
    private static string Tail(FileStream output)
    {
        output.Flush();
        long length = output.Length;
        byte[] buffer = new byte[(int)Math.Min(length, 32 * 1024)];
        output.Seek(length - buffer.Length, SeekOrigin.Begin);
        output.ReadExactly(buffer);
        string text = System.Text.Encoding.UTF8.GetString(buffer);
        return new string(text.Where(ch => ch == '\n' || !char.IsControl(ch)).ToArray());
    }

    private static string? LastLine(string text) =>
        text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .LastOrDefault(l => !l.StartsWith("at ", StringComparison.Ordinal)) is { } line ? (line.Length > 200 ? line[..200] + "…" : line) : null;

    private static string ExitText(int code) => code switch
    {
        -1 => "timed out",
        < 0 or > 255 => $"exit code 0x{code:X8}",
        _ => $"exit code {code}"
    };

    public static List<string> Properties(SessionDescriptor s, string trust, string temp, string game) =>
    ["-Dminecraft.api.env=custom", $"-Dminecraft.api.session.host=https://127.0.0.1:{s.HttpsPort}/session",
        // Older Authlib builds (1.16-1.18) also read auth/account hosts; everything there is refused by the vault.
        $"-Dminecraft.api.auth.host=https://127.0.0.1:{s.HttpsPort}/auth", $"-Dminecraft.api.account.host=https://127.0.0.1:{s.HttpsPort}/account",
        $"-Dminecraft.api.services.host=https://127.0.0.1:{s.HttpsPort}/services",
        $"-Dminecraft.api.profiles.host=https://127.0.0.1:{s.HttpsPort}/profiles",
        "-Djavax.net.ssl.trustStore=" + trust, "-Djavax.net.ssl.trustStoreType=JKS", "-Djavax.net.ssl.trustStorePassword=" + JavaTrustStore.Password,
        // Keep every write inside sandbox-writable folders.
        // (Natives/JNA/LWJGL extraction already point at the per-launch natives folder via the version's arguments.)
        "-XX:-UsePerfData", "-Djava.io.tmpdir=" + temp, "-Duser.home=" + game];

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

    // Windows needs USERPROFILE/LOCALAPPDATA to set up an AppContainer process, so these paths are passed (they are
    // only names; the sandbox can't open them).
    internal static Dictionary<string, string> SandboxEnvironment(string temp)
    {
        var environment = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (System.Collections.DictionaryEntry entry in Environment.GetEnvironmentVariables())
            if (entry.Key is string key && Inherited.Contains(key) && entry.Value is string value) environment[key] = value;
        environment["TEMP"] = temp; environment["TMP"] = temp;
        return environment;
    }
}
