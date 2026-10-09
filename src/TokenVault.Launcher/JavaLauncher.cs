using System.Diagnostics;
using System.Text.RegularExpressions;
using TokenVault.Core;

namespace TokenVault.Launcher;

public static class JavaLauncher
{
    public static async Task<int> LaunchAsync(Configuration c, SessionDescriptor session, CancellationToken ct)
    {
        if (session.MinecraftVersion != c.MinecraftVersion || session.ExpiresAt <= DateTimeOffset.UtcNow ||
            session.HttpsPort != c.HttpsPort || session.GamePort != c.GamePort)
            throw new InvalidDataException("Vault descriptor does not match configuration or has expired.");
        string javaVersion = await CaptureAsync(c.JavaPath, ["-version"], null, ct);
        if (!Regex.IsMatch(javaVersion, "version \"25(?:[.\"])", RegexOptions.CultureInvariant))
            throw new InvalidOperationException("Java 25 is required.");
        string temp = Path.Combine(Path.GetTempPath(), "TokenVault-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temp);
        try
        {
            string certificate = Path.Combine(temp, "vault.cer"), trust = Path.Combine(temp, "vault.jks");
            await File.WriteAllBytesAsync(certificate, Convert.FromBase64String(session.CertificateDer), ct);
            await CaptureAsync(c.KeytoolPath, ["-importcert", "-noprompt", "-alias", "vault", "-file", certificate,
                "-keystore", trust, "-storetype", "JKS", "-storepass", "changeit"], null, ct);
            var installed = InstalledFabric.Resolve(c, session, temp);
            var properties = Properties(c, session, trust);
            var probe = new List<string>(properties) { "--class-path", installed.ClassPath,
                Path.Combine(AppContext.BaseDirectory, "AuthlibProbe.java"), $"https://127.0.0.1:{session.HttpsPort}" };
            string output = await CaptureAsync(c.JavaPath, probe, session.FakeToken, ct);
            if (!output.Contains("AUTHLIB_PROBE_OK", StringComparison.Ordinal)) throw new InvalidOperationException("Authlib verification failed.");
            var info = ProcessInfo(c.JavaPath);
            info.WorkingDirectory = Configuration.Expand(c.GameDirectory);
            foreach (string argument in installed.JvmArguments) info.ArgumentList.Add(argument);
            foreach (string argument in properties) info.ArgumentList.Add(argument);
            info.ArgumentList.Add("-Xmx" + c.MemoryMb + "M");
            info.ArgumentList.Add("-Dfabric.modsFolder=" + Configuration.Expand(c.ModsDirectory));
            info.ArgumentList.Add(installed.MainClass);
            foreach (string argument in installed.GameArguments) info.ArgumentList.Add(argument);
            // No command-line logging, @argfiles, token files, or real-token environment inheritance.
            Console.WriteLine("Starting Fabric 26.1.2 through the local connection broker.");
            using var game = Process.Start(info) ?? throw new InvalidOperationException("Could not start Java.");
            try { await game.WaitForExitAsync(ct); return game.ExitCode; }
            finally { if (!game.HasExited) game.Kill(entireProcessTree: true); }
        }
        finally
        {
            try { Directory.Delete(temp, recursive: true); }
            catch (IOException) { Console.Error.WriteLine("Temporary public certificate/native files are still in use."); }
        }
    }

    public static List<string> Properties(Configuration c, SessionDescriptor s, string trust) =>
    ["-Dminecraft.api.env=custom", $"-Dminecraft.api.session.host=https://127.0.0.1:{s.HttpsPort}/session",
        $"-Dminecraft.api.services.host=https://127.0.0.1:{s.HttpsPort}/services",
        $"-Dminecraft.api.profiles.host=https://127.0.0.1:{s.HttpsPort}/profiles",
        "-Djavax.net.ssl.trustStore=" + trust, "-Djavax.net.ssl.trustStoreType=JKS", "-Djavax.net.ssl.trustStorePassword=changeit"];

    private static ProcessStartInfo ProcessInfo(string executable)
    {
        var info = new ProcessStartInfo(executable) { UseShellExecute = false };
        var keep = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        { "SystemRoot", "WINDIR", "SystemDrive", "PATH", "PATHEXT", "TEMP", "TMP", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "PROGRAMDATA",
            "ProgramFiles", "ProgramFiles(x86)", "CommonProgramFiles", "PROCESSOR_ARCHITECTURE", "NUMBER_OF_PROCESSORS", "USERNAME", "USERDOMAIN" };
        foreach (var key in info.Environment.Keys.ToArray()) if (!keep.Contains(key)) info.Environment.Remove(key);
        return info;
    }

    private static async Task<string> CaptureAsync(string executable, IEnumerable<string> args, string? input, CancellationToken ct)
    {
        var info = ProcessInfo(executable);
        info.RedirectStandardOutput = true; info.RedirectStandardError = true; info.RedirectStandardInput = input is not null;
        foreach (var arg in args) info.ArgumentList.Add(arg);
        using var process = Process.Start(info) ?? throw new InvalidOperationException("Failed to start prerequisite tool.");
        Task<string> stdout = process.StandardOutput.ReadToEndAsync(ct), stderr = process.StandardError.ReadToEndAsync(ct);
        if (input is not null) { await process.StandardInput.WriteLineAsync(input); process.StandardInput.Close(); }
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromSeconds(60));
        try { await process.WaitForExitAsync(timeout.Token); }
        finally { if (!process.HasExited) process.Kill(entireProcessTree: true); }
        string result = await stdout + await stderr;
        if (process.ExitCode != 0) throw new InvalidOperationException("Java/keytool/Authlib prerequisite failed. Check Java 25, paths, and the running vault.");
        return result; // Never echoed: JVM diagnostics could contain its fake token.
    }
}
