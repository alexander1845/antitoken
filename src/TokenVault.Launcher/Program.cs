using TokenVault.Core;
using TokenVault.Launcher;

if (!OperatingSystem.IsWindows()) { Console.Error.WriteLine("The launcher requires Windows x64."); return 2; }
try
{
    if (args.Length != 2 || args[0] != "launch") throw new ArgumentException("Usage: TokenVault.Launcher launch <config.json>");
    var config = Configuration.Load(args[1]);
    using var cancel = new CancellationTokenSource();
    Console.CancelKeyPress += (_, e) => { e.Cancel = true; cancel.Cancel(); };
    var session = await SessionPipe.ReadAsync(config, cancel.Token);
    return await JavaLauncher.LaunchAsync(config, session, cancel.Token);
}
catch (Exception ex)
{
    // Launcher holds only the fake credential. Still do not dump diagnostics with args.
    Console.Error.WriteLine($"Launch refused ({ex.GetType().Name}). Verify installed Fabric, Java 25, configuration, and vault identity.");
    return 1;
}
