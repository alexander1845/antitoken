using TokenVault.Core;
using TokenVault.Vault;

if (!OperatingSystem.IsWindows())
{
    Console.Error.WriteLine("The vault requires Windows. Portable security tests run in TokenVault.Tests.");
    return 2;
}
try
{
    if (args.Length != 2 || args[0] is not ("auth" or "host" or "dev"))
        throw new ArgumentException("Usage: TokenVault.Vault auth|host|dev <config.json>");
    var config = Configuration.Load(args[1]);
    if (args[0] == "dev" && config.HardeningMode != "same-user-development")
        throw new UserVisibleException("The combined dev command requires explicit same-user-development mode. Use separate host/launcher processes in isolated mode.");
    Isolation.Verify(config, args[1]);
    using var cancel = new CancellationTokenSource();
    Console.CancelKeyPress += (_, e) => { e.Cancel = true; cancel.Cancel(); };
    var cache = new RefreshCache(Path.Combine(Configuration.Expand(config.DataDirectory), "vault.bin"));
    using var identity = await OAuthLogin.LoginAsync(config, cache.Attach, cancel.Token);
    Console.WriteLine($"Authenticated: {identity.Profile.Name} ({identity.Profile.Id}). Tokens are never printed.");
    if (args[0] == "host") await VaultHost.RunAsync(config, identity, cancel.Token);
    if (args[0] == "dev")
    {
        Task hosting = VaultHost.RunAsync(config, identity, cancel.Token);
        try
        {
            var descriptor = await TokenVault.Launcher.SessionPipe.ReadAsync(config, cancel.Token);
            return await TokenVault.Launcher.JavaLauncher.LaunchAsync(config, descriptor, cancel.Token);
        }
        finally
        {
            cancel.Cancel();
            try { await hosting; } catch (OperationCanceledException) { }
        }
    }
    return 0;
}
catch (UserVisibleException ex)
{
    Console.Error.WriteLine(ex.Message);
    return 1;
}
catch (Exception ex)
{
    // Never print arbitrary exception messages, stacks, HTTP bodies, or MSAL PII.
    Console.Error.WriteLine($"Operation failed ({ex.GetType().Name}). Check configuration, connectivity, app approval and account permissions.");
    return 1;
}
