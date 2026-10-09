namespace TokenVault.App;

internal static class Program
{
    [STAThread]
    private static int Main()
    {
        ApplicationConfiguration.Initialize();
        if (!OperatingSystem.IsWindowsVersionAtLeast(10))
        {
            MessageBox.Show("Token Vault needs Windows 10 or 11.", "Token Vault", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 2;
        }
        // One vault per Windows session: the local ports and the sandbox profile are shared.
        using var single = new Mutex(initiallyOwned: true, @"Local\TokenVault.App", out bool first);
        if (!first)
        {
            MessageBox.Show("Token Vault is already running.", "Token Vault", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return 1;
        }
        Application.Run(new MainForm());
        return 0;
    }
}
