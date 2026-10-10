using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using Microsoft.Win32;

namespace TokenVault.App;

public partial class App : Application
{
    private Mutex? single;
    public const string AfterUpdate = "--after-update";

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        // One vault per Windows session: the local ports and the sandbox profile are shared.
        single = new Mutex(initiallyOwned: true, @"Local\TokenVault.App", out bool first);
        // Restarted by the updater: the previous copy is still closing, so wait for it instead of refusing to start.
        if (!first && e.Args.Contains(AfterUpdate))
        {
            try { first = single.WaitOne(TimeSpan.FromSeconds(20)); }
            catch (AbandonedMutexException) { first = true; }
        }
        if (!first)
        {
            MessageBox.Show("Token Vault is already open.", "Token Vault", MessageBoxButton.OK, MessageBoxImage.Information);
            Shutdown(1);
            return;
        }
        // Anything unexpected is written to a crash log (no account data: only the exception type and code locations)
        // and explained to the player, instead of the window just vanishing.
        DispatcherUnhandledException += (_, args) =>
        {
            ReportCrash(args.Exception);
            args.Handled = true;
            Shutdown(2);
        };
        if (IsDarkMode()) ApplyDarkPalette();
        new MainWindow().Show();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        single?.Dispose();
        base.OnExit(e);
    }

    private static void ReportCrash(Exception ex)
    {
        try
        {
            string path = System.IO.Path.Combine(TokenVault.Core.AppPaths.Data, "crash.log");
            System.IO.Directory.CreateDirectory(TokenVault.Core.AppPaths.Data);
            var lines = new List<string> { $"{DateTimeOffset.UtcNow:O} Token Vault {TokenVault.Vault.BuildInfo.Version}" };
            for (var e = ex; e is not null; e = e.InnerException)
                lines.Add(e.GetType().FullName + (e is System.Windows.Markup.XamlParseException ? ": " + e.Message : "") + Environment.NewLine + e.StackTrace);
            System.IO.File.AppendAllLines(path, lines);
        }
        catch (Exception) { }
        MessageBox.Show("Token Vault ran into an unexpected problem and has to close. Details were saved to crash.log in its data folder.",
            "Token Vault", MessageBoxButton.OK, MessageBoxImage.Error);
    }

    public static bool IsDarkMode()
    {
        using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
        return key?.GetValue("AppsUseLightTheme") is int light && light == 0;
    }

    // Theme colours live in Themes/Light.xaml and Themes/Dark.xaml; styles reference them dynamically.
    private void ApplyDarkPalette() =>
        Resources.MergedDictionaries[0] = new ResourceDictionary { Source = new Uri("Themes/Dark.xaml", UriKind.Relative) };

    // Dark title bar to match (Windows 10 2004+ / 11). Purely cosmetic.
    public static void MatchTitleBar(Window window)
    {
        if (!IsDarkMode()) return;
        int dark = 1;
        _ = DwmSetWindowAttribute(new WindowInteropHelper(window).EnsureHandle(), 20, ref dark, sizeof(int));
    }

    // Windows 11: round the window's corners like other modern apps (ignored on Windows 10).
    public static void RoundCorners(Window window)
    {
        int round = 2; // DWMWCP_ROUND
        _ = DwmSetWindowAttribute(new WindowInteropHelper(window).EnsureHandle(), 33, ref round, sizeof(int));
    }

    [DllImport("dwmapi.dll")] private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);
}
