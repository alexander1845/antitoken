using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using Microsoft.Win32;

namespace TokenVault.App;

public partial class App : Application
{
    private Mutex? single;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        // One vault per Windows session: the local ports and the sandbox profile are shared.
        single = new Mutex(initiallyOwned: true, @"Local\TokenVault.App", out bool first);
        if (!first)
        {
            MessageBox.Show("Token Vault is already open.", "Token Vault", MessageBoxButton.OK, MessageBoxImage.Information);
            Shutdown(1);
            return;
        }
        if (IsDarkMode()) ApplyDarkPalette();
        new MainWindow().Show();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        single?.Dispose();
        base.OnExit(e);
    }

    public static bool IsDarkMode()
    {
        using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
        return key?.GetValue("AppsUseLightTheme") is int light && light == 0;
    }

    private void ApplyDarkPalette()
    {
        void Set(string key, string color) => Resources[key] = new SolidColorBrush((Color)ColorConverter.ConvertFromString(color));
        Set("Bg", "#1C1C1E"); Set("Sidebar", "#161618"); Set("Hover", "#2A2A2D"); Set("Selected", "#323236");
        Set("Line", "#38383C"); Set("Text", "#F2F2F4"); Set("Secondary", "#9A9AA0");
        Set("Accent", "#3D8BFF"); Set("AccentHover", "#5C9DFF"); Set("OnAccent", "#FFFFFF");
        Set("Good", "#3CCB65"); Set("Warn", "#FFA53A"); Set("Bad", "#FF5A55");
    }

    // Dark title bar to match (Windows 10 2004+ / 11). Purely cosmetic.
    public static void MatchTitleBar(Window window)
    {
        if (!IsDarkMode()) return;
        int dark = 1;
        _ = DwmSetWindowAttribute(new WindowInteropHelper(window).EnsureHandle(), 20, ref dark, sizeof(int));
    }

    [DllImport("dwmapi.dll")] private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);
}
