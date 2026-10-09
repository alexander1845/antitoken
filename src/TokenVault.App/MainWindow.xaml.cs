using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using Microsoft.Identity.Client;
using Microsoft.Win32;
using TokenVault.Core;
using TokenVault.Launcher;
using TokenVault.Packs;
using TokenVault.Vault;

namespace TokenVault.App;

public partial class MainWindow : Window
{
    private Configuration settings = new();
    private List<Instance> instances = [];
    private MinecraftIdentity? identity;
    private GameSandbox? sandbox;
    private CancellationTokenSource? running;
    private bool busy;
    private Uri? codePage;

    public MainWindow()
    {
        InitializeComponent();
        SourceInitialized += (_, _) => App.MatchTitleBar(this);
        Loaded += (_, _) => Initialize();
        Closing += OnClosing;
        DragOver += (_, e) => { e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop) && !busy ? DragDropEffects.Copy : DragDropEffects.None; e.Handled = true; };
        Drop += async (_, e) => { if (e.Data.GetData(DataFormats.FileDrop) is string[] files) await ImportAsync(files); };
        ServerAddress.TextChanged += (_, _) => ServerHint.Visibility = ServerAddress.Text.Length == 0 ? Visibility.Visible : Visibility.Collapsed;
        LimitsText.Text =
            "•  A bad mod can still act inside the game while you play: chat, move or drop items, disconnect you.\n" +
            "•  Programs running outside the sandbox on your PC (malware) can read anything you can.\n" +
            "•  Playing these mods in another launcher removes this protection.\n" +
            "•  A mod can show a fake login screen. Token Vault never asks for your password inside the game.";
    }

    private Instance? Selected => (Library.SelectedItem as LibraryRow)?.Instance;

    private void Initialize()
    {
        try
        {
            PrivateDirectory.Ensure(AppPaths.Data);
            try { settings = Configuration.LoadOrDefault(AppPaths.Config); }
            catch (Exception ex) when (ex is InvalidDataException or System.Text.Json.JsonException) { Log("Settings were unreadable; using defaults."); }
            instances = InstanceStore.Load();
            InstanceStore.Save(instances);
            try { JavaLauncher.CleanStaleRuns(); } catch (IOException) { }
            try { sandbox = GameSandbox.Open(); } catch (Exception ex) { Log("Sandbox: " + Describe(ex)); }
        }
        catch (Exception ex) { Error(ex); }
        RefreshLibrary(settings.SelectedInstance);
        RefreshServers();
        RefreshProtection();
        RefreshAccount();
        SetBusy(false);
    }

    // ===================== Play =====================

    private async void Play_Click(object sender, RoutedEventArgs e)
    {
        if (running is not null) { running.Cancel(); return; }
        if (Selected is not { } instance || busy) return;
        if (sandbox is null) { Error("The Windows sandbox is unavailable, so Token Vault won't start the game."); return; }
        using var cts = new CancellationTokenSource();
        running = cts;
        SetBusy(true);
        PlayButton.Content = "Stop";
        PlayButton.IsEnabled = true;
        try
        {
            if (sandbox.HasLoopbackExemption() == false && !await ApproveNetworkingAsync(ask: true)) { Status("Play needs the one-time approval."); return; }

            var progress = new Progress<InstallProgress>(p => Status(p.Stage, p.Fraction));
            Status("Checking game files…", 0);
            using var http = GameInstaller.CreateHttp();
            string profile = await new GameInstaller(http).EnsureAsync(settings, instance.LoaderVersion, progress, cts.Token);
            if (instance.LoaderVersion is null)
            {
                instance.LoaderVersion = profile["fabric-loader-".Length..^("-" + settings.MinecraftVersion).Length];
                InstanceStore.Save(instances);
            }

            var account = await EnsureSignedInAsync(cts.Token);
            InstanceStore.CreateFolder(instance);
            var launch = instance.Apply(settings, profile);
            await using var session = await VaultSession.StartAsync(launch, account, AppPaths.AuditLog, cts.Token);
            Status($"Playing as {account.Profile.Name}.", null);
            int code = await JavaLauncher.LaunchAsync(launch, session.Descriptor, sandbox, Log, cts.Token);
            Status(code == 0 ? "Ready to play." : $"Minecraft closed unexpectedly (code {code}). Its log is in the instance folder under logs.", null,
                code == 0 ? null : "Bad");
        }
        catch (OperationCanceledException) when (cts.IsCancellationRequested) { Status("Game stopped."); }
        catch (Exception ex) { Error(ex); }
        finally
        {
            running = null;
            CodePanel.Visibility = Visibility.Collapsed;
            PlayButton.Content = "Play";
            SetBusy(false);
            RefreshAccount();
            RefreshLibrary(instance.Id);
        }
    }

    private async Task<bool> ApproveNetworkingAsync(bool ask)
    {
        if (sandbox is null) return false;
        if (ask && MessageBox.Show(this,
                "Minecraft runs in a Windows sandbox, which can't reach Token Vault on this PC until Windows allows it.\n\n" +
                "Windows will ask for administrator approval once. Only this sandbox is allowed to connect to this PC " +
                "(127.0.0.1). No other setting changes and no account is created.",
                "One-time approval", MessageBoxButton.OKCancel, MessageBoxImage.Information) != MessageBoxResult.OK)
            return false;
        bool ok = await sandbox.RequestLoopbackExemptionAsync();
        Log(ok ? "Sandbox networking approved." : "Sandbox networking was not approved.");
        RefreshProtection();
        return ok;
    }

    // ===================== Account =====================

    private async Task<MinecraftIdentity> EnsureSignedInAsync(CancellationToken ct)
    {
        if (identity is { } current && current.ExpiresAt > DateTimeOffset.UtcNow.AddMinutes(15)) return current;
        identity?.Dispose();
        identity = null;
        var cache = new RefreshCache(AppPaths.RefreshCache);
        if (!settings.RememberSignIn && cache.Exists) cache.Delete();
        // Sign-in only happens while no game runs, so no mod is alive during the browser flow.
        var options = new SignInOptions
        {
            UseDeviceCode = settings.UseDeviceCode,
            Progress = new Progress<string>(message => Status(message)),
            ShowDeviceCode = (code, page) => Dispatcher.InvokeAsync(() =>
            {
                codePage = page;
                CodeText.Text = code;
                CodeUrl.Text = page.Host + page.AbsolutePath.TrimEnd('/');
                CodePanel.Visibility = Visibility.Visible;
                Status("Waiting for you to enter the code…");
            }).Task
        };
        try { identity = await OAuthLogin.LoginAsync(settings, settings.RememberSignIn ? cache.Attach : null, ct, options); }
        finally { await Dispatcher.InvokeAsync(() => CodePanel.Visibility = Visibility.Collapsed); }
        Log($"Signed in as {identity.Profile.Name}.");
        RefreshAccount();
        return identity;
    }

    private async void SignIn_Click(object sender, RoutedEventArgs e)
    {
        if (busy) return;
        using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(15));
        SetBusy(true);
        try { await EnsureSignedInAsync(cts.Token); Status("Signed in."); }
        catch (Exception ex) { Error(ex); }
        finally { SetBusy(false); RefreshAccount(); }
    }

    private void SignOut_Click(object sender, RoutedEventArgs e)
    {
        identity?.Dispose();
        identity = null;
        try { new RefreshCache(AppPaths.RefreshCache).Delete(); } catch (Exception ex) { Error(ex); }
        Status("Signed out on this PC.");
        Log("Signed out. To revoke access at Microsoft too, visit account.live.com/consent/Manage.");
        RefreshAccount();
    }

    private void RefreshAccount()
    {
        bool saved = File.Exists(AppPaths.RefreshCache);
        AccountName.Text = identity?.Profile.Name ?? (saved ? "Saved sign-in" : "Not signed in");
        AccountDetail.Text = identity is not null ? "Signed in. Your tokens stay in Token Vault."
            : saved ? "Used automatically when you press Play."
            : "You'll sign in with Microsoft when you press Play.";
        SignInButton.Visibility = identity is null ? Visibility.Visible : Visibility.Collapsed;
        SignOutButton.Visibility = identity is not null || saved ? Visibility.Visible : Visibility.Collapsed;
        SignOutButton.Margin = new Thickness(SignInButton.Visibility == Visibility.Visible ? 18 : 0, 0, 0, 0);
    }

    private void OpenCodePage_Click(object sender, RoutedEventArgs e)
    {
        try { Clipboard.SetText(CodeText.Text); } catch (System.Runtime.InteropServices.COMException) { }
        if (codePage is not null) Open(codePage.AbsoluteUri);
    }

    // ===================== Library & import =====================

    private void RefreshLibrary(string? select = null)
    {
        string? id = select ?? Selected?.Id;
        var rows = instances.Select(i => new LibraryRow(i)).ToList();
        Library.ItemsSource = rows;
        Library.SelectedItem = rows.FirstOrDefault(r => r.Instance.Id == id) ?? rows.FirstOrDefault();
        RefreshInstance();
    }

    private void Library_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (Selected is { } instance && settings.SelectedInstance != instance.Id)
        {
            settings.SelectedInstance = instance.Id;
            TrySaveSettings();
        }
        RefreshInstance();
    }

    private void RefreshInstance()
    {
        if (Selected is not { } instance) return;
        InstanceTitle.Text = instance.Name;
        int mods = instance.CountMods();
        InstanceDetail.Text = string.Join("  ·  ", new[]
        {
            "Minecraft " + settings.MinecraftVersion,
            "Fabric " + (instance.LoaderVersion ?? "(latest)"),
            mods == 1 ? "1 mod" : $"{mods} mods",
            instance.Source == "New" ? null : "from " + instance.Source
        }.Where(s => s is not null));
        MissingPanel.Visibility = instance.Missing.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        MissingTitle.Text = instance.Missing.Count == 1 ? "1 file needs to be downloaded by hand" : $"{instance.Missing.Count} files need to be downloaded by hand";
        MissingList.ItemsSource = instance.Missing;
    }

    private async void Import_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Title = "Import a modpack or mods", Filter = PackImporter.Filter, Multiselect = true };
        if (dialog.ShowDialog(this) == true) await ImportAsync(dialog.FileNames);
    }

    private async void AddMods_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Title = "Add mods to " + Selected?.Name, Filter = "Mods (*.jar)|*.jar", Multiselect = true };
        if (dialog.ShowDialog(this) == true) await ImportAsync(dialog.FileNames);
    }

    // .jar files go into the selected instance; anything else becomes a new instance.
    private async Task ImportAsync(string[] paths)
    {
        if (busy) { Status("Close the game before importing."); return; }
        SetBusy(true);
        try
        {
            var jars = paths.Where(p => File.Exists(p) && PackImporter.IsModFile(p)).ToList();
            if (jars.Count > 0 && Selected is { } target)
            {
                InstanceStore.CreateFolder(target);
                PackImporter.AddMods(target, jars);
                Status(jars.Count == 1 ? $"Added {Path.GetFileName(jars[0])}." : $"Added {jars.Count} mods to {target.Name}.");
            }
            using var http = PackImporter.CreateHttp();
            var importer = new PackImporter(http);
            foreach (string path in paths.Except(jars))
            {
                var progress = new Progress<InstallProgress>(p => Status(p.Stage, p.Fraction));
                var instance = await importer.ImportAsync(path, progress, CancellationToken.None);
                instances.Add(instance);
                InstanceStore.Save(instances);
                RefreshLibrary(instance.Id);
                Status(instance.Missing.Count == 0 ? $"Imported {instance.Name}. Press Play when you're ready."
                    : $"Imported {instance.Name}, but some files must be downloaded by hand (see below).", null,
                    instance.Missing.Count == 0 ? null : "Warn");
            }
        }
        catch (Exception ex) { Error(ex); }
        finally { SetBusy(false); RefreshLibrary(); }
    }

    private void Remove_Click(object sender, RoutedEventArgs e)
    {
        if (Selected is not { } instance || busy) return;
        if (MessageBox.Show(this, $"Remove \"{instance.Name}\"?\n\nIts worlds, mods and settings will be deleted from this PC.",
                "Remove", MessageBoxButton.OKCancel, MessageBoxImage.Warning) != MessageBoxResult.OK) return;
        try { InstanceStore.DeleteFolder(instance); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { Error("Some files are in use. Close the game and try again."); return; }
        instances.Remove(instance);
        if (instances.Count == 0) instances = InstanceStore.Load(); // recreates a default instance
        InstanceStore.Save(instances);
        RefreshLibrary();
        Status($"Removed {instance.Name}.");
    }

    private void OpenFolder_Click(object sender, RoutedEventArgs e)
    {
        if (Selected is not { } instance) return;
        InstanceStore.CreateFolder(instance);
        Open(instance.Directory);
    }

    private void MissingDone_Click(object sender, RoutedEventArgs e)
    {
        if (Selected is not { } instance) return;
        instance.Missing.Clear();
        InstanceStore.Save(instances);
        RefreshInstance();
    }

    private void MissingLink_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string page } && Uri.TryCreate(page, UriKind.Absolute, out var uri) &&
            uri.Scheme == "https" && uri.Host == "www.curseforge.com")
            Open(uri.AbsoluteUri);
    }

    // ===================== Servers =====================

    private void RefreshServers()
    {
        ServerList.ItemsSource = settings.Servers.Select(s => new ServerRow(s)).ToList();
        NoServers.Visibility = settings.Servers.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private void AddServer_Click(object sender, RoutedEventArgs e) => AddServer();
    private void ServerAddress_KeyDown(object sender, KeyEventArgs e) { if (e.Key == Key.Enter) { AddServer(); e.Handled = true; } }

    private void AddServer()
    {
        try
        {
            var entry = ServerEntry.Parse(ServerAddress.Text);
            if (!settings.Servers.Any(s => s.Host == entry.Host && s.Port == entry.Port)) settings.Servers.Add(entry);
            settings.Save(AppPaths.Config);
            ServerAddress.Text = "";
            RefreshServers();
            Status(running is null ? $"Added {entry.Host}." : $"Added {entry.Host}. It appears in the game next time you press Play.");
        }
        catch (Exception ex) { Error(ex); }
    }

    private void RemoveServer_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: ServerEntry entry }) return;
        settings.Servers.Remove(entry);
        TrySaveSettings();
        RefreshServers();
    }

    // ===================== Protection =====================

    private void RefreshProtection()
    {
        bool? network = sandbox?.HasLoopbackExemption();
        var rows = new List<ProtectionRow>
        {
            Ok("account", "Your sign-in stays in Token Vault",
                "Minecraft only gets a stand-in token that Mojang rejects. Your Microsoft and Minecraft tokens never enter the game."),
            sandbox is null
                ? Bad("sandbox", "Sandbox unavailable", "Windows couldn't create the sandbox, so Token Vault won't start the game.")
                : Ok("sandbox", "Mods are sandboxed",
                    "The game runs in a Windows sandbox. Mods can't open your files, browsers, other launchers or Token Vault itself."),
            Ok("servers", "Signs in only to your servers",
                "Token Vault joins servers itself, and only the ones listed above. The game can't use your account anywhere else."),
            settings.AllowClipboard
                ? Warn("clipboard", "Clipboard is shared with the game", "Copy and paste work in the game, so mods could read what you copy.", "Make private")
                : Ok("clipboard", "Clipboard is private", "Mods can't read what you copy, like passwords. Copy and paste in the game is off.", "Allow copy & paste"),
            network switch
            {
                true => Ok("network", "Sandbox networking approved", "The game can reach Token Vault on this PC. Nothing else was changed."),
                false => Warn("network", "One-time approval needed",
                    "The first time you play, Windows asks an administrator to let the sandbox reach Token Vault on this PC.", "Approve now"),
                null => Warn("network", "Sandbox networking unknown", "If the game can't connect, approve it again.", "Approve"),
            }
        };
        if (settings.ClientId.Length == 0)
            rows.Add(new("signin", "i", Brush("Secondary"), "Sign-in uses Prism Launcher's public app ID",
                $"Microsoft's sign-in page will say \"{AuthenticationDefaults.BuiltInClientName}\". Token Vault borrows its public ID so you don't have to register an app. Your password only ever goes to Microsoft.",
                "Use my own"));
        ProtectionList.ItemsSource = rows;

        ProtectionRow Ok(string key, string title, string detail, string? action = null) => new(key, "✓", Brush("Good"), title, detail, action);
        ProtectionRow Warn(string key, string title, string detail, string? action = null) => new(key, "!", Brush("Warn"), title, detail, action);
        ProtectionRow Bad(string key, string title, string detail) => new(key, "✕", Brush("Bad"), title, detail, null);
    }

    private async void ProtectionAction_Click(object sender, RoutedEventArgs e)
    {
        switch ((sender as Button)?.Tag as string)
        {
            case "clipboard":
                if (running is not null) { Status("Change this when the game is closed."); return; }
                settings.AllowClipboard = !settings.AllowClipboard;
                TrySaveSettings();
                RefreshProtection();
                break;
            case "network":
                if (!busy) await ApproveNetworkingAsync(ask: true);
                break;
            case "signin":
                Settings_Click(sender, e);
                ClientIdBox.Focus();
                break;
        }
    }

    private void LimitsToggle_Click(object sender, RoutedEventArgs e) =>
        LimitsText.Visibility = LimitsText.Visibility == Visibility.Visible ? Visibility.Collapsed : Visibility.Visible;

    private void ActivityToggle_Click(object sender, RoutedEventArgs e)
    {
        bool show = ActivityLog.Visibility != Visibility.Visible;
        ActivityLog.Visibility = show ? Visibility.Visible : Visibility.Collapsed;
        ActivityToggle.Content = show ? "Hide activity" : "Show activity";
    }

    // ===================== Settings =====================

    private void Settings_Click(object sender, RoutedEventArgs e)
    {
        MemoryBox.Text = settings.MemoryMb.ToString(System.Globalization.CultureInfo.InvariantCulture);
        JavaBox.Text = settings.JavaPath;
        RememberBox.IsChecked = settings.RememberSignIn;
        DeviceCodeBox.IsChecked = settings.UseDeviceCode;
        ClientIdBox.Text = settings.ClientId;
        ClientIdHint.Text = $"Leave empty to use the built-in one ({AuthenticationDefaults.BuiltInClientName}'s public ID). If you publish Token Vault, register your own.";
        HomePage.Visibility = Visibility.Collapsed;
        SettingsPage.Visibility = Visibility.Visible;
    }

    private void SettingsDone_Click(object sender, RoutedEventArgs e)
    {
        var next = settings.Clone();
        next.JavaPath = JavaBox.Text.Trim();
        next.RememberSignIn = RememberBox.IsChecked == true;
        next.UseDeviceCode = DeviceCodeBox.IsChecked == true;
        next.ClientId = ClientIdBox.Text.Trim();
        if (!int.TryParse(MemoryBox.Text, out int memory) || memory is < 512 or > 65536)
        { MessageBox.Show(this, "Memory must be between 512 and 65536 MB.", "Settings"); return; }
        next.MemoryMb = memory;
        try { next.Save(AppPaths.Config); }
        catch (InvalidDataException ex) { MessageBox.Show(this, ex.Message, "Settings"); return; }
        if (next.ClientId != settings.ClientId) { identity?.Dispose(); identity = null; } // different app: sign in again
        settings = next;
        SettingsCancel_Click(sender, e);
        RefreshProtection();
        RefreshAccount();
    }

    private void SettingsCancel_Click(object sender, RoutedEventArgs e)
    {
        SettingsPage.Visibility = Visibility.Collapsed;
        HomePage.Visibility = Visibility.Visible;
    }

    private void BrowseJava_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Title = "Choose java.exe (Java 25)", Filter = "java.exe|java.exe" };
        if (dialog.ShowDialog(this) == true) JavaBox.Text = dialog.FileName;
    }

    private void OpenInstall_Click(object sender, RoutedEventArgs e) => Open(Directory.CreateDirectory(Configuration.Expand(settings.MinecraftDirectory)).FullName);
    private void OpenData_Click(object sender, RoutedEventArgs e) => Open(AppPaths.Data);

    private void TrySaveSettings()
    {
        try { settings.Save(AppPaths.Config); } catch (Exception ex) { Error(ex); }
    }

    // ===================== Shell =====================

    private void OnClosing(object? sender, System.ComponentModel.CancelEventArgs e)
    {
        if (running is null) return;
        if (MessageBox.Show(this, "Closing Token Vault also closes Minecraft.", "Token Vault", MessageBoxButton.OKCancel, MessageBoxImage.Question) != MessageBoxResult.OK)
        { e.Cancel = true; return; }
        running.Cancel(); // the job object also ends the game when this process exits
    }

    private void SetBusy(bool value)
    {
        busy = value;
        bool idle = !value;
        PlayButton.IsEnabled = running is not null || (idle && sandbox is not null);
        ImportButton.IsEnabled = idle;
        AddModsButton.IsEnabled = idle;
        RemoveButton.IsEnabled = idle;
        Library.IsEnabled = idle;
        SignInButton.IsEnabled = idle;
        SignOutButton.IsEnabled = idle;
        SettingsButton.IsEnabled = idle;
        if (idle) Progress.Visibility = Visibility.Hidden;
    }

    private void Status(string text, double? fraction = null, string? tone = null)
    {
        if (!Dispatcher.CheckAccess()) { Dispatcher.BeginInvoke(() => Status(text, fraction, tone)); return; }
        StatusText.Text = text;
        StatusText.Foreground = tone is null ? Brush("Secondary") : Brush(tone);
        Progress.Visibility = fraction is null ? Visibility.Hidden : Visibility.Visible;
        if (fraction is double f) Progress.Value = Math.Clamp(f, 0, 1);
        Log(text);
    }

    private void Log(string text)
    {
        if (!Dispatcher.CheckAccess()) { Dispatcher.BeginInvoke(() => Log(text)); return; }
        if (ActivityLog.LineCount > 2000) ActivityLog.Clear();
        ActivityLog.AppendText($"{DateTime.Now:HH:mm:ss}  {text}{Environment.NewLine}");
        ActivityLog.ScrollToEnd();
    }

    private void Error(Exception ex) => Error(Describe(ex));
    private void Error(string message) => Status(message, null, "Bad");

    // Never shows arbitrary exception text: library messages can contain account details or request data.
    private static string Describe(Exception ex) => ex switch
    {
        UserVisibleException or InvalidDataException or FileNotFoundException or DirectoryNotFoundException => ex.Message,
        MsalException { ErrorCode: "authentication_canceled" or "access_denied" or "authorization_declined" } => "Sign-in was canceled.",
        MsalException { ErrorCode: "code_expired" or "expired_token" } => "The sign-in code expired. Press Play to get a new one.",
        MsalException { ErrorCode: "invalid_client" or "unauthorized_client" } =>
            "Microsoft rejected the application ID. Clear it in Settings to use the built-in one, or check your registration.",
        MsalException msal => $"Microsoft sign-in didn't finish ({msal.ErrorCode}). Try again, or turn on code sign-in in Settings.",
        System.Net.Sockets.SocketException { SocketErrorCode: System.Net.Sockets.SocketError.AddressAlreadyInUse } or
            IOException { InnerException: Microsoft.AspNetCore.Connections.AddressInUseException } =>
            "Another program is using Token Vault's local ports (25597/25599). Close it and try again.",
        System.Net.Http.HttpRequestException => "Couldn't reach the internet service. Check your connection and try again.",
        UnauthorizedAccessException => "Windows denied access to a file Token Vault needs.",
        _ => $"Something went wrong ({ex.GetType().Name})."
    };

    private Brush Brush(string key) => (Brush)FindResource(key);

    private static void Open(string target)
    {
        try { Process.Start(new ProcessStartInfo(target) { UseShellExecute = true })?.Dispose(); }
        catch (System.ComponentModel.Win32Exception) { }
    }
}

public sealed record LibraryRow(Instance Instance)
{
    public string Name => Instance.Name;
    public string Summary
    {
        get
        {
            int mods = Instance.CountMods();
            string count = mods == 1 ? "1 mod" : $"{mods} mods";
            return Instance.Source == "New" ? count : $"{count} · {Instance.Source}";
        }
    }
}

public sealed record ServerRow(ServerEntry Entry)
{
    public string Name => Entry.Name;
    public string Address => Entry.Port == 25565 ? Entry.Host : $"{Entry.Host}:{Entry.Port}";
}

public sealed record ProtectionRow(string Key, string Glyph, Brush Color, string Title, string Detail, string? Action)
{
    public Visibility ActionVisibility => Action is null ? Visibility.Collapsed : Visibility.Visible;
}
