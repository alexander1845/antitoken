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
    private CancellationTokenSource? signIn;
    private bool busy, closeConfirmed;
    private TaskCompletionSource<bool>? dialog;
    private Uri? codePage;
    private int modsVersion;
    private int unseenBlocks;
    private readonly List<ActivityItem> activity = [];

    public MainWindow()
    {
        InitializeComponent();
        SourceInitialized += (_, _) => App.MatchTitleBar(this);
        Loaded += (_, _) => Initialize();
        Closing += OnClosing;
        PreviewKeyDown += (_, e) => { if (e.Key == Key.Escape && Overlay.Visibility == Visibility.Visible) { DialogSecondary_Click(this, e); e.Handled = true; } };
        DragOver += (_, e) => { e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop) && !busy ? DragDropEffects.Copy : DragDropEffects.None; e.Handled = true; };
        Drop += async (_, e) => { if (e.Data.GetData(DataFormats.FileDrop) is string[] files) await ImportAsync(files); };
        ServerAddress.TextChanged += (_, _) => ServerHint.Visibility = ServerAddress.Text.Length == 0 ? Visibility.Visible : Visibility.Collapsed;
        LimitsList.ItemsSource = new[]
        {
            new Limit("Actions inside the game", "A bad mod can still chat, move or drop items, or disconnect you while you play. It can't take your account with it."),
            new Limit("Malware outside the sandbox", "Programs already running on your PC as you (or as administrator) can read anything you can."),
            new Limit("Other launchers", "Playing these mods in another launcher removes this protection. Use Token Vault for modded play."),
            new Limit("Fake login screens", "A mod can draw a fake login screen. Token Vault never asks for your password inside the game.")
        };
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
            GameFolders.Ensure(sandbox?.Sid, Log); // also moves instances from older builds
        }
        catch (Exception ex) { Error(ex); }
        RefreshLibrary(settings.SelectedInstance);
        RefreshServers();
        RefreshSecurity();
        RefreshAccount();
        SetBusy(false);
        Status("Ready");
    }

    // ===================== Navigation =====================

    private void Nav_Checked(object sender, RoutedEventArgs e)
    {
        if (!IsInitialized) return;
        LibraryPage.Visibility = NavLibrary.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        ServersPage.Visibility = NavServers.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        SecurityPage.Visibility = NavSecurity.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        SettingsPage.Visibility = NavSettings.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        if (NavSettings.IsChecked == true) LoadSettingsPage();
        if (NavSecurity.IsChecked == true) { unseenBlocks = 0; RefreshSecurity(); }
    }

    private void Tab_Checked(object sender, RoutedEventArgs e)
    {
        if (!IsInitialized) return;
        bool mods = TabMods.IsChecked == true;
        ModsView.Visibility = mods ? Visibility.Visible : Visibility.Collapsed;
        ActivityLog.Visibility = mods ? Visibility.Collapsed : Visibility.Visible;
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
        SetPlayButton(stop: true);
        HideBanner();
        try
        {
            if (sandbox.IsSetUp() == false && !await ApproveSetupAsync()) { Status("Play needs the one-time approval."); return; }

            // Everything slow runs off the UI thread so the window stays responsive.
            var progress = new Progress<InstallProgress>(p => Status(p.Stage, p.Fraction));
            Status("Checking game files…", 0);
            using var http = GameInstaller.CreateHttp();
            var target = instance.Apply(settings);
            var box = sandbox;
            var installed = await Task.Run(() => new GameInstaller(http).EnsureAsync(target, instance.LoaderVersion, box, progress, cts.Token));
            if (instance.LoaderVersion is null && installed.LoaderVersion is not null)
            {
                instance.LoaderVersion = installed.LoaderVersion; // pin the loader build this instance was set up with
                InstanceStore.Save(instances);
            }

            var account = await EnsureSignedInAsync(cts.Token);
            InstanceStore.CreateFolder(instance);
            var launch = instance.Apply(settings, installed);
            string clientJar = Path.Combine(launch.MinecraftDirectory, "versions", launch.MinecraftVersion, launch.MinecraftVersion + ".jar");
            launch.Protocol = await Task.Run(() => InstalledVersion.Protocol(clientJar, launch.MinecraftVersion));
            await using var session = await Task.Run(() => VaultSession.StartAsync(launch, account, AppPaths.AuditLog, cts.Token, Observe, ApproveJoinAsync));
            Status($"Starting {instance.Name}…", tone: "Accent");
            var game = sandbox;
            int code = await Task.Run(() => JavaLauncher.LaunchAsync(launch, session.Descriptor, game, line =>
            {
                Log(line);
                if (line.StartsWith("Starting Minecraft", StringComparison.Ordinal)) Status($"Playing {instance.Name} as {account.Profile.Name}", tone: "Accent");
            }, cts.Token));
            if (code == 0) Status("Ready");
            else Error($"Minecraft closed unexpectedly (exit code {code}). Its log is in the instance folder under logs\\latest.log.");
        }
        catch (OperationCanceledException) when (cts.IsCancellationRequested) { Status("Game stopped"); }
        catch (Exception ex) { Error(ex); }
        finally
        {
            running = null;
            CloseDialog(false);
            SetPlayButton(stop: false);
            SetBusy(false);
            RefreshAccount();
            RefreshLibrary(instance.Id);
        }
    }

    private void SetPlayButton(bool stop)
    {
        PlayButton.Style = (Style)FindResource(stop ? typeof(Button) : "Primary");
        PlayLabel.Text = stop ? "Stop" : "Play";
        PlayIcon.Text = stop ? "\uE71A" : "\uE768";
        PlayButton.IsEnabled = stop || (!busy && sandbox is not null);
    }

    private async Task<bool> ApproveSetupAsync()
    {
        if (sandbox is null) return false;
        if (!await AskAsync("One-time sandbox setup",
                "Windows will ask for administrator approval once, for two small changes that only affect Token Vault's sandbox:\n\n" +
                "•  let it connect to Token Vault on this PC, and\n" +
                $"•  let it see the folder names at the top of {Path.GetPathRoot(AppPaths.GameRoot)} (names only, not files), which Java needs.\n\n" +
                "No account is created and nothing else changes.", "Continue"))
            return false;
        bool ok = await sandbox.RequestSetupAsync();
        Log(ok ? "Sandbox setup approved." : "Sandbox setup was not approved.");
        RefreshSecurity();
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
        using var cancel = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cancel.CancelAfter(TimeSpan.FromMinutes(15));
        signIn = cancel;
        // Sign-in only happens while no game runs, so no mod is alive during the browser flow.
        var options = new SignInOptions
        {
            UseDeviceCode = settings.UseDeviceCode,
            Progress = new Progress<string>(message => Status(message, tone: "Accent")),
            ShowDeviceCode = (code, page) => Dispatcher.InvokeAsync(() => ShowCode(code, page)).Task
        };
        try { identity = await OAuthLogin.LoginAsync(settings, settings.RememberSignIn ? cache.Attach : null, cancel.Token, options); }
        finally { signIn = null; await Dispatcher.InvokeAsync(() => CloseDialog(false)); }
        Log($"Signed in as {identity.Profile.Name}.");
        RefreshAccount();
        return identity;
    }

    private void ShowCode(string code, Uri page)
    {
        codePage = page;
        _ = OpenDialogAsync("Sign in with this code",
            $"Open {page.Host}{page.AbsolutePath.TrimEnd('/')}, enter the code below and choose your Microsoft account. This window continues on its own.",
            "Copy code and open Microsoft", "Cancel", code: code);
    }

    private async void SignIn_Click(object sender, RoutedEventArgs e)
    {
        if (busy) return;
        SetBusy(true);
        HideBanner();
        try { await EnsureSignedInAsync(CancellationToken.None); Status("Signed in"); }
        catch (OperationCanceledException) { Status("Sign-in canceled"); }
        catch (Exception ex) { Error(ex); }
        finally { SetBusy(false); RefreshAccount(); }
    }

    private async void SignOut_Click(object sender, RoutedEventArgs e)
    {
        if (busy || !await AskAsync("Sign out?", "Token Vault forgets your saved sign-in on this PC. You'll sign in with Microsoft again next time you play.", "Sign out"))
            return;
        identity?.Dispose();
        identity = null;
        try { new RefreshCache(AppPaths.RefreshCache).Delete(); } catch (Exception ex) { Error(ex); }
        Status("Signed out");
        Log("Signed out. To revoke access at Microsoft too, visit account.live.com/consent/Manage.");
        RefreshAccount();
        RefreshSecurity();
    }

    private void RefreshAccount()
    {
        bool saved = File.Exists(AppPaths.RefreshCache);
        string? name = identity?.Profile.Name;
        AccountName.Text = name ?? (saved ? "Saved account" : "Not signed in");
        AccountDetail.Text = name is not null ? "Signed in" : saved ? "Signs in when you play" : "Microsoft account";
        AccountTile.Background = name is null ? Brush("Selected") : Tiles.For(name);
        AccountInitial.Text = name is null ? "\uE77B" : name[..1].ToUpperInvariant();
        AccountInitial.FontFamily = name is null ? (FontFamily)FindResource("IconFont") : (FontFamily)FindResource("UiFont");
        AccountInitial.Foreground = name is null ? Brush("Secondary") : Brushes.White;
        SignInButton.Visibility = name is null ? Visibility.Visible : Visibility.Collapsed;
        SignOutButton.Visibility = name is not null || saved ? Visibility.Visible : Visibility.Collapsed;
        SignOutButton.Margin = new Thickness(SignInButton.Visibility == Visibility.Visible ? 14 : 0, 0, 0, 0);
        if (IsLoaded) RefreshSecurity();
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

    private async void RefreshInstance()
    {
        if (Selected is not { } instance) return;
        InstanceTitle.Text = instance.Name;
        InstanceInitial.Text = Tiles.Initial(instance.Name);
        InstanceTile.Background = Tiles.For(instance.Name);
        MissingPanel.Visibility = instance.Missing.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        MissingTitle.Text = instance.Missing.Count == 1 ? "1 file needs to be downloaded by hand" : $"{instance.Missing.Count} files need to be downloaded by hand";
        MissingList.ItemsSource = instance.Missing;

        int version = ++modsVersion;
        var mods = await Task.Run(() => ModInfo.List(instance.ModsDirectory));
        if (version != modsVersion) return; // a newer selection won
        ModList.ItemsSource = mods.Select(m => new ModRow(m, Path.Combine(instance.ModsDirectory, m.File))).ToList();
        ModsEmpty.Visibility = mods.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        ModCount.Text = mods.Count == 0 ? "" : "  " + mods.Count;
        InstanceFacts.ItemsSource = new[]
        {
            "Minecraft " + instance.MinecraftVersion,
            instance.Loader == "vanilla" ? "Vanilla" : GameInstaller.LoaderName(instance.Loader) + " " + (instance.LoaderVersion ?? "(newest)"),
            mods.Count == 1 ? "1 mod" : $"{mods.Count} mods"
        };
    }

    private List<string>? releases;

    private async void NewInstance_Click(object sender, RoutedEventArgs e)
    {
        if (busy) return;
        NewName.Text = "";
        NewLoader.ItemsSource = GameInstaller.Loaders.Select(l => new LoaderItem(l)).ToList();
        NewLoader.SelectedIndex = Array.IndexOf(GameInstaller.Loaders, "fabric");
        NewVersion.ItemsSource = releases ?? [Configuration.DefaultVersion];
        NewVersion.SelectedItem = Configuration.DefaultVersion;
        NewHint.Text = "The newest stable loader build is chosen automatically.";
        DialogCard.Visibility = Visibility.Collapsed;
        NewInstanceCard.Visibility = Visibility.Visible;
        Overlay.Visibility = Visibility.Visible;
        NewName.Focus();
        if (releases is not null) return;
        try
        {
            using var http = GameInstaller.CreateHttp();
            releases = await Task.Run(() => new GameInstaller(http).ReleasesAsync(CancellationToken.None));
            string? keep = NewVersion.SelectedItem as string;
            NewVersion.ItemsSource = releases;
            NewVersion.SelectedItem = keep is not null && releases.Contains(keep) ? keep : releases.FirstOrDefault();
        }
        catch (Exception ex) { NewHint.Text = "Couldn't load the version list: " + Describe(ex); }
    }

    private void NewInstanceCreate_Click(object sender, RoutedEventArgs e)
    {
        if (NewVersion.SelectedItem is not string version || NewLoader.SelectedItem is not LoaderItem loader) return;
        string name = NewName.Text.Trim();
        if (name.Length == 0) name = loader.Id == "vanilla" ? "Minecraft " + version : $"{loader} {version}";
        if (name.Length > 60 || name.Any(char.IsControl)) { NewHint.Text = "Choose a shorter name."; return; }
        var instance = new Instance { Name = name, MinecraftVersion = version, Loader = loader.Id };
        instances.Add(instance);
        InstanceStore.Save(instances);
        CloseDialog(false);
        RefreshLibrary(instance.Id);
        Status($"Created {name}. Press Play to install it.");
    }

    private void NewInstanceCancel_Click(object sender, RoutedEventArgs e) => CloseDialog(false);

    private async void Import_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Title = "Import a modpack or mods", Filter = PackImporter.Filter, Multiselect = true };
        if (dialog.ShowDialog(this) == true) await ImportAsync(dialog.FileNames);
    }

    private async void AddMods_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Title = "Add mods to " + Selected?.Name, Filter = "Fabric mods (*.jar)|*.jar", Multiselect = true };
        if (dialog.ShowDialog(this) == true) await ImportAsync(dialog.FileNames);
    }

    // .jar files go into the selected instance; anything else becomes a new instance.
    private async Task ImportAsync(string[] paths)
    {
        if (busy) { Status("Close the game before importing"); return; }
        SetBusy(true);
        HideBanner();
        NavLibrary.IsChecked = true;
        try
        {
            var jars = paths.Where(p => File.Exists(p) && PackImporter.IsModFile(p)).ToList();
            if (jars.Count > 0 && Selected is { } target)
            {
                await Task.Run(() => { InstanceStore.CreateFolder(target); PackImporter.AddMods(target, jars); });
                Status(jars.Count == 1 ? $"Added {Path.GetFileName(jars[0])}" : $"Added {jars.Count} mods to {target.Name}");
            }
            using var http = PackImporter.CreateHttp();
            var importer = new PackImporter(http);
            foreach (string path in paths.Except(jars))
            {
                var progress = new Progress<InstallProgress>(p => Status(p.Stage, p.Fraction));
                var instance = await Task.Run(() => importer.ImportAsync(path, progress, CancellationToken.None));
                instances.Add(instance);
                InstanceStore.Save(instances);
                RefreshLibrary(instance.Id);
                Status(instance.Missing.Count == 0 ? $"Imported {instance.Name}" : $"Imported {instance.Name}; some files need downloading by hand");
            }
        }
        catch (Exception ex) { Error(ex); }
        finally { SetBusy(false); RefreshLibrary(); }
    }

    private async void Remove_Click(object sender, RoutedEventArgs e)
    {
        if (Selected is not { } instance || busy) return;
        if (!await AskAsync($"Remove {instance.Name}?", "Its worlds, mods and settings are deleted from this PC. This can't be undone.", "Remove", danger: true))
            return;
        try { InstanceStore.DeleteFolder(instance); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { Error("Some files are in use. Close the game and try again."); return; }
        instances.Remove(instance);
        if (instances.Count == 0) instances = InstanceStore.Load(); // recreates a default instance
        InstanceStore.Save(instances);
        RefreshLibrary();
        Status($"Removed {instance.Name}");
    }

    private async void RemoveMod_Click(object sender, RoutedEventArgs e)
    {
        if (busy || Selected is not { } instance || sender is not Button { Tag: string path } ||
            !SandboxPolicy.IsWithin(path, instance.ModsDirectory)) return;
        if (!await AskAsync($"Remove {Path.GetFileName(path)}?", "The mod file is deleted from this instance.", "Remove", danger: true)) return;
        try { File.Delete(path); Status("Removed " + Path.GetFileName(path)); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { Error("That file is in use. Close the game and try again."); }
        RefreshInstance();
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
        ServersEmpty.Visibility = settings.Servers.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
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
            HideBanner();
            Status(running is null ? $"Added {entry.Host}" : $"Added {entry.Host}. It appears in the game next time you play.");
        }
        catch (Exception ex) { Error(ex); }
    }

    private void RemoveServer_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: ServerEntry entry }) return;
        settings.Servers.Remove(entry);
        TrySaveSettings();
        RefreshServers();
        Status($"Removed {entry.Host}");
    }

    // ===================== Security =====================

    private void RefreshSecurity()
    {
        bool? network = sandbox?.IsSetUp();
        bool saved = File.Exists(AppPaths.RefreshCache);
        ConfirmJoinsSwitch.IsChecked = settings.ConfirmJoins;
        ClipboardSwitch.IsChecked = settings.AllowClipboard;
        RememberSwitch.IsChecked = settings.RememberSignIn;
        NetworkOk.Visibility = network == true ? Visibility.Visible : Visibility.Collapsed;
        NetworkButton.Visibility = network == true || sandbox is null ? Visibility.Collapsed : Visibility.Visible;
        NetworkDetail.Text = sandbox is null ? "Windows couldn't create the sandbox, so Token Vault won't start the game."
            : network == true ? "Approved: the sandbox can reach Token Vault on this PC and see top-level folder names."
            : "Needed once: Windows asks an administrator to let the sandbox reach Token Vault on this PC.";
        SavedDetail.Text = identity is not null ? $"Signed in as {identity.Profile.Name}. Sign out to remove it from this PC."
            : saved ? "A sign-in is saved on this PC. Sign out to remove it." : "Nothing saved on this PC.";
        ForgetButton.IsEnabled = !busy && (identity is not null || saved);

        var issues = new List<string>();
        if (sandbox is null) issues.Add("the sandbox is unavailable");
        if (!settings.ConfirmJoins) issues.Add("joins aren't confirmed");
        if (settings.AllowClipboard) issues.Add("the game can read your clipboard");
        bool failed = sandbox is null;
        SecurityTitle.Text = failed ? "Protection unavailable" : issues.Count == 0 ? "Your account is protected" : "Protected, with exceptions";
        SecuritySummary.Text = failed ? "Token Vault won't start the game without its sandbox."
            : issues.Count == 0 ? (network == true ? "Every protection is on." : "Every protection is on. Windows asks for one approval the first time you play.")
            : "Your sign-in is safe, but " + string.Join(" and ", issues) + ".";
        SecurityHero.Background = Brush(failed ? "Bad" : issues.Count == 0 ? "Accent" : "Warn");
        SecurityBadge.Visibility = failed || issues.Count > 0 || unseenBlocks > 0 ? Visibility.Visible : Visibility.Collapsed;
        ActivityList.ItemsSource = activity.ToList();
        ActivityEmpty.Visibility = activity.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        ClearActivityButton.Visibility = activity.Count == 0 ? Visibility.Collapsed : Visibility.Visible;
    }

    private void ConfirmJoins_Click(object sender, RoutedEventArgs e)
    {
        settings.ConfirmJoins = ConfirmJoinsSwitch.IsChecked == true;
        TrySaveSettings();
        RefreshSecurity();
        Status(running is not null ? "Applies the next time you press Play" : settings.ConfirmJoins ? "Token Vault will ask before every join" : "Joins no longer need approval");
    }

    private void Clipboard_Click(object sender, RoutedEventArgs e)
    {
        settings.AllowClipboard = ClipboardSwitch.IsChecked == true;
        TrySaveSettings();
        RefreshSecurity();
        Status(running is not null ? "Applies the next time you press Play" : settings.AllowClipboard ? "Copy and paste allowed in the game" : "Clipboard is private");
    }

    private void Remember_Click(object sender, RoutedEventArgs e)
    {
        settings.RememberSignIn = RememberSwitch.IsChecked == true;
        TrySaveSettings();
        if (!settings.RememberSignIn) try { new RefreshCache(AppPaths.RefreshCache).Delete(); } catch (IOException) { }
        RefreshSecurity();
        RefreshAccount();
        Status(settings.RememberSignIn ? "You'll stay signed in on this PC" : "Your sign-in won't be saved on this PC");
    }

    private async void Network_Click(object sender, RoutedEventArgs e)
    {
        if (!busy) await ApproveSetupAsync();
    }

    private void ClearActivity_Click(object sender, RoutedEventArgs e)
    {
        activity.Clear();
        RefreshSecurity();
    }

    // Join approval runs in Token Vault's own window, where the sandboxed game can't click.
    private Task<bool> ApproveJoinAsync(ServerEntry server, CancellationToken ct) =>
        Dispatcher.InvokeAsync(() => JoinPrompt.AskAsync(server, identity?.Profile.Name ?? "you", ct)).Task.Unwrap();

    // Turns the vault's sanitized audit events into plain-language activity.
    private void Observe(string message)
    {
        if (!Dispatcher.CheckAccess()) { Dispatcher.BeginInvoke(() => Observe(message)); return; }
        string[] part = message.Split(':', 3);
        string Server(string host) => settings.Servers.FirstOrDefault(s => s.Host == host)?.Name ?? host;
        ActivityItem? item = (part[0], part.ElementAtOrDefault(1), part.ElementAtOrDefault(2)) switch
        {
            ("broker", "authenticated", var host) => new("\uE73E", Brush("Good"), $"Signed in to {Server(host!)}", "Token Vault made the connection. The game never saw your token."),
            ("broker", "approved", var host) => new("\uE8FB", Brush("Good"), $"You approved joining {Server(host!)}", "Approved in Token Vault's window."),
            ("broker", "blocked", var host) => new("\uE733", Brush("Bad"), $"Blocked a join to {Server(host!)}", "It wasn't approved. If you didn't try to join, a mod may have."),
            ("broker", "busy", var host) => new("\uE733", Brush("Bad"), $"Blocked a second connection to {Server(host!)}", "Only one connection at a time is allowed. Something tried to open another."),
            ("http", _, "join-always-denied") => new("\uE733", Brush("Bad"), "Blocked a direct server sign-in", "The game asked to sign in to a server by itself. Only Token Vault does that."),
            ("http", _, var route) when route is not null && (route.StartsWith("denied", StringComparison.Ordinal) || route == "unknown-or-forbidden") =>
                new("\uE733", Brush("Bad"), "Blocked an account request", "The game asked Minecraft's services for something outside the allowed list (for example a name or skin change)."),
            ("session", "started", _) => new("\uE768", Brush("Secondary"), "Game session started", "Your stand-in token was created for this session."),
            ("session", "closed", _) => new("\uE71A", Brush("Secondary"), "Game session ended", "The stand-in token and local connections were closed."),
            _ => null
        };
        if (item is null) return;
        activity.Insert(0, item);
        if (activity.Count > 200) activity.RemoveAt(activity.Count - 1);
        if (item.Brush == Brush("Bad")) { unseenBlocks++; Log(item.Title); }
        RefreshSecurity();
    }

    // ===================== Settings =====================

    private void LoadSettingsPage()
    {
        MemoryBox.Text = settings.MemoryMb.ToString(System.Globalization.CultureInfo.InvariantCulture);
        JavaBox.Text = settings.JavaPath;
        DeviceCodeBox.IsChecked = settings.UseDeviceCode;
        ClientIdBox.Text = settings.ClientId;
        ClientIdHint.Text = $"Empty uses the built-in public ID ({AuthenticationDefaults.BuiltInClientName}'s).";
    }

    private void SettingsSave_Click(object sender, RoutedEventArgs e)
    {
        var next = settings.Clone();
        next.JavaPath = JavaBox.Text.Trim();
        next.UseDeviceCode = DeviceCodeBox.IsChecked == true;
        next.ClientId = ClientIdBox.Text.Trim();
        if (!int.TryParse(MemoryBox.Text, out int memory) || memory is < 512 or > 65536) { Error("Memory must be between 512 and 65536 MB."); return; }
        next.MemoryMb = memory;
        try { next.Save(AppPaths.Config); }
        catch (InvalidDataException ex) { Error(ex.Message); return; }
        if (next.ClientId != settings.ClientId) { identity?.Dispose(); identity = null; } // a different app means signing in again
        settings = next;
        HideBanner();
        Status("Settings saved");
        RefreshSecurity();
        RefreshAccount();
    }

    private void SettingsRevert_Click(object sender, RoutedEventArgs e) => LoadSettingsPage();

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

    // ===================== Dialog overlay =====================

    private Task<bool> AskAsync(string title, string body, string primary, bool danger = false) =>
        OpenDialogAsync(title, body, primary, "Cancel", danger: danger);

    private Task<bool> OpenDialogAsync(string title, string body, string primary, string? secondary, bool danger = false, string? code = null)
    {
        dialog?.TrySetResult(false);
        NewInstanceCard.Visibility = Visibility.Collapsed;
        DialogCard.Visibility = Visibility.Visible;
        DialogTitle.Text = title;
        DialogBody.Text = body;
        DialogPrimary.Content = primary;
        DialogPrimary.Style = (Style)FindResource(danger ? "Danger" : "Primary");
        DialogSecondary.Content = secondary ?? "";
        DialogSecondary.Visibility = secondary is null ? Visibility.Collapsed : Visibility.Visible;
        DialogCode.Text = code ?? "";
        DialogCode.Visibility = code is null ? Visibility.Collapsed : Visibility.Visible;
        Overlay.Visibility = Visibility.Visible;
        DialogPrimary.Focus();
        dialog = new TaskCompletionSource<bool>();
        return dialog.Task;
    }

    private void CloseDialog(bool result)
    {
        Overlay.Visibility = Visibility.Collapsed;
        NewInstanceCard.Visibility = Visibility.Collapsed;
        DialogCode.Visibility = Visibility.Collapsed;
        dialog?.TrySetResult(result);
        dialog = null;
    }

    private void DialogPrimary_Click(object sender, RoutedEventArgs e)
    {
        if (DialogCode.Visibility == Visibility.Visible) // sign-in code: copy and open, keep showing the code
        {
            try { Clipboard.SetText(DialogCode.Text); } catch (System.Runtime.InteropServices.COMException) { }
            if (codePage is not null) Open(codePage.AbsoluteUri);
            return;
        }
        CloseDialog(true);
    }

    private void DialogSecondary_Click(object sender, RoutedEventArgs e)
    {
        if (DialogCode.Visibility == Visibility.Visible) signIn?.Cancel();
        CloseDialog(false);
    }

    // ===================== Shell =====================

    private async void OnClosing(object? sender, System.ComponentModel.CancelEventArgs e)
    {
        if (running is null || closeConfirmed) return;
        e.Cancel = true;
        if (!await AskAsync("Quit Token Vault?", "Minecraft is still running. Quitting Token Vault closes the game too.", "Quit", danger: true)) return;
        closeConfirmed = true;
        running?.Cancel(); // the job object also ends the game when this process exits
        Close();
    }

    private void SetBusy(bool value)
    {
        busy = value;
        bool idle = !value;
        PlayButton.IsEnabled = running is not null || (idle && sandbox is not null);
        ImportButton.IsEnabled = idle;
        NewInstanceButton.IsEnabled = idle;
        AddModsButton.IsEnabled = idle;
        RemoveButton.IsEnabled = idle;
        Library.IsEnabled = idle;
        ModList.IsEnabled = idle;
        SignInButton.IsEnabled = idle;
        SignOutButton.IsEnabled = idle;
        ForgetButton.IsEnabled = idle;
        if (idle) ProgressArea.Visibility = Visibility.Collapsed;
    }

    private void Status(string text, double? fraction = null, string? tone = null)
    {
        if (!Dispatcher.CheckAccess()) { Dispatcher.BeginInvoke(() => Status(text, fraction, tone)); return; }
        StatusText.Text = text;
        StatusDot.Fill = Brush(tone ?? (busy ? "Accent" : "Good"));
        ProgressArea.Visibility = fraction is null ? Visibility.Collapsed : Visibility.Visible;
        if (fraction is double f)
        {
            Progress.Value = Math.Clamp(f, 0, 1);
            ProgressText.Text = $"{Math.Clamp(f, 0, 1):P0}";
        }
        Log(text);
    }

    private void Log(string text)
    {
        if (!Dispatcher.CheckAccess()) { Dispatcher.BeginInvoke(() => Log(text)); return; }
        if (ActivityLog.LineCount > 2000) ActivityLog.Clear();
        ActivityLog.AppendText($"{DateTime.Now:HH:mm:ss}  {text}{Environment.NewLine}");
        ActivityLog.ScrollToEnd();
    }

    private void Error(Exception ex)
    {
        Error(Describe(ex));
        // Where it failed (code locations only, no data) goes to the activity log to help with bug reports.
        if (ex is not (UserVisibleException or OperationCanceledException) && ex.StackTrace is { } trace)
            Log($"Details: {ex.GetType().Name} at " + string.Join(" < ", trace.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Take(4).Select(l => l.StartsWith("at ", StringComparison.Ordinal) ? l[3..].Split(" in ")[0] : l)));
    }

    private void Error(string message)
    {
        BannerText.Text = message;
        Banner.Visibility = Visibility.Visible;
        Status("Something went wrong", tone: "Bad");
        Log("Error: " + message);
    }

    private void HideBanner() => Banner.Visibility = Visibility.Collapsed;
    private void Banner_Close(object sender, RoutedEventArgs e) => HideBanner();

    // Never shows arbitrary exception text: library messages can contain account details or request data.
    private static string Describe(Exception ex) => ex switch
    {
        UserVisibleException or InvalidDataException or FileNotFoundException or DirectoryNotFoundException => ex.Message,
        OperationCanceledException => "Canceled.",
        MsalException { ErrorCode: "authentication_canceled" or "access_denied" or "authorization_declined" } => "Sign-in was canceled.",
        MsalException { ErrorCode: "code_expired" or "expired_token" } => "The sign-in code expired. Press Play to get a new one.",
        MsalException { ErrorCode: "invalid_client" or "unauthorized_client" } =>
            "Microsoft rejected the application ID. Clear it in Settings to use the built-in one, or check your registration.",
        MsalException msal => $"Microsoft sign-in didn't finish ({msal.ErrorCode}). Try again, or turn on \"Sign in with a code\" in Settings.",
        System.Net.Sockets.SocketException { SocketErrorCode: System.Net.Sockets.SocketError.AddressAlreadyInUse } or
            IOException { InnerException: Microsoft.AspNetCore.Connections.AddressInUseException } =>
            "Another program is using Token Vault's local ports (25597 or 25599). Close it and try again.",
        System.Net.Http.HttpRequestException => "Couldn't reach the internet. Check your connection and try again.",
        UnauthorizedAccessException => "Windows denied access to a file Token Vault needs.",
        // Windows' own error text describes the failure, not the request, so it is safe to show.
        System.ComponentModel.Win32Exception win32 => $"Windows reported an error: {win32.Message} (error {win32.NativeErrorCode}).",
        _ => $"Something unexpected went wrong ({ex.GetType().Name}). Try again."
    };

    private Brush Brush(string key) => (Brush)FindResource(key);

    private static void Open(string target)
    {
        try { Process.Start(new ProcessStartInfo(target) { UseShellExecute = true })?.Dispose(); }
        catch (System.ComponentModel.Win32Exception) { }
    }
}

// Flat monogram colours, stable per name.
internal static class Tiles
{
    private static readonly Brush[] Palette = new[] { "#2A7F6F", "#3D63B8", "#5A55B0", "#8550A8", "#A84866", "#B5653A", "#4F5D73", "#2B7C9C" }
        .Select(c => { var b = new SolidColorBrush((Color)ColorConverter.ConvertFromString(c)); b.Freeze(); return (Brush)b; }).ToArray();

    public static Brush For(string name)
    {
        uint hash = 2166136261;
        foreach (char c in name.ToLowerInvariant()) hash = (hash ^ c) * 16777619;
        return Palette[hash % (uint)Palette.Length];
    }

    public static string Initial(string name) =>
        name.FirstOrDefault(char.IsLetterOrDigit) is var c && c != default ? char.ToUpperInvariant(c).ToString() : "?";
}

public sealed record LibraryRow(Instance Instance)
{
    public string Name => Instance.Name;
    public string Initial => Tiles.Initial(Instance.Name);
    public Brush Tile => Tiles.For(Instance.Name);
    public string Summary
    {
        get
        {
            int mods = Instance.CountMods();
            string count = mods == 1 ? "1 mod" : $"{mods} mods";
            return $"{GameInstaller.LoaderName(Instance.Loader)} {Instance.MinecraftVersion} · {count}";
        }
    }
}

public sealed record ModRow(ModInfo Mod, string Path)
{
    public string Name => Mod.Name;
    public string Initial => Tiles.Initial(Mod.Name);
    public Brush Tile => Tiles.For(Mod.Name);
    public string Detail => Mod.Version is null ? Mod.File : $"{Mod.Version}  ·  {Mod.File}";
    public string Size => Mod.Size switch
    {
        >= 1024 * 1024 => $"{Mod.Size / 1048576.0:0.0} MB",
        >= 1024 => $"{Mod.Size / 1024} KB",
        _ => $"{Mod.Size} B"
    };
}

public sealed record ServerRow(ServerEntry Entry)
{
    public string Name => Entry.Name;
    public string Initial => Tiles.Initial(Entry.Name);
    public Brush Tile => Tiles.For(Entry.Host);
    public string Address => Entry.Port == 25565 ? Entry.Host : $"{Entry.Host}:{Entry.Port}";
}

public sealed record ActivityItem(string Glyph, Brush Brush, string Title, string Detail)
{
    public string Time { get; } = DateTime.Now.ToString("HH:mm");
}

public sealed record Limit(string Title, string Detail);

public sealed record LoaderItem(string Id)
{
    public override string ToString() => GameInstaller.LoaderName(Id);
}
