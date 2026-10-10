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
    private VaultSession? liveSession;
    private Telemetry telemetry = new(new System.Net.Http.HttpClient(), () => false, "", "", "");
    private UpdateInfo? update;
    private bool updateInstalled;
    private bool launching;
    private int onboardingStep;
    private readonly System.Windows.Threading.DispatcherTimer toastTimer = new() { Interval = TimeSpan.FromSeconds(4) };
    private System.Windows.Media.Animation.Storyboard? pulse;

    public MainWindow()
    {
        InitializeComponent();
        SourceInitialized += (_, _) => { App.MatchTitleBar(this); App.RoundCorners(this); };
        StateChanged += (_, _) => FitMaximized();
        toastTimer.Tick += (_, _) => { toastTimer.Stop(); if (ProgressArea.Visibility != Visibility.Visible) Toast.Visibility = Visibility.Collapsed; };
        Loaded += (_, _) => Initialize();
        Closing += OnClosing;
        PreviewKeyDown += (_, e) => { if (e.Key == Key.Escape && Overlay.Visibility == Visibility.Visible) { DialogSecondary_Click(this, e); e.Handled = true; } };
        DragOver += (_, e) => { e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop) && !busy ? DragDropEffects.Copy : DragDropEffects.None; e.Handled = true; };
        Drop += async (_, e) => { if (e.Data.GetData(DataFormats.FileDrop) is string[] files) await ImportAsync(files); };
        ServerAddress.TextChanged += (_, _) => ServerHint.Visibility = ServerAddress.Text.Length == 0 ? Visibility.Visible : Visibility.Collapsed;
        LimitsList.ItemsSource = new[]
        {
            new Limit("Actions inside the game", "While you're on a server, a bad mod controls that connection: it can chat, trade, give items away or hand the connection to someone else until you disconnect. Use Disconnect at the top of Token Vault if anything looks wrong. It can't sign in as you afterwards."),
            new Limit("Signed chat", "With signed chat on, a mod can copy the chat-signing key and sign chat as you for about two days. Turn it off above if your servers don't need it."),
            new Limit("Servers you add", "A server on your list can quietly pass your sign-in on to a different server. Only add servers you trust."),
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
            if (settings.InstallId.Length == 0) { settings.InstallId = Guid.NewGuid().ToString("N"); TrySaveSettings(); }
            telemetry = Telemetry.Create(() => settings.ShareUsageStatistics == true, settings.InstallId);
            if (Environment.ProcessPath is { } exe) try { Updater.CleanUp(exe); } catch (IOException) { } catch (UnauthorizedAccessException) { }
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
        if (!settings.OnboardingCompleted) ShowOnboarding();
        _ = AfterStartAsync();
    }

    private async Task AfterStartAsync()
    {
        if (settings.OnboardingCompleted && settings.ShareUsageStatistics is null && telemetry.Configured)
        {
            bool share = await AskAsync("Help improve Token Vault?",
                "Token Vault can send anonymous usage statistics: which features are used, which Minecraft versions and loaders, and whether launches and joins work.\n\n" +
                "It never sends your account, servers, mods, files or anything from the game. You can change this in Settings.", "Share statistics");
            settings.ShareUsageStatistics = share;
            TrySaveSettings();
            if (share) telemetry.Track("consent_given");
        }
        telemetry.Track("app_started", new Dictionary<string, string>
        {
            ["protection"] = File.Exists(AppPaths.RefreshCache) ? (RefreshCache.Protection(AppPaths.RefreshCache).StartsWith("TPM") ? "tpm" : "dpapi") : "none",
            ["confirm_joins"] = settings.ConfirmJoins ? "on" : "off", ["chat_signing"] = settings.AllowChatSigning ? "on" : "off",
            ["clipboard"] = settings.AllowClipboard ? "on" : "off"
        });
        // Then look for updates now and every six hours while Token Vault is open.
        while (true)
        {
            try { if (settings.CheckForUpdates && !updateInstalled) await CheckForUpdateAsync(); }
            catch (Exception ex) { Log("Update check failed (" + ex.GetType().Name + ")."); }
            await Task.Delay(TimeSpan.FromHours(6));
        }
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
        launching = true;
        LaunchStep(0, "Getting ready", "Checking that everything is in place.", null);
        try
        {
            if (sandbox.IsSetUp() == false && !await ApproveSetupAsync()) { ShowToast("Playing needs the one-time sandbox setup."); return; }

            // Everything slow runs off the UI thread so the window stays responsive.
            var progress = new Progress<InstallProgress>(p =>
            {
                string[] part = p.Stage.Split(" — ", 2);
                LaunchStep(0, part[0].TrimEnd('…'), part.Length > 1 ? part[1] : "This only happens the first time, or after an update.", p.Fraction is > 0 and < 1 ? p.Fraction : null);
            });
            LaunchStep(0, "Checking game files", $"Minecraft {instance.MinecraftVersion}, {GameInstaller.LoaderName(instance.Loader)}", null);
            using var http = GameInstaller.CreateHttp();
            var target = instance.Apply(settings);
            var box = sandbox;
            var installed = await Task.Run(() => new GameInstaller(http).EnsureAsync(target, instance.LoaderVersion, box, progress, cts.Token));
            if (instance.LoaderVersion is null && installed.LoaderVersion is not null)
            {
                instance.LoaderVersion = installed.LoaderVersion; // pin the loader build this instance was set up with
                InstanceStore.Save(instances);
            }

            LaunchStep(1, "Signing in", "Using your saved Microsoft sign-in.", null);
            var account = await EnsureSignedInAsync(cts.Token);
            LaunchStep(2, "Starting Minecraft", $"Starting the game in the sandbox as {account.Profile.Name}.", null);
            InstanceStore.CreateFolder(instance);
            var launch = instance.Apply(settings, installed);
            string clientJar = Path.Combine(launch.MinecraftDirectory, "versions", launch.MinecraftVersion, launch.MinecraftVersion + ".jar");
            launch.Protocol = await Task.Run(() => InstalledVersion.Protocol(clientJar, launch.MinecraftVersion));
            // Only the game's own processes may use the local server connections (not other programs or Windows users).
            var origin = new ConnectionOrigin();
            await using var session = await Task.Run(() => VaultSession.StartAsync(launch, account, AppPaths.AuditLog, cts.Token, Observe, ApproveJoinAsync, origin));
            liveSession = session;
            var game = sandbox;
            var started = DateTime.UtcNow;
            telemetry.Track("game_launched", new Dictionary<string, string> { ["minecraft_version"] = instance.MinecraftVersion, ["loader"] = instance.Loader });
            int code = await Task.Run(() => JavaLauncher.LaunchAsync(launch, session.Descriptor, game, line =>
            {
                Log(line);
                if (line.StartsWith("Starting Minecraft", StringComparison.Ordinal))
                    Dispatcher.BeginInvoke(() => LaunchPlaying(instance.Name, account.Profile.Name));
            }, cts.Token, process => origin.Allow((client, server) => LoopbackPeers.OwnerOf(client, server) is int pid && process.Contains(pid))));
            telemetry.Track("game_exited", new Dictionary<string, string>
            {
                ["result"] = code == 0 ? "ok" : "error", ["minutes"] = ((int)(DateTime.UtcNow - started).TotalMinutes).ToString(System.Globalization.CultureInfo.InvariantCulture)
            });
            if (code != 0) Error($"Minecraft closed unexpectedly (exit code {code}). Its log is in the instance folder under logs\\latest.log.");
        }
        catch (OperationCanceledException) when (cts.IsCancellationRequested) { ShowToast("Game stopped"); }
        catch (Exception ex) { Error(ex); }
        finally
        {
            launching = false;
            HideLaunch();
            running = null;
            liveSession = null;
            ConnectionBar.Visibility = Visibility.Collapsed;
            if (updateInstalled) ShowUpdate();
            CloseDialog(false);
            SetPlayButton(stop: false);
            SetBusy(false);
            RefreshAccount();
            RefreshLibrary(instance.Id);
        }
    }

    // ----- Launch progress card -----

    // step: 0 game files, 1 sign-in, 2 start. fraction: null shows a pulsing bar (working, length unknown).
    private void LaunchStep(int step, string title, string detail, double? fraction)
    {
        if (!Dispatcher.CheckAccess()) { Dispatcher.BeginInvoke(() => LaunchStep(step, title, detail, fraction)); return; }
        if (!launching) return;
        LaunchPanel.Visibility = Visibility.Visible;
        var dots = new[] { (Step0Dot, Step0Glyph, Step0Label), (Step1Dot, Step1Glyph, Step1Label), (Step2Dot, Step2Glyph, Step2Label) };
        for (int i = 0; i < dots.Length; i++)
        {
            var (dot, glyph, label) = dots[i];
            bool done = i < step, current = i == step;
            dot.Background = done ? Brush("Accent") : Brushes.Transparent;
            dot.BorderBrush = done || current ? Brush("Accent") : Brush("LineStrong");
            glyph.Text = done ? "\uE73E" : (i + 1).ToString(System.Globalization.CultureInfo.InvariantCulture);
            glyph.FontFamily = done ? (FontFamily)FindResource("IconFont") : (FontFamily)FindResource("UiFont");
            glyph.Foreground = done ? Brush("OnAccent") : current ? Brush("Accent") : Brush("Tertiary");
            label.Foreground = done || current ? Brush("Text") : Brush("Tertiary");
            label.FontWeight = current ? FontWeights.SemiBold : FontWeights.Normal;
        }
        LaunchTitle.Text = title;
        LaunchDetail.Text = detail;
        LaunchProgress.Visibility = Visibility.Visible;
        if (fraction is double f) { StopPulse(); LaunchProgress.Value = Math.Clamp(f, 0, 1); }
        else StartPulse();
    }

    private void LaunchPlaying(string instanceName, string player)
    {
        if (!launching) return;
        LaunchStep(3, "Playing " + instanceName, $"Minecraft is running in the sandbox as {player}. Close the game or press Stop to end it.", 1);
        LaunchProgress.Visibility = Visibility.Collapsed;
    }

    private void HideLaunch()
    {
        StopPulse();
        LaunchPanel.Visibility = Visibility.Collapsed;
    }

    private void StartPulse()
    {
        LaunchProgress.Value = 1;
        if (pulse is not null) return;
        var fade = new System.Windows.Media.Animation.DoubleAnimation(1, 0.25, TimeSpan.FromMilliseconds(900)) { AutoReverse = true, RepeatBehavior = System.Windows.Media.Animation.RepeatBehavior.Forever };
        System.Windows.Media.Animation.Storyboard.SetTarget(fade, LaunchProgress);
        System.Windows.Media.Animation.Storyboard.SetTargetProperty(fade, new PropertyPath(OpacityProperty));
        pulse = new System.Windows.Media.Animation.Storyboard();
        pulse.Children.Add(fade);
        pulse.Begin(this, true);
    }

    private void StopPulse()
    {
        pulse?.Stop(this);
        pulse = null;
        LaunchProgress.Opacity = 1;
    }

    private void SetPlayButton(bool stop)
    {
        PlayButton.Style = (Style)FindResource(stop ? typeof(Button) : "Primary");
        PlayLabel.Text = stop ? "Stop" : "Play";
        System.Windows.Automation.AutomationProperties.SetName(PlayButton, PlayLabel.Text);
        PlayIcon.Text = stop ? "\uE71A" : "\uE768";
        PlayButton.IsEnabled = stop || (!busy && sandbox is not null);
    }

    private async Task<bool> ApproveSetupAsync()
    {
        if (sandbox is null) return false;
        if (!await AskAsync("One-time sandbox setup",
                "Windows will ask for administrator approval once, for small changes that only affect Token Vault's sandbox:\n\n" +
                "•  let it connect to Token Vault on this PC,\n" +
                $"•  let it see the folder names at the top of {Path.GetPathRoot(AppPaths.GameRoot)} (names only, not files), which Java needs, and\n" +
                $"•  mark {AppPaths.GameRoot} as a sandbox folder so the game can save there.\n\n" +
                "No account is created and nothing else changes.", "Continue"))
            return false;
        bool ok = await sandbox.RequestSetupAsync();
        Log(ok ? "Sandbox setup approved." : "Sandbox setup was not approved.");
        RefreshSecurity();
        return ok;
    }

    // ===================== Window =====================

    private void Minimize_Click(object sender, RoutedEventArgs e) => SystemCommands.MinimizeWindow(this);
    private void Maximize_Click(object sender, RoutedEventArgs e)
    {
        if (WindowState == WindowState.Maximized) SystemCommands.RestoreWindow(this);
        else SystemCommands.MaximizeWindow(this);
    }
    private void Close_Click(object sender, RoutedEventArgs e) => SystemCommands.CloseWindow(this);

    // A maximised window without a system frame reaches past the screen edges by the resize border; pad it back in.
    private void FitMaximized()
    {
        bool max = WindowState == WindowState.Maximized;
        var frame = SystemParameters.WindowResizeBorderThickness;
        Root.Margin = max ? new Thickness(frame.Left + 4, frame.Top + 4, frame.Right + 4, frame.Bottom + 4) : new Thickness(0);
        MaximizeButton.Content = max ? "\uE923" : "\uE922";
        MaximizeButton.ToolTip = max ? "Restore" : "Maximize";
    }

    // ===================== First run =====================

    private StackPanel[] OnboardingSteps => [WelcomeStep, SafetyStep, SandboxStep, SignInStep, DoneStep];

    private void ShowOnboarding()
    {
        Onboarding.Visibility = Visibility.Visible;
        StatisticsCard.Visibility = telemetry.Configured ? Visibility.Visible : Visibility.Collapsed;
        OnboardingStatistics.IsChecked = settings.ShareUsageStatistics == true;
        GoToStep(0);
    }

    private void GoToStep(int step)
    {
        onboardingStep = Math.Clamp(step, 0, OnboardingSteps.Length - 1);
        var steps = OnboardingSteps;
        for (int i = 0; i < steps.Length; i++) steps[i].Visibility = i == onboardingStep ? Visibility.Visible : Visibility.Collapsed;
        var current = steps[onboardingStep];
        current.BeginAnimation(OpacityProperty, new System.Windows.Media.Animation.DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(220)));
        int dot = 0;
        foreach (var child in OnboardingDots.Children.OfType<System.Windows.Shapes.Ellipse>())
            child.Fill = Brush(dot++ == onboardingStep ? "Accent" : "LineStrong");
        OnboardingBack.Visibility = onboardingStep > 0 && onboardingStep < steps.Length - 1 ? Visibility.Visible : Visibility.Collapsed;
        if (current == SignInStep && identity is { } signedIn) ShowSignInResult($"Signed in as {signedIn.Profile.Name}.", good: true);
        if (current == DoneStep)
            DoneDetail.Text = identity is null && !File.Exists(AppPaths.RefreshCache)
                ? "Pick an instance in your library and press Play. Token Vault asks you to sign in the first time."
                : "Pick an instance in your library and press Play, or drop a modpack onto the window.";
    }

    private void OnboardingNext_Click(object sender, RoutedEventArgs e)
    {
        int next = onboardingStep + 1;
        if (next == 2 && sandbox?.IsSetUp() == true) next++; // already set up: nothing to ask
        GoToStep(next);
    }

    private void OnboardingBack_Click(object sender, RoutedEventArgs e)
    {
        int back = onboardingStep - 1;
        if (back == 2 && sandbox?.IsSetUp() == true) back--;
        GoToStep(back);
    }

    private async void OnboardingSandbox_Click(object sender, RoutedEventArgs e)
    {
        if (sandbox is null) { ShowSandboxResult("Windows couldn't create the sandbox on this PC, so the game can't start. You can still look around.", good: false); return; }
        bool ok;
        try { ok = await sandbox.RequestSetupAsync(); }
        catch (Exception ex) { ShowSandboxResult(Describe(ex), good: false); return; }
        Log(ok ? "Sandbox setup approved." : "Sandbox setup was not approved.");
        if (!ok) { ShowSandboxResult("Windows didn't give its OK. You can do this later from the Security page.", good: false); return; }
        ShowSandboxResult("Done. The sandbox is ready.", good: true);
        RefreshSecurity();
        await Task.Delay(700);
        if (onboardingStep == 2) GoToStep(3);
    }

    private void ShowSandboxResult(string text, bool good)
    {
        SandboxResult.Text = text;
        SandboxResult.Foreground = Brush(good ? "Good" : "Bad");
        SandboxResult.Visibility = Visibility.Visible;
    }

    private void ShowSignInResult(string text, bool good)
    {
        SignInResult.Text = text;
        SignInResult.Foreground = Brush(good ? "Good" : "Bad");
        SignInResult.Visibility = Visibility.Visible;
    }

    private void OnboardingCode_Click(object sender, RoutedEventArgs e)
    {
        settings.UseDeviceCode = true;
        TrySaveSettings();
        OnboardingSignIn_Click(sender, e);
    }

    private async void OnboardingSignIn_Click(object sender, RoutedEventArgs e)
    {
        if (busy) return;
        SetBusy(true);
        OnboardingSignInButton.IsEnabled = false;
        ShowSignInResult(settings.UseDeviceCode ? "Getting a sign-in code from Microsoft…" : "Finish signing in in your browser…", good: true);
        try
        {
            var account = await EnsureSignedInAsync(CancellationToken.None);
            ShowSignInResult($"Signed in as {account.Profile.Name}.", good: true);
            await Task.Delay(700);
            if (onboardingStep == 3) GoToStep(4);
        }
        catch (OperationCanceledException) { ShowSignInResult("Sign-in was canceled.", good: false); }
        catch (Exception ex) { ShowSignInResult(Describe(ex), good: false); }
        finally { OnboardingSignInButton.IsEnabled = true; SetBusy(false); RefreshAccount(); }
    }

    private void OnboardingFinish_Click(object sender, RoutedEventArgs e)
    {
        if (telemetry.Configured)
        {
            bool share = OnboardingStatistics.IsChecked == true;
            if (share && settings.ShareUsageStatistics != true) { settings.ShareUsageStatistics = true; telemetry.Track("consent_given"); }
            else settings.ShareUsageStatistics = share;
        }
        settings.OnboardingCompleted = true;
        TrySaveSettings();
        Onboarding.BeginAnimation(OpacityProperty, null);
        Onboarding.Visibility = Visibility.Collapsed;
        RefreshSecurity();
        RefreshAccount();
    }

    // ===================== Account =====================

    private async Task<MinecraftIdentity> EnsureSignedInAsync(CancellationToken ct)
    {
        // Reused only if it outlasts a whole game session, so the session isn't cut short by an old sign-in.
        if (identity is { } current && current.ExpiresAt > DateTimeOffset.UtcNow.AddMinutes(Math.Min(settings.SessionMinutes, 12 * 60) + 5)) return current;
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
                telemetry.Track("pack_imported", new Dictionary<string, string> { ["source"] = instance.Source.Split(' ')[0], ["loader"] = instance.Loader });
                Log($"{instance.Name}: Minecraft {instance.MinecraftVersion}, {GameInstaller.LoaderName(instance.Loader)} {instance.LoaderVersion ?? "(newest)"}.");
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
        ChatSigningSwitch.IsChecked = settings.AllowChatSigning;
        RememberSwitch.IsChecked = settings.RememberSignIn;
        NetworkOk.Visibility = network == true ? Visibility.Visible : Visibility.Collapsed;
        NetworkButton.Visibility = network == true || sandbox is null ? Visibility.Collapsed : Visibility.Visible;
        NetworkDetail.Text = sandbox is null ? "Windows couldn't create the sandbox, so Token Vault won't start the game."
            : network == true ? "Approved: the sandbox can reach Token Vault on this PC and see top-level folder names."
            : "Needed once: Windows asks an administrator to let the sandbox reach Token Vault on this PC.";
        SavedDetail.Text = identity is not null ? $"Signed in as {identity.Profile.Name}. Sign out to remove it from this PC."
            : saved ? $"A sign-in is saved on this PC, encrypted with {RefreshCache.Protection(AppPaths.RefreshCache)}. Sign out to remove it." : "Nothing saved on this PC.";
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

    private void ChatSigning_Click(object sender, RoutedEventArgs e)
    {
        settings.AllowChatSigning = ChatSigningSwitch.IsChecked == true;
        TrySaveSettings();
        RefreshSecurity();
        Status(running is not null ? "Applies the next time you press Play" : settings.AllowChatSigning ? "Signed chat on" : "Signed chat off: the game won't get a chat-signing key");
    }

    // Ends the live server connection. The game shows "connection lost"; the player can join again (with approval).
    private void Disconnect_Click(object sender, RoutedEventArgs e)
    {
        if (liveSession?.DisconnectActive() == true) Status("Disconnected from the server");
        ConnectionBar.Visibility = Visibility.Collapsed;
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
            ("broker", "failed", var rest) => new("\uE783", Brush("Bad"), $"Couldn't join {Server(rest!.Split(':')[0])}", "The game shows the reason on its disconnect screen."),
            ("broker", "foreign", var host) => new("\uE733", Brush("Bad"), $"Refused a connection to {Server(host!)}", "Something other than the game tried to use your sign-in. It was turned away."),
            ("broker", "expired", var host) => new("\uE783", Brush("Bad"), $"Couldn't join {Server(host!)}", "This game session's sign-in expired. Close Minecraft and press Play again."),
            ("broker", "busy", var host) => new("\uE733", Brush("Bad"), $"Blocked a second connection to {Server(host!)}", "Only one connection at a time is allowed. Something tried to open another."),
            ("http", _, "join-always-denied") => new("\uE733", Brush("Bad"), "Blocked a direct server sign-in", "The game asked to sign in to a server by itself. Only Token Vault does that."),
            ("http", _, var route) when route is not null && (route.StartsWith("denied", StringComparison.Ordinal) || route == "unknown-or-forbidden") =>
                new("\uE733", Brush("Bad"), "Blocked an account request", "The game asked Minecraft's services for something outside the allowed list (for example a name or skin change)."),
            ("session", "started", _) => new("\uE768", Brush("Secondary"), "Game session started", "Your stand-in token was created for this session."),
            ("session", "closed", _) => new("\uE71A", Brush("Secondary"), "Game session ended", "The stand-in token and local connections were closed."),
            _ => null
        };
        if ((part[0], part.ElementAtOrDefault(1)) is ("broker", "connected") && part.ElementAtOrDefault(2) is { } live)
        {
            ConnectionText.Text = $"Signed in to {Server(live)} as {identity?.Profile.Name ?? "you"}. Didn't join this yourself, or something looks wrong? Disconnect.";
            ConnectionBar.Visibility = Visibility.Visible;
        }
        if ((part[0], part.ElementAtOrDefault(1)) is ("broker", "disconnected")) ConnectionBar.Visibility = Visibility.Collapsed;
        string? statistic = (part[0], part.ElementAtOrDefault(1)) switch
        {
            ("broker", "approved") => "join_approved", ("broker", "blocked") => "join_blocked", ("broker", "failed") => "join_failed",
            ("broker", "foreign") => "join_refused_foreign", _ => null
        };
        if (statistic is not null) telemetry.Track(statistic);
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
        UpdatesBox.IsChecked = settings.CheckForUpdates;
        UpdatesHint.Text = BuildInfo.UpdatePublicKey.Length > 0
            ? $"Checks GitHub for new releases and installs one only if its signature matches Token Vault's release key. This is version {BuildInfo.Version}."
            : $"Checks GitHub for new releases and tells you about them. This build can't verify updates itself, so it doesn't install them. This is version {BuildInfo.Version}.";
        StatisticsBox.IsChecked = settings.ShareUsageStatistics == true;
        StatisticsBox.IsEnabled = telemetry.Configured;
        StatisticsHint.Text = telemetry.Configured
            ? "Which features are used and whether launches and joins work. Never your account, servers, mods, files or anything from the game."
            : "This build doesn't send statistics.";
    }

    private void SettingsSave_Click(object sender, RoutedEventArgs e)
    {
        var next = settings.Clone();
        next.JavaPath = JavaBox.Text.Trim();
        next.UseDeviceCode = DeviceCodeBox.IsChecked == true;
        next.ClientId = ClientIdBox.Text.Trim();
        next.CheckForUpdates = UpdatesBox.IsChecked == true;
        if (telemetry.Configured) next.ShareUsageStatistics = StatisticsBox.IsChecked == true;
        bool consented = next.ShareUsageStatistics == true && settings.ShareUsageStatistics != true;
        if (!int.TryParse(MemoryBox.Text, out int memory) || memory is < 512 or > 65536) { Error("Memory must be between 512 and 65536 MB."); return; }
        next.MemoryMb = memory;
        try { next.Save(AppPaths.Config); }
        catch (InvalidDataException ex) { Error(ex.Message); return; }
        if (next.ClientId != settings.ClientId) { identity?.Dispose(); identity = null; } // a different app means signing in again
        settings = next;
        if (consented) telemetry.Track("consent_given");
        if (settings.CheckForUpdates && update is null) _ = CheckForUpdateAsync();
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

    // ===================== Updates =====================

    // Finds a newer release; when this build can verify it, downloads it, checks its signature and puts it in place
    // (it runs from the next start). Otherwise only offers the download page.
    private async Task CheckForUpdateAsync()
    {
        try
        {
            using var http = Updater.CreateHttp();
            var updater = new Updater(http, BuildInfo.UpdateRepository, BuildInfo.UpdatePublicKey, BuildInfo.Version);
            var found = await Task.Run(() => updater.CheckAsync(CancellationToken.None));
            if (found is null || updateInstalled) return;
            update = found;
            telemetry.Track("update_available", new Dictionary<string, string> { ["from_version"] = BuildInfo.Version.ToString(), ["to_version"] = found.Version.ToString() });
            string? exe = Environment.ProcessPath;
            if (updater.CanInstall && found.Installable && exe is not null && Path.GetFileName(exe).Equals("TokenVault.exe", StringComparison.OrdinalIgnoreCase))
            {
                Log($"Downloading Token Vault {found.Version}…");
                string staging = Path.Combine(AppPaths.Root, "Updates");
                PrivateDirectory.Ensure(staging);
                var staged = await Task.Run(() => updater.DownloadAsync(found, staging, CancellationToken.None));
                Updater.Install(staged, exe);
                updateInstalled = true;
                Log($"Token Vault {found.Version} is installed; it starts next time.");
                telemetry.Track("update_installed", new Dictionary<string, string> { ["from_version"] = BuildInfo.Version.ToString(), ["to_version"] = found.Version.ToString() });
            }
            ShowUpdate();
        }
        catch (Exception ex) when (ex is UpdateException or System.Net.Http.HttpRequestException or IOException or UnauthorizedAccessException or
                                       System.Text.Json.JsonException or TaskCanceledException or KeyNotFoundException or InvalidOperationException)
        {
            Log("Update: " + (ex is UpdateException or System.Net.Http.HttpRequestException ? ex.Message : ex.GetType().Name));
            if (ex is UpdateException) telemetry.Track("update_failed");
            if (update is not null) ShowUpdate();
        }
    }

    private void ShowUpdate()
    {
        if (update is null) return;
        if (updateInstalled)
        {
            UpdateText.Text = running is null
                ? $"Token Vault {update.Version} is installed. Restart to start using it."
                : $"Token Vault {update.Version} is installed. It starts the next time you open Token Vault.";
            UpdateButton.Content = "Restart now";
            UpdateButton.Visibility = running is null ? Visibility.Visible : Visibility.Collapsed;
        }
        else
        {
            UpdateText.Text = $"Token Vault {update.Version} is available.";
            UpdateButton.Content = "Download";
            UpdateButton.Visibility = Visibility.Visible;
        }
        UpdateBar.Visibility = Visibility.Visible;
    }

    private void Update_Click(object sender, RoutedEventArgs e)
    {
        if (update is null) return;
        if (!updateInstalled)
        {
            if (update.Page.Scheme == "https" && update.Page.Host == "github.com") Open(update.Page.AbsoluteUri);
            return;
        }
        if (running is not null || Environment.ProcessPath is not { } exe) return;
        try { Process.Start(new ProcessStartInfo(exe) { UseShellExecute = false, ArgumentList = { App.AfterUpdate } })?.Dispose(); }
        catch (System.ComponentModel.Win32Exception) { Error("Couldn't restart Token Vault. Close it and open it again to finish updating."); return; }
        closeConfirmed = true;
        Application.Current.Shutdown();
    }

    private void UpdateClose_Click(object sender, RoutedEventArgs e) => UpdateBar.Visibility = Visibility.Collapsed;

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
        if (idle && ProgressArea.Visibility == Visibility.Visible) { ProgressArea.Visibility = Visibility.Collapsed; Toast.Visibility = Visibility.Collapsed; }
    }

    // Short confirmations appear as a toast in the corner and fade on their own; while the game is starting, sign-in
    // messages go to the launch card instead.
    private void Status(string text, double? fraction = null, string? tone = null)
    {
        if (!Dispatcher.CheckAccess()) { Dispatcher.BeginInvoke(() => Status(text, fraction, tone)); return; }
        Log(text);
        if (launching && fraction is null) { LaunchDetail.Text = text; return; }
        StatusText.Text = text;
        StatusDot.Fill = Brush(tone ?? "Good");
        ProgressArea.Visibility = fraction is null ? Visibility.Collapsed : Visibility.Visible;
        if (fraction is double f)
        {
            Progress.Value = Math.Clamp(f, 0, 1);
            ProgressText.Text = $"{Math.Clamp(f, 0, 1):P0}";
        }
        Toast.Visibility = Visibility.Visible;
        toastTimer.Stop();
        toastTimer.Start();
    }

    private void ShowToast(string text) => Status(text);

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
        Toast.Visibility = Visibility.Collapsed;
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
