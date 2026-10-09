using System.Diagnostics;
using Microsoft.Identity.Client;
using TokenVault.Core;
using TokenVault.Launcher;
using TokenVault.Vault;

namespace TokenVault.App;

internal sealed class MainForm : Form
{
    private Configuration config = new();
    private MinecraftIdentity? identity;
    private GameSandbox? sandbox;
    private CancellationTokenSource? running;

    private readonly Label accountStatus = new() { AutoSize = true, Anchor = AnchorStyles.Left };
    private readonly Button signIn = new() { Text = "Sign in", AutoSize = true };
    private readonly Button signOut = new() { Text = "Sign out", AutoSize = true };
    private readonly TextBox server = new() { Dock = DockStyle.Fill, PlaceholderText = "play.example.net" };
    private readonly NumericUpDown serverPort = new() { Minimum = 1, Maximum = 65535, Value = 25565, Width = 80 };
    private readonly ComboBox profile = new() { Dock = DockStyle.Fill, DropDownStyle = ComboBoxStyle.DropDown };
    private readonly TextBox minecraftDirectory = new() { Dock = DockStyle.Fill };
    private readonly TextBox instanceDirectory = new() { Dock = DockStyle.Fill };
    private readonly TextBox modsDirectory = new() { Dock = DockStyle.Fill };
    private readonly TextBox javaPath = new() { Dock = DockStyle.Fill, PlaceholderText = "Automatic (Java from the official launcher)" };
    private readonly NumericUpDown memory = new() { Minimum = 512, Maximum = 65536, Increment = 512, Value = 4096, Width = 80 };
    private readonly TextBox clientId = new() { Dock = DockStyle.Fill };
    private readonly CheckBox clipboard = new() { AutoSize = true, Text = "Let the game use the clipboard (copy/paste in chat)" };
    private readonly CheckBox remember = new() { AutoSize = true, Text = "Remember my sign-in on this PC (encrypted for my Windows user)" };
    private readonly Label sandboxStatus = new() { AutoSize = true, Anchor = AnchorStyles.Left };
    private readonly Button allowNetwork = new() { Text = "Allow (one-time admin prompt)", AutoSize = true };
    private readonly Button play = new() { Text = "Play", AutoSize = true, MinimumSize = new Size(140, 40) };
    private readonly Button stop = new() { Text = "Stop game", AutoSize = true, MinimumSize = new Size(100, 40), Enabled = false };
    private readonly TextBox log = new() { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical };
    private readonly List<Control> settings = [];

    public MainForm()
    {
        Text = "Token Vault — sandboxed Minecraft 26.1.2 + Fabric";
        ClientSize = new Size(820, 760);
        MinimumSize = new Size(640, 600);
        StartPosition = FormStartPosition.CenterScreen;
        Font = new Font("Segoe UI", 9.5f);

        var grid = new TableLayoutPanel { Dock = DockStyle.Top, AutoSize = true, ColumnCount = 3, Padding = new Padding(12, 8, 12, 0) };
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));

        Heading(grid, "Account");
        Row(grid, "Status", accountStatus, Buttons(signIn, signOut));
        Heading(grid, "Game");
        Row(grid, "Server", server, Buttons(new Label { Text = "Port", AutoSize = true, Anchor = AnchorStyles.Left }, serverPort), true);
        Row(grid, "Fabric profile", profile, Buttons(Button("Refresh", (_, _) => RefreshProfiles())), true);
        Row(grid, "Minecraft folder", minecraftDirectory, Buttons(Button("Browse…", (_, _) => BrowseFolder(minecraftDirectory))), true);
        Row(grid, "Instance folder", instanceDirectory, Buttons(Button("Browse…", (_, _) => BrowseFolder(instanceDirectory))), true);
        Row(grid, "Mods folder", modsDirectory, Buttons(Button("Browse…", (_, _) => BrowseFolder(modsDirectory)), Button("Open", (_, _) => OpenModsFolder())), true);
        Row(grid, "Java 25", javaPath, Buttons(Button("Browse…", (_, _) => BrowseJava()), Button("Detect", (_, _) => DetectJava())), true);
        Row(grid, "Memory (MB)", memory, null, true);
        Row(grid, "", clipboard, null, true);
        Row(grid, "", remember, null, true);
        Heading(grid, "Sandbox");
        Row(grid, "Networking", sandboxStatus, Buttons(allowNetwork));
        Heading(grid, "Advanced");
        Row(grid, "Microsoft app ID", clientId, Buttons(Button("Security info", (_, _) => ShowSecurityInfo())), true);

        var actions = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, Padding = new Padding(12, 10, 12, 6) };
        actions.Controls.AddRange([play, stop]);
        var logPanel = new Panel { Dock = DockStyle.Fill, Padding = new Padding(12, 0, 12, 12) };
        logPanel.Controls.Add(log);
        Controls.Add(logPanel);
        Controls.Add(actions);
        Controls.Add(grid);

        play.Font = new Font(Font.FontFamily, 11f, FontStyle.Bold);
        play.Click += async (_, _) => await PlayAsync();
        stop.Click += (_, _) => running?.Cancel();
        signIn.Click += async (_, _) => await SignInAsync();
        signOut.Click += (_, _) => SignOut();
        allowNetwork.Click += async (_, _) => await AllowNetworkAsync(ask: false);
        Load += (_, _) => Initialize();
        FormClosing += (_, e) =>
        {
            if (running is null) return;
            if (MessageBox.Show(this, "Closing Token Vault also closes Minecraft. Close anyway?", "Token Vault",
                    MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) { e.Cancel = true; return; }
            running.Cancel(); // the job object also kills the game when this process ends
        };
    }

    private void Initialize()
    {
        try
        {
            PrivateDirectory.Ensure(AppPaths.Data);
            config = Configuration.LoadOrDefault(AppPaths.Config);
        }
        catch (Exception ex) when (ex is InvalidDataException or System.Text.Json.JsonException)
        {
            Log("Settings file was invalid; using defaults.");
            config = new Configuration();
        }
        catch (Exception ex) { Fail(ex); }
        try { JavaLauncher.CleanStaleRuns(); } catch (IOException) { }
        WriteUi(config);
        RefreshProfiles();
        RefreshAccount();
        try { sandbox = GameSandbox.Open(); } catch (Exception ex) { Fail(ex); }
        RefreshSandbox();
        Log("Ready. Mods run in a Windows sandbox; your Microsoft/Minecraft tokens stay in this window's process only.");
    }

    // ---------- Play / stop

    private async Task PlayAsync()
    {
        Configuration c;
        try { c = ReadUi(); c.Save(AppPaths.Config); config = c; }
        catch (Exception ex) { Fail(ex); return; }
        if (string.IsNullOrWhiteSpace(c.ServerHost)) { Warn("Enter the server address first."); return; }
        if (!Guid.TryParse(c.ClientId, out _)) { Warn("Enter your approved Microsoft application (client) ID under Advanced. See README."); return; }

        using var cts = new CancellationTokenSource();
        running = cts;
        SetState(busy: true, gameRunning: false);
        try
        {
            sandbox ??= GameSandbox.Open();
            if (sandbox.HasLoopbackExemption() == false && !await AllowNetworkAsync(ask: true)) return;
            var id = await EnsureSignedInAsync(c, cts.Token);
            await using var session = await VaultSession.StartAsync(c, id, AppPaths.AuditLog, cts.Token);
            Log($"Vault running for {id.Profile.Name}; the game gets a fake token and can only reach {c.ServerHost}:{c.ServerPort} through Token Vault.");
            SetState(busy: true, gameRunning: true);
            int code = await JavaLauncher.LaunchAsync(c, session.Descriptor, sandbox, Log, cts.Token);
            Log(code == 0 ? "Minecraft closed." : $"Minecraft exited with code {code}. See logs\\latest.log in the instance folder.");
        }
        catch (OperationCanceledException) when (cts.IsCancellationRequested) { Log("Game stopped."); }
        catch (Exception ex) { Fail(ex); }
        finally
        {
            running = null;
            SetState(busy: false, gameRunning: false);
            RefreshAccount();
        }
    }

    // ---------- Account

    private async Task<MinecraftIdentity> EnsureSignedInAsync(Configuration c, CancellationToken ct)
    {
        if (identity is { } current && current.ExpiresAt > DateTimeOffset.UtcNow.AddMinutes(15)) return current;
        identity?.Dispose();
        identity = null;
        var cache = new RefreshCache(AppPaths.RefreshCache);
        if (!c.RememberSignIn && cache.Exists) cache.Delete();
        Log(cache.Exists ? "Using your saved sign-in…" : "Opening your browser to sign in with Microsoft…");
        // Sign-in only happens while no game is running, so no mod is alive while the browser flow is open.
        identity = await OAuthLogin.LoginAsync(c, c.RememberSignIn ? cache.Attach : null, ct);
        Log($"Signed in as {identity.Profile.Name}.");
        return identity;
    }

    private async Task SignInAsync()
    {
        Configuration c;
        try { c = ReadUi(); c.Save(AppPaths.Config); config = c; }
        catch (Exception ex) { Fail(ex); return; }
        if (!Guid.TryParse(c.ClientId, out _)) { Warn("Enter your approved Microsoft application (client) ID under Advanced. See README."); return; }
        using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(12));
        SetState(busy: true, gameRunning: false);
        try { await EnsureSignedInAsync(c, cts.Token); }
        catch (Exception ex) { Fail(ex); }
        finally { SetState(busy: false, gameRunning: false); RefreshAccount(); }
    }

    private void SignOut()
    {
        identity?.Dispose();
        identity = null;
        try { new RefreshCache(AppPaths.RefreshCache).Delete(); }
        catch (Exception ex) { Fail(ex); }
        Log("Signed out on this PC. To revoke this app's access at Microsoft too, remove it at account.live.com/consent/Manage.");
        RefreshAccount();
    }

    private void RefreshAccount()
    {
        accountStatus.Text = identity is not null ? $"Signed in as {identity.Profile.Name}"
            : File.Exists(AppPaths.RefreshCache) ? "Saved sign-in on this PC (used when you press Play)"
            : "Not signed in (your browser opens when you press Play)";
        signOut.Enabled = running is null && (identity is not null || File.Exists(AppPaths.RefreshCache));
    }

    // ---------- Sandbox networking

    private async Task<bool> AllowNetworkAsync(bool ask)
    {
        if (sandbox is null) return false;
        if (ask && MessageBox.Show(this,
                "Minecraft runs in a Windows sandbox that, by default, cannot reach Token Vault on this PC (127.0.0.1).\n\n" +
                "Windows needs administrator approval ONCE to allow local connections for this sandbox only. " +
                "No other setting is changed and no extra Windows account is created.\n\nContinue?",
                "Allow sandbox networking", MessageBoxButtons.OKCancel, MessageBoxIcon.Information) != DialogResult.OK)
            return false;
        bool ok = await sandbox.RequestLoopbackExemptionAsync();
        Log(ok ? "Sandbox networking allowed." : "Sandbox networking is not allowed yet; the game cannot start without it.");
        RefreshSandbox();
        return ok;
    }

    private void RefreshSandbox()
    {
        bool? ok = sandbox?.HasLoopbackExemption();
        sandboxStatus.Text = sandbox is null ? "Sandbox unavailable" : ok switch
        {
            true => "Ready",
            false => "Needs one-time approval",
            null => "Unknown (use Allow if the game cannot connect)"
        };
        allowNetwork.Visible = sandbox is not null && ok != true;
    }

    // ---------- Settings

    private void WriteUi(Configuration c)
    {
        server.Text = c.ServerHost;
        serverPort.Value = c.ServerPort;
        profile.Text = c.FabricProfile;
        minecraftDirectory.Text = c.MinecraftDirectory;
        instanceDirectory.Text = c.GameDirectory;
        modsDirectory.Text = c.ModsDirectory;
        javaPath.Text = c.JavaPath;
        memory.Value = Math.Clamp(c.MemoryMb, 512, 65536);
        clientId.Text = Guid.TryParse(c.ClientId, out _) ? c.ClientId : "";
        clipboard.Checked = c.AllowClipboard;
        remember.Checked = c.RememberSignIn;
    }

    private Configuration ReadUi()
    {
        var c = Configuration.LoadOrDefault(AppPaths.Config); // keeps advanced values (ports, allowlist) from the file
        c.ServerHost = server.Text.Trim();
        c.ServerPort = (int)serverPort.Value;
        c.FabricProfile = profile.Text.Trim();
        c.MinecraftDirectory = minecraftDirectory.Text.Trim();
        c.GameDirectory = instanceDirectory.Text.Trim();
        c.ModsDirectory = modsDirectory.Text.Trim();
        c.JavaPath = javaPath.Text.Trim();
        c.MemoryMb = (int)memory.Value;
        c.ClientId = clientId.Text.Trim();
        c.AllowClipboard = clipboard.Checked;
        c.RememberSignIn = remember.Checked;
        c.Validate();
        return c;
    }

    private void RefreshProfiles()
    {
        string current = profile.Text;
        profile.Items.Clear();
        try
        {
            string versions = Path.Combine(Configuration.Expand(minecraftDirectory.Text), "versions");
            if (Directory.Exists(versions))
                foreach (string name in Directory.EnumerateDirectories(versions).Select(Path.GetFileName).OfType<string>()
                             .Where(n => n.StartsWith("fabric-loader-", StringComparison.Ordinal) && n.EndsWith("-" + config.MinecraftVersion, StringComparison.Ordinal)).Order())
                    profile.Items.Add(name);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException) { }
        profile.Text = profile.Items.Count == 0 || profile.Items.Contains(current) ? current : (string)profile.Items[^1]!;
        if (profile.Items.Count == 0) Log("No Fabric 26.1.2 profile found. Install Fabric for 26.1.2 with the Fabric installer, then press Refresh.");
    }

    private void BrowseFolder(TextBox target)
    {
        using var dialog = new FolderBrowserDialog { UseDescriptionForTitle = true, Description = "Choose a folder", ShowNewFolderButton = true };
        try { dialog.InitialDirectory = Configuration.Expand(target.Text); } catch (ArgumentException) { }
        if (dialog.ShowDialog(this) == DialogResult.OK) target.Text = dialog.SelectedPath;
        if (target == minecraftDirectory) RefreshProfiles();
    }

    private void BrowseJava()
    {
        using var dialog = new OpenFileDialog { Filter = "java.exe|java.exe", Title = "Choose Java 25 (java.exe)" };
        if (dialog.ShowDialog(this) == DialogResult.OK) javaPath.Text = dialog.FileName;
    }

    private void DetectJava()
    {
        try
        {
            var c = ReadUi();
            c.JavaPath = "";
            string? found = JavaLocator.Find(c);
            if (found is null) Warn("No Java 25 found. Start Minecraft 26.1.2 once in the official launcher, or install a Java 25 JDK.");
            else { javaPath.Text = ""; Log("Detected Java: " + found + (JavaLocator.IsJdk(found) ? " (JDK)" : " (runtime)")); }
        }
        catch (Exception ex) { Fail(ex); }
    }

    private void OpenModsFolder()
    {
        try
        {
            string path = Directory.CreateDirectory(Configuration.Expand(modsDirectory.Text)).FullName;
            Process.Start(new ProcessStartInfo("explorer.exe") { ArgumentList = { path } })?.Dispose();
        }
        catch (Exception ex) { Fail(ex); }
    }

    private void ShowSecurityInfo() => MessageBox.Show(this,
        "What Token Vault protects:\n" +
        "• Your Microsoft refresh token and Minecraft access token never enter the game. The game gets a fake token that Mojang rejects.\n" +
        "• Minecraft and all mods run in a Windows AppContainer sandbox: they cannot read your other files (browser cookies, " +
        "the official launcher's sign-in, Token Vault's saved sign-in), cannot read Token Vault's memory, and can only write to the instance folder.\n" +
        "• Joining a server is done by Token Vault itself, only for the server you configured. The game cannot ask it to log in anywhere else.\n\n" +
        "What it cannot stop:\n" +
        "• A malicious mod can still act inside the game you are playing (chat, items, disconnecting) and use your chat-signing key.\n" +
        "• Malware running outside the sandbox as your Windows user (or as admin) can read anything you can.\n" +
        "• Running the same mods through another launcher removes this protection.",
        "Security", MessageBoxButtons.OK, MessageBoxIcon.Information);

    // ---------- UI helpers

    private void SetState(bool busy, bool gameRunning)
    {
        if (IsDisposed) return;
        if (InvokeRequired) { BeginInvoke(() => SetState(busy, gameRunning)); return; }
        play.Enabled = !busy;
        stop.Enabled = gameRunning;
        signIn.Enabled = !busy;
        signOut.Enabled = !busy && (identity is not null || File.Exists(AppPaths.RefreshCache));
        allowNetwork.Enabled = !busy;
        foreach (var control in settings) control.Enabled = !busy;
    }

    private void Log(string message)
    {
        if (IsDisposed) return;
        if (InvokeRequired) { BeginInvoke(() => Log(message)); return; }
        log.AppendText($"{DateTime.Now:HH:mm:ss}  {message}{Environment.NewLine}");
    }

    private void Warn(string message)
    {
        Log(message);
        MessageBox.Show(this, message, "Token Vault", MessageBoxButtons.OK, MessageBoxIcon.Warning);
    }

    private void Fail(Exception ex)
    {
        string message = Describe(ex);
        Log("Error: " + message);
        MessageBox.Show(this, message, "Token Vault", MessageBoxButtons.OK, MessageBoxIcon.Error);
    }

    // Never shows arbitrary exception text: library messages can contain account details or request data.
    private static string Describe(Exception ex) => ex switch
    {
        UserVisibleException or InvalidDataException or FileNotFoundException or DirectoryNotFoundException => ex.Message,
        MsalException msal => $"Microsoft sign-in failed ({msal.ErrorCode}).",
        System.Net.Sockets.SocketException { SocketErrorCode: System.Net.Sockets.SocketError.AddressAlreadyInUse } or
            IOException { InnerException: Microsoft.AspNetCore.Connections.AddressInUseException } =>
            "A Token Vault port is already in use. Close other programs using ports 25597–25599, or change them in config.json.",
        HttpRequestException => "Network error while contacting Microsoft/Minecraft services.",
        _ => $"Operation failed ({ex.GetType().Name})."
    };

    private void Heading(TableLayoutPanel grid, string text)
    {
        var label = new Label { Text = text, AutoSize = true, Font = new Font(Font, FontStyle.Bold), Margin = new Padding(0, 12, 0, 4) };
        grid.Controls.Add(label);
        grid.SetColumnSpan(label, 3);
    }

    private void Row(TableLayoutPanel grid, string label, Control field, Control? buttons, bool setting = false)
    {
        grid.Controls.Add(new Label { Text = label, AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(0, 6, 8, 6) });
        grid.Controls.Add(field);
        if (buttons is not null) grid.Controls.Add(buttons); else grid.Controls.Add(new Label { AutoSize = true });
        if (setting) { settings.Add(field); if (buttons is not null) settings.Add(buttons); }
    }

    private static FlowLayoutPanel Buttons(params Control[] controls)
    {
        var panel = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = Padding.Empty };
        panel.Controls.AddRange(controls);
        return panel;
    }

    private static Button Button(string text, EventHandler click)
    {
        var button = new Button { Text = text, AutoSize = true };
        button.Click += click;
        return button;
    }
}
