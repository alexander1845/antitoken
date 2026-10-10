using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using TokenVault.Core;

namespace TokenVault.App;

// Asks the player to approve a server sign-in. This window belongs to Token Vault (normal integrity); Windows' UIPI
// stops the sandboxed (low integrity) game from clicking it or sending it keys. Block is the safe default:
// Escape, closing the window, or the timeout all block.
// The game can still choose WHEN this window appears, and so line it up under a click the player is about to make
// (an in-game button drawn where Join will be). So Join only works after the window has been visible and active for a
// moment, and the window's position and button order vary, so a click aimed in advance doesn't land on Join.
public partial class JoinPrompt : Window
{
    private readonly TaskCompletionSource<bool> result = new();
    private readonly DispatcherTimer timer = new() { Interval = TimeSpan.FromSeconds(1) };
    private readonly DispatcherTimer arm = new() { Interval = TimeSpan.FromMilliseconds(1200) };
    private static readonly Random Placement = new();
    private DateTime deadline;

    private JoinPrompt()
    {
        InitializeComponent();
        arm.Tick += (_, _) => { arm.Stop(); if (IsActive) JoinButton.IsEnabled = true; };
        Activated += (_, _) => { JoinButton.IsEnabled = false; arm.Stop(); arm.Start(); };
        Deactivated += (_, _) => { JoinButton.IsEnabled = false; arm.Stop(); };
        Loaded += (_, _) => Place();
        if (Placement.Next(2) == 0) { Grid.SetColumn(JoinButton, 0); Grid.SetColumn(BlockButton, 2); }
    }

    // Somewhere near the middle of the screen, not at a fixed spot.
    private void Place()
    {
        var area = SystemParameters.WorkArea;
        double dx = Placement.Next(-220, 221), dy = Placement.Next(-160, 161);
        Left = Math.Max(area.Left, Math.Min(area.Left + (area.Width - ActualWidth) / 2 + dx, area.Right - ActualWidth));
        Top = Math.Max(area.Top, Math.Min(area.Top + (area.Height - ActualHeight) / 2 + dy, area.Bottom - ActualHeight));
    }

    public static Task<bool> AskAsync(ServerEntry server, string player, CancellationToken ct)
    {
        var prompt = new JoinPrompt();
        prompt.ServerTile.Background = Tiles.For(server.Host);
        prompt.ServerInitial.Text = Tiles.Initial(server.Name);
        prompt.Heading.Text = $"Join {server.Name}?";
        prompt.Detail.Text = $"{(server.Port == 25565 ? server.Host : $"{server.Host}:{server.Port}")}  ·  as {player}";
        prompt.deadline = DateTime.UtcNow.AddSeconds(25);
        prompt.Tick();
        prompt.timer.Tick += (_, _) => prompt.Tick();
        prompt.timer.Start();
        var registration = ct.Register(() => prompt.Dispatcher.BeginInvoke(() => prompt.Finish(false)));
        prompt.Closed += (_, _) => { registration.Dispose(); prompt.timer.Stop(); prompt.arm.Stop(); prompt.result.TrySetResult(false); };
        prompt.SourceInitialized += (_, _) => { App.MatchTitleBar(prompt); App.RoundCorners(prompt); };
        prompt.Show();
        prompt.Activate();
        prompt.BlockButton.Focus();
        return prompt.result.Task;
    }

    private void Tick()
    {
        int left = (int)Math.Ceiling((deadline - DateTime.UtcNow).TotalSeconds);
        if (left <= 0) { Finish(false); return; }
        Countdown.Text = $"Blocks automatically in {left} s.";
    }

    private void Finish(bool join)
    {
        result.TrySetResult(join);
        if (IsLoaded) Close();
    }

    private void Join_Click(object sender, RoutedEventArgs e) { if (JoinButton.IsEnabled && IsActive) Finish(true); }
    private void Block_Click(object sender, RoutedEventArgs e) => Finish(false);
}
