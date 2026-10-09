using System.Windows;
using System.Windows.Threading;
using TokenVault.Core;

namespace TokenVault.App;

// Asks the player to approve a server sign-in. This window belongs to Token Vault (normal integrity); Windows' UIPI
// stops the sandboxed (low integrity) game from clicking it or sending it keys. Block is the safe default:
// Escape, closing the window, or the timeout all block.
public partial class JoinPrompt : Window
{
    private readonly TaskCompletionSource<bool> result = new();
    private readonly DispatcherTimer timer = new() { Interval = TimeSpan.FromSeconds(1) };
    private DateTime deadline;

    private JoinPrompt() => InitializeComponent();

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
        prompt.Closed += (_, _) => { registration.Dispose(); prompt.timer.Stop(); prompt.result.TrySetResult(false); };
        prompt.SourceInitialized += (_, _) => App.MatchTitleBar(prompt);
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

    private void Join_Click(object sender, RoutedEventArgs e) => Finish(true);
    private void Block_Click(object sender, RoutedEventArgs e) => Finish(false);
}
