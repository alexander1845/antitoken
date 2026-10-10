using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace TokenVault.Launcher;

// Keeps the mouse inside the game window while the game wants it captured.
//
// Minecraft (GLFW) captures the mouse in-game by hiding the cursor and confining it to its window with ClipCursor.
// Windows refuses ClipCursor and SetCursorPos to the sandbox (they need write access to the window station, which a
// low-integrity AppContainer doesn't get), so the hidden cursor drifted off the window and clicks landed on whatever
// was underneath. Token Vault does the confining instead: only while a window of the game's own job is in front and
// has hidden the cursor, and only to that window's client area. It lets go as soon as a menu shows the cursor, another
// window comes to the front or the game ends. The sandbox gains nothing; this is what an unsandboxed game does itself.
[SupportedOSPlatform("windows")]
public sealed class CursorLock : IDisposable
{
    private readonly SandboxedProcess game;
    private readonly CancellationTokenSource stop = new();
    private readonly Thread thread;
    private IntPtr lastWindow;
    private bool lastWindowIsGame;

    private CursorLock(SandboxedProcess game)
    {
        this.game = game;
        thread = new Thread(Run) { IsBackground = true, Name = "Token Vault cursor lock", Priority = ThreadPriority.AboveNormal };
        thread.Start();
    }

    public static CursorLock Start(SandboxedProcess game) => new(game);

    private void Run()
    {
        // Physical pixels throughout, whatever the monitors' scaling.
        SetThreadDpiAwarenessContext(new IntPtr(-4) /* PER_MONITOR_AWARE_V2 */);
        bool clipped = false;
        try
        {
            while (!stop.IsCancellationRequested)
            {
                if (Wanted(out var area))
                {
                    // Re-applied when it changed or something else (alt-tab, a UAC prompt) reset it.
                    if (!clipped || !GetClipCursor(out var current) || !current.Equals(area)) ClipCursor(ref area);
                    clipped = true;
                }
                else if (clipped)
                {
                    ClipCursor(IntPtr.Zero);
                    clipped = false;
                }
                stop.Token.WaitHandle.WaitOne(clipped ? 50 : 10);
            }
        }
        finally { if (clipped) ClipCursor(IntPtr.Zero); }
    }

    // The game's window is in front, not minimised, and has hidden the cursor (GLFW's "disabled" mode, i.e. in-game).
    private bool Wanted(out Rect area)
    {
        area = default;
        IntPtr window = GetForegroundWindow();
        if (window == IntPtr.Zero || IsIconic(window)) return false;
        if (window != lastWindow)
        {
            lastWindow = window;
            lastWindowIsGame = GetWindowThreadProcessId(window, out uint pid) != 0 && game.Contains((int)pid);
        }
        if (!lastWindowIsGame) return false;
        var cursor = new CursorInfo { Size = Marshal.SizeOf<CursorInfo>() };
        if (!GetCursorInfo(ref cursor) || (cursor.Cursor != IntPtr.Zero && (cursor.Flags & 1 /* CURSOR_SHOWING */) != 0)) return false;
        if (!GetClientRect(window, out var client)) return false;
        var origin = new Point();
        if (!ClientToScreen(window, ref origin)) return false;
        area = new Rect { Left = origin.X, Top = origin.Y, Right = origin.X + client.Right, Bottom = origin.Y + client.Bottom };
        // Only while the cursor is actually over the game, so a cursor hidden elsewhere is never pulled in.
        return client.Right > 0 && client.Bottom > 0 && cursor.Position.X >= area.Left && cursor.Position.X < area.Right &&
               cursor.Position.Y >= area.Top && cursor.Position.Y < area.Bottom;
    }

    public void Dispose()
    {
        stop.Cancel();
        thread.Join(TimeSpan.FromSeconds(2));
        stop.Dispose();
    }

    [StructLayout(LayoutKind.Sequential)] private struct Point { public int X, Y; }
    [StructLayout(LayoutKind.Sequential)] private struct Rect { public int Left, Top, Right, Bottom; }
    [StructLayout(LayoutKind.Sequential)] private struct CursorInfo { public int Size, Flags; public IntPtr Cursor; public Point Position; }

    [DllImport("user32.dll")] private static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] private static extern bool IsIconic(IntPtr window);
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr window, out uint processId);
    [DllImport("user32.dll")] private static extern bool GetCursorInfo(ref CursorInfo info);
    [DllImport("user32.dll")] private static extern bool GetClientRect(IntPtr window, out Rect rect);
    [DllImport("user32.dll")] private static extern bool ClientToScreen(IntPtr window, ref Point point);
    [DllImport("user32.dll")] private static extern bool ClipCursor(ref Rect rect);
    [DllImport("user32.dll")] private static extern bool ClipCursor(IntPtr rect);
    [DllImport("user32.dll")] private static extern bool GetClipCursor(out Rect rect);
    [DllImport("user32.dll")] private static extern IntPtr SetThreadDpiAwarenessContext(IntPtr context);
}
