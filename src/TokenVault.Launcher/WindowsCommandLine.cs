using System.Text;

namespace TokenVault.Launcher;

// Quotes arguments with the rules CommandLineToArgvW / the MSVC runtime (and therefore java.exe) use to split them.
public static class WindowsCommandLine
{
    public static string Build(string executable, IEnumerable<string> arguments)
    {
        var line = new StringBuilder();
        Append(line, executable);
        foreach (string argument in arguments) { line.Append(' '); Append(line, argument); }
        if (line.Length >= 32767) throw new InvalidDataException("Java command line is too long.");
        return line.ToString();
    }

    private static void Append(StringBuilder line, string argument)
    {
        if (argument.Contains('\0')) throw new InvalidDataException("Arguments cannot contain NUL.");
        if (argument.Length > 0 && argument.IndexOfAny([' ', '\t', '\n', '\v', '"']) < 0) { line.Append(argument); return; }
        line.Append('"');
        for (int i = 0; i < argument.Length; i++)
        {
            int backslashes = 0;
            while (i < argument.Length && argument[i] == '\\') { backslashes++; i++; }
            if (i == argument.Length) { line.Append('\\', backslashes * 2); break; }
            if (argument[i] == '"') line.Append('\\', backslashes * 2 + 1).Append('"');
            else line.Append('\\', backslashes).Append(argument[i]);
        }
        line.Append('"');
    }
}
