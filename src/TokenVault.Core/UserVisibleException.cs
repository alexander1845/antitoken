namespace TokenVault.Core;

// Only developer-written messages; never construct this with upstream body text.
public sealed class UserVisibleException(string message) : Exception(message);
