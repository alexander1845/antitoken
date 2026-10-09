# Token Vault

**Play Minecraft with mods you don't fully trust, without risking your account.**

Most account thefts in modded Minecraft are simple: a mod reads the session token the game holds in
memory and sends it to someone else, who then plays as you, or worse, takes over your Microsoft
account. Token Vault is a Minecraft launcher for Windows that makes that impossible. The game and
every mod run in a Windows sandbox and never receive your real sign-in. Token Vault keeps it and
handles the parts of signing in that need it.

It uses your normal Windows account, has one Play button, and needs no second user and no official
launcher.

> **Status: 1.0, early release.** Tested end to end on Windows with vanilla and Fabric, including joining
> online-mode servers. Quilt, Forge and NeoForge are experimental. See [Limits](#what-it-doesnt-protect-against).

---

## Download and first run

1. Download **TokenVault-win-x64.zip** from the [latest release](../../releases/latest) and unzip it
   anywhere. Keep `AuthlibProbe.java` in the same folder as `TokenVault.exe`.
2. Run `TokenVault.exe`. Nothing else needs to be installed.
3. Press **Play**. The first time:
   * Windows asks once for administrator approval for the sandbox (see [below](#the-one-time-windows-prompt)).
   * Minecraft, its Java runtime and the mod loader download from Mojang and the loader's servers. Every
     file is checked against its published hash.
   * Your browser opens Microsoft's sign-in page. Your password only ever goes to Microsoft.
4. Add your servers under **Servers**. They appear in the game's Multiplayer list.

### "Windows protected your PC"

New programs that aren't signed by a publisher Windows recognises get this blue SmartScreen screen.
Click **More info → Run anyway**. Code-signed release builds don't show this screen
(see [Releasing](#releasing)). Until then the warning is expected, and you can check the build by
comparing it with the CI artifact or by building it yourself.

If **Smart App Control** is turned on, Windows blocks unsigned programs completely and has no "Run
anyway" option. You'll need a signed release.

## Features

* **One-click Play** for any Minecraft release from 1.8 onwards, vanilla or Fabric. Quilt, Forge and
  NeoForge are experimental.
* **Modpack import**: drag a Modrinth `.mrpack`, CurseForge `.zip`, Prism/MultiMC export, any
  `.zip`/`.7z`/`.rar`/`.tar` or loose `.jar` files onto the window. Each pack becomes its own instance.
  Sign-in files other launchers keep are never copied in.
* **Join approval**: before anything signs in to a server as you, Token Vault asks in its own window,
  which the game can't click.
* **Activity view**: every join, blocked join and blocked account request, in plain language.
* **Clipboard protection**: by default the game can't read what you copy, such as passwords from a
  password manager.

## How it protects you

```
 Token Vault (your Windows user)                    Windows sandbox (low integrity)
 ───────────────────────────────                    ───────────────────────────────
 your real sign-in, encrypted on disk               Java → Minecraft → every mod
 local API: 3 read-only calls  ◄─── fake token ──   can't read your files
 server login broker           ◄─── game traffic ─  can't read Token Vault's memory
```

1. **The game gets a fake token.** It is random and useless to anyone who steals it. The game's
   account requests go to Token Vault, which answers only three harmless read-only calls with your real
   token and refuses everything else, including name and skin changes.
2. **Token Vault signs in to servers itself.** The game connects to Token Vault, which does the
   encrypted login with the server and then passes the game traffic through. The server sees exactly
   the packets a normal client sends, and the added latency is negligible. A mod can't ask Token Vault
   to sign in to some other server, because the secret that ties a sign-in to a connection is generated
   and kept by Token Vault.
3. **The game runs in an AppContainer**, the Windows sandbox used for browser and Store apps. It can't
   read your documents, browser data or other launchers' sign-in files. It can't read Token Vault's
   memory, change files outside its game folders, or drive other windows.
4. **Your saved sign-in is encrypted** with AES-256-GCM under a key that is protected by your PC's
   **TPM** chip and Windows DPAPI. A copied file is useless on any other computer. Signing out destroys
   the key.

The full design, threat model and cryptographic analysis are in
[docs/CRYPTOGRAPHY.md](docs/CRYPTOGRAPHY.md).

### The one-time Windows prompt

Windows needs an administrator's approval once for three small changes that apply only to Token
Vault's sandbox:

* let it connect to Token Vault on this PC (`CheckNetIsolation LoopbackExempt`),
* let it see folder **names** at the top of your system drive, which Java needs,
* mark `C:\TokenVault` as a folder the sandbox may write to (a low integrity label; access is still
  limited by the folder's private permissions).

No account is created, no service is installed, and nothing else changes.

## What it doesn't protect against

* **What happens while you play.** A malicious mod controls the session you're in: it can chat, move,
  drop items or disconnect you, and sign chat messages. It can't take your account with it afterwards.
  Only play valuable accounts with mods you trust.
* **Malware already on your PC.** Programs running outside the sandbox as you (or as administrator) can
  read whatever you can. That's antivirus territory.
* **Playing the same mods elsewhere.** In another launcher those mods run unsandboxed.
* **Fake login screens.** Token Vault never asks for your password inside the game. Sign-in only happens
  in your browser, before the game starts.
* **Local services.** The sandbox can reach anything listening on `127.0.0.1` while you play.

## Where things are

| | |
|---|---|
| Game files, instances | `C:\TokenVault` (private to your Windows user) |
| Settings, saved sign-in, activity log | `%LOCALAPPDATA%\TokenVault\Data` (never shared with the game) |

To uninstall: delete those folders and `TokenVault.exe`. To also remove the sandbox's loopback
exemption, run `CheckNetIsolation LoopbackExempt -d -n=TokenVault.MinecraftSandbox` as administrator.

## Building from source

Requires the .NET 8 SDK or newer.

```powershell
dotnet build TokenVault.sln -c Release
dotnet run --project tests/TokenVault.Tests -c Release   # security regression suite
./scripts/Build.ps1                                       # tests + single-file exe in artifacts/TokenVault
```

| Project | Role |
|---|---|
| `TokenVault.App` | WPF window: library, Play, servers, security, settings |
| `TokenVault.Vault` | Microsoft sign-in, encrypted sign-in storage, local HTTPS API, server login broker |
| `TokenVault.Launcher` | Game installer, AppContainer sandbox, folder policy, Java truststore |
| `TokenVault.Packs` | Modpack and archive import |
| `TokenVault.Core` | Settings, Minecraft packet I/O and crypto, envelope encryption |

### Releasing

Push a tag such as `v1.0.0` and CI builds, tests and publishes a GitHub release with the zip attached.
To sign builds (which removes the "unknown publisher" warning), add two repository secrets:
`SIGNING_CERT_PFX_BASE64` (your code-signing certificate as base64) and `SIGNING_CERT_PASSWORD`.
Affordable options include an OV certificate from a CA, Microsoft's Azure Trusted Signing, or the free
SignPath Foundation programme for open-source projects. A new certificate still builds SmartScreen
reputation over the first downloads.

### Sign-in application ID

Microsoft sign-in needs a registered application ID. By default Token Vault uses the public ID that
Prism Launcher publishes, so Microsoft's consent page says "Prism Launcher". If you distribute your own
build, register your own app (personal Microsoft accounts, public client, redirect
`http://127.0.0.1:25597/`, Minecraft API approval) and set it under **Settings**.

## Documentation

* [CRYPTOGRAPHY.md](docs/CRYPTOGRAPHY.md): design, threat model, protocol analysis, verification
* [ALLOWLIST.md](docs/ALLOWLIST.md): exactly which account calls the game may make
* [ACCEPTANCE.md](docs/ACCEPTANCE.md): manual release checks
* [VALIDATION.md](docs/VALIDATION.md): what has been tested, and how

## License

MIT. Token Vault is not affiliated with Mojang or Microsoft. No Mojang, Microsoft, Fabric or JDK
binaries are included; they are downloaded from their publishers on first run.
