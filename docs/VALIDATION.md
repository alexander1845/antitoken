# Validation record — 2026-10-09

Target: Windows x64 launcher, Minecraft **26.1.2**, protocol **775**, Fabric example
loader **0.19.5**, Java **25**, Authlib **7.0.63**. Tests below were performed in a
Linux build environment. No Microsoft account credentials were supplied.

## Update — one-click Play, modpack import, WPF interface

| Check | Result | Scope |
|---|---|---|
| `dotnet build` of all six projects, warnings as errors | PASS | Windows 11, SDK 8.0.425 |
| Single-file `dotnet publish` (WPF, win-x64) | PASS | `TokenVault.exe` + `AuthlibProbe.java` |
| Mojang/Fabric metadata the installer depends on | Checked live | 26.1.2 manifest (Java component `java-runtime-epsilon`, asset index 30, Authlib 7.0.63 SHA-1 matches the pin), Fabric 0.19.5 profile JSON (libraries carry SHA-1) |
| New tests: `servers.dat` NBT, server address parsing, pack format detection, pack/installer path safety, version/loader refusal | Written, **not run locally** | Smart App Control blocks unsigned test DLLs on the dev PC; CI runs them |
| Installer download, sign-in with the built-in client ID, WPF window, pack downloads (Modrinth/CurseForge) | **NOT RUN** | Needs a run on a PC that allows the unsigned exe |
| CurseForge public download endpoint without an API key | **UNVERIFIED** | Files that fail are listed for manual download |

## Update — no second Windows account, AppContainer sandbox, GUI

The separate-user vault (installer script, alternate-credential host, named-pipe handoff,
cross-user ACL checks, console CLIs) was replaced by a single WinForms app. The game JVM
now runs in a Windows AppContainer with a job object, and the vault runs as the normal user.

| Check | Result | Scope |
|---|---|---|
| Full `dotnet build` of all five projects on Windows 11 | PASS | .NET SDK 8.0.425, MSBuild + analyzers, warnings as errors, 0 warnings |
| Self-contained single-file `dotnet publish` (win-x64) | PASS | Produces `TokenVault.exe` + `AuthlibProbe.java` |
| Regression test executable on that Windows PC | **NOT RUN** | Windows Smart App Control (on) refuses to load the freshly built unsigned test DLLs. The setting was not changed. CI runs the suite. |
| New test group: sandbox folder policy, Windows argument quoting, JKS format/digest | Written, not executed locally | Same reason; runs in CI |
| AppContainer process creation, loopback exemption, ACL/Low-label grants, job limits | **NOT RUN** | Not executed (would modify this PC's sandbox profiles/ACLs, and the unsigned exe is blocked). Needs ACCEPTANCE items 1, 7, 9 |
| Java 25 + LWJGL/OpenGL/OpenAL inside an AppContainer | **UNKNOWN** | Largest compatibility risk. GPU drivers or Java path canonicalization may misbehave in the sandbox. Failure mode: the game doesn't start, never an unsandboxed launch |

Earlier results below cover code (packet I/O, crypto, HTTPS boundary, broker) that this
change did not alter.

## Completed (earlier, Linux build environment)

| Check | Result | Scope |
|---|---|---|
| All four C# projects compiled | PASS | .NET 8.0.425 Roslyn compiler, C# 12, nullable checking and compiler warnings as errors; real MSAL 4.90.1 and .NET/AspNetCore references |
| Packet framing / compression / invalid input | PASS | Roundtrips at multiple lengths/thresholds; truncated, overflowing and oversized frames refused |
| Minecraft signed SHA-1 / continuous AES-CFB8 | PASS | Positive and negative hash vectors; independent Python/OpenSSL-compatible CFB8 vector; unaligned/chunked encryption |
| Fake JWT / refresh-only persistence filter | PASS | Unique fake JWTs, future expiry, access/ID-token removal, unknown-schema refusal; actual pinned MSAL cache serialization checked |
| OAuth callback boundary | PASS | Explicit 127.0.0.1 listener; wrong state denied; valid synthetic form POST accepted; missing PKCE refused |
| HTTPS vault API boundary | PASS | Self-signed TLS, correct fake-to-real canary substitution, all join aliases/name/skin mutations denied, caller URL/query refused, wrong fake denied, upstream error/redirect suppressed, literal secret response canary suppressed |
| Online broker integration | PASS | Local mock online server decrypts the broker's fresh RSA-wrapped secret and verifies its matching join hash; mock JVM does not see encryption request; Fabric query, compression, login ACK and 100 KB bidirectional encrypted relay succeed |
| Offline upstream | PASS | Broker refuses login success without online authentication; no authentication call issued |
| Installed profile resolution | PASS | Exact published 26.1.2 and Fabric manifests plus real client/Authlib JARs; library placeholders for layout validation; no game launch |
| Authlib custom environment / TLS | PASS | Real Authlib 7.0.63 and dependencies on JDK 25; shipped AuthlibProbe.java successfully fetches attributes from the real Kestrel boundary using a synthetic upstream |
| Missing truststore negative probe | PASS | The same Authlib probe fails without the vault certificate |
| Fake credential at real Mojang endpoint | PASS | A newly generated synthetic fake JWT sent once to the public join endpoint was rejected with HTTP 403; no real account/token used |
| Source whitespace / patch check | PASS | `git diff --check` |

Console security harness result: **7/7 test groups passed**. Fixture/profile and
real-JAR checks are additional checks, not extra claims about live gameplay.

The first CFB test caught platform buffering in .NET's built-in CFB transform.
The corrected stream uses platform AES as the block primitive with explicit
standard CFB8 state progression, then passes the independent vector and protocol
integration. The compatibility investigation also confirmed Authlib requires all
three custom hosts and that MSAL's default HttpListener uses `localhost`; the
literal-IPv4 OAuth adapter avoids that callback mismatch.

## Not completed / do not infer PASS

* Full SDK `dotnet restore/build/publish` was **not completed in this container**.
  The installed SDK CLI and MSBuild fail while reading Linux process metadata
  (`Process.StartTime` / `ProcessName`) before project execution. The four projects
  were instead compiled directly with that SDK's Roslyn compiler and their real
  framework/package assemblies. This validates C# compilation and runnable tests,
  but is not a substitute for Windows MSBuild/publish or SDK analyzer validation.
* Windows DPAPI encryption/decryption and refresh-token rotation across logins.
* Windows AppContainer launch, folder grants, loopback exemption and job behaviour
  (see the table above).
* A real Microsoft → Xbox → XSTS → Minecraft authentication using the user's
  approved application ID and account. Application approval cannot be granted by
  source code; XSTS error messages are implemented but not exercised on real accounts.
* A real **Fabric 26.1.2 game/UI launch** and join to a live online-mode Minecraft
  server with the user's mods, signed chat, resources and server plugins.
* Full JVM/launcher memory inspection against a real bearer-token canary on Windows.
* Exhaustive empirical endpoint coverage across actual gameplay/telemetry/mods.
* Independent security audit, performance qualification, or protection against
  arbitrary local gameplay control / item transfers.

Run [ACCEPTANCE.md](ACCEPTANCE.md) before treating this as a release. Windows/Linux
CI is configured but has not been executed on a remote runner in this task.

## Sources used to pin compatibility

* Mojang version manifest: https://piston-meta.mojang.com/mc/game/version_manifest_v2.json
* The official 26.1.2 client JAR's embedded `version.json`: protocol 775, Java 25.
* Official Authlib 7.0.63 artifact SHA-1:
  `54895b4e25e8b9b4cbbbe25f24eccf2b71b1ac2b`.
* https://www.minecraft.net/en-us/article/minecraft-java-edition-26-1-2
* https://fabricmc.net/2026/03/14/261.html
* https://meta.fabricmc.net/v2/versions/loader/26.1.2/0.19.5/profile/json
* https://github.com/PrismarineJS/minecraft-data/blob/master/data/pc/26.1/protocol.json
* https://learn.microsoft.com/en-us/dotnet/api/microsoft.identity.client.extensibility.icustomwebui.acquireauthorizationcodeasync
* https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata
* https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights

No proprietary game/runtime binaries, live credentials, private certificates,
account records, test process dumps or Microsoft account tokens are distributed
in the source package.
