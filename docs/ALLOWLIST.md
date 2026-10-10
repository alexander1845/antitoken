# JVM-facing API policy

Target: Minecraft 26.1.2, Authlib 7.0.63. This list is a restrictive implementation
policy, not a claim that every gameplay path has been observed on a live account.
The executable Authlib probe and manual acceptance procedure collect that evidence.

| Method and local path | Default | Upstream | Credential |
|---|---|---|---|
| GET /services/player/attributes | Allow | api.minecraftservices.com/player/attributes | Vault bearer |
| POST /services/player/certificates | Allow unless signed chat is off | api.minecraftservices.com/player/certificates | Vault bearer |
| GET /services/publickeys | Allow | api.minecraftservices.com/publickeys | None |
| GET /services/privileges | Allow (Minecraft 1.16.4–1.17) | api.minecraftservices.com/privileges | Vault bearer |
| GET /session/session/minecraft/profile/&lt;uuid&gt; | Allow (`?unsigned=true/false` only) | sessionserver.mojang.com/session/minecraft/profile/&lt;uuid&gt; | None |
| POST /session/session/minecraft/join | **Always 403** | None | None |
| POST /session/minecraft/join | **Always 403** | None | None |
| Name changes, skin changes, telemetry, entitlements, all other paths/methods | **403** | None | None |

The extra `/session` in the first join path is intentional: Authlib appends
`/session/minecraft/join` to the configured session base `/session`.

The game connects to the local Minecraft-protocol broker. The broker handles
online authentication itself, so legitimate gameplay does not need an HTTP join
endpoint. Only the broker's internal code can call Mojang's real join endpoint.

`Allowlist` in configuration can only REMOVE permissions from the compiled ceiling.
It cannot add join, wildcard routes, alternate hosts, redirects or methods.
No request bodies, query strings, cookies, arbitrary headers or destination URLs
are forwarded. The certificate POST is rebuilt with an empty JSON object.
Only successful bodies are returned; no upstream headers or error bodies escape.
A response containing the real bearer token is refused and its buffer erased.

Certificate responses contain a profile/chat private signing key. The JVM needs
that key for signed chat. It is not the Minecraft bearer token and does not
replace online-mode join authentication. A malicious mod can copy it and sign
chat as the player until it expires (about two days). Turning "Signed chat" off
on the Protection panel removes this route from the effective list.

Every request, including one with a wrong bearer, counts toward a limit of 120
per minute.

Observation mode still enforces the identical policy. Denied routes remain denied;
there is intentionally no permissive training mode using real credentials.
Logs contain time, method, classified/sanitized endpoint and broker state, never
Authorization headers, request/response bodies, fake tokens, real tokens or join
hashes. This observes the vault only, not every network request made by a mod.

To extend the policy: reproduce a missing operation on a test account, inspect
its semantics and response, add a fixed mapping plus an adversarial test, and
review the change. Seeing traffic is not sufficient evidence that an operation is safe.
