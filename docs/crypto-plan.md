# Crypto and Auth Plan

This driver should be source-led, not discovered by poking Apple TVs and hoping
the result is stable. There are two authorities for this layer:

- Snap One DriverWorks documentation tells us what Lua/runtime capabilities are
  available inside Control4.
- Local pyatv source tells us the exact Apple Companion/HAP protocol flow.

## What DriverWorks Gives Us

DriverWorks documents high-level crypto APIs such as `C4:Hash`, `C4:HMAC`,
`C4:PBKDF2`, `C4:Encrypt`, and `C4:Decrypt`. For lower-level crypto, OS 3.4.1
adds a modified `lua-openssl` interface. The SDK's `lua-openssl` section also
documents important removals:

- socket APIs are removed from OpenSSL BIO/SSL; Control4 networking should use
  documented TCP/network interfaces instead.
- `ec`, `rsa`, and other deprecated direct modules are replaced by `pkey`.
- `srp` is removed and the documentation says there is no replacement.

That means Pair-Setup cannot be treated as a small wrapper around a built-in SRP
module. It needs a real SRP implementation decision.

## What pyatv Tells Us

For Companion, pyatv uses HAP credentials and HAP pairing:

- Pair-Setup starts with a `PS_Start` frame containing TLV8 `{Method: 0,
  SeqNo: 1}` and `_pwTy = 1`.
- Pair-Setup then uses SRP-3072/SHA512 with username `Pair-Setup` and the
  on-screen PIN.
- Pair-Verify uses X25519, Ed25519 signatures, HKDF-SHA512, and
  ChaCha20-Poly1305 with HAP's eight-byte nonce convention.
- Companion credentials serialize as four colon-separated hex fields:
  `ltpk:ltsk:atv_id:client_id`.
- App launch uses encrypted OPACK `_launchApp` requests containing either
  `_bundleID` or `_urlS`.

## Implementation Order

1. Support imported pyatv HAP credentials first.
   This lets the driver verify an existing pairing and run an encrypted
   Companion session without solving native SRP immediately.

2. Implement a `Crypto` adapter around documented Control4 primitives.
   The adapter should expose random bytes, HMAC-SHA512/HKDF-SHA512, X25519,
   Ed25519 sign/verify, and ChaCha20-Poly1305. If an operation depends on
   `lua-openssl`, it should live behind this adapter so local tests can use
   fixtures or a reference implementation. The first provider implementation is
   `OpenSSLCrypto`, which wraps raw HAP keys as RFC 8410 DER keys for
   `lua-openssl` and uses documented `pkey`, `cipher`, and `C4:HMAC` calls.
   It should fail loudly at the exact primitive if Control4's runtime differs
   from the documented API; it should not iterate through undocumented call
   shapes.

3. Implement Pair-Verify and encrypted Companion frames.
   Pair-Verify is the fastest route to a serverless driver when credentials are
   imported from pyatv.

4. Add native Pair-Setup only after SRP is deliberately solved.
   The driver now has an experimental pure-Lua SRP-3072/SHA512 implementation
   for Pair-Setup. It is pinned to deterministic vectors generated from
   pyatv's `srptools` dependency, but imported credentials remain the safer
   hardware path until native pairing passes controller validation.

## Testing Without Guessing

- Lua unit tests validate frame/TLV8/OPACK output against pyatv-generated golden
  vectors.
- Credential parse/stringify tests validate pyatv's on-disk credential format.
- Crypto adapter tests should use deterministic vectors from pyatv source or
  generated locally from pyatv, not live-device observations.
- SRP tests compare `x`, `A`, `u`, `K`, M1, and M2 verification against
  deterministic `srptools` vectors.
- Composer exposes a single `Prewarm Crypto` action for installer use after
  pairing. Lower-level crypto diagnostics should stay in tests or debug builds,
  not in the normal commissioning flow.
- A real Apple TV test is reserved for final compatibility: verify credentials,
  start the Companion session, fetch apps, and launch one known bundle id.
