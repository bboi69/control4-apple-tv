# Control4 Apple TV Driver

This workspace is for a self-contained Control4 Lua driver that replaces a
pyatv-backed web server. The target is not full pyatv parity. The target is a
Control4-native Apple TV driver with Universal Minidriver "mini app" support.

## Scope

Primary protocol:

- Apple TV Companion protocol

Primary features:

- Pair and verify with Apple TV
- Persist credentials in Control4
- Fetch launchable app list
- Launch apps by bundle id or deep-link URL
- Route Universal Minidriver selections to Apple TV `_launchApp`
- Route Control4 remote commands to Apple TV `_hidC`

Out of scope:

- AirPlay streaming
- RAOP
- Full MRP parity
- Legacy Apple TV 2/3 DMAP support

## Files

- `driver.lua` - Control4 driver scaffold and testable Apple TV protocol core
- `driver.xml` - initial Control4 package definition with media player and mini-app switcher proxies
- `driver.c4zproj` - DriverPackager project file matching SDK sample structure
- `tests/test_driver.lua` - local Lua tests with no Control4 runtime required
- `tests/socket_integration.lua` - LuaSocket loopback Apple TV client test
- `tools/fake_companion_server.py` - local TCP Apple TV frame recorder
- `tools/package_driver.py` - simple c4z archive builder for Composer testing
- `tools/pyatv_reference.py` - pyatv comparison helper for real Apple TV tests
- `tools/generate_srp_vectors.py` - srptools reference generator for SRP tests
- `docs/testing.md` - testing strategy and commands
- `docs/roadmap.md` - phased implementation checklist
- `docs/crypto-plan.md` - source-backed Apple TV authentication plan
- `docs/hardware-validation.md` - Composer/Controller validation checklist

## Current Status

The scaffold has real Apple TV frame and TLV8 helpers, a pyatv-vector-tested
OPACK subset, native Pair-Setup credential persistence, Pair-Verify frame
plumbing, encrypted protocol frame wrapping, driver command dispatch, app-list
state publishing, and Control4 mini-app routing. It also has a protocol client
state machine tested both with injected transports and a real LuaSocket
localhost TCP loopback for Pair-Verify, encrypted-session enablement, and
encrypted app launch. The remaining blocker for a live encrypted session is the
real Control4 crypto provider behind the adapter being validated on hardware.
The driver now contains an `OpenSSLCrypto` provider for X25519, Ed25519,
HKDF-SHA512, and ChaCha20-Poly1305, plus a Composer action to check those
primitives and log specific failures. Native Pair-Setup has an
experimental pure-Lua SRP-3072/SHA512 path with srptools-derived vectors and is
the intended user-facing onboarding path.

Covered pyatv-derived fixtures:

- documented Pair-Setup M1 frame
- `_launchApp` with bundle id
- `_launchApp` with URL/deep link
- `FetchLaunchableApplicationsEvent`
- `_hidC`
- `_sessionStart`
- Pair-Verify start/next auth frames
- SRP Pair-Setup math vectors from srptools
