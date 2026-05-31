# Control4 Apple TV Driver

This workspace is for a self-contained Control4 Lua driver that replaces a
pyatv-backed web server. The target is not full pyatv parity. The target is a
Control4-native Apple TV driver with Universal Minidriver "mini app" support.

For Halo push-to-talk voice, this driver intentionally relies on Control4's
native Apple TV voice path. The custom driver launches Mini Apps, then can hand
room focus to the native `appleTV.c4z` driver so Halo voice continues through
AppleBridge/Voice Coordinator.

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
- Optional handoff to the native Apple TV driver after Mini App launch for Halo push-to-talk

Out of scope:

- AirPlay streaming
- Custom Halo push-to-talk audio processing
- RAOP
- Full MRP parity
- Legacy Apple TV 2/3 DMAP support

## Recommended Setup

### If You Need Halo Push-To-Talk

Set up Control4's native Apple TV voice path first:

1. Install and configure the native AppleBridge / Apple TV drivers as usual.
2. Pair or activate the native Apple TV driver for the Apple TV you want to control.
3. Add the native Apple TV source to the room's **Watch** menu.
4. On the native Apple TV driver, disable the menu-tap behaviors that could disturb app launches:
   - `Send Menu Tap on ON = False`
   - `Send Menu Tap/Hold on OFF = False`
5. Manually select the native Apple TV source in the room and confirm Halo push-to-talk works.

After native voice works, install and configure this driver:

1. Add this driver to the project and set `Apple TV Address`.
2. Run `Pair Apple TV`, enter the PIN in `Pairing PIN`, and wait for pairing to complete.
3. Run `Pair AirPlay`, enter the AirPlay PIN when prompted, and wait for completion.
4. Run `Prewarm Crypto` and wait for `Crypto Prewarm Status` to show `Complete`.
5. Run `Connect Apple TV`; the expected connected state is `SESSION_ACTIVE`.
6. Run `Refresh App List`.
7. Run `Refresh Native Apple TV Drivers`.
8. Set `After Mini App Launch = Select Native Apple TV Driver`.
9. Set `Native Apple TV Driver` to the native `appleTV.c4z` driver for the same room/Apple TV.

Keep the native Apple TV source in the room's Watch menu. If it is removed,
Halo may report that the room is not voice-capable after handoff.

### Without Halo Push-To-Talk

Use the same pairing steps, but leave `After Mini App Launch = Return To This Driver`.
In that mode Mini App selections launch the Apple TV app and then return room focus
to this driver's main Apple TV proxy.

## Mini Apps

This driver exposes an App Switcher proxy with 25 MiniApp input bindings. Bind
Universal Minidrivers to those inputs. When Control4 selects a MiniApp input, the
driver resolves the MiniApp name against the Apple TV app list and known aliases,
then sends an Apple TV `_launchApp` request.

Recommended Mini App workflow:

1. Pair and connect the driver.
2. Run `Refresh App List`.
3. Bind Universal Minidrivers to the desired `MiniApp` inputs on the App Switcher proxy.
4. Select the MiniApp from Watch, Navigator, or Programming and confirm the app launches.

Exact bundle IDs from the Apple TV app list are the most reliable launch targets,
but common names such as Netflix, YouTube, DirecTV, Hulu, Disney+, Max, Peacock,
and Prime Video are also aliased.

## Composer Actions

- `Pair Apple TV`: pairs Companion remote control, app list, and app launch support.
- `Pair AirPlay`: pairs the metadata monitor used for Current App and Now Playing.
- `Prewarm Crypto`: prepares cached crypto data after pairing so reconnects are faster.
- `Connect Apple TV`: opens the connection, performs Pair-Verify, starts the Companion session, and subscribes to status events.
- `Disconnect Apple TV`: closes the active Companion connection.
- `Refresh App List`: requests launchable apps from the Apple TV and updates the `Launch App` list.
- `Print App List`: prints the launchable app list to Lua output.
- `Launch App`: launches the row selected in the `Launch App` property.
- `Refresh Native Apple TV Drivers`: populates the `Native Apple TV Driver` dropdown with native `appleTV.c4z` drivers.
- `Reset Pairing`: clears stored credentials so the Apple TV can be paired again.

## Key Properties

- `After Mini App Launch`: choose `Return To This Driver` or `Select Native Apple TV Driver`.
- `Native Apple TV Driver`: native `appleTV.c4z` driver to select after a Mini App launch.
- `Launch App`: dynamic app selector populated by `Refresh App List`.
- `Pairing PIN`: enter Apple TV pairing PINs here.
- `Crypto Prewarm Status`: progress/result of `Prewarm Crypto`.
- `Debug Mode`: prints diagnostic logs to Lua output.

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

The driver has real Apple TV frame and TLV8 helpers, a pyatv-vector-tested
OPACK subset, native Pair-Setup credential persistence, Pair-Verify, encrypted
protocol frame wrapping, driver command dispatch, app-list state publishing,
now-playing metadata, AirPlay monitor support, and Control4 mini-app routing.
It also has manual Composer crypto prewarm so commissioning can pair first and
then prepare cached crypto data before handoff.

Covered pyatv-derived fixtures:

- documented Pair-Setup M1 frame
- `_launchApp` with bundle id
- `_launchApp` with URL/deep link
- `FetchLaunchableApplicationsEvent`
- `_hidC`
- `_sessionStart`
- Pair-Verify start/next auth frames
- SRP Pair-Setup math vectors from srptools
