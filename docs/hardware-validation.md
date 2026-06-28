# Hardware Validation Checklist

Run these in Composer Pro after loading `control4_apple_tv.c4z`. The goal of
the first pass is not broad Apple TV compatibility; it is to find the first real
runtime mismatch with enough detail to fix it.

## 1. Load And Inspect

- Confirm the driver loads without Lua syntax/runtime errors.
- Confirm the read-only `Driver Version` property is populated.
- Confirm `Connection State` is either `Disconnected` or `Credentials Loaded`.
- Turn `Debug Mode` on before running diagnostic actions when detailed logs are needed.

## 2. Optional Native Voice Prerequisite

Complete this section before configuring this driver if the room will use Halo
push-to-talk.

- Configure Control4's native AppleBridge / Apple TV drivers normally.
- Add the native Apple TV source to the room's **Watch** menu.
- On the native Apple TV driver, disable menu-tap behaviors:
  - `Send Menu Tap on ON = False`
  - `Send Menu Tap/Hold on OFF = False`
- Manually select the native Apple TV source in the room.
- Confirm Halo push-to-talk works before proceeding.

This custom driver does not implement the Apple TV voice audio path. It launches
Mini Apps and can hand room focus to the native Apple TV driver after launch.

## 3. Native Pairing

Set `Apple TV Address`, then run the `Pair Apple TV` action. When the Apple TV
shows a PIN, enter it in the `Pairing PIN` property.

Expected result:

- `Connection State`: `PAIR_SETUP_COMPLETE`

## 4. AirPlay Pairing

Run `Pair AirPlay`. When the Apple TV shows a PIN or the driver prompts for one,
enter it in `Pairing PIN`.

AirPlay pairing powers the metadata monitor for Current App and Now Playing.

## 5. Crypto Prewarm

Run `Prewarm Crypto` after pairing. Wait for `Crypto Prewarm Status` to show
`Complete`.

## 6. Pair-Verify And Session

Run `Connect Apple TV`.

Expected progression:

- `CONNECTED`
- `PAIR_VERIFY_STARTED`
- `READY`
- `SESSION_STARTING`
- `SESSION_ACTIVE`

Any failure here is now after the local source-backed frame, OPACK, and crypto
shape tests. Capture the driver logs so the failing frame or primitive can be
isolated.

## 7. App Launch

Run the `Launch App` command with a known bundle id, for example:

```text
com.netflix.Netflix
```

Then bind one Universal Minidriver to one of the `RF_MINI_APP` inputs and select
it from Navigator. The driver should route the selected minidriver service id to
Companion `_launchApp`.

## 8. Mini Apps

- Run `Refresh App List`.
- Bind Universal Minidrivers to the MiniApp inputs on the App Switcher proxy.
- Select a MiniApp from Watch/Navigator/Programming.
- Confirm the corresponding Apple TV app launches.

If an app does not launch, run `Print App List` and compare the MiniApp name with
the Apple TV app list. Exact bundle IDs are the most reliable targets.

## 9. Push-To-Talk Handoff

Use this only after the native Apple TV driver already works with Halo voice.

- Run `Refresh Native Apple TV Drivers`.
- Set `After Mini App Launch` to `Select Native Apple TV Driver`.
- Set `Native Apple TV Driver` to the native `appleTV.c4z` driver for this room/Apple TV.
- Leave the native Apple TV source in the room's Watch menu.
- Select a MiniApp.

Expected logs:

```text
native Apple TV driver proxy resolved: driver=<native-driver-id> proxy=<native-proxy-id>
mini app native handoff selecting device <native-driver-id> in room <room-id> nativeProxy=<native-proxy-id>
mini app native handoff verified: room=<room-id> selected=<native-driver-id>
```

After the verified handoff, Halo push-to-talk should use the native Apple TV
driver's voice path. If Halo says to switch to a voice-capable room, verify that
the native Apple TV source is in the room Watch menu and that PTT works when the
native source is selected manually.
