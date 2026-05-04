# Hardware Validation Checklist

Run these in Composer Pro after loading `control4_apple_tv.c4z`. The goal of
the first pass is not broad Apple TV compatibility; it is to find the first real
runtime mismatch with enough detail to fix it.

## 1. Load And Inspect

- Confirm the driver loads without Lua syntax/runtime errors.
- Confirm the read-only `Driver Version` property is populated.
- Confirm `Connection State` is either `Disconnected` or `Credentials Loaded`.
- Turn `Debug Mode` on before running diagnostic actions when detailed logs are needed.

## 2. Crypto Provider

Run the `Check Crypto Provider` action.

Expected result:

- `Connection State`: `Crypto Provider OK`

If it fails, copy the Composer `Connection State` value and the driver log line.
The error is expected to name the exact primitive, such as `hmac`,
`sign Ed25519`, `verify Ed25519`, or `create ChaCha20-Poly1305 encrypt context`.

## 3. Native Pairing

Set `Apple TV Address`, then run the `Pair Apple TV` action. When the Apple TV
shows a PIN, enter it in the `Pairing PIN` property.

Expected result:

- `Connection State`: `PAIR_SETUP_COMPLETE`

## 4. Pair-Verify And Session

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

## 5. App Launch

Run the `Launch App` command with a known bundle id, for example:

```text
com.netflix.Netflix
```

Then bind one Universal Minidriver to one of the `RF_MINI_APP` inputs and select
it from Navigator. The driver should route the selected minidriver service id to
Companion `_launchApp`.
