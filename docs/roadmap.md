# Implementation Roadmap

## Phase 1: Proven Protocol Primitives

- Companion frame wrapper
- TLV8 encoder/decoder
- Minimal OPACK encoder/decoder
- Pair-Setup M1 golden vector from pyatv docs
- Control4 Universal Minidriver routing scaffold

Exit criteria:

- Local Lua tests pass.
- At least one byte-for-byte pyatv protocol fixture passes.

## Phase 2: OPACK Coverage

Add golden vectors for:

- `FetchLaunchableApplicationsEvent` - done
- `_launchApp` - done
- `_hidC` - done
- `_sessionStart` - done
- Pair-Verify start/next - done
- `_sessionStop`

Required OPACK features:

- object references/pointers - initial support done
- longer byte arrays - initial support done
- larger integers - initial support done
- arrays
- dictionary ordering fixture support

## Phase 3: Crypto Feasibility

Implement imported pyatv credentials first, then validate Control4
`lua-openssl` support for Pair-Verify:

- random bytes
- SHA/HMAC/HKDF - DriverWorks documents `C4:HMAC`; HKDF can be layered on it
- Ed25519
- X25519
- ChaCha20-Poly1305
- imported `ltpk:ltsk:atv_id:client_id` HAP credentials - done
- Pair-Verify frame flow with injectable crypto provider - done
- Control4 `lua-openssl` crypto provider - implemented, hardware validation pending
- Composer crypto provider check action - done

Track native Pair-Setup separately:

- SRP-3072/SHA512 with username `Pair-Setup` - experimental implementation done
- DriverWorks `lua-openssl` removes `srp` and documents no replacement
- srptools-derived SRP source-vector tests - done
- keep native pairing behind hardware validation before trusting it

Exit criteria:

- Pair-Verify crypto can be reproduced locally against pyatv-derived fixtures
  using imported HAP credentials.

## Phase 4: Companion Session

- Pair-Setup M1-M6 - experimental state machine done
- credential persistence with `C4:PersistSetValue(..., true)` - initial support done
- Pair-Verify M1-M4 - frame plumbing and local socket flow done, hardware validation pending
- encrypted frame send/receive - frame wrapper and local socket flow done, provider hardware validation pending
- TCP client state machine - done
- `_sessionStart` for `com.apple.tvremoteservices` - done
- `_sessionStop` on close - done

## Phase 5: Apps and Mini Apps

- fetch app list
- persist app catalog
- launch by bundle id
- launch by URL/deep link
- wire `RF_MINI_APP` bindings
- validate one test minidriver, likely Netflix

## Phase 6: Control4 Packaging

- `driver.xml` scaffold
- proxy/binding layout
- `.c4z` packaging
- Composer Pro install test
- Navigator mini-app UX test
