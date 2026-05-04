# Testing Strategy

This port uses pyatv as the behavioral reference, not as code to transliterate
line by line.

## Test Layers

1. Pure Lua tests run with a mocked Control4 environment.
2. pyatv reference scripts capture app list and app launch behavior from a real
   Apple TV.
3. A local fake Companion server records binary frames from the Lua client.
4. Control4 hardware tests validate DriverWorks lifecycle, persistence,
   Universal Minidriver bindings, and Navigator behavior.

## Current Local Commands

Run the Lua scaffold tests:

```sh
lua tests/test_driver.lua
```

Run the LuaSocket loopback Companion client test:

```sh
eval "$(luarocks path)"
lua tests/socket_integration.lua
```

Start the frame recorder:

```sh
python3 tools/fake_companion_server.py --host 127.0.0.1 --port 49153
```

Capture pyatv app behavior from a real Apple TV:

```sh
python3 tools/pyatv_reference.py --address 192.168.1.50
python3 tools/pyatv_reference.py --address 192.168.1.50 --launch com.netflix.Netflix
```

Regenerate local OPACK fixtures from the cloned pyatv source:

```sh
python3 tools/generate_pyatv_vectors.py
```

Regenerate SRP reference vectors from pyatv's `srptools` dependency:

```sh
python3 tools/generate_srp_vectors.py
```

Parse the Control4 XML:

```sh
python3 -c 'import xml.etree.ElementTree as ET; ET.parse("driver.xml"); print("driver.xml ok")'
```

Validate the local driver package structure:

```sh
python3 tools/validate_driver_structure.py
```

Build a simple c4z archive for Composer testing:

```sh
python3 tools/package_driver.py
```

## Guardrails

The initial OPACK implementation is intentionally tiny. It exists to exercise
the architecture and local tests. Before real Apple TV use, every Companion
message encoder must pass golden-vector tests against pyatv source-derived
fixtures. Real Apple TV tests are compatibility checks after the source-backed
frame and crypto behavior is implemented.
