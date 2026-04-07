# opaquepp

A C++ wrapper around the [opaque-ke](https://github.com/facebook/opaque-ke) Rust crate, providing a clean object-oriented interface for the [OPAQUE](https://datatracker.ietf.org/doc/rfc9807/) password-authenticated key exchange (PAKE) protocol.

OPAQUE allows a client to authenticate to a server using a password without ever exposing that password to the server — not during registration, not during login, and not even if the server is compromised.

## Requirements

- CMake 3.22 or later
- A C++20-capable compiler
- Rust toolchain (stable)

## Dependencies

- [opaque-ke](https://github.com/facebook/opaque-ke) — Rust implementation of the OPAQUE protocol
- [Corrosion](https://github.com/corrosion-rs/corrosion) — CMake integration for Rust crates
- [argon2-kdf](https://github.com/nicowillis/argon2-kdf) — Argon2 key derivation used internally by the protocol

## Including in your project

Add `opaquepp` as a subdirectory or use CMake's `FetchContent`:

```cmake
include(FetchContent)

FetchContent_Declare(
  opaquepp
  GIT_REPOSITORY https://github.com/ikea400/opaquepp.git
  GIT_TAG        main
)
FetchContent_MakeAvailable(opaquepp)

target_link_libraries(your_target PRIVATE opaquepp)
```

Then include the header in your source files:

```cpp
#include "opaque++.h"
```

## Usage

The library exposes three main classes: `OpaqueServerSetup`, `OpaqueServer`, and `OpaqueClient`.

### Registration

```cpp
#include "opaque++.h"

// One-time server setup — persist this across sessions
auto serverSetup = std::make_shared<OpaqueServerSetup>();

const std::string clientIdentifier = "alice";
const std::string serverIdentifier = "example.com";
const std::string_view password = "hunter2";

OpaqueClient client(password, clientIdentifier, serverIdentifier, "");
OpaqueServer server(serverSetup, clientIdentifier, serverIdentifier, "");

// Step 1: client initiates registration
const auto registrationRequest = client.startRegistration();

// Step 2: server responds
const auto registrationResponse = server.startRegistration(registrationRequest);

// Step 3: client finalizes and produces a registration record
const auto registrationRecord = client.finishRegistration(registrationResponse);

// Store registrationRecord server-side, associated with clientIdentifier
```

### Login

```cpp
const std::string context = "example.com";

OpaqueClient client(password, clientIdentifier, serverIdentifier, context);
OpaqueServer server(serverSetup, clientIdentifier, serverIdentifier, context);

// Step 1: client initiates login
const auto loginRequest = client.startLogin();

// Step 2: server responds (requires the stored registration record)
const auto loginResponse = server.startLogin(clientIdentifier, registrationRecord, loginRequest);

// Step 3: client finalizes login
const auto finishLoginRequest = client.finishLogin(loginResponse);

// Step 4: server verifies
server.finishLogin(finishLoginRequest);

// Both sides now hold the same session key
auto clientSessionKey = client.getSessionKey();
auto serverSessionKey = server.getSessionKey();
```

If authentication fails, `finishLogin` throws an `InvalidLoginException`.

## License

See [LICENSE.txt](LICENSE.txt).
