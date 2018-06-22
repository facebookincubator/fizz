<p align="center">
  <img width="500" height="216" alt="Fizz" src="logo2x.png">
</p>
Fizz is a TLS 1.3 implementation.

Fizz currently supports TLS 1.3 drafts 18-28. HelloRetryRequest, early data,
and client authentication are only supported on draft 19 and above. Each draft
also has a corresponding "fb" version. These match the draft versions except
for some minor record layer differences.

## Dependencies
Fizz largely depends on three libraries: [folly](https://www.github.com/facebook/folly),
[OpenSSL](https://www.openssl.org/), and [libsodium](https://github.com/jedisct1/libsodium).

## Source Layout
- `fizz/crypto`:   Cryptographic primitive implementations (most are wrapping
                   OpenSSL or libsodium)
- `fizz/record`:   TLS 1.3 record layer parsing
- `fizz/protocol`: Common protocol code shared between client and server
- `fizz/client`:   Client protocol implementation
- `fizz/server`:   Server protocol implementation

## Design
The core protocol implementations are in `ClientProtocol` and `ServerProtocol`.
`FizzClientContext` and `FizzServerContext` provide configuration options.
`FizzClient` and `FizzServer` (which both inherit from `FizzBase`) provide
applications with an interface to interact with the state machine.
`FizzClient`/`FizzServer` receives events from the application layer, invokes the
correct event handler, and invokes the application `ActionVisitor` to process the
actions.

`AsyncFizzClient` and `AsyncFizzServer` provide implementations of the folly
`AsyncTransportWrapper` interface. They own an underlying transport (for example
`AsyncSocket`) and perform the TLS handshake and encrypt/decrypt application
data.

## Sample Applications
`ClientSocket` and `ServerSocket` provide sample usage of `AsyncFizzClient` and
`AsyncFizzServer` and can be used to start up a simple TLS 1.3 client or server
over a TCP connection.

For example, to start ServerSocket on port 443 with a specified cert:
`ServerSocket -port 443 -cert foo.pem -key foo.key`. Then, on the same host,
you can connect with `ClientSocket -host localhost -port 443`. ClientSocket will
dump the data it gets and both will remain running until interrupted via CTRL+C.
