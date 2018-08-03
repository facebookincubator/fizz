<p align="center">
  <img width="500" height="216" alt="Fizz" src="logo2x.png">
</p>
Fizz is a TLS 1.3 implementation.

Fizz currently supports TLS 1.3 drafts 23-28.  Each draft also has a
corresponding "fb" version. These match the draft versions except for some
minor record layer differences.

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

## Features

Fizz has several important features needed from a modern TLS library.

### Performance

Fizz supports scatter/gather IO by default via folly's IOBufs, and will encrypt
data in-place whenever possible, saving memcpys. Due to this and several
other optimizations, we found in our load balancer benchmarks that Fizz has 10%
higher throughput than out prior SSL library which uses folly's
[AsyncSSLSocket](https://github.com/facebook/folly/blob/master/folly/io/async/AsyncSSLSocket.h).
Fizz also consumes less memory per connection than AsyncSSLSocket.

### Async by default

Fizz has asynchronous APIs to be able to offload functions like certificate
signing and ticket decryption. The API is based on folly's
[Futures](https://github.com/facebook/folly/tree/master/folly/futures) for painless
async programming.

### TLS features

Fizz supports APIs like exported keying material as well as zero-copy APIs
needed to use TLS in other protocols like QUIC.

### Secure design abstractions

Fizz is built on a custom state machine which uses the power of the C++ type system
to treat states and actions as types of their own. As the code changes, this allows us
to catch invalid state transitions as compilation errors instead of runtime errors and
helps us move fast.

## Sample Applications

`ClientSocket` and `ServerSocket` provide sample usage of `AsyncFizzClient` and
`AsyncFizzServer` and can be used to start up a simple TLS 1.3 client or server
over a TCP connection.

For example, to start ServerSocket on port 443 with a specified cert:
`ServerSocket -port 443 -cert foo.pem -key foo.key`. Then, on the same host,
you can connect with `ClientSocket -host localhost -port 443`. ClientSocket will
dump the data it gets and both will remain running until interrupted via CTRL+C.

## Contributing

We'd love to have your help in making Fizz better. If you're interested, please
read our guide to [guide to contributing](CONTRIBUTING.md)

## License
Fizz is BSD licensed, as found in the LICENSE file.

## Reporting and Fixing Security Issues

Please do not open GitHub issues or pull requests - this makes the problem
immediately visible to everyone, including malicious actors. Security issues in
Fizz can be safely reported via Facebook's Whitehat Bug Bounty program:

https://www.facebook.com/whitehat

Facebook's security team will triage your report and determine whether or not is
it eligible for a bounty under our program.


