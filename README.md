# hush-noise

A Go implementation of the [Noise Protocol Framework](https://noiseprotocol.org) — the secure channel layer underneath WireGuard and Signal.

TLS is designed for the web: certificate authorities, domain names, server-authenticates-client. Noise is designed for peers: no CA, no PKI, both sides authenticate each other with keypairs they own. `hush-noise` is part of the [hush](https://github.com/julianbonomini) stack — a set of primitives built on the belief that privacy should be invisible infrastructure, not a feature you configure.

## Installation

```sh
go get github.com/julianbonomini/hush-noise
```

## Example

```go
package main

import (
    "context"
    "fmt"
    "net"

    noise "github.com/julianbonomini/hush-noise"
)

func main() {
    // Each peer generates a long-term keypair once and persists it.
    initiatorKP, _ := noise.GenerateKeypair()
    responderKP, _ := noise.GenerateKeypair()

    // Any io.ReadWriter works — TCP, Unix socket, net.Pipe, etc.
    iConn, rConn, _ := openConnections()

    // Handshake runs concurrently on both sides.
    var iSession, rSession *noise.Session
    done := make(chan struct{})
    go func() {
        rSession, _ = noise.Accept(context.Background(), rConn, responderKP)
        close(done)
    }()
    iSession, _ = noise.Dial(context.Background(), iConn, initiatorKP)
    <-done

    // Send and receive encrypted messages.
    iSession.Send([]byte("hello"))
    msg, _ := rSession.Receive()
    fmt.Println(string(msg)) // hello
}

func openConnections() (net.Conn, net.Conn, error) {
    a, b := net.Pipe()
    return a, b, nil
}
```

## Security properties

- **Mutual authentication** — both peers prove ownership of their static keypair during the handshake. Neither side can be impersonated.
- **Forward secrecy** — session keys are derived from ephemeral Diffie-Hellman values. Compromising a long-term keypair does not decrypt past sessions.
- **Remote identity** — after the handshake, `session.RemotePublicKey()` returns the authenticated static public key of the peer. What you do with that key — whether to accept or reject the connection — is your responsibility. The library guarantees the cryptographic identity; trust policy is yours.
- **Cipher suite** — `Noise_XX_25519_ChaChaPoly_BLAKE2s`. ChaCha20-Poly1305 for constant-time encryption on all platforms; no timing side-channels without hardware AES.

## API reference

Full godoc at [pkg.go.dev/github.com/julianbonomini/hush-noise](https://pkg.go.dev/github.com/julianbonomini/hush-noise).
