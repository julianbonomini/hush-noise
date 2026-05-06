// Package noise implements the Noise Protocol Framework for Go.
// It provides a high-level Dial/Accept API for establishing authenticated,
// encrypted sessions between peers using the XX handshake pattern with
// the Noise_XX_25519_ChaChaPoly_BLAKE2s cipher suite.
//
// # Typical usage
//
//	// Generate a long-term keypair (persist and reuse across restarts).
//	kp, err := noise.GenerateKeypair()
//
//	// Initiator side:
//	session, err := noise.Dial(ctx, conn, kp)
//
//	// Responder side:
//	session, err := noise.Accept(ctx, conn, kp)
//
//	// Send and receive encrypted messages:
//	err = session.Send([]byte("hello"))
//	msg, err := session.Receive()
//
// # Key management
//
// The library never generates or persists keypairs on its own. Call
// [GenerateKeypair] once and serialise the result for reuse:
//
//	priv := kp.Private()  // [32]byte — store securely
//	pub  := kp.PublicKey  // [32]byte — share freely
//
//	// Restore from stored bytes:
//	kp = noise.NewKeypair(priv, pub)
package noise

// ProtocolName is the full Noise protocol identifier negotiated during the
// handshake. Callers that need to verify or log the cipher suite can use
// this constant.
const ProtocolName = protocolName
