package noise

import (
	"crypto/rand"

	"golang.org/x/crypto/curve25519"
)

// Keypair is a static X25519 public/private key pair representing a peer's
// long-term identity. Generated and stored by the caller; passed into Dial
// and Accept. The library never generates or persists keypairs.
type Keypair struct {
	PrivateKey [32]byte
	PublicKey  [32]byte
}

// GenerateKeypair generates a fresh X25519 Keypair using a cryptographically
// secure random source. Keypair generation is a convenience helper; callers
// are responsible for persisting the returned Keypair.
func GenerateKeypair() (Keypair, error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return Keypair{}, err
	}
	// Clamp per RFC 7748
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return Keypair{}, err
	}
	var kp Keypair
	copy(kp.PrivateKey[:], priv[:])
	copy(kp.PublicKey[:], pub)
	return kp, nil
}

// derivePublicKey computes the X25519 public key from a private key.
// Used internally for test vector setup where only the private key is given.
func derivePublicKey(priv [32]byte) ([32]byte, error) {
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return [32]byte{}, err
	}
	var out [32]byte
	copy(out[:], pub)
	return out, nil
}
func dh(privKey, pubKey [32]byte) ([32]byte, error) {
	out, err := curve25519.X25519(privKey[:], pubKey[:])
	if err != nil {
		return [32]byte{}, err
	}
	var result [32]byte
	copy(result[:], out)
	return result, nil
}
