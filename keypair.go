package noise

import (
	"crypto/rand"

	"golang.org/x/crypto/curve25519"
)

// Keypair is a static X25519 public/private key pair representing a peer's
// long-term identity. Generated and stored by the caller; passed into Dial
// and Accept. The library never generates or persists keypairs.
//
// PublicKey is exported for sharing with peers; the private key is accessible
// only via the Private() method to reduce accidental exposure.
type Keypair struct {
	privateKey [32]byte
	PublicKey  [32]byte
}

// NewKeypair constructs a Keypair from raw private and public key bytes.
// Use this when restoring a previously serialised keypair.
func NewKeypair(priv, pub [32]byte) Keypair {
	return Keypair{privateKey: priv, PublicKey: pub}
}

// Private returns the raw private key bytes.
// Handle the return value with care — it is sensitive key material.
func (kp Keypair) Private() [32]byte {
	return kp.privateKey
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
	copy(kp.privateKey[:], priv[:])
	copy(kp.PublicKey[:], pub)
	return kp, nil
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
