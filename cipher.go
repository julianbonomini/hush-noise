package noise

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// maxMessageSize is the Noise protocol hard cap on message size.
	maxMessageSize = 65535
	// tagSize is the AEAD authentication tag length for ChaCha20-Poly1305.
	tagSize = 16
)

// cipherState implements the Noise CipherState object.
// It wraps ChaCha20-Poly1305 and tracks the nonce counter.
// Invariant: n must never overflow — a nonce overflow panics.
type cipherState struct {
	k [32]byte
	n uint64
}

func newCipherState(key [32]byte) *cipherState {
	return &cipherState{k: key}
}

// encrypt encrypts plaintext with additional data ad, returning ciphertext+tag.
func (cs *cipherState) encrypt(ad, plaintext []byte) []byte {
	if cs.n == ^uint64(0) {
		// Invariant Violation: nonce overflow — crashing is safer than
		// silently reusing a nonce.
		panic("noise: cipherState nonce overflow")
	}
	aead, err := chacha20poly1305.New(cs.k[:])
	if err != nil {
		panic(fmt.Sprintf("noise: failed to create AEAD: %v", err))
	}
	nonce := cs.nonce()
	cs.n++
	return aead.Seal(nil, nonce, plaintext, ad)
}

// decrypt decrypts ciphertext with additional data ad, returning plaintext.
// Returns an error if authentication fails (Expected Failure).
func (cs *cipherState) decrypt(ad, ciphertext []byte) ([]byte, error) {
	if cs.n == ^uint64(0) {
		panic("noise: cipherState nonce overflow")
	}
	aead, err := chacha20poly1305.New(cs.k[:])
	if err != nil {
		panic(fmt.Sprintf("noise: failed to create AEAD: %v", err))
	}
	nonce := cs.nonce()
	cs.n++
	plaintext, err := aead.Open(nil, nonce, ciphertext, ad)
	if err != nil {
		return nil, fmt.Errorf("noise: decrypt failed: %w", err)
	}
	return plaintext, nil
}

// nonce encodes cs.n as a 12-byte little-endian nonce (per Noise spec §4).
func (cs *cipherState) nonce() []byte {
	var n [12]byte
	binary.LittleEndian.PutUint64(n[4:], cs.n)
	return n[:]
}
