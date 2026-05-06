package noise

import (
	"fmt"

	"golang.org/x/crypto/blake2s"
)

// symmetricState implements the Noise SymmetricState object.
// It maintains the chaining key (ck), handshake hash (h), and an
// embedded cipherState for encrypting/decrypting handshake payloads.
type symmetricState struct {
	ck     [32]byte // chaining key
	h      [32]byte // handshake hash
	cs     *cipherState
	hasKey bool
}

// newSymmetricState initialises a SymmetricState with the protocol name.
// Per spec §5.2: if len(name) <= 32, h = name padded with zeros; else h = HASH(name).
func newSymmetricState(protocolName string) *symmetricState {
	ss := &symmetricState{}
	name := []byte(protocolName)
	if len(name) <= 32 {
		copy(ss.h[:], name)
	} else {
		ss.h = blake2s256(name)
	}
	ss.ck = ss.h
	return ss
}

// mixKey updates the chaining key and initialises a new cipherState.
// Per spec §5.2 MixKey.
func (ss *symmetricState) mixKey(inputKeyMaterial []byte) {
	ck, k := hkdf2(ss.ck[:], inputKeyMaterial)
	copy(ss.ck[:], ck)
	var key [32]byte
	copy(key[:], k)
	ss.cs = newCipherState(key)
	ss.hasKey = true
}

// mixHash updates the handshake hash.
// Per spec §5.2 MixHash: h = HASH(h || data).
func (ss *symmetricState) mixHash(data []byte) {
	ss.h = blake2s256(append(ss.h[:], data...))
}

// encryptAndHash encrypts plaintext (or passes it through if no key yet),
// mixes the ciphertext into h, and returns the ciphertext.
func (ss *symmetricState) encryptAndHash(plaintext []byte) []byte {
	var ciphertext []byte
	if ss.hasKey {
		ciphertext = ss.cs.encrypt(ss.h[:], plaintext)
	} else {
		ciphertext = plaintext
	}
	ss.mixHash(ciphertext)
	return ciphertext
}

// decryptAndHash decrypts ciphertext (or passes it through if no key yet),
// mixes the ciphertext into h, and returns the plaintext.
func (ss *symmetricState) decryptAndHash(ciphertext []byte) ([]byte, error) {
	var plaintext []byte
	if ss.hasKey {
		var err error
		plaintext, err = ss.cs.decrypt(ss.h[:], ciphertext)
		if err != nil {
			return nil, fmt.Errorf("noise: symmetricState decrypt: %w", err)
		}
	} else {
		plaintext = ciphertext
	}
	ss.mixHash(ciphertext)
	return plaintext, nil
}

// split returns two CipherStates for post-handshake transport.
// Per spec §5.2 Split.
func (ss *symmetricState) split() (send, recv *cipherState) {
	k1, k2 := hkdf2(ss.ck[:], []byte{})
	var sendKey, recvKey [32]byte
	copy(sendKey[:], k1)
	copy(recvKey[:], k2)
	return newCipherState(sendKey), newCipherState(recvKey)
}

// blake2s256 returns the BLAKE2s-256 hash of data.
func blake2s256(data []byte) [32]byte {
	h, err := blake2s.New256(nil)
	if err != nil {
		panic(fmt.Sprintf("noise: blake2s init: %v", err))
	}
	h.Write(data)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// hkdf2 derives two 32-byte output keys from a chaining key and input key
// material, per the Noise Protocol spec §4:
//
//	temp_key = HMAC-BLAKE2s(chaining_key, ikm)
//	output1  = HMAC-BLAKE2s(temp_key, 0x01)
//	output2  = HMAC-BLAKE2s(temp_key, output1 || 0x02)
//
// HMAC-BLAKE2s uses the standard RFC 2104 construction with BLAKE2s (block size 64).
func hkdf2(ck, ikm []byte) ([]byte, []byte) {
	tempKey := hmacBlake2s(ck, ikm)
	out1 := hmacBlake2s(tempKey, []byte{0x01})
	out2 := hmacBlake2s(tempKey, append(out1, 0x02))
	return out1, out2
}

// hmacBlake2s computes HMAC-BLAKE2s-256(key, data) per RFC 2104.
// BLAKE2s block size is 64 bytes.
func hmacBlake2s(key, data []byte) []byte {
	const blockSize = 64
	if len(key) > blockSize {
		h := blake2s256(key)
		key = h[:]
	}
	ipad := make([]byte, blockSize+len(data))
	opad := make([]byte, blockSize)
	for i := 0; i < blockSize; i++ {
		if i < len(key) {
			ipad[i] = key[i] ^ 0x36
			opad[i] = key[i] ^ 0x5c
		} else {
			ipad[i] = 0x36
			opad[i] = 0x5c
		}
	}
	copy(ipad[blockSize:], data)
	inner := blake2s256(ipad)
	outer := blake2s256(append(opad, inner[:]...))
	return outer[:]
}
