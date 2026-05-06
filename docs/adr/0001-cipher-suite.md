# Use Noise_XX_25519_ChaChaPoly_BLAKE2s as the cipher suite

We use ChaCha20-Poly1305 instead of AES-GCM as the symmetric cipher. ChaCha20-Poly1305 is constant-time in software on all platforms — it has no timing side-channels in the absence of hardware AES acceleration, unlike AES-GCM which leaks timing information when the CPU lacks AES-NI. This makes the library safe on mobile, embedded, and any future target where hardware AES is not guaranteed. The full suite is `Noise_XX_25519_ChaChaPoly_BLAKE2s`, the same combination used by WireGuard.
