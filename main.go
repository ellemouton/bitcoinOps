package main

func main() {
	// get random 256 bit number (k) -> Private key.
	// must be a number between 1 and n (the order of the btc ecc)
	// do this by picking a random numer, then do SHA256 and
	// check that it is smaller than n. If not, retry.
	// Use a cryptographically secure pseudorandom number generator (CSPRNG)
	// and seed from a source with sufficient entropy
	// Represent the priv key in a number of ways: hex, WIF, WIF-compressed

	// Calculate the Public key (K) from the priv key: K = k*G using
	// the secp256k1 standard. This should result in a (x, y) pair of 32 bytes each
	// Represent the private key in a number of ways. Compressed and uncompressed

	// Get the bitcoin address. K -> SHA256 -> RIPEMD160 -> A
	// Encode the address in Base52Check
	// Do this for both compressed pubkey and uncompressed pubkey

}
