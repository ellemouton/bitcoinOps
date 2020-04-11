package main

import (
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"

	"golang.org/x/crypto/ripemd160"
)

func main() {
	// get random 256 bit number (k) -> Private key.
	// must be a number between 1 and n (the order of the btc ecc)
	// do this by picking a random numer, then do SHA256 and
	// check that it is smaller than n. If not, retry.
	// Use a cryptographically secure pseudorandom number generator (CSPRNG)
	// and seed from a source with sufficient entropy
	// Represent the priv key in a number of ways: hex, WIF, WIF-compressed
	curve := elliptic.P256()
	privKey := new(big.Int)
	privKey.Sub(curve.Params().N, big.NewInt(100))

	fmt.Println("Private Key:", privKey)

	// Calculate the Public key (K) from the priv key: K = k*G using
	// the secp256k1 standard. This should result in a (x, y) pair of 32 bytes each
	// Represent the private key in a number of ways. Compressed and uncompressed
	KxInt, KyInt := curve.Params().ScalarBaseMult(privKey.Bytes())
	Kx, Ky := KxInt.Bytes(), KyInt.Bytes()

	ucPubKey := append([]byte{0x04}, Kx...)
	ucPubKey = append(ucPubKey, Ky...)

	fmt.Println("Pub Key coords:", hex.EncodeToString(Kx), hex.EncodeToString(Ky))
	fmt.Println(hex.EncodeToString(ucPubKey))

	// Get the bitcoin address. K -> SHA256 -> RIPEMD160 -> A
	// Encode the address in Base58Check
	// Do this for both compressed pubkey and uncompressed pubkey

	h256 := sha256.New()
	h256.Write(ucPubKey)

	rip160 := ripemd160.New()
	rip160.Write(h256.Sum(nil))

	pubKeyHash := rip160.Sum(nil)
	fmt.Println("Pubkey hash:", hex.EncodeToString(pubKeyHash))
	fmt.Println(len(pubKeyHash))

	address := Base58Check(0x00, pubKeyHash)

}

func Base58Check(version byte, payload []byte) []byte {
	b := append([]byte{version}, payload...)
	h := sha256.New()
	h.Write(b)
	h.Write(h.Sum(nil))
	return append(b, h.Sum(nil)[:4]...)
}
