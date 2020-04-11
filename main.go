package main

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcutil/base58"
)

var curve = elliptic.P256().Params()

var compressed = flag.Bool("compressed", true, "Public key in compressed format")

type PublicKey struct {
	x          *big.Int
	y          *big.Int
	compressed bool
}

func (p *PublicKey) Hex() []byte {
	if p.compressed {

	}
	return append([]byte{0x04}, append(p.x.Bytes(), p.y.Bytes()...)...)
}

// func (p *PublicKey) Address() {
//	if p.compressed {

//	}

//	p.x.Bytes()
//}

type PrivateKey struct {
	k      *big.Int
	pubkey *PublicKey
}

func (p *PrivateKey) Hex() []byte {
	if p.pubkey.compressed {
		return append(p.k.Bytes(), 0x01)
	}
	return p.k.Bytes()
}

func (p *PrivateKey) Wif() string {
	return base58.CheckEncode(p.Hex(), 0x80)
}

// New creates a new PrivateKey by generating a random number
func New(compressed bool) *PrivateKey {
	buf := make([]byte, 32)
	z := new(big.Int)

	for z.Cmp(big.NewInt(1)) == -1 || z.Cmp(curve.N) == 1 {
		_, err := rand.Read(buf)
		if err != nil {
			return nil
		}
		z.SetBytes(buf)
	}

	KxInt, KyInt := curve.ScalarBaseMult(z.Bytes())
	pubKey := &PublicKey{
		x:          KxInt,
		y:          KyInt,
		compressed: compressed,
	}

	return &PrivateKey{
		k:      z,
		pubkey: pubKey,
	}
}

func main() {
	flag.Parse()

	pk := New(*compressed)
	fmt.Println(pk.Wif())
	fmt.Println(hex.EncodeToString(pk.Hex()))
	fmt.Println(hex.EncodeToString(pk.pubkey.Hex()))
	fmt.Println(hex.EncodeToString(pk.pubkey.x.Bytes()))
	fmt.Println(hex.EncodeToString(pk.pubkey.y.Bytes()))
}
