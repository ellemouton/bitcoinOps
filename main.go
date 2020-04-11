package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/ripemd160"
)

var curve = btcec.S256()

var compressed = flag.Bool("compressed", true, "Public key in compressed format")

type PublicKey struct {
	x          *big.Int
	y          *big.Int
	compressed bool
}

func (p *PublicKey) Raw() []byte {
	if !p.compressed {
		return append([]byte{0x04}, append(p.x.Bytes(), p.y.Bytes()...)...)
	}
	if p.y.Bit(0) == 0 {
		return append([]byte{0x02}, p.x.Bytes()...)
	}
	return append([]byte{0x03}, p.x.Bytes()...)
}

func (p *PublicKey) Hex() string {
	return hex.EncodeToString(p.Raw())
}

func (p *PublicKey) Hash() []byte {
	h256 := sha256.New()
	h256.Write(p.Raw())

	rip160 := ripemd160.New()
	rip160.Write(h256.Sum(nil))

	return rip160.Sum(nil)
}
func (p *PublicKey) Address() string {
	return base58.CheckEncode(p.Hash(), 0x00)
}

type PrivateKey struct {
	k      *big.Int
	pubkey *PublicKey
}

func (p *PrivateKey) Raw() []byte {
	if p.pubkey.compressed {
		return append(p.k.Bytes(), 0x01)
	}
	return p.k.Bytes()
}

func (p *PrivateKey) Hex() string {
	return hex.EncodeToString(p.Raw())
}

func (p *PrivateKey) Wif() string {
	return base58.CheckEncode(p.Raw(), 0x80)
}

// New creates a new PrivateKey by generating a random number
func New(compressed bool) *PrivateKey {
	buf := make([]byte, 32)
	z := new(big.Int)

	for z.Cmp(big.NewInt(1)) == -1 || z.Cmp(curve.Params().N) == 1 {
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
	fmt.Println(pk.pubkey.Hex())
	fmt.Println(pk.pubkey.Address())
}
