package main

import (
	"bufio"
	"crypto/aes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/text/unicode/norm"
)

var curve = btcec.S256()

const (
	P2PKHAddressVersion = 0x00
	P2SHAddressVersion  = 0x05
	WifVersion          = 0x80

	CompPrivKeySuffix    = 0x01
	UncompPubKeyPrefix   = 0x04
	CompEvenPubKeyPrefix = 0x02
	CompOddPubKeyPrefix  = 0x03

	Bip38PrefixByte1 = 0x01
	Bip38PrefixByte2 = 0x42
)

type PublicKey struct {
	x          *big.Int
	y          *big.Int
	compressed bool
}

func (p *PublicKey) Raw() []byte {
	if !p.compressed {
		return append([]byte{UncompPubKeyPrefix}, append(p.x.Bytes(), p.y.Bytes()...)...)
	}
	if p.y.Bit(0) == 0 {
		return append([]byte{CompEvenPubKeyPrefix}, p.x.Bytes()...)
	}
	return append([]byte{CompOddPubKeyPrefix}, p.x.Bytes()...)
}

func (p *PublicKey) Hex() string {
	return hex.EncodeToString(p.Raw())
}

func (p *PublicKey) Hash() []byte {
	return Hash160(p.Raw())
}

func (p *PublicKey) Address() string {
	return base58.CheckEncode(p.Hash(), P2PKHAddressVersion)
}

type PrivateKey struct {
	k      *big.Int
	pubkey *PublicKey
}

func (p *PrivateKey) Raw() []byte {
	if p.pubkey.compressed {
		return append(p.k.Bytes(), CompPrivKeySuffix)
	}
	return p.k.Bytes()
}

func (p *PrivateKey) Hex() string {
	return hex.EncodeToString(p.Raw())
}

func (p *PrivateKey) Wif() string {
	return base58.CheckEncode(p.Raw(), WifVersion)
}

func (p *PrivateKey) Info() string {
	return fmt.Sprintf("Compressed: %v\nHex: %v\nWIF: %v\nAddress: %v\n", p.pubkey.compressed, p.Hex(), p.Wif(), p.Address())
}

func (p *PrivateKey) Address() string {
	return p.pubkey.Address()
}

func (p *PrivateKey) Encrypt(pass string) (string, error) {
	passphrase := norm.NFC.String(pass)
	privKey := p.Raw()
	addresshash := DoubleSha256([]byte(p.Address()))[:4]

	scryptKey, err := scrypt.Key([]byte(passphrase), addresshash, 16384, 8, 8, 64)
	if err != nil {
		return "", err
	}

	derivedhalf1, derivedhalf2 := scryptKey[:32], scryptKey[32:]

	block, err := aes.NewCipher(derivedhalf2)
	if err != nil {
		return "", err
	}

	data1, err := XOR(privKey[:16], derivedhalf1[:16])
	if err != nil {
		return "", err
	}

	data2, err := XOR(privKey[16:], derivedhalf1[16:])
	if err != nil {
		return "", err
	}

	encryptedhalf1, encryptedhalf2 := make([]byte, 16), make([]byte, 16)
	block.Encrypt(encryptedhalf1, data1)
	block.Encrypt(encryptedhalf2, data2)

	flagbyte := 0x00
	flagbyte ^= 0xc0 // non-EC mutliplied only for now

	if p.pubkey.compressed {
		flagbyte ^= 0x20
	}

	final := append([]byte{Bip38PrefixByte2, byte(flagbyte)}, append(addresshash, append(encryptedhalf1, encryptedhalf2...)...)...)
	return base58.CheckEncode(final, Bip38PrefixByte1), nil
}

func Decrypt(privKey, pass string) (*PrivateKey, error) {
	passphrase := norm.NFC.String(pass)
	b, version, err := base58.CheckDecode(privKey)
	if err != nil {
		return nil, err
	}

	if version != Bip38PrefixByte1 || b[0] != Bip38PrefixByte2 {
		return nil, errors.New("Invalid bip28 encrypted privkey")
	}

	compFlag := b[1] & 0x02

	salt := b[2:6]

	scryptKey, err := scrypt.Key([]byte(passphrase), salt, 16384, 8, 8, 64)
	if err != nil {
		return nil, err
	}

	derivedhalf1, derivedhalf2 := scryptKey[:32], scryptKey[32:]

	block, err := aes.NewCipher(derivedhalf2)
	if err != nil {
		return nil, err
	}

	decryptedhalf1, decryptedhalf2 := make([]byte, 16), make([]byte, 16)
	block.Decrypt(decryptedhalf1, b[6:22])
	block.Decrypt(decryptedhalf2, b[22:])

	data1, err := XOR(decryptedhalf1, derivedhalf1[:16])
	if err != nil {
		return nil, err
	}

	data2, err := XOR(decryptedhalf2, derivedhalf1[16:])
	if err != nil {
		return nil, err
	}

	decryptedKey := append(data1, data2...)

	if compFlag != 0 {
		decryptedKey = append(decryptedKey, CompPrivKeySuffix)
	}

	return NewFromHex(decryptedKey)
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

func NewFromHex(h []byte) (*PrivateKey, error) {
	k := new(big.Int)
	var compressed bool

	if len(h) == 32 {
		compressed = false
		k.SetBytes(h)
	} else if len(h) == 33 && h[32] == CompPrivKeySuffix {
		compressed = true
		k.SetBytes(h[:32])
	} else {
		return nil, errors.New("Invalid Private Key Hex")
	}

	KxInt, KyInt := curve.ScalarBaseMult(k.Bytes())
	pubKey := &PublicKey{
		x:          KxInt,
		y:          KyInt,
		compressed: compressed,
	}

	return &PrivateKey{
		k:      k,
		pubkey: pubKey,
	}, nil
}

func NewFromWif(s string) (*PrivateKey, error) {
	b, version, err := base58.CheckDecode(s)
	if err != nil {
		return nil, err
	}

	if version == WifVersion {
		return NewFromHex(b)
	} else if version == Bip38PrefixByte1 && b[0] == Bip38PrefixByte2 {
		reader := bufio.NewReader(os.Stdin)
		fmt.Println("Enter Passphrase: ")
		passphrase, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}

		return Decrypt(s, strings.TrimSpace(passphrase))
	}
	return nil, errors.New("Invalid Wif")
}
