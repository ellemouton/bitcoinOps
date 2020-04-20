package eckeys

import (
	"flag"
	"fmt"
	"log"
	"testing"

	bip32 "github.com/tyler-smith/go-bip32"
	bip39 "github.com/tyler-smith/go-bip39"
)

func TestECKeys(t *testing.T) {
	flag.Parse()

	//	pk1 := New(*compressed)
	//	fmt.Println(pk1.Info())
	//
	//pk2, err := NewFromWif("5J3mBbAH58CpQ3Y5RNJpUKPE62SQ5tfcvU2JpbnkeyhfsYB1Jcn")
	//if err != nil {
	//	log.Fatal(err)
	//}

	//fmt.Println(pk2.Info())

	//passphrase := "MyTestPassphrase"
	//fmt.Println(passphrase)

	//fmt.Println(pk2.Encrypt(passphrase))

	//pk1, err := Decrypt("6PRTHL6mWa48xSopbU1cKrVjpKbBZxcLRRCdctLJ3z5yxE87MobKoXdTsJ", passphrase)
	//if err != nil {
	//	log.Fatal(err)
	//}
	//fmt.Println(pk1.Info())

	ent, err := bip39.NewEntropy(128)
	if err != nil {
		log.Fatal(err)
	}

	mnemonic, err := bip39.NewMnemonic(ent)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(mnemonic)

	seed := bip39.NewSeed(mnemonic, "")
	if err != nil {
		log.Fatal(err)
	}

	master, err := bip32.NewMasterKey(seed)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(master)
}
