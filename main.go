package main

import (
	"flag"
	"fmt"
	"log"
)

func main() {
	flag.Parse()

	//	pk1 := New(*compressed)
	//	fmt.Println(pk1.Info())
	//
	pk2, err := NewFromWif("5J3mBbAH58CpQ3Y5RNJpUKPE62SQ5tfcvU2JpbnkeyhfsYB1Jcn")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(pk2.Info())

	passphrase := "MyTestPassphrase"
	fmt.Println(passphrase)

	fmt.Println(pk2.Encrypt(passphrase))

	pk1, err := Decrypt("6PRTHL6mWa48xSopbU1cKrVjpKbBZxcLRRCdctLJ3z5yxE87MobKoXdTsJ", passphrase)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(pk1.Info())

	pk3, err := NewFromWif("6PRTHL6mWa48xSopbU1cKrVjpKbBZxcLRRCdctLJ3z5yxE87MobKoXdTsJ")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(pk3.Info())

}
