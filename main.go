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

	pk2.Encrypt(passphrase)
	//fmt.Println(pk3.Info())
}
