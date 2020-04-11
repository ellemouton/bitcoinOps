package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
)

func main() {
	flag.Parse()

	pk1 := New(*compressed)
	fmt.Println(pk1.Info())

	decoded, err := hex.DecodeString(os.Args[2])
	if err != nil {
		log.Fatal(err)
	}

	pk2, err := NewFromHex(decoded)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(pk2.Info())
}
