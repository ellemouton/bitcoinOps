package main

import (
	"flag"
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/btcsuite/btcutil/base58"
	"github.com/ellemouton/bitcoinOps/helper"
	"github.com/tyler-smith/go-bip32"
)

func main() {
	flag.Parse()

	if *extendedKey == "" {
		log.Fatalln("No key given")
	}

	key, err := bip32.B58Deserialize(*extendedKey)
	if err != nil {
		log.Fatalln(err)
	}

	pathArr, err := getPath(*path)
	if err != nil {
		log.Fatal(err)
	}

	for _, p := range pathArr {
		key, err = key.NewChildKey(p)
		if err != nil {
			log.Fatal(err)
		}
	}

	fmt.Println("--------------------------------------------")
	fmt.Println("Path		Address")
	fmt.Println("--------------------------------------------")
	for i := 0; i < *numAddr; i++ {
		k, err := key.NewChildKey(uint32(i))
		if err != nil {
			log.Fatal(err)
		}
		addr := base58.CheckEncode(helper.Hash160(k.PublicKey().Key), 0x00)
		fmt.Printf("m/%s/%d\t%s\n", *path, i, addr)
	}
	fmt.Println("--------------------------------------------")
}

func getPath(path string) ([]uint32, error) {
	p := strings.Split(path, "/")

	var final []uint32

	if len(p) == 1 && p[0] == "" {
		return nil, nil
	}

	for _, v := range p {
		var i uint32
		if strings.HasSuffix(v, "'") {
			num, err := strconv.Atoi(v[:len(v)-1])
			if err != nil {
				return nil, err
			}
			i = uint32(1<<31 + num)
		} else {
			num, err := strconv.Atoi(v)
			if err != nil {
				return nil, err
			}
			i = uint32(num)
		}
		final = append(final, i)
	}

	return final, nil
}
