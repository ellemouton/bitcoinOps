package main

import "flag"

var extendedKey = flag.String("ek", "", "Extended Private Key (prefixed with 'xpriv)'")
var path = flag.String("path", "", "HD path. Example: \"0/10'/4\"")
var numAddr = flag.Int("num", 10, "Number of addresses to derive")
