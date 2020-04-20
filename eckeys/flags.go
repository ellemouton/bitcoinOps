package eckeys

import "flag"

var compressed = flag.Bool("compressed", true, "Public key in compressed format")
var encrypt = flag.Bool("encrypt", false, "Encrypt private key as per bip38")
