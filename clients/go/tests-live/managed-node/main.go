package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"github.com/marcgauthier/libmurmur/clients/go/tests-live/managedharness"
)

func decode(value string, target []byte) error {
	bytes, err := hex.DecodeString(value)
	if err != nil || len(bytes) != len(target) {
		return fmt.Errorf("want %d hex bytes", len(target))
	}
	copy(target, bytes)
	return nil
}
func main() {
	path := flag.String("path", "", "store path")
	keyHex := flag.String("key", "", "32-byte encryption key")
	databaseHex := flag.String("database", "", "16-byte database identity")
	originHex := flag.String("origin", "", "16-byte origin identity")
	seedHex := flag.String("seed", "", "32-byte signing seed")
	flag.Parse()
	var key, seed [32]byte
	var database, origin [16]byte
	for _, arg := range []struct {
		value  string
		target []byte
	}{{*keyHex, key[:]}, {*databaseHex, database[:]}, {*originHex, origin[:]}, {*seedHex, seed[:]}} {
		if err := decode(arg.value, arg.target); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	}
	db, err := managedharness.OpenNative(*path, key, database, origin, seed)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	defer db.Close()
	if err := managedharness.Serve(db, os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
