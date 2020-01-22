// Copyright (C) 2019-2020 Algorand, Inc.
// This file is part of go-algorand
//
// go-algorand is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// go-algorand is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with go-algorand.  If not, see <https://www.gnu.org/licenses/>.

// dsign creates keys for signing data in LogicSig scripts.
//
// dsign creates signatures on data that will verify under
// the LogicSig ed25519verify opcode.
package main

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/transactions/logic"
)

func failFast(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintf(os.Stderr, "usage: %s <key-file> <lsig-file> <data-to-sign>\n", os.Args[0])
		os.Exit(-1)
	}

	// public/private key file
	keyfname := os.Args[1]

	// program file
	lsigfname := os.Args[2]

	kdata, err := ioutil.ReadFile(keyfname)
	failFast(err)

	var seed crypto.Seed
	copy(seed[:], kdata)
	sec := crypto.GenerateSignatureSecrets(seed)
	fmt.Fprintf(os.Stdout, "Public Key: %s\nPublic Key Hexa: %s\n", base32.StdEncoding.EncodeToString(sec.SignatureVerifier[:]),
		hex.Dump(sec.SignatureVerifier[:]))

	pdata, err := ioutil.ReadFile(lsigfname)
	failFast(err)

	// message
	datastr := []byte(os.Args[3])

	fmt.Fprintf(os.Stdout, "Data String:\n Ascii: %s\nBase64: %s\nHex: %s\n\n", datastr, base64.StdEncoding.EncodeToString(datastr), hex.Dump(datastr))

	program1str := fmt.Sprintf("%s", pdata)

	program1, err := logic.AssembleString(program1str)
	failFast(err)

	dsig := sec.Sign(logic.Msg{
		ProgramHash: crypto.HashObj(logic.Program(program1)),
		Data:        datastr,
	})

	fmt.Fprintf(os.Stdout, "Signature base64 program from file: %s\n", base64.StdEncoding.EncodeToString(dsig[:]))
}
