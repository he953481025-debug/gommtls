package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/duo/gommtls/mmtls"
)

func main() {
	filePath := flag.String("f", "", "read input from file")
	rawBinary := flag.Bool("x", false, "treat input file as raw binary (not hex)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "MMTLS Binary Packet Parser\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  echo \"16f104...\" | go run ./cmd/parser\n")
		fmt.Fprintf(os.Stderr, "  go run ./cmd/parser -f capture.hex\n")
		fmt.Fprintf(os.Stderr, "  go run ./cmd/parser -x -f capture.bin\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	var input []byte
	var err error

	if *filePath != "" {
		input, err = os.ReadFile(*filePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
			os.Exit(1)
		}
	} else {
		input, err = io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading stdin: %v\n", err)
			os.Exit(1)
		}
	}

	var data []byte
	if *rawBinary {
		data = input
	} else {
		hexStr := mmtls.CleanHexString(string(input))
		hexStr = strings.TrimSpace(hexStr)
		if hexStr == "" {
			fmt.Fprintf(os.Stderr, "Error: empty input\n")
			os.Exit(1)
		}
		data, err = hex.DecodeString(hexStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error decoding hex: %v\n", err)
			os.Exit(1)
		}
	}

	records, err := mmtls.ParseRecords(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: partial parse: %v\n", err)
	}

	if len(records) == 0 {
		fmt.Fprintf(os.Stderr, "No records found in input (%d bytes)\n", len(data))
		os.Exit(1)
	}

	fmt.Print(mmtls.FormatRecords(records))
}
