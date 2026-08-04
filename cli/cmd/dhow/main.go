// Command dhow is the air-gapped data courier CLI.
//
// Usage:
//
//	dhow keygen   - generate an operator key
//	dhow send     - encode a directory into QR frames
//	dhow recv     - decode captured frames back into a directory
//	dhow verify   - verify a received dataset
//	dhow version  - print version and ABI information
//
// Run "dhow help" for the full surface, or "dhow <command> -h" for a
// command's flags.
package main

import (
	"os"

	"dhow/cli/internal/cli"
)

func main() {
	os.Exit(cli.Run(cli.Env{
		Stdout: os.Stdout,
		Stderr: os.Stderr,
		Stdin:  os.Stdin,
		Args:   os.Args[1:],
	}))
}
