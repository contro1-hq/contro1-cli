//go:build unix

package cmd

import "os"

func isRootProcess() bool { return os.Geteuid() == 0 }
