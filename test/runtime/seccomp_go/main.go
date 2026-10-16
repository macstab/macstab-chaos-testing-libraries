// Runtime probe for test_seccomp.sh: a statically linked Go program
// (CGO_ENABLED=0), which LD_PRELOAD cannot reach, under chaos-init.
//
// Usage: seccomp_go open <path> | openms <path>
package main

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
)

func tryOpen(path string) string {
	file, err := os.OpenFile(path, os.O_RDONLY|os.O_CREATE, 0o644)
	if err == nil {
		file.Close()
		return "ok"
	}
	var errno syscall.Errno
	if errors.As(err, &errno) && errno == syscall.EIO {
		return "EIO"
	}
	return err.Error()
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: seccomp_go open|openms <path>")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "open":
		fmt.Println(tryOpen(os.Args[2]))
	case "openms":
		start := time.Now()
		tryOpen(os.Args[2])
		fmt.Println(time.Since(start).Milliseconds())
	}
}
