// Runtime probe for test_seccomp.sh: a statically linked Go program
// (CGO_ENABLED=0), which LD_PRELOAD cannot reach, under chaos-init.
//
// Usage: seccomp_go open <path> | openms <path> | dial <port> | recvms <port>
package main

import (
	"errors"
	"fmt"
	"net"
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

// dial listens on 127.0.0.1:port and dials it.
func dial(port string) string {
	listener, err := net.Listen("tcp", "127.0.0.1:"+port)
	if err != nil {
		return err.Error()
	}
	defer listener.Close()
	conn, err := net.Dial("tcp", "127.0.0.1:"+port)
	if err != nil {
		var errno syscall.Errno
		if errors.As(err, &errno) && errno == syscall.ECONNREFUSED {
			return "ECONNREFUSED"
		}
		return err.Error()
	}
	conn.Close()
	return "ok"
}

// recvms measures how long the server side of 127.0.0.1:port takes to read one byte.
func recvms(port string) int64 {
	listener, err := net.Listen("tcp", "127.0.0.1:"+port)
	if err != nil {
		return -1
	}
	defer listener.Close()
	go func() {
		conn, err := net.Dial("tcp", "127.0.0.1:"+port)
		if err == nil {
			conn.Write([]byte("x"))
			time.Sleep(time.Second)
			conn.Close()
		}
	}()
	conn, err := listener.Accept()
	if err != nil {
		return -1
	}
	defer conn.Close()
	buffer := make([]byte, 1)
	start := time.Now()
	conn.Read(buffer)
	return time.Since(start).Milliseconds()
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
	case "dial":
		fmt.Println(dial(os.Args[2]))
	case "recvms":
		fmt.Println(recvms(os.Args[2]))
	}
}
