// Command seccomp_go is the Go tracee for test_seccomp.sh. Built with CGO_ENABLED=0 it is a
// static binary that makes raw system calls without libc, so LD_PRELOAD mode cannot reach it;
// faults it observes come only from chaos-init in SECCOMP mode. Each mode prints one result
// line for the script to compare.
//
// Usage:
//
//	seccomp_go open <path>    os.OpenFile(O_RDONLY|O_CREATE): "ok", "EIO" or the error text
//	seccomp_go openms <path>  the same, printing the elapsed ms (LATENCY checks)
//	seccomp_go dial <port>    listen on 127.0.0.1:<port>, net.Dial it: "ok" or "ECONNREFUSED"
//	seccomp_go recvms <port>  ms the server side takes to read one byte the client sent
//	seccomp_go spawn          os/exec runs /bin/true: "ok", "EAGAIN" or the error text
//	seccomp_go mmap <bytes>   syscall.Mmap of that many anonymous bytes: "ok" or "ENOMEM"
//
// Exit status: 0 after printing; 2 on bad usage.
package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"
)

// tryOpen opens path with O_CREATE and closes it: "ok", "EIO" or the error text.
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

// dial listens on 127.0.0.1:port and dials it; returns "ok", "ECONNREFUSED" or the error
// text.
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

// recvms returns how many ms the accepted server connection on 127.0.0.1:port blocks in Read
// for the one byte a client goroutine sends, or -1 on a setup error. A recv LATENCY rule on
// that port must add its delay here.
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
	if len(os.Args) < 2 || (os.Args[1] != "spawn" && len(os.Args) != 3) {
		fmt.Fprintln(os.Stderr, "usage: seccomp_go open|openms <path> | dial|recvms <port> | spawn | mmap <bytes>")
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
	case "spawn":
		// os/exec starts children with clone(CLONE_VFORK|CLONE_VM), which chaos-init maps to
		// the posix_spawn operation, so a posix_spawn rule must fail it.
		err := exec.Command("/bin/true").Run()
		var errno syscall.Errno
		switch {
		case err == nil:
			fmt.Println("ok")
		case errors.As(err, &errno) && errno == syscall.EAGAIN:
			fmt.Println("EAGAIN")
		default:
			fmt.Println(err.Error())
		}
	case "mmap":
		length, _ := strconv.Atoi(os.Args[2])
		_, err := syscall.Mmap(-1, 0, length, syscall.PROT_READ, syscall.MAP_ANON|syscall.MAP_PRIVATE)
		if errors.Is(err, syscall.ENOMEM) {
			fmt.Println("ENOMEM")
		} else if err == nil {
			fmt.Println("ok")
		} else {
			fmt.Println(err.Error())
		}
	}
}
