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
//	seccomp_go clock          time.Now() twice around a 20 ms sleep: the wall second, whether
//	                          both reads agree, and the monotonic difference in ms
//	seccomp_go torn <path>    writes ten bytes twice -- once through syscall.Write and once
//	                          through os.File.Write -- and prints both counts, for TORN:
//	                          the raw call shows the tear, the os.File one does not, because
//	                          internal/poll re-issues the rest until the buffer is written
//	seccomp_go throttle <path> writes 512 KiB through os.File in two halves and prints the
//	                          elapsed ms: a rate still holds, because the loop that hides a
//	                          short write issues the remainder at the same rate
//	seccomp_go trickle <port> sends ten bytes over a loopback pair and prints what one
//	                          net.Conn.Read returned, for TRICKLE
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
	if len(os.Args) < 2 ||
		(os.Args[1] != "spawn" && os.Args[1] != "clock" && len(os.Args) != 3) {
		fmt.Fprintln(os.Stderr,
			"usage: seccomp_go open|openms|torn|throttle <path> | "+
				"dial|recvms|trickle <port> | "+
				"spawn | clock | mmap <bytes>")
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
	case "clock":
		// time.Now() reads the wall clock and the monotonic clock in one call, both from
		// the vDSO -- so this only sees a time rule once chaos-init has made the vDSO
		// lookups of this image fail. A wall-clock rule must show in the seconds while
		// time.Since stays right, which is the property Go programs depend on.
		first := time.Now()
		time.Sleep(20 * time.Millisecond)
		second := time.Now()
		fmt.Printf("sec=%d same=%t since=%dms\n", first.Unix(), first.Unix() == second.Unix(),
			second.Sub(first).Milliseconds())
	case "torn":
		// Two writes of ten bytes: the raw system call and the os.File wrapper. Measured:
		// the raw call returns the shortened count, the wrapper returns ten, because
		// internal/poll.FD.Write loops until the buffer is written. A TORN rule is
		// therefore visible to a Go program only where it makes the call itself.
		fd, err := syscall.Open(os.Args[2], syscall.O_WRONLY|syscall.O_CREAT|syscall.O_TRUNC, 0o644)
		if err != nil {
			fmt.Printf("open=%v\n", err)
			return
		}
		raw, rawErr := syscall.Write(fd, []byte("0123456789"))
		syscall.Close(fd)
		file, err := os.OpenFile(os.Args[2], os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
		if err != nil {
			fmt.Printf("open=%v\n", err)
			return
		}
		wrapped, wrappedErr := file.Write([]byte("0123456789"))
		file.Close()
		if rawErr != nil || wrappedErr != nil {
			fmt.Printf("raw=%v wrapped=%v\n", rawErr, wrappedErr)
			return
		}
		fmt.Printf("raw=%d wrapped=%d\n", raw, wrapped)
	case "trickle":
		// One net.Conn.Read is one read system call, so a chunked receive shows up as a
		// count below what was asked for, with the rest still in the socket.
		listener, err := net.Listen("tcp", "127.0.0.1:"+os.Args[2])
		if err != nil {
			fmt.Printf("listen=%v\n", err)
			return
		}
		defer listener.Close()
		client, err := net.Dial("tcp", "127.0.0.1:"+os.Args[2])
		if err != nil {
			fmt.Printf("dial=%v\n", err)
			return
		}
		defer client.Close()
		server, err := listener.Accept()
		if err != nil {
			fmt.Printf("accept=%v\n", err)
			return
		}
		defer server.Close()
		if _, err = client.Write([]byte("0123456789")); err != nil {
			fmt.Printf("send=%v\n", err)
			return
		}
		buffer := make([]byte, 10)
		got, err := server.Read(buffer)
		if err != nil {
			fmt.Printf("read=%v\n", err)
			return
		}
		fmt.Printf("first=%d\n", got)
	case "throttle":
		// 512 KiB in two halves through os.File. The write loop re-issues what a
		// shortened call left, so the rate shows up as time rather than as a short write.
		file, err := os.OpenFile(os.Args[2], os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
		if err != nil {
			fmt.Printf("open=%v\n", err)
			return
		}
		block := make([]byte, 256*1024)
		start := time.Now()
		for round := 0; round < 2; round++ {
			if _, err = file.Write(block); err != nil {
				fmt.Printf("write=%v\n", err)
				file.Close()
				return
			}
		}
		file.Close()
		fmt.Printf("%d\n", time.Since(start).Milliseconds())
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
