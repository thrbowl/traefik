package tcp

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
)

func dialProxyDestination(srcAddrString string, dstAddrString string) (*net.TCPConn, error) {
	srcAddr, err := net.ResolveTCPAddr("tcp", srcAddrString)
	if err != nil {
		return nil, &net.OpError{Op: "dial", Err: fmt.Errorf("build src address: %s", err)}
	}

	dstAddr, err := net.ResolveTCPAddr("tcp", dstAddrString)
	if err != nil {
		return nil, &net.OpError{Op: "dial", Err: fmt.Errorf("build dst address: %s", err)}
	}

	srcSocketAddress, err := tcpAddrToSocketAddr(srcAddr)
	if err != nil {
		return nil, &net.OpError{Op: "dial", Err: fmt.Errorf("build local socket address: %s", err)}
	}

	dstSocketAddress, err := tcpAddrToSocketAddr(dstAddr)
	if err != nil {
		return nil, &net.OpError{Op: "dial", Err: fmt.Errorf("build destination socket address: %s", err)}
	}

	fileDescriptor, err := syscall.Socket(tcpAddrFamily("tcp", dstAddr, srcAddr), syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
	if err != nil {
		return nil, &net.OpError{Op: "dial", Err: fmt.Errorf("socket open: %s", err)}
	}

	if err = syscall.SetsockoptInt(fileDescriptor, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		syscall.Close(fileDescriptor)
		return nil, &net.OpError{Op: "dial", Err: fmt.Errorf("set socket option: SO_REUSEADDR: %s", err)}
	}

	if err = syscall.SetsockoptInt(fileDescriptor, syscall.SOL_IP, syscall.IP_TRANSPARENT, 1); err != nil {
		syscall.Close(fileDescriptor)
		return nil, &net.OpError{Op: "dial", Err: fmt.Errorf("set socket option: IP_TRANSPARENT: %s", err)}
	}

	if err = syscall.SetNonblock(fileDescriptor, true); err != nil {
		syscall.Close(fileDescriptor)
		return nil, &net.OpError{Op: "dial", Err: fmt.Errorf("set socket option: SO_NONBLOCK: %s", err)}
	}

	if err = syscall.Bind(fileDescriptor, srcSocketAddress); err != nil {
		syscall.Close(fileDescriptor)
		return nil, &net.OpError{Op: "dial", Err: fmt.Errorf("socket bind: %s", err)}
	}

	if err = syscall.Connect(fileDescriptor, dstSocketAddress); err != nil && !strings.Contains(err.Error(), "operation now in progress") {
		syscall.Close(fileDescriptor)
		return nil, &net.OpError{Op: "dial", Err: fmt.Errorf("socket connect: %s", err)}
	}

	fdFile := os.NewFile(uintptr(fileDescriptor), fmt.Sprintf("net-tcp-dial-%s", dstAddrString))
	defer fdFile.Close()

	conn, err := net.FileConn(fdFile)
	if err != nil {
		syscall.Close(fileDescriptor)
		return nil, &net.OpError{Op: "dial", Err: fmt.Errorf("convert file descriptor to connection: %s", err)}
	}

	return conn.(*net.TCPConn), nil
}

// tcpAddToSockerAddr will convert a TCPAddr
// into a Sockaddr that may be used when
// connecting and binding sockets
func tcpAddrToSocketAddr(addr *net.TCPAddr) (syscall.Sockaddr, error) {
	switch {
	case addr.IP.To4() != nil:
		ip := [4]byte{}
		copy(ip[:], addr.IP.To4())

		return &syscall.SockaddrInet4{Addr: ip, Port: addr.Port}, nil

	default:
		ip := [16]byte{}
		copy(ip[:], addr.IP.To16())

		zoneID, err := strconv.ParseUint(addr.Zone, 10, 32)
		if err != nil {
			return nil, err
		}

		return &syscall.SockaddrInet6{Addr: ip, Port: addr.Port, ZoneId: uint32(zoneID)}, nil
	}
}

// tcpAddrFamily will attempt to work
// out the address family based on the
// network and TCP addresses
func tcpAddrFamily(net string, laddr, raddr *net.TCPAddr) int {
	switch net[len(net)-1] {
	case '4':
		return syscall.AF_INET
	case '6':
		return syscall.AF_INET6
	}

	if (laddr == nil || laddr.IP.To4() != nil) &&
		(raddr == nil || laddr.IP.To4() != nil) {
		return syscall.AF_INET
	}
	return syscall.AF_INET6
}
