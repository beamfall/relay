//go:build !linux && !darwin

package protocol

import "net"

func boundUnsentBacklog(conn *net.TCPConn) net.Conn { return conn }
