//go:build !unix

package agent

import "syscall"

const relayUDPPooledSupported = false

func readUpstreamUDPPooled(syscall.RawConn) (*[]byte, int, error) {
	return nil, 0, syscall.ENOTSUP
}
