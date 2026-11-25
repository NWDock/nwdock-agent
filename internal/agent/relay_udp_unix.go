//go:build unix

package agent

import "syscall"

const relayUDPPooledSupported = true

// readUpstreamUDPPooled 在 netpoller 上零缓冲等待上游 UDP 可读，仅在有包到达时
// 从 relayUDPBufPool 借出 64KiB 切片读包，由调用方写回客户端后立刻归还池中，
// 避免每条空闲 UDP 会话长期按 64KiB 常驻堆内存。
func readUpstreamUDPPooled(rc syscall.RawConn) (*[]byte, int, error) {
	var (
		gotBuf  *[]byte
		gotN    int
		readErr error
	)
	ctrlErr := rc.Read(func(fd uintptr) bool {
		bp := relayUDPBufPool.Get().(*[]byte)
		for {
			n, err := syscall.Read(int(fd), *bp)
			if err == syscall.EINTR {
				// 信号中断时内核缓冲可能已有可读数据，直接原地重试，
				// 避免在 Linux EPOLLET 下返回 false 进入 waitRead 错过边沿事件。
				continue
			}
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
				relayUDPBufPool.Put(bp)
				return false
			}
			if err != nil {
				relayUDPBufPool.Put(bp)
				readErr = err
				return true
			}
			gotBuf = bp
			gotN = n
			return true
		}
	})
	if ctrlErr != nil {
		if gotBuf != nil {
			relayUDPBufPool.Put(gotBuf)
		}
		return nil, 0, ctrlErr
	}
	if readErr != nil {
		return nil, 0, readErr
	}
	return gotBuf, gotN, nil
}
