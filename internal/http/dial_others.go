package http

import (
	"context"
	"net"
	"time"
)

// DialContext is a function to make custom Dial for internode communications
type DialContext func(ctx context.Context, network, address string) (net.Conn, error)

// NewCustomDialContext configures a custom dialer for internode communications
func NewCustomDialContext(dialTimeout time.Duration) DialContext {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := &net.Dialer{
			Timeout: dialTimeout,
		}
		return dialer.DialContext(ctx, network, addr)
	}
}
