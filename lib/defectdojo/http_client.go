package defectdojo

import (
	"net"
	"net/http"
	"sync"
	"time"
)

var (
	clientPoolMu sync.Mutex
	clientPool   = make(map[time.Duration]*http.Client)
)

// getHTTPClient returns a shared http.Client for the given timeout.
// Reusing clients enables connection pooling and reduces per-request allocations.
func getHTTPClient(timeout time.Duration) *http.Client {
	clientPoolMu.Lock()
	defer clientPoolMu.Unlock()
	if c, ok := clientPool[timeout]; ok {
		return c
	}
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          256,
		MaxIdleConnsPerHost:   64,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	c := &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}
	clientPool[timeout] = c
	return c
}