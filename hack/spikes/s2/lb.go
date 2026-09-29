package main

import (
	"context"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// runLB is a layer 4 load balancer, as a Kubernetes Service or a cloud load
// balancer would be: round robin over the backends that accept a connection,
// TLS passing through untouched.
func runLB(args []string) error {
	fs := flag.NewFlagSet("lb", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:9700", "listen address")
	backendList := fs.String("backends", "127.0.0.1:9701,127.0.0.1:9702", "backend addresses")
	admin := fs.String("admin", "127.0.0.1:9710", "spike admin address (HTTP)")
	_ = fs.Parse(args)

	backends := strings.Split(*backendList, ",")
	active := make([]atomic.Int64, len(backends))
	var next atomic.Uint64

	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", *addr)
	if err != nil {
		return err
	}
	adminMux := http.NewServeMux()
	adminMux.HandleFunc("GET /spike/stats", func(w http.ResponseWriter, _ *http.Request) {
		counts := map[string]int64{}
		for i, b := range backends {
			counts[b] = active[i].Load()
		}
		writeJSON(w, counts)
	})
	go func() {
		srv := &http.Server{Addr: *admin, Handler: adminMux, ReadHeaderTimeout: 10 * time.Second}
		log.Fatal(srv.ListenAndServe())
	}()
	log.Printf("lb: %s -> %v", *addr, backends)

	dialer := &net.Dialer{Timeout: time.Second}
	for {
		client, err := ln.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer func() { _ = client.Close() }()
			start := int(next.Add(1) % uint64(len(backends))) //nolint:gosec // G115: the remainder is smaller than the number of backends
			for i := range backends {
				b := (start + i) % len(backends)
				server, err := dialer.DialContext(context.Background(), "tcp", backends[b])
				if err != nil {
					continue
				}
				active[b].Add(1)
				pipe(client, server)
				active[b].Add(-1)
				return
			}
		}()
	}
}

// pipe copies both ways until either side closes, then closes both.
func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	_ = a.Close()
	_ = b.Close()
	<-done
}
