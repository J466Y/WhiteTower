package tracing

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"

	"github.com/J466Y/WhiteTower/internal/platform/config"
	"github.com/J466Y/WhiteTower/internal/version"
)

// httpClient sends spans to an OTLP/HTTP receiver, as gzipped protobuf. It
// stands in for the otlptracehttp exporter, which links gRPC, grpc-gateway
// and genproto into the binary (about 8 MB) although OTLP over HTTP uses none
// of them; the otlptrace exporter still turns spans into OTLP.
type httpClient struct {
	url       string
	userAgent string
	client    *http.Client
}

// One batch gets up to maxAttempts attempts, the delay doubling from
// retryDelay, or longer when the receiver asks. The batch span processor
// gives an export 30 seconds, then drops the batch.
const maxAttempts = 5

var retryDelay = time.Second

func newHTTPClient(cfg config.OTLP, v version.Info) (*httpClient, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile) //nolint:gosec // G304: the operator chooses the file
		if err != nil {
			return nil, fmt.Errorf("tracing.otlp.ca_file: %w", err)
		}
		tlsConfig.RootCAs = x509.NewCertPool()
		if !tlsConfig.RootCAs.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("tracing.otlp.ca_file: no PEM certificate in %s", cfg.CAFile)
		}
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig
	return &httpClient{
		url:       strings.TrimRight(cfg.Endpoint, "/") + "/v1/traces",
		userAgent: "whitetower/" + v.Version,
		client: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
			// A receiver has no reason to redirect, and following one could
			// send spans elsewhere.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

func (c *httpClient) Start(context.Context) error { return nil }

func (c *httpClient) Stop(context.Context) error {
	c.client.CloseIdleConnections()
	return nil
}

// UploadTraces sends one batch of spans. It tries again when the receiver
// cannot be reached or asks to (429, 502, 503 and 504), until ctx ends.
func (c *httpClient) UploadTraces(ctx context.Context, spans []*tracepb.ResourceSpans) error {
	// TracesData has the wire format of ExportTraceServiceRequest, whose Go
	// package would bring in gRPC.
	data, err := proto.Marshal(&tracepb.TracesData{ResourceSpans: spans})
	if err != nil {
		return err
	}
	var body bytes.Buffer
	zw := gzip.NewWriter(&body)
	if _, err := zw.Write(data); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}

	delay := retryDelay
	for attempt := 1; ; attempt++ {
		retry, wait, err := c.send(ctx, body.Bytes())
		if err == nil || !retry || attempt == maxAttempts {
			return err
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(max(wait, delay)):
		}
		delay *= 2
	}
}

// send makes one attempt. It reports whether a failure is worth another
// attempt, and how long the receiver asked to wait before it.
func (c *httpClient) send(ctx context.Context, body []byte) (retry bool, wait time.Duration, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return false, 0, err
	}
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("User-Agent", c.userAgent)
	resp, err := c.client.Do(req)
	if err != nil {
		// The receiver may be restarting: try again, unless ctx has ended
		// or its certificate was refused.
		var refused *tls.CertificateVerificationError
		return ctx.Err() == nil && !errors.As(err, &refused), 0, fmt.Errorf("sending spans: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))

	switch code := resp.StatusCode; {
	case code >= 200 && code < 300:
		return false, 0, nil
	case code == http.StatusTooManyRequests || code == http.StatusBadGateway ||
		code == http.StatusServiceUnavailable || code == http.StatusGatewayTimeout:
		return true, retryAfter(resp.Header.Get("Retry-After")), fmt.Errorf("sending spans to %s: %s", c.url, resp.Status)
	default:
		return false, 0, fmt.Errorf("sending spans to %s: %s", c.url, resp.Status)
	}
}

// retryAfter reads a Retry-After header given in seconds, capped at 30
// seconds, the time an export gets.
func retryAfter(v string) time.Duration {
	s, err := strconv.Atoi(v)
	if err != nil || s <= 0 {
		return 0
	}
	return min(time.Duration(s)*time.Second, 30*time.Second)
}
