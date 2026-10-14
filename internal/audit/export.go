// Package audit provides the tamper-evident audit log and its export pipeline (plan P1-02).
package audit

import (
	"bytes"
	"cmp"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gowebpki/jcs"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"

	"github.com/J466Y/WhiteTower/internal/audit/auditdb"
	"github.com/J466Y/WhiteTower/internal/platform/clock"
	"github.com/J466Y/WhiteTower/internal/platform/db"
	"github.com/J466Y/WhiteTower/internal/platform/jobs"
	"github.com/J466Y/WhiteTower/internal/platform/logging"
	"github.com/J466Y/WhiteTower/internal/platform/metrics"
	"github.com/J466Y/WhiteTower/internal/version"
)

// Sink is an export destination for sealed audit events (plan P1-02, step 8).
type Sink interface {
	// Name returns the sink identifier used to track its cursor in audit_export_cursors.
	Name() string
	// Export sends a batch of events in index order. Returning nil means the batch
	// was durably accepted, allowing the exporter to advance the sink's cursor.
	Export(ctx context.Context, batch []auditdb.ExportLeavesRow) error
	// Close flushes and releases any open resources.
	Close() error
}

// Pseudonymizer replaces human principal identifiers with deterministic, one-way
// pseudonymous UUIDs (requirement NFR-20).
type Pseudonymizer struct {
	key []byte
}

// NewPseudonymizer returns a pseudonymizer using the secret key.
func NewPseudonymizer(key []byte) *Pseudonymizer {
	return &Pseudonymizer{key: key}
}

// Pseudonymize returns a deterministic RFC 4122 UUID derived from principalID and the secret key.
func (p *Pseudonymizer) Pseudonymize(principalID string) string {
	if principalID == "" || len(p.key) == 0 {
		return principalID
	}
	mac := hmac.New(sha256.New, p.key)
	mac.Write([]byte(principalID))
	sum := mac.Sum(nil)

	var u uuid.UUID
	copy(u[:], sum[:16])
	u[6] = (u[6] & 0x0f) | 0x50 // version 5
	u[8] = (u[8] & 0x3f) | 0x80 // RFC 4122 variant
	return u.String()
}

// PseudonymizeCanonical returns canonical JSON with human principal identifiers replaced.
func (p *Pseudonymizer) PseudonymizeCanonical(raw []byte) ([]byte, error) {
	if len(p.key) == 0 || len(raw) == 0 {
		return raw, nil
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	if data, ok := doc["data"].(map[string]any); ok {
		p.pseudonymizeMap(data)
	}
	marshaled, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	transformed, err := jcs.Transform(marshaled)
	if err != nil {
		return nil, fmt.Errorf("canonicalize json: %w", err)
	}
	return transformed, nil
}

func (p *Pseudonymizer) pseudonymizeMap(m map[string]any) {
	for _, val := range m {
		if sub, ok := val.(map[string]any); ok {
			if t, ok := sub["type"].(string); ok && t == "human" {
				if id, ok := sub["id"].(string); ok && id != "" {
					sub["id"] = p.Pseudonymize(id)
				}
			}
			p.pseudonymizeMap(sub)
		}
	}
}

// rotatingWriter writes to a file with size-based rotation, or to stdout.
type rotatingWriter struct {
	mu         sync.Mutex
	path       string
	isStdout   bool
	maxBytes   int64
	maxBackups int
	file       *os.File
	size       int64
}

func newRotatingWriter(path string, maxBytes int64, maxBackups int) (*rotatingWriter, error) {
	if path == "-" || path == "stdout" {
		return &rotatingWriter{path: path, isStdout: true}, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("create export dir: %w", err)
	}
	f, err := os.OpenFile(filepath.Clean(path), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // G304: the operator chooses the export file
	if err != nil {
		return nil, fmt.Errorf("open export file: %w", err)
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("stat export file: %w", err)
	}
	return &rotatingWriter{
		path:       path,
		maxBytes:   maxBytes,
		maxBackups: maxBackups,
		file:       f,
		size:       fi.Size(),
	}, nil
}

func (w *rotatingWriter) Write(p []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.isStdout {
		_, err := os.Stdout.Write(p)
		return err
	}

	if w.maxBytes > 0 && w.size+int64(len(p)) > w.maxBytes {
		if err := w.rotate(); err != nil {
			return err
		}
	}

	n, err := w.file.Write(p)
	w.size += int64(n)
	return err
}

func (w *rotatingWriter) rotate() error {
	_ = w.file.Close()

	if w.maxBackups > 0 {
		for i := w.maxBackups - 1; i >= 1; i-- {
			oldPath := fmt.Sprintf("%s.%d", w.path, i)
			newPath := fmt.Sprintf("%s.%d", w.path, i+1)
			_ = os.Rename(oldPath, newPath)
		}
		_ = os.Rename(w.path, w.path+".1")
	}

	f, err := os.OpenFile(filepath.Clean(w.path), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) //nolint:gosec // G304: the operator chooses the export file
	if err != nil {
		return fmt.Errorf("open rotated export file: %w", err)
	}
	w.file = f
	w.size = 0
	return nil
}

func (w *rotatingWriter) Sync() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.isStdout || w.file == nil {
		return nil
	}
	return w.file.Sync()
}

func (w *rotatingWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.isStdout || w.file == nil {
		return nil
	}
	err := w.file.Close()
	w.file = nil
	return err
}

// JSONLSink writes sealed events as line-delimited JSON.
type JSONLSink struct {
	name   string
	writer *rotatingWriter
}

// NewJSONLSink returns a JSON Lines sink.
func NewJSONLSink(path string, maxSizeMB int, maxBackups int) (*JSONLSink, error) {
	maxBytes := int64(maxSizeMB) * 1024 * 1024
	rw, err := newRotatingWriter(path, maxBytes, maxBackups)
	if err != nil {
		return nil, err
	}
	return &JSONLSink{name: "jsonl", writer: rw}, nil
}

// Name returns the sink identifier.
func (s *JSONLSink) Name() string { return s.name }

// Export writes the batch of events to the JSON Lines sink and flushes to disk.
func (s *JSONLSink) Export(ctx context.Context, batch []auditdb.ExportLeavesRow) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	var buf bytes.Buffer
	for _, row := range batch {
		buf.Write(row.Canonical)
		buf.WriteByte('\n')
	}
	if err := s.writer.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("write jsonl export: %w", err)
	}
	if err := s.writer.Sync(); err != nil {
		return fmt.Errorf("sync jsonl export: %w", err)
	}
	return nil
}

// Close closes the underlying writer.
func (s *JSONLSink) Close() error { return s.writer.Close() }

// OTLPSinkOptions configure the OTLP/HTTP export sink.
type OTLPSinkOptions struct {
	// Endpoint is the base URL of the receiver (such as http://collector:4318).
	Endpoint string
	// CAFile is an optional path to PEM certificate authorities for https.
	CAFile string
	// Timeout bounds how long export HTTP requests may take.
	Timeout time.Duration
	// Headers are optional custom headers sent with every export request.
	Headers map[string]string
}

// OTLPSink exports audit log records to an OpenTelemetry collector over HTTP.
type OTLPSink struct {
	name    string
	url     string
	client  *http.Client
	headers map[string]string
}

// NewOTLPSink creates an OTLP/HTTP log exporter.
func NewOTLPSink(opts OTLPSinkOptions) (*OTLPSink, error) {
	url := strings.TrimRight(opts.Endpoint, "/")
	if !strings.HasSuffix(url, "/v1/logs") {
		url += "/v1/logs"
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	if opts.CAFile != "" {
		caCert, err := os.ReadFile(filepath.Clean(opts.CAFile)) //nolint:gosec // G304: the operator chooses the CA file
		if err != nil {
			return nil, fmt.Errorf("read otlp ca file: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, errors.New("failed to parse otlp ca certificate")
		}
		transport.TLSClientConfig = &tls.Config{
			RootCAs:    pool,
			MinVersion: tls.VersionTLS12,
		}
	}

	return &OTLPSink{
		name: "otlp",
		url:  url,
		client: &http.Client{
			Transport: transport,
			Timeout:   timeout,
		},
		headers: opts.Headers,
	}, nil
}

// Name returns the sink identifier.
func (s *OTLPSink) Name() string { return s.name }

// Export ships a batch of audit events as OTLP log records in protobuf format.
func (s *OTLPSink) Export(ctx context.Context, batch []auditdb.ExportLeavesRow) error {
	if len(batch) == 0 {
		return nil
	}

	records := make([]*logspb.LogRecord, 0, len(batch))
	for _, row := range batch {
		rec := s.buildRecord(row)
		records = append(records, rec)
	}

	req := &collogspb.ExportLogsServiceRequest{
		ResourceLogs: []*logspb.ResourceLogs{
			{
				Resource: &resourcepb.Resource{
					Attributes: []*commonpb.KeyValue{
						{
							Key:   "service.name",
							Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "whitetower"}},
						},
						{
							Key:   "service.version",
							Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: version.Get().Version}},
						},
					},
				},
				ScopeLogs: []*logspb.ScopeLogs{
					{
						Scope: &commonpb.InstrumentationScope{
							Name:    "whitetower.audit",
							Version: version.Get().Version,
						},
						LogRecords: records,
					},
				},
			},
		},
	}

	body, err := proto.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal otlp request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create otlp request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-protobuf")
	httpReq.Header.Set("User-Agent", "whitetower-exporter/"+version.Get().Version)
	for k, v := range s.headers {
		httpReq.Header.Set(k, v)
	}

	resp, err := s.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("send otlp request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("otlp collector returned status %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

func (s *OTLPSink) buildRecord(row auditdb.ExportLeavesRow) *logspb.LogRecord {
	severity := logspb.SeverityNumber_SEVERITY_NUMBER_INFO
	sevText := "INFO"
	if row.Outcome != nil {
		sevText = strings.ToUpper(*row.Outcome)
		switch *row.Outcome {
		case "deny", "blocked", "failure":
			severity = logspb.SeverityNumber_SEVERITY_NUMBER_WARN
		case "error":
			severity = logspb.SeverityNumber_SEVERITY_NUMBER_ERROR
		}
	}

	attrs := []*commonpb.KeyValue{
		{Key: "audit.leaf_index", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: row.LeafIndex}}},
		{Key: "audit.event_id", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: row.EventID}}},
		{Key: "audit.type", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: row.Type}}},
		{Key: "audit.source", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: row.Source}}},
		{Key: "audit.action", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: row.Action}}},
	}
	if row.Outcome != nil {
		attrs = append(attrs, &commonpb.KeyValue{Key: "audit.outcome", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: *row.Outcome}}})
	}
	if row.ActorType != "" {
		attrs = append(attrs, &commonpb.KeyValue{Key: "audit.actor_type", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: row.ActorType}}})
	}
	if row.ActorID != nil {
		attrs = append(attrs, &commonpb.KeyValue{Key: "audit.actor_id", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: *row.ActorID}}})
	}
	if row.SubjectAgentID != nil {
		attrs = append(attrs, &commonpb.KeyValue{Key: "audit.subject_agent_id", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: row.SubjectAgentID.String()}}})
	}
	if row.RequestID != nil {
		attrs = append(attrs, &commonpb.KeyValue{Key: "audit.request_id", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: *row.RequestID}}})
	}
	if row.TraceID != nil {
		attrs = append(attrs, &commonpb.KeyValue{Key: "audit.trace_id", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: *row.TraceID}}})
	}
	if row.Reason != nil {
		attrs = append(attrs, &commonpb.KeyValue{Key: "audit.reason", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: *row.Reason}}})
	}

	rec := &logspb.LogRecord{
		TimeUnixNano:         uint64(row.EventTime.UnixNano()),
		ObservedTimeUnixNano: uint64(row.IngestedAt.UnixNano()),
		SeverityNumber:       severity,
		SeverityText:         sevText,
		EventName:            row.Type,
		Body:                 &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: string(row.Canonical)}},
		Attributes:           attrs,
	}

	if row.TraceID != nil && len(*row.TraceID) == 32 {
		if traceBytes, err := hex.DecodeString(*row.TraceID); err == nil && len(traceBytes) == 16 {
			rec.TraceId = traceBytes
		}
	}

	return rec
}

// Close is a no-op for OTLPSink.
func (s *OTLPSink) Close() error { return nil }

// ExporterOptions are what the exporter needs from the server.
type ExporterOptions struct {
	DB           *db.DB
	Sinks        []Sink
	PollInterval time.Duration
	BatchSize    int
	PseudonymKey []byte
	Clock        clock.Clock
	Logger       *slog.Logger
	Metrics      *metrics.Audit
}

// Exporter ships sealed events from the Merkle tree in index order to configured sinks,
// tracking progress with a persistent cursor per sink (plan P1-02, step 8).
type Exporter struct {
	opts          ExporterOptions
	pseudonymizer *Pseudonymizer
	pollInterval  time.Duration
	batchSize     int
}

// NewExporter returns an exporter.
func NewExporter(opts ExporterOptions) *Exporter {
	opts.Clock = cmp.Or[clock.Clock](opts.Clock, clock.System)
	interval := opts.PollInterval
	if interval <= 0 {
		interval = time.Second
	}
	batchSize := opts.BatchSize
	if batchSize <= 0 {
		batchSize = 500
	}
	var pseudo *Pseudonymizer
	if len(opts.PseudonymKey) > 0 {
		pseudo = NewPseudonymizer(opts.PseudonymKey)
	}
	return &Exporter{
		opts:          opts,
		pseudonymizer: pseudo,
		pollInterval:  interval,
		batchSize:     batchSize,
	}
}

// Job returns the exporter as the background job audit-exporter.
func (e *Exporter) Job() jobs.Job {
	return jobs.Job{Name: "audit-exporter", Schedule: jobs.Every(e.pollInterval), Run: e.Run}
}

// Run exports sealed events to all configured sinks, round after round, until ctx ends.
func (e *Exporter) Run(ctx context.Context) error {
	defer func() {
		for _, s := range e.opts.Sinks {
			_ = s.Close()
		}
	}()

	if len(e.opts.Sinks) == 0 {
		<-ctx.Done()
		return ctx.Err()
	}

	retry := e.pollInterval
	for {
		wait := e.pollInterval
		hasMore, err := e.round(ctx)
		switch {
		case ctx.Err() != nil:
			return ctx.Err()
		case err != nil:
			e.opts.Logger.Log(ctx, slog.LevelWarn, "audit exporter: export round failed",
				"error", logging.Sanitize(err.Error()), "retry_in", retry.String())
			wait, retry = retry, min(2*retry, 5*time.Second)
		default:
			retry = e.pollInterval
			if hasMore {
				wait = 0
			}
		}

		if wait > 0 {
			t := e.opts.Clock.NewTimer(wait)
			select {
			case <-ctx.Done():
				t.Stop()
				return ctx.Err()
			case <-t.C():
			}
		}
	}
}

// round executes one export cycle across all configured sinks.
func (e *Exporter) round(ctx context.Context) (bool, error) {
	var treeSize int64
	err := e.opts.DB.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		var err error
		treeSize, err = auditdb.New(tx).TreeSize(ctx)
		return err
	})
	if err != nil {
		return false, err
	}

	hasMore := false
	for _, sink := range e.opts.Sinks {
		more, err := e.exportSink(ctx, sink, treeSize)
		if err != nil {
			return false, err
		}
		if more {
			hasMore = true
		}
	}
	return hasMore, nil
}

func (e *Exporter) exportSink(ctx context.Context, sink Sink, treeSize int64) (bool, error) {
	var cursor auditdb.WhitetowerAuditExportCursor
	var rows []auditdb.ExportLeavesRow

	err := e.opts.DB.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := auditdb.New(tx)
		c, err := q.GetExportCursor(ctx, sink.Name())
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				c = auditdb.WhitetowerAuditExportCursor{
					Sink:          sink.Name(),
					LastLeafIndex: -1,
				}
			} else {
				return err
			}
		}
		cursor = c
		limit := int32(min(max(1, e.batchSize), 5000))
		rows, err = q.ExportLeaves(ctx, auditdb.ExportLeavesParams{
			AfterLeafIndex: cursor.LastLeafIndex,
			BatchLimit:     limit,
		})
		return err
	})
	if err != nil {
		return false, err
	}

	if len(rows) == 0 {
		lag := max(0, treeSize-(cursor.LastLeafIndex+1))
		e.opts.Metrics.ExportLag(sink.Name(), lag)
		e.opts.Metrics.ExportCursor(sink.Name(), cursor.LastLeafIndex)
		return false, nil
	}

	// Apply pseudonymization of human identifiers if enabled (NFR-20).
	if e.pseudonymizer != nil {
		for i := range rows {
			if rows[i].ActorType == "human" && rows[i].ActorID != nil {
				pseudo := e.pseudonymizer.Pseudonymize(*rows[i].ActorID)
				rows[i].ActorID = &pseudo
			}
			canon, err := e.pseudonymizer.PseudonymizeCanonical(rows[i].Canonical)
			if err != nil {
				return false, fmt.Errorf("pseudonymize event %s: %w", rows[i].ID, err)
			}
			rows[i].Canonical = canon
		}
	}

	// Ship to sink.
	start := e.opts.Clock.Now()
	if err := sink.Export(ctx, rows); err != nil {
		e.opts.Metrics.ExportFailed(sink.Name())
		return false, fmt.Errorf("sink %s: %w", sink.Name(), err)
	}
	took := e.opts.Clock.Now().Sub(start)
	e.opts.Metrics.ExportDuration(sink.Name(), took)

	// Durably record advanced cursor.
	lastIndex := rows[len(rows)-1].LeafIndex
	err = e.opts.DB.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		return auditdb.New(tx).SetExportCursor(ctx, auditdb.SetExportCursorParams{
			Sink:          sink.Name(),
			LastLeafIndex: lastIndex,
			UpdatedAt:     e.opts.Clock.Now(),
		})
	})
	if err != nil {
		return false, fmt.Errorf("update cursor %s: %w", sink.Name(), err)
	}

	e.opts.Metrics.Exported(sink.Name(), len(rows))
	e.opts.Metrics.ExportCursor(sink.Name(), lastIndex)
	e.opts.Metrics.ExportLag(sink.Name(), max(0, treeSize-(lastIndex+1)))

	return len(rows) == e.batchSize, nil
}
