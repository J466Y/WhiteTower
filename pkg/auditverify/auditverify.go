// Package auditverify verifies White Tower's audit log: its events, the
// Merkle tree over them (RFC 6962), the checkpoints signed over the tree (the
// C2SP tlog-checkpoint format), and the proofs that an event is in the tree
// or that one tree extends another (plan P1-02, step 7).
//
// It shares no code with the core that writes the log, so that it checks the
// core rather than repeat it, and auditors can read it, run it and trust it
// apart from White Tower. It reads a log through a Source: the core's
// database, its API or an export.
package auditverify

import "golang.org/x/mod/sumdb/tlog"

// Hash is a hash of the tree: a leaf's, a subtree's or a root. Hashing, and
// where a log stores each hash, are those of golang.org/x/mod/sumdb/tlog.
type Hash = tlog.Hash

// LeafHash returns the hash of the leaf that holds an event: the RFC 6962
// hash of the event's canonical bytes (RFC 8785), as the log stores them.
func LeafHash(event []byte) Hash { return tlog.RecordHash(event) }
