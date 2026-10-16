package rest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/J466Y/WhiteTower/internal/api/rest/gen"
	"github.com/J466Y/WhiteTower/internal/api/rest/problem"
	"github.com/J466Y/WhiteTower/internal/audit"
	"github.com/J466Y/WhiteTower/internal/authz"
	"github.com/J466Y/WhiteTower/internal/platform/auth"
)

// GetAuditEvents queries the audit log with filters and cursor pagination.
// Reads of the audit log are themselves audited (AUD-09).
func (s Server) GetAuditEvents(ctx context.Context, request gen.GetAuditEventsRequestObject) (gen.GetAuditEventsResponseObject, error) {
	if s.auditLog == nil {
		return nil, problem.New(problem.Internal, "audit log not initialized")
	}
	p := auth.PrincipalFrom(ctx)
	if p == nil {
		return nil, problem.New(problem.Unauthenticated, "authentication required")
	}

	grant, ok := authz.EffectiveGrant(p.Roles, authz.PermissionAuditEventsRead)
	if !ok {
		return nil, problem.New(problem.Forbidden, "your roles do not permit reading audit events")
	}

	var targetAgentID *uuid.UUID
	var ownerPrincipalID *uuid.UUID

	switch grant.Scope {
	case authz.ScopeAll:
		targetAgentID = request.Params.AgentId
	case authz.ScopeOwn:
		principalUUID, err := uuid.Parse(p.ID)
		if err != nil {
			return nil, fmt.Errorf("parsing principal ID %q: %w", p.ID, err)
		}
		if request.Params.AgentId != nil {
			isOwner, err := s.auditLog.IsAgentOwner(ctx, *request.Params.AgentId, principalUUID)
			if err != nil {
				return nil, fmt.Errorf("checking agent ownership: %w", err)
			}
			if !isOwner {
				return nil, problem.New(problem.Forbidden, "you do not own the specified agent")
			}
			targetAgentID = request.Params.AgentId
		} else {
			ownerPrincipalID = &principalUUID
		}
	default:
		return nil, problem.New(problem.Forbidden, "your roles do not permit reading audit events")
	}

	filter := audit.EventFilter{
		From:             request.Params.From,
		To:               request.Params.To,
		AgentID:          targetAgentID,
		ActorID:          request.Params.ActorId,
		ActorType:        request.Params.ActorType,
		EventType:        request.Params.Type,
		Action:           request.Params.Action,
		Outcome:          request.Params.Outcome,
		Source:           request.Params.Source,
		OwnerPrincipalID: ownerPrincipalID,
	}
	if request.Params.Cursor != nil {
		filter.Cursor = *request.Params.Cursor
	}
	if request.Params.Limit != nil {
		filter.Limit = *request.Params.Limit
	}

	result, err := s.auditLog.QueryEvents(ctx, filter)
	if err != nil {
		return nil, problem.New(problem.BadRequest, err.Error())
	}

	// Record read audit event (AUD-09, ST-12).
	queryDetails := make(map[string]any)
	if filter.AgentID != nil {
		queryDetails["agent_id"] = filter.AgentID.String()
	}
	if filter.ActorID != nil {
		queryDetails["actor_id"] = *filter.ActorID
	}
	if filter.ActorType != nil {
		queryDetails["actor_type"] = *filter.ActorType
	}
	if filter.EventType != nil {
		queryDetails["type"] = *filter.EventType
	}
	if filter.Action != nil {
		queryDetails["action"] = *filter.Action
	}
	if filter.Outcome != nil {
		queryDetails["outcome"] = *filter.Outcome
	}
	if filter.Source != nil {
		queryDetails["source"] = *filter.Source
	}
	if filter.From != nil {
		queryDetails["from"] = filter.From.Format(time.RFC3339)
	}
	if filter.To != nil {
		queryDetails["to"] = filter.To.Format(time.RFC3339)
	}

	_ = s.auditLog.RecordRead(ctx, audit.ReadAuditParams{
		Actor:          p,
		Operation:      "query",
		Query:          queryDetails,
		ResultsCount:   len(result.Events),
		SubjectAgentID: filter.AgentID,
	})

	genEvents := make([]gen.AuditEvent, len(result.Events))
	for i, e := range result.Events {
		var subject *string
		if e.SubjectAgentID != nil {
			s := e.SubjectAgentID.String()
			subject = &s
		}
		genEvents[i] = gen.AuditEvent{
			Id:         e.ID,
			Time:       e.Time,
			Source:     e.Source,
			Type:       e.Type,
			Subject:    subject,
			ActorType:  e.ActorType,
			ActorId:    e.ActorID,
			Action:     e.Action,
			Outcome:    e.Outcome,
			Reason:     e.Reason,
			RequestId:  e.RequestID,
			TraceId:    e.TraceID,
			IngestedAt: e.IngestedAt,
			Data:       e.Data,
			Canonical:  e.Canonical,
		}
	}

	var nextCursor *string
	if result.NextCursor != "" {
		nextCursor = &result.NextCursor
	}

	return gen.GetAuditEvents200JSONResponse{
		Events:     genEvents,
		NextCursor: nextCursor,
	}, nil
}

// GetAuditEvent retrieves an audit event by ID with its Merkle tree inclusion proof.
// Reads of the audit log are themselves audited (AUD-09).
func (s Server) GetAuditEvent(ctx context.Context, request gen.GetAuditEventRequestObject) (gen.GetAuditEventResponseObject, error) {
	if s.auditLog == nil {
		return nil, problem.New(problem.Internal, "audit log not initialized")
	}
	p := auth.PrincipalFrom(ctx)
	if p == nil {
		return nil, problem.New(problem.Unauthenticated, "authentication required")
	}

	grant, ok := authz.EffectiveGrant(p.Roles, authz.PermissionAuditEventsRead)
	if !ok {
		return nil, problem.New(problem.Forbidden, "your roles do not permit reading audit events")
	}

	detail, err := s.auditLog.GetEvent(ctx, request.Id)
	if err != nil {
		if errors.Is(err, audit.ErrEventNotFound) {
			return nil, problem.New(problem.NotFound, "audit event not found")
		}
		return nil, fmt.Errorf("retrieving audit event: %w", err)
	}

	// Verify ownership scope if principal has ScopeOwn.
	if grant.Scope == authz.ScopeOwn {
		if detail.Event.SubjectAgentID == nil {
			return nil, problem.New(problem.Forbidden, "you do not have permission to view this event")
		}
		principalUUID, err := uuid.Parse(p.ID)
		if err != nil {
			return nil, fmt.Errorf("parsing principal ID %q: %w", p.ID, err)
		}
		isOwner, err := s.auditLog.IsAgentOwner(ctx, *detail.Event.SubjectAgentID, principalUUID)
		if err != nil {
			return nil, fmt.Errorf("checking agent ownership: %w", err)
		}
		if !isOwner {
			return nil, problem.New(problem.Forbidden, "you do not have permission to view this event")
		}
	}

	// Record read audit event (AUD-09, ST-12).
	_ = s.auditLog.RecordRead(ctx, audit.ReadAuditParams{
		Actor:          p,
		Operation:      "get",
		Query:          map[string]any{"event_id": request.Id.String()},
		ResultsCount:   1,
		SubjectAgentID: detail.Event.SubjectAgentID,
	})

	var subject *string
	if detail.Event.SubjectAgentID != nil {
		s := detail.Event.SubjectAgentID.String()
		subject = &s
	}

	event := gen.AuditEvent{
		Id:         detail.Event.ID,
		Time:       detail.Event.Time,
		Source:     detail.Event.Source,
		Type:       detail.Event.Type,
		Subject:    subject,
		ActorType:  detail.Event.ActorType,
		ActorId:    detail.Event.ActorID,
		Action:     detail.Event.Action,
		Outcome:    detail.Event.Outcome,
		Reason:     detail.Event.Reason,
		RequestId:  detail.Event.RequestID,
		TraceId:    detail.Event.TraceID,
		IngestedAt: detail.Event.IngestedAt,
		Data:       detail.Event.Data,
		Canonical:  detail.Event.Canonical,
	}

	var proof *gen.AuditInclusionProof
	if detail.Proof != nil {
		proof = &gen.AuditInclusionProof{
			LeafIndex:  detail.Proof.LeafIndex,
			TreeSize:   detail.Proof.TreeSize,
			RootHash:   detail.Proof.RootHash,
			Hashes:     detail.Proof.Hashes,
			Checkpoint: detail.Proof.Checkpoint,
		}
	}

	return gen.GetAuditEvent200JSONResponse{
		Event: event,
		Proof: proof,
	}, nil
}

// GetAuditCheckpoints lists stored signed checkpoints.
func (s Server) GetAuditCheckpoints(ctx context.Context, _ gen.GetAuditCheckpointsRequestObject) (gen.GetAuditCheckpointsResponseObject, error) {
	if s.auditLog == nil {
		return nil, problem.New(problem.Internal, "audit log not initialized")
	}
	p := auth.PrincipalFrom(ctx)
	if p == nil {
		return nil, problem.New(problem.Unauthenticated, "authentication required")
	}

	if _, ok := authz.EffectiveGrant(p.Roles, authz.PermissionAuditVerify); !ok {
		return nil, problem.New(problem.Forbidden, "your roles do not permit viewing checkpoints")
	}

	checkpoints, err := s.auditLog.ListCheckpoints(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing checkpoints: %w", err)
	}

	_ = s.auditLog.RecordRead(ctx, audit.ReadAuditParams{
		Actor:        p,
		Operation:    "checkpoints",
		ResultsCount: len(checkpoints),
	})

	out := make([]gen.AuditCheckpoint, len(checkpoints))
	for i, cp := range checkpoints {
		out[i] = gen.AuditCheckpoint{
			TreeSize:  cp.TreeSize,
			RootHash:  cp.RootHash,
			KeyId:     cp.KeyID,
			Note:      cp.Note,
			CreatedAt: cp.CreatedAt,
		}
	}

	return gen.GetAuditCheckpoints200JSONResponse(out), nil
}

// GetAuditKeys lists public halves of checkpoint signing keys as JWKs.
func (s Server) GetAuditKeys(ctx context.Context, _ gen.GetAuditKeysRequestObject) (gen.GetAuditKeysResponseObject, error) {
	if s.auditLog == nil {
		return nil, problem.New(problem.Internal, "audit log not initialized")
	}
	p := auth.PrincipalFrom(ctx)
	if p == nil {
		return nil, problem.New(problem.Unauthenticated, "authentication required")
	}

	if _, ok := authz.EffectiveGrant(p.Roles, authz.PermissionAuditVerify); !ok {
		return nil, problem.New(problem.Forbidden, "your roles do not permit viewing checkpoint keys")
	}

	rawKeys, err := s.auditLog.CheckpointKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading checkpoint keys: %w", err)
	}

	_ = s.auditLog.RecordRead(ctx, audit.ReadAuditParams{
		Actor:        p,
		Operation:    "keys",
		ResultsCount: len(rawKeys),
	})

	out := make([]map[string]interface{}, 0, len(rawKeys))
	for _, raw := range rawKeys {
		var jwk map[string]interface{}
		if err := json.Unmarshal(raw, &jwk); err != nil {
			continue
		}
		out = append(out, jwk)
	}

	return gen.GetAuditKeys200JSONResponse(out), nil
}
