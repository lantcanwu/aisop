package models

import (
	"time"

	"github.com/google/uuid"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

type EventStatus string

const (
	StatusCreated         EventStatus = "created"
	StatusTriaged         EventStatus = "triaged"
	StatusInProgress      EventStatus = "in_progress"
	StatusResolved        EventStatus = "resolved"
	StatusClosed          EventStatus = "closed"
	StatusPendingApproval EventStatus = "pending_approval"
)

type EventClassification string

const (
	ClassificationUnknown       EventClassification = "unknown"
	ClassificationFalsePositive EventClassification = "false_positive"
	ClassificationConfirmed     EventClassification = "confirmed"
	ClassificationPending       EventClassification = "pending"
)

type IoCType string

const (
	IoCTypeIP     IoCType = "ip"
	IoCTypeDomain IoCType = "domain"
	IoCTypeHash   IoCType = "hash"
	IoCTypeEmail  IoCType = "email"
	IoCTypeURL    IoCType = "url"
)

type IoC struct {
	Type       IoCType   `json:"type"`
	Value      string    `json:"value"`
	Source     string    `json:"source"`
	Updated    time.Time `json:"updated"`
	Tags       []string  `json:"tags,omitempty"`
	Confidence float64   `json:"confidence,omitempty"`
}

type AIAnalysisResult struct {
	Summary     string   `json:"summary"`
	AttackType  string   `json:"attack_type"`
	Confidence  float64  `json:"confidence"`
	Impact      string   `json:"impact"`
	Suggestions []string `json:"suggestions"`
	TTP         []string `json:"ttp,omitempty"`
}

type SecurityEvent struct {
	ID             string                 `json:"id"`
	Source         string                 `json:"source"`
	SourceType     string                 `json:"source_type"`
	EventType      string                 `json:"event_type"`
	Severity       Severity               `json:"severity"`
	Status         EventStatus            `json:"status"`
	Classification EventClassification    `json:"classification"`
	Title          string                 `json:"title"`
	Description    string                 `json:"description"`
	RawData        map[string]interface{} `json:"raw_data"`
	IoCs           []IoC                  `json:"iocs"`
	AssetIDs       []string               `json:"asset_ids"`
	TTP            []string               `json:"ttp"`
	AIAnalysis     *AIAnalysisResult      `json:"ai_analysis,omitempty"`
	CorrelationIDs []string               `json:"correlation_ids"`
	CreatedAt      time.Time              `json:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at"`
	ClassifiedAt   *time.Time             `json:"classified_at,omitempty"`
	ResolvedAt     *time.Time             `json:"resolved_at,omitempty"`
	ClosedAt       *time.Time             `json:"closed_at,omitempty"`
}

func (e *SecurityEvent) SetID() {
	if e.ID == "" {
		e.ID = uuid.New().String()
	}
}

func (e *SecurityEvent) SetTimestamps() {
	now := time.Now()
	if e.CreatedAt.IsZero() {
		e.CreatedAt = now
	}
	e.UpdatedAt = now
}

func ParseSeverity(s string) Severity {
	switch s {
	case "critical", "crit", "fatal", "emergency", "alert":
		return SeverityCritical
	case "high", "error", "err":
		return SeverityHigh
	case "medium", "warning", "warn":
		return SeverityMedium
	case "low", "notice", "info":
		return SeverityLow
	default:
		return SeverityInfo
	}
}

func ParseIoCType(t string) IoCType {
	switch t {
	case "ip", "ipv4", "ipv6":
		return IoCTypeIP
	case "domain", "hostname", "fqdn":
		return IoCTypeDomain
	case "hash", "md5", "sha1", "sha256":
		return IoCTypeHash
	case "email", "email_address":
		return IoCTypeEmail
	case "url", "uri":
		return IoCTypeURL
	default:
		return IoCTypeDomain
	}
}
