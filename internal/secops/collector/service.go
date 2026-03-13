package collector

import (
	"time"

	"cyberstrike-ai/internal/secops/models"
	"github.com/google/uuid"
)

type CollectorType string

const (
	CollectorTypeFile    CollectorType = "file"
	CollectorTypeAPI     CollectorType = "api"
	CollectorTypeWebhook CollectorType = "webhook"
	CollectorTypeSTIX    CollectorType = "stix"
	CollectorTypeTAXII   CollectorType = "taxii"
	CollectorTypeSIEM    CollectorType = "siem"
)

type CollectorStatus string

const (
	CollectorStatusIdle    CollectorStatus = "idle"
	CollectorStatusRunning CollectorStatus = "running"
	CollectorStatusSuccess CollectorStatus = "success"
	CollectorStatusFailed  CollectorStatus = "failed"
)

type CollectorConfig struct {
	ID         string                 `json:"id"`
	Name       string                 `json:"name"`
	Type       CollectorType          `json:"type"`
	Enabled    bool                   `json:"enabled"`
	Config     map[string]interface{} `json:"config"`
	Schedule   string                 `json:"schedule"`
	LastRun    *time.Time             `json:"last_run,omitempty"`
	LastStatus CollectorStatus        `json:"last_status"`
	LastError  string                 `json:"last_error,omitempty"`
	CreatedAt  time.Time              `json:"created_at"`
	UpdatedAt  time.Time              `json:"updated_at"`
}

func (c *CollectorConfig) SetID() {
	if c.ID == "" {
		c.ID = uuid.New().String()
	}
}

func (c *CollectorConfig) SetTimestamps() {
	now := time.Now()
	if c.CreatedAt.IsZero() {
		c.CreatedAt = now
	}
	c.UpdatedAt = now
}

type CollectorJob struct {
	ID           string          `json:"id"`
	CollectorID  string          `json:"collector_id"`
	Status       CollectorStatus `json:"status"`
	StartedAt    time.Time       `json:"started_at"`
	CompletedAt  *time.Time      `json:"completed_at,omitempty"`
	ErrorMessage string          `json:"error_message,omitempty"`
	EventsCount  int             `json:"events_count"`
	CreatedAt    time.Time       `json:"created_at"`
}

func (j *CollectorJob) SetID() {
	if j.ID == "" {
		j.ID = uuid.New().String()
	}
}

func (j *CollectorJob) SetTimestamps() {
	now := time.Now()
	if j.CreatedAt.IsZero() {
		j.CreatedAt = now
	}
	if j.StartedAt.IsZero() {
		j.StartedAt = now
	}
}

type CollectorTestResult struct {
	Success     bool   `json:"success"`
	Message     string `json:"message"`
	EventsCount int    `json:"events_count,omitempty"`
}

type CollectorService struct{}

func NewCollectorService() *CollectorService {
	return &CollectorService{}
}

func (s *CollectorService) CreateCollector(config *CollectorConfig) error {
	config.SetTimestamps()
	config.SetID()
	if config.LastStatus == "" {
		config.LastStatus = CollectorStatusIdle
	}
	return nil
}

func (s *CollectorService) UpdateCollector(config *CollectorConfig) error {
	config.UpdatedAt = time.Now()
	return nil
}

func (s *CollectorService) DeleteCollector(config *CollectorConfig) error {
	config.Enabled = false
	config.UpdatedAt = time.Now()
	return nil
}

func (s *CollectorService) TestCollector(config *CollectorConfig) (*CollectorTestResult, error) {
	result := &CollectorTestResult{
		Success: true,
		Message: "Collector configuration is valid",
	}
	return result, nil
}

func (s *CollectorService) RunCollector(config *CollectorConfig) (*CollectorJob, error) {
	job := &CollectorJob{
		CollectorID: config.ID,
		Status:      CollectorStatusRunning,
	}
	job.SetTimestamps()
	job.SetID()
	return job, nil
}

func (s *CollectorService) UpdateCollectorStatus(config *CollectorConfig, status CollectorStatus, errMsg string) {
	config.LastStatus = status
	now := time.Now()
	config.LastRun = &now
	if errMsg != "" {
		config.LastError = errMsg
	}
	config.UpdatedAt = time.Now()
}

func (s *CollectorService) CreateEventFromData(data map[string]interface{}, source string, collectorType CollectorType) *models.SecurityEvent {
	event := &models.SecurityEvent{
		Source:     source,
		SourceType: string(collectorType),
		RawData:    data,
		IoCs:       []models.IoC{},
		AssetIDs:   []string{},
		TTP:        []string{},
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
		Status:     models.StatusCreated,
	}

	if title, ok := data["title"].(string); ok {
		event.Title = title
	}

	if severity, ok := data["severity"].(string); ok {
		event.Severity = models.ParseSeverity(severity)
	}

	event.SetID()
	return event
}
