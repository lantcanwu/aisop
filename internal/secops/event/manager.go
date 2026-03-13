package event

import (
	"time"

	"cyberstrike-ai/internal/secops/enricher"
	"cyberstrike-ai/internal/secops/models"
	"cyberstrike-ai/internal/secops/normalizer"
)

type EventManager struct {
	eventStore EventStore
	normalizer *normalizer.Normalizer
	enricher   *enricher.EnricherService
}

type EventStore interface {
	Save(event *models.SecurityEvent) error
	Get(id string) (*models.SecurityEvent, error)
	List(filter EventFilter) ([]*models.SecurityEvent, error)
	Update(event *models.SecurityEvent) error
	Delete(id string) error
}

type EventFilter struct {
	Source         string
	SourceType     string
	Severity       []models.Severity
	Status         []models.EventStatus
	Classification []models.EventClassification
	EventType      string
	StartTime      time.Time
	EndTime        time.Time
	Keyword        string
	Page           int
	Limit          int
}

func NewEventManager() *EventManager {
	return &EventManager{
		normalizer: normalizer.NewNormalizer(),
		enricher:   enricher.NewEnricherService(),
	}
}

func (m *EventManager) CreateEvent(event *models.SecurityEvent) error {
	event.SetTimestamps()
	if event.ID == "" {
		event.SetID()
	}
	if event.Status == "" {
		event.Status = models.StatusCreated
	}
	if event.Classification == "" {
		event.Classification = models.ClassificationPending
	}
	if event.Severity == "" {
		event.Severity = models.SeverityInfo
	}

	m.normalizer.Normalize(event)

	return nil
}

func (m *EventManager) GetEvent(id string) (*models.SecurityEvent, error) {
	return nil, nil
}

func (m *EventManager) ListEvents(filter EventFilter) ([]*models.SecurityEvent, int, error) {
	if filter.Limit == 0 {
		filter.Limit = 20
	}
	if filter.Page == 0 {
		filter.Page = 1
	}
	return nil, 0, nil
}

func (m *EventManager) UpdateEvent(event *models.SecurityEvent) error {
	event.UpdatedAt = time.Now()
	return nil
}

func (m *EventManager) DeleteEvent(id string) error {
	return nil
}

func (m *EventManager) ClassifyEvent(event *models.SecurityEvent, classification models.EventClassification, reason string) error {
	if !isValidClassification(classification) {
		return ErrInvalidClassification
	}

	event.Classification = classification
	now := time.Now()
	event.ClassifiedAt = &now
	event.UpdatedAt = now

	if event.RawData == nil {
		event.RawData = make(map[string]interface{})
	}
	event.RawData["classification_reason"] = reason

	if classification == models.ClassificationFalsePositive {
		event.Status = models.StatusClosed
		event.ClosedAt = &now
	}

	return nil
}

func (m *EventManager) UpdateStatus(event *models.SecurityEvent, status models.EventStatus) error {
	if !isValidStatusTransition(event.Status, status) {
		return ErrInvalidStatusTransition
	}

	oldStatus := event.Status
	event.Status = status
	event.UpdatedAt = time.Now()

	switch status {
	case models.StatusInProgress:
		if event.Status == models.StatusCreated || event.Status == models.StatusTriaged {
			event.Status = models.StatusInProgress
		}
	case models.StatusResolved:
		now := time.Now()
		event.ResolvedAt = &now
	case models.StatusClosed:
		now := time.Now()
		event.ClosedAt = &now
	case models.StatusPendingApproval:
	}

	if event.RawData == nil {
		event.RawData = make(map[string]interface{})
	}
	event.RawData["status_change"] = map[string]string{
		"from": string(oldStatus),
		"to":   string(status),
	}

	return nil
}

func (m *EventManager) AddTimelineEntry(event *models.SecurityEvent, action, userID, content string) {
	entry := TimelineEntry{
		Action:    action,
		UserID:    userID,
		Content:   content,
		CreatedAt: time.Now(),
	}

	if event.RawData == nil {
		event.RawData = make(map[string]interface{})
	}

	timeline := m.getTimeline(event)
	timeline = append(timeline, entry)
	event.RawData["timeline"] = timeline
}

func (m *EventManager) getTimeline(event *models.SecurityEvent) []TimelineEntry {
	if event.RawData == nil {
		return []TimelineEntry{}
	}
	if timeline, ok := event.RawData["timeline"].([]TimelineEntry); ok {
		return timeline
	}
	return []TimelineEntry{}
}

type TimelineEntry struct {
	Action    string    `json:"action"`
	UserID    string    `json:"user_id"`
	Content   string    `json:"content"`
	CreatedAt time.Time `json:"created_at"`
}

type Classification struct {
	Type                models.EventClassification
	Reason              string
	FalsePositiveReason string
	ConfirmedThreatType string
}

var (
	ErrInvalidClassification   = &EventError{Message: "invalid classification"}
	ErrInvalidStatusTransition = &EventError{Message: "invalid status transition"}
	ErrEventNotFound           = &EventError{Message: "event not found"}
	ErrUnauthorized            = &EventError{Message: "unauthorized"}
)

type EventError struct {
	Message string
}

func (e *EventError) Error() string {
	return e.Message
}

func isValidClassification(c models.EventClassification) bool {
	switch c {
	case models.ClassificationUnknown,
		models.ClassificationFalsePositive,
		models.ClassificationConfirmed,
		models.ClassificationPending:
		return true
	}
	return false
}

func isValidStatusTransition(from, to models.EventStatus) bool {
	validTransitions := map[models.EventStatus][]models.EventStatus{
		models.StatusCreated: {
			models.StatusTriaged,
			models.StatusInProgress,
			models.StatusClosed,
		},
		models.StatusTriaged: {
			models.StatusInProgress,
			models.StatusClosed,
			models.StatusPendingApproval,
		},
		models.StatusInProgress: {
			models.StatusResolved,
			models.StatusPendingApproval,
			models.StatusClosed,
		},
		models.StatusPendingApproval: {
			models.StatusInProgress,
			models.StatusResolved,
			models.StatusClosed,
		},
		models.StatusResolved: {
			models.StatusClosed,
			models.StatusInProgress,
		},
		models.StatusClosed: {},
	}

	allowed, ok := validTransitions[from]
	if !ok {
		return false
	}

	for _, status := range allowed {
		if status == to {
			return true
		}
	}

	return false
}

type InMemoryEventStore struct {
	events map[string]*models.SecurityEvent
}

func NewInMemoryEventStore() *InMemoryEventStore {
	return &InMemoryEventStore{
		events: make(map[string]*models.SecurityEvent),
	}
}

func (s *InMemoryEventStore) Save(event *models.SecurityEvent) error {
	s.events[event.ID] = event
	return nil
}

func (s *InMemoryEventStore) Get(id string) (*models.SecurityEvent, error) {
	return s.events[id], nil
}

func (s *InMemoryEventStore) List(filter EventFilter) ([]*models.SecurityEvent, int, error) {
	results := make([]*models.SecurityEvent, 0)

	for _, event := range s.events {
		if filter.Source != "" && event.Source != filter.Source {
			continue
		}
		if filter.EventType != "" && event.EventType != filter.EventType {
			continue
		}
		if len(filter.Severity) > 0 && !containsSeverity(filter.Severity, event.Severity) {
			continue
		}
		if len(filter.Status) > 0 && !containsStatus(filter.Status, event.Status) {
			continue
		}

		results = append(results, event)
	}

	return results, len(results), nil
}

func (s *InMemoryEventStore) Update(event *models.SecurityEvent) error {
	s.events[event.ID] = event
	return nil
}

func (s *InMemoryEventStore) Delete(id string) error {
	delete(s.events, id)
	return nil
}

func containsSeverity(list []models.Severity, s models.Severity) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}

func containsStatus(list []models.EventStatus, s models.EventStatus) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}
