package event

import (
	"encoding/json"
	"time"

	"cyberstrike-ai/internal/secops/models"
)

type EventService struct {
	// 添加服务依赖
}

func NewEventService() *EventService {
	return &EventService{}
}

func (s *EventService) CreateEvent(event *models.SecurityEvent) error {
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
	if event.IoCs == nil {
		event.IoCs = []models.IoC{}
	}
	if event.AssetIDs == nil {
		event.AssetIDs = []string{}
	}
	if event.TTP == nil {
		event.TTP = []string{}
	}
	if event.CorrelationIDs == nil {
		event.CorrelationIDs = []string{}
	}
	if event.RawData == nil {
		event.RawData = make(map[string]interface{})
	}
	return nil
}

func (s *EventService) ParseEventFromJSON(data []byte) (*models.SecurityEvent, error) {
	event := &models.SecurityEvent{}
	if err := json.Unmarshal(data, event); err != nil {
		return nil, err
	}
	s.NormalizeEvent(event)
	event.SetTimestamps()
	event.SetID()
	return event, nil
}

func (s *EventService) NormalizeEvent(event *models.SecurityEvent) {
	if event.Severity != "" {
		event.Severity = models.ParseSeverity(string(event.Severity))
	}
}

func (s *EventService) ClassifyEvent(event *models.SecurityEvent, classification models.EventClassification) error {
	event.Classification = classification
	now := time.Now()
	event.ClassifiedAt = &now
	event.UpdatedAt = time.Now()
	return nil
}

func (s *EventService) ResolveEvent(event *models.SecurityEvent) error {
	event.Status = models.StatusResolved
	now := time.Now()
	event.ResolvedAt = &now
	event.UpdatedAt = time.Now()
	return nil
}

func (s *EventService) CloseEvent(event *models.SecurityEvent) error {
	event.Status = models.StatusClosed
	now := time.Now()
	event.ClosedAt = &now
	event.UpdatedAt = time.Now()
	return nil
}

func (s *EventService) ExtractIoCs(event *models.SecurityEvent) []models.IoC {
	iocs := []models.IoC{}
	if event.RawData == nil {
		return iocs
	}

	ipFields := []string{"src_ip", "source_ip", "dst_ip", "dest_ip", "ip", "client_ip", "attacker_ip"}
	for _, field := range ipFields {
		if ip, ok := event.RawData[field].(string); ok && ip != "" {
			iocs = append(iocs, models.IoC{
				Type:    models.IoCTypeIP,
				Value:   ip,
				Source:  field,
				Updated: time.Now(),
			})
		}
	}

	if domain, ok := event.RawData["domain"].(string); ok && domain != "" {
		iocs = append(iocs, models.IoC{
			Type:    models.IoCTypeDomain,
			Value:   domain,
			Source:  "domain",
			Updated: time.Now(),
		})
	}

	if hostname, ok := event.RawData["hostname"].(string); ok && hostname != "" {
		iocs = append(iocs, models.IoC{
			Type:    models.IoCTypeDomain,
			Value:   hostname,
			Source:  "hostname",
			Updated: time.Now(),
		})
	}

	if url, ok := event.RawData["url"].(string); ok && url != "" {
		iocs = append(iocs, models.IoC{
			Type:    models.IoCTypeURL,
			Value:   url,
			Source:  "url",
			Updated: time.Now(),
		})
	}

	event.IoCs = iocs
	return iocs
}
