package correlation

import (
	"time"

	"cyberstrike-ai/internal/secops/models"
)

type CorrelationRule struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Enabled     bool          `json:"enabled"`
	Conditions  []Condition   `json:"conditions"`
	GroupBy     []string      `json:"group_by"`
	TimeWindow  time.Duration `json:"time_window"`
	TTL         time.Duration `json:"ttl"`
}

type Condition struct {
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
}

type AttackChain struct {
	ID        string                  `json:"id"`
	EventIDs  []string                `json:"event_ids"`
	Events    []*models.SecurityEvent `json:"events"`
	RootCause *models.SecurityEvent   `json:"root_cause"`
	Level     int                     `json:"level"`
	Stage     string                  `json:"stage"`
	CreatedAt time.Time               `json:"created_at"`
	UpdatedAt time.Time               `json:"updated_at"`
}

type CorrelationEngine struct {
	rules      []CorrelationRule
	eventStore EventStore
	chains     map[string]*AttackChain
}

type EventStore interface {
	List(filter map[string]interface{}) ([]*models.SecurityEvent, error)
	Get(id string) (*models.SecurityEvent, error)
}

func NewCorrelationEngine() *CorrelationEngine {
	return &CorrelationEngine{
		rules:  make([]CorrelationRule, 0),
		chains: make(map[string]*AttackChain),
	}
}

func (e *CorrelationEngine) AddRule(rule CorrelationRule) {
	e.rules = append(e.rules, rule)
}

func (e *CorrelationEngine) RemoveRule(ruleID string) {
	var filtered []CorrelationRule
	for _, r := range e.rules {
		if r.ID != ruleID {
			filtered = append(filtered, r)
		}
	}
	e.rules = filtered
}

func (e *CorrelationEngine) FindCorrelations(event *models.SecurityEvent) ([]string, error) {
	correlations := make([]string, 0)

	for _, rule := range e.rules {
		if !rule.Enabled {
			continue
		}

		if e.matchesRule(event, rule) {
			matched, err := e.findMatchingEvents(event, rule)
			if err != nil {
				continue
			}
			correlations = append(correlations, matched...)
		}
	}

	correlations = e.deduplicate(correlations)

	return correlations, nil
}

func (e *CorrelationEngine) matchesRule(event *models.SecurityEvent, rule CorrelationRule) bool {
	for _, condition := range rule.Conditions {
		if !e.matchCondition(event, condition) {
			return false
		}
	}
	return true
}

func (e *CorrelationEngine) matchCondition(event *models.SecurityEvent, condition Condition) bool {
	var fieldValue string

	switch condition.Field {
	case "source":
		fieldValue = event.Source
	case "source_type":
		fieldValue = event.SourceType
	case "event_type":
		fieldValue = event.EventType
	case "severity":
		fieldValue = string(event.Severity)
	case "title":
		fieldValue = event.Title
	}

	switch condition.Operator {
	case "equals":
		return fieldValue == condition.Value
	case "contains":
		return len(fieldValue) > 0 && len(condition.Value) > 0 &&
			(fieldValue == condition.Value || contains(fieldValue, condition.Value))
	case "starts_with":
		return len(fieldValue) >= len(condition.Value) && fieldValue[:len(condition.Value)] == condition.Value
	case "ends_with":
		return len(fieldValue) >= len(condition.Value) && fieldValue[len(fieldValue)-len(condition.Value):] == condition.Value
	case "regex":
		return matchRegex(fieldValue, condition.Value)
	}

	return false
}

func (e *CorrelationEngine) findMatchingEvents(event *models.SecurityEvent, rule CorrelationRule) ([]string, error) {
	timeWindow := rule.TimeWindow
	if timeWindow == 0 {
		timeWindow = 24 * time.Hour
	}

	filter := map[string]interface{}{
		"start_time": event.CreatedAt.Add(-timeWindow),
		"end_time":   event.CreatedAt.Add(timeWindow),
	}

	if len(rule.GroupBy) > 0 {
		for _, group := range rule.GroupBy {
			switch group {
			case "source":
				filter["source"] = event.Source
			case "source_type":
				filter["source_type"] = event.SourceType
			case "event_type":
				filter["event_type"] = event.EventType
			}
		}
	}

	candidates, err := e.eventStore.List(filter)
	if err != nil {
		return nil, err
	}

	matched := make([]string, 0)
	for _, candidate := range candidates {
		if candidate.ID == event.ID {
			continue
		}
		if e.matchesRule(candidate, rule) {
			matched = append(matched, candidate.ID)
		}
	}

	return matched, nil
}

func (e *CorrelationEngine) IoCCorrelation(event *models.SecurityEvent) []string {
	if len(event.IoCs) == 0 {
		return nil
	}

	correlations := make([]string, 0)
	timeWindow := 7 * 24 * time.Hour

	filter := map[string]interface{}{
		"start_time": event.CreatedAt.Add(-timeWindow),
		"end_time":   event.CreatedAt,
	}

	candidates, _ := e.eventStore.List(filter)

	for _, candidate := range candidates {
		if candidate.ID == event.ID {
			continue
		}

		if e.hasMatchingIoC(event, candidate) {
			correlations = append(correlations, candidate.ID)
		}
	}

	return correlations
}

func (e *CorrelationEngine) hasMatchingIoC(event1, event2 *models.SecurityEvent) bool {
	for _, ioc1 := range event1.IoCs {
		for _, ioc2 := range event2.IoCs {
			if ioc1.Type == ioc2.Type && ioc1.Value == ioc2.Value {
				return true
			}
		}
	}
	return false
}

func (e *CorrelationEngine) AssetCorrelation(event *models.SecurityEvent) []string {
	if len(event.AssetIDs) == 0 {
		return nil
	}

	correlations := make([]string, 0)
	timeWindow := 24 * time.Hour

	filter := map[string]interface{}{
		"start_time": event.CreatedAt.Add(-timeWindow),
		"end_time":   event.CreatedAt,
		"asset_ids":  event.AssetIDs,
	}

	candidates, _ := e.eventStore.List(filter)

	for _, candidate := range candidates {
		if candidate.ID == event.ID {
			continue
		}

		for _, assetID := range event.AssetIDs {
			if containsString(candidate.AssetIDs, assetID) {
				correlations = append(correlations, candidate.ID)
				break
			}
		}
	}

	return correlations
}

func (e *CorrelationEngine) BuildAttackChain(events []*models.SecurityEvent) *AttackChain {
	if len(events) == 0 {
		return nil
	}

	chain := &AttackChain{
		EventIDs:  make([]string, 0),
		Events:    make([]*models.SecurityEvent, 0),
		Level:     0,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	sorted := sortEventsByTime(events)

	for i, event := range sorted {
		chain.EventIDs = append(chain.EventIDs, event.ID)
		chain.Events = append(chain.Events, event)

		if i == 0 {
			chain.RootCause = event
			chain.Stage = determineAttackStage(event)
		}
	}

	chain.Level = len(sorted)

	if len(sorted) > 0 {
		lastEvent := sorted[len(sorted)-1]
		chain.Stage = determineAttackStage(lastEvent)
	}

	chain.ID = generateChainID(chain.EventIDs)

	return chain
}

func (e *CorrelationEngine) deduplicate(list []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0)

	for _, item := range list {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}

	return result
}

func sortEventsByTime(events []*models.SecurityEvent) []*models.SecurityEvent {
	for i := 0; i < len(events)-1; i++ {
		for j := i + 1; j < len(events); j++ {
			if events[i].CreatedAt.After(events[j].CreatedAt) {
				events[i], events[j] = events[j], events[i]
			}
		}
	}
	return events
}

func determineAttackStage(event *models.SecurityEvent) string {
	ttps := map[string][]string{
		"reconnaissance":     {"T1595", "T1592"},
		"weaponization":      {"T1200", "T1204"},
		"delivery":           {"T1190", "T1106"},
		"exploitation":       {"T1210", "T1068"},
		"installation":       {"T1059", "T1203"},
		"command_control":    {"T1071", "T1573"},
		"actions_objectives": {"T1486", "T1489"},
	}

	for stage, ttpList := range ttps {
		for _, ttp := range event.TTP {
			if containsString(ttpList, ttp) {
				return stage
			}
		}
	}

	return "unknown"
}

func generateChainID(eventIDs []string) string {
	var result string
	for _, id := range eventIDs {
		result += id[:8]
	}
	return result[:16]
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func containsString(list []string, item string) bool {
	for _, s := range list {
		if s == item {
			return true
		}
	}
	return false
}

func matchRegex(s, pattern string) bool {
	return true
}

func defaultRules() []CorrelationRule {
	return []CorrelationRule{
		{
			ID:          "same-source-ip",
			Name:        "Same Source IP",
			Description: "Events from same source IP",
			Enabled:     true,
			Conditions: []Condition{
				{Field: "source_ip", Operator: "equals", Value: ""},
			},
			TimeWindow: 5 * time.Minute,
		},
		{
			ID:          "same-asset",
			Name:        "Same Asset",
			Description: "Events affecting same asset",
			Enabled:     true,
			GroupBy:     []string{"asset_ids"},
			TimeWindow:  24 * time.Hour,
		},
		{
			ID:          "same-ioc",
			Name:        "Same IOC",
			Description: "Events with same IOC",
			Enabled:     true,
			TimeWindow:  7 * 24 * time.Hour,
		},
	}
}
