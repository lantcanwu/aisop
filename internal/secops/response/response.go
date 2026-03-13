package response

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"cyberstrike-ai/internal/secops/models"
)

type ActionType string

const (
	ActionIsolateHost      ActionType = "isolate_host"
	ActionUnisolateHost    ActionType = "unisolate_host"
	ActionBlockIP          ActionType = "block_ip"
	ActionUnblockIP        ActionType = "unblock_ip"
	ActionDisableUser      ActionType = "disable_user"
	ActionEnableUser       ActionType = "enable_user"
	ActionStopService      ActionType = "stop_service"
	ActionStartService     ActionType = "start_service"
	ActionExecuteScript    ActionType = "execute_script"
	ActionSendNotification ActionType = "send_notification"
	ActionCreateTicket     ActionType = "create_ticket"
	ActionAddToBlocklist   ActionType = "add_to_blocklist"
)

type ActionStatus string

const (
	ActionStatusPending   ActionStatus = "pending"
	ActionStatusRunning   ActionStatus = "running"
	ActionStatusCompleted ActionStatus = "completed"
	ActionStatusFailed    ActionStatus = "failed"
	ActionStatusCancelled ActionStatus = "cancelled"
)

type ActionExecution struct {
	ID          string                 `json:"id"`
	EventID     string                 `json:"event_id"`
	Action      ActionType             `json:"action"`
	Target      string                 `json:"target"`
	Parameters  map[string]interface{} `json:"parameters"`
	Status      ActionStatus           `json:"status"`
	Result      string                 `json:"result"`
	Error       string                 `json:"error,omitempty"`
	RequestedBy string                 `json:"requested_by"`
	ApprovedBy  string                 `json:"approved_by,omitempty"`
	ExecutedAt  *time.Time             `json:"executed_at,omitempty"`
	CompletedAt *time.Time             `json:"completed_at,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
}

type Playbook struct {
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Enabled     bool             `json:"enabled"`
	TriggerOn   []string         `json:"trigger_on"`
	Actions     []PlaybookAction `json:"actions"`
	CreatedAt   time.Time        `json:"created_at"`
	UpdatedAt   time.Time        `json:"updated_at"`
}

type PlaybookAction struct {
	Order           int                    `json:"order"`
	Action          ActionType             `json:"action"`
	Target          string                 `json:"target"`
	Parameters      map[string]interface{} `json:"parameters"`
	Condition       string                 `json:"condition,omitempty"`
	ContinueOnError bool                   `json:"continue_on_error"`
}

type Executor interface {
	Execute(action *ActionExecution) error
	GetName() string
}

type ResponseService struct {
	executors map[ActionType]Executor
	playbooks map[string]*Playbook
	actions   map[string]*ActionExecution
	mu        sync.RWMutex
}

func NewResponseService() *ResponseService {
	s := &ResponseService{
		executors: make(map[ActionType]Executor),
		playbooks: make(map[string]*Playbook),
		actions:   make(map[string]*ActionExecution),
	}

	s.registerDefaultExecutors()

	return s
}

func (s *ResponseService) registerDefaultExecutors() {
	s.executors[ActionIsolateHost] = &EDRExecutor{}
	s.executors[ActionBlockIP] = &FirewallExecutor{}
	s.executors[ActionDisableUser] = &DirectoryExecutor{}
}

func (s *ResponseService) RegisterExecutor(action ActionType, executor Executor) {
	s.executors[action] = executor
}

func (s *ResponseService) ExecuteAction(action *ActionExecution) error {
	executor, ok := s.executors[action.Action]
	if !ok {
		return fmt.Errorf("no executor registered for action: %s", action.Action)
	}

	action.Status = ActionStatusRunning
	now := time.Now()
	action.ExecutedAt = &now

	err := executor.Execute(action)
	if err != nil {
		action.Status = ActionStatusFailed
		action.Error = err.Error()
	} else {
		action.Status = ActionStatusCompleted
		completedAt := time.Now()
		action.CompletedAt = &completedAt
	}

	s.mu.Lock()
	s.actions[action.ID] = action
	s.mu.Unlock()

	return err
}

func (s *ResponseService) GetAction(id string) (*ActionExecution, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	action, ok := s.actions[id]
	return action, ok
}

func (s *ResponseService) ListActions(eventID string) []*ActionExecution {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*ActionExecution, 0)
	for _, action := range s.actions {
		if eventID == "" || action.EventID == eventID {
			result = append(result, action)
		}
	}

	return result
}

func (s *ResponseService) CancelAction(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	action, ok := s.actions[id]
	if !ok {
		return fmt.Errorf("action not found: %s", id)
	}

	if action.Status == ActionStatusCompleted || action.Status == ActionStatusFailed {
		return fmt.Errorf("cannot cancel completed or failed action")
	}

	action.Status = ActionStatusCancelled
	return nil
}

func (s *ResponseService) CreatePlaybook(playbook *Playbook) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	playbook.CreatedAt = time.Now()
	playbook.UpdatedAt = time.Now()
	s.playbooks[playbook.ID] = playbook

	return nil
}

func (s *ResponseService) GetPlaybook(id string) (*Playbook, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	playbook, ok := s.playbooks[id]
	return playbook, ok
}

func (s *ResponseService) ListPlaybooks() []*Playbook {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*Playbook, 0, len(s.playbooks))
	for _, playbook := range s.playbooks {
		result = append(result, playbook)
	}

	return result
}

func (s *ResponseService) ExecutePlaybook(playbookID string, event *models.SecurityEvent, requestedBy string) ([]*ActionExecution, error) {
	s.mu.RLock()
	playbook, ok := s.playbooks[playbookID]
	s.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("playbook not found: %s", playbookID)
	}

	results := make([]*ActionExecution, 0)

	for _, pa := range playbook.Actions {
		action := &ActionExecution{
			EventID:     event.ID,
			Action:      pa.Action,
			Target:      resolveTarget(pa.Target, event),
			Parameters:  pa.Parameters,
			Status:      ActionStatusPending,
			RequestedBy: requestedBy,
			CreatedAt:   time.Now(),
		}

		err := s.ExecuteAction(action)
		results = append(results, action)

		if err != nil && !pa.ContinueOnError {
			return results, err
		}
	}

	return results, nil
}

func (s *ResponseService) TriggerPlaybooks(event *models.SecurityEvent) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, playbook := range s.playbooks {
		if !playbook.Enabled {
			continue
		}

		for _, trigger := range playbook.TriggerOn {
			if s.shouldTrigger(trigger, event) {
				go s.ExecutePlaybook(playbook.ID, event, "system")
				break
			}
		}
	}

	return nil
}

func (s *ResponseService) shouldTrigger(trigger string, event *models.SecurityEvent) bool {
	switch trigger {
	case "critical_high":
		return event.Severity == models.SeverityCritical || event.Severity == models.SeverityHigh
	case "confirmed_attack":
		return event.Classification == models.ClassificationConfirmed
	case "new_event":
		return event.Status == models.StatusCreated
	case "unclassified":
		return event.Classification == models.ClassificationPending
	}

	return strings.Contains(trigger, string(event.EventType))
}

func resolveTarget(target string, event *models.SecurityEvent) string {
	if target == "" {
		return ""
	}

	target = strings.ReplaceAll(target, "{{event.id}}", event.ID)
	target = strings.ReplaceAll(target, "{{event.source}}", event.Source)

	if len(event.AssetIDs) > 0 {
		target = strings.ReplaceAll(target, "{{event.asset_id}}", event.AssetIDs[0])
	}

	if len(event.IoCs) > 0 {
		target = strings.ReplaceAll(target, "{{event.ioc}}", event.IoCs[0].Value)
	}

	return target
}

type EDRExecutor struct{}

func (e *EDRExecutor) Execute(action *ActionExecution) error {
	return fmt.Errorf("EDR integration not configured")
}

func (e *EDRExecutor) GetName() string {
	return "EDR"
}

type FirewallExecutor struct{}

func (e *FirewallExecutor) Execute(action *ActionExecution) error {
	return fmt.Errorf("Firewall integration not configured")
}

func (e *FirewallExecutor) GetName() string {
	return "Firewall"
}

type DirectoryExecutor struct{}

func (e *DirectoryExecutor) Execute(action *ActionExecution) error {
	return fmt.Errorf("Directory integration not configured")
}

func (e *DirectoryExecutor) GetName() string {
	return "Directory"
}

type ScriptExecutor struct {
	scriptPath string
}

func (e *ScriptExecutor) Execute(action *ActionExecution) error {
	return fmt.Errorf("Script execution not implemented")
}

func (e *ScriptExecutor) GetName() string {
	return "Script"
}
