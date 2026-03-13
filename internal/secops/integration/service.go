package integration

import (
	"strings"
	"sync"
	"time"

	"cyberstrike-ai/internal/secops/models"
	"cyberstrike-ai/internal/secops/skills"
	"cyberstrike-ai/internal/secops/ticket"
)

type AnalysisContext struct {
	Event           *models.SecurityEvent
	TriggeredSkills []string
	ToolsExecuted   []string
	AnalysisResult  string
	Suggestions     []ResponseAction
	CreatedAt       time.Time
}

type ResponseAction struct {
	ID         string                 `json:"id"`
	Action     string                 `json:"action"`
	Target     string                 `json:"target"`
	Parameters map[string]interface{} `json:"parameters"`
	Reason     string                 `json:"reason"`
	RiskLevel  string                 `json:"risk_level"`
	Status     string                 `json:"status"`
	ApprovedBy string                 `json:"approved_by,omitempty"`
	CreatedAt  time.Time              `json:"created_at"`
}

type ApprovalRecord struct {
	ID          string     `json:"id"`
	ActionID    string     `json:"action_id"`
	Action      string     `json:"action"`
	Target      string     `json:"target"`
	Status      string     `json:"status"`
	RequesterID string     `json:"requester_id"`
	ApproverID  string     `json:"approver_id,omitempty"`
	Comment     string     `json:"comment"`
	CreatedAt   time.Time  `json:"created_at"`
	ProcessedAt *time.Time `json:"processed_at,omitempty"`
}

type IntegrationService struct {
	skillsMatcher *skills.SkillsMatcher
	ticketService *ticket.TicketService
	analysisCtx   map[string]*AnalysisContext
	approvals     map[string]*ApprovalRecord
	mu            sync.RWMutex
}

func NewIntegrationService(skillsDir string, ticketSvc *ticket.TicketService) *IntegrationService {
	matcher := skills.NewSkillsMatcher(skillsDir)
	matcher.LoadSkills()

	return &IntegrationService{
		skillsMatcher: matcher,
		ticketService: ticketSvc,
		analysisCtx:   make(map[string]*AnalysisContext),
		approvals:     make(map[string]*ApprovalRecord),
	}
}

func (s *IntegrationService) AnalyzeEvent(event *models.SecurityEvent) *AnalysisContext {
	ctx := &AnalysisContext{
		Event:           event,
		TriggeredSkills: []string{},
		ToolsExecuted:   []string{},
		Suggestions:     []ResponseAction{},
		CreatedAt:       time.Now(),
	}

	eventType := detectEventType(event)
	triggeredSkills := s.skillsMatcher.MatchSkills(eventType, event.Title+" "+event.Description)
	for _, skill := range triggeredSkills {
		ctx.TriggeredSkills = append(ctx.TriggeredSkills, skill.Name)
	}

	ctx.AnalysisResult = s.generateAnalysisSummary(event, triggeredSkills)
	ctx.Suggestions = s.generateSuggestions(event)

	s.mu.Lock()
	s.analysisCtx[event.ID] = ctx
	s.mu.Unlock()

	return ctx
}

func (s *IntegrationService) GetAnalysis(eventID string) *AnalysisContext {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.analysisCtx[eventID]
}

func (s *IntegrationService) CreateApproval(action ResponseAction, requesterID string) *ApprovalRecord {
	approval := &ApprovalRecord{
		ID:          generateID(),
		ActionID:    action.ID,
		Action:      action.Action,
		Target:      action.Target,
		Status:      "pending",
		RequesterID: requesterID,
		CreatedAt:   time.Now(),
	}

	s.mu.Lock()
	s.approvals[approval.ID] = approval
	s.mu.Unlock()

	return approval
}

func (s *IntegrationService) ApproveAction(approvalID, approverID, comment string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	approval, ok := s.approvals[approvalID]
	if !ok {
		return ErrApprovalNotFound
	}

	if approval.Status != "pending" {
		return ErrApprovalAlreadyProcessed
	}

	approval.Status = "approved"
	approval.ApproverID = approverID
	approval.Comment = comment
	now := time.Now()
	approval.ProcessedAt = &now

	return nil
}

func (s *IntegrationService) RejectAction(approvalID, approverID, comment string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	approval, ok := s.approvals[approvalID]
	if !ok {
		return ErrApprovalNotFound
	}

	if approval.Status != "pending" {
		return ErrApprovalAlreadyProcessed
	}

	approval.Status = "rejected"
	approval.ApproverID = approverID
	approval.Comment = comment
	now := time.Now()
	approval.ProcessedAt = &now

	return nil
}

func (s *IntegrationService) GetPendingApprovals() []*ApprovalRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*ApprovalRecord, 0)
	for _, a := range s.approvals {
		if a.Status == "pending" {
			result = append(result, a)
		}
	}
	return result
}

func detectEventType(event *models.SecurityEvent) string {
	titleLower := strings.ToLower(event.Title)
	descLower := strings.ToLower(event.Description)
	content := titleLower + " " + descLower

	patterns := map[string]string{
		"sql":     "sql_injection",
		"注入":      "sql_injection",
		"xss":     "xss",
		"跨站脚本":    "xss",
		"command": "command_injection",
		"命令注入":    "command_injection",
		"brute":   "brute_force",
		"暴力":      "brute_force",
		"登录失败":    "brute_force",
		"钓鱼":      "phishing",
		"phish":   "phishing",
		"malware": "malware",
		"病毒":      "malware",
		"木马":      "malware",
		"trojan":  "malware",
		"ddos":    "ddos",
		"dos":     "ddos",
		"洪水攻击":    "ddos",
		"leak":    "data_leak",
		"泄露":      "data_leak",
		"拖库":      "data_leak",
		"api":     "api_security",
		"api异常":   "api_security",
		"文件上传":    "file_upload",
		"文件包含":    "file_upload",
		"ssrf":    "ssrf",
		"csrf":    "csrf",
		"权限":      "privilege_escalation",
		"提权":      "privilege_escalation",
	}

	for keyword, eventType := range patterns {
		if strings.Contains(content, keyword) {
			return eventType
		}
	}

	return "unknown"
}

func (s *IntegrationService) generateAnalysisSummary(event *models.SecurityEvent, matchedSkills []*skills.Skill) string {
	var sb strings.Builder
	sb.WriteString("## 事件分析\n\n")
	sb.WriteString("**事件类型**: " + detectEventType(event) + "\n\n")

	if len(matchedSkills) > 0 {
		sb.WriteString("**触发的 Skills**:\n")
		for _, skill := range matchedSkills {
			sb.WriteString("- " + skill.Name + ": " + skill.Description + "\n")
		}
		sb.WriteString("\n")
	}

	sb.WriteString("**IoC 指标**:\n")
	for _, ioc := range event.IoCs {
		sb.WriteString("- " + string(ioc.Type) + ": " + ioc.Value + "\n")
	}

	return sb.String()
}

func (s *IntegrationService) generateSuggestions(event *models.SecurityEvent) []ResponseAction {
	suggestions := []ResponseAction{}

	severity := event.Severity

	switch severity {
	case models.SeverityCritical, models.SeverityHigh:
		suggestions = append(suggestions, ResponseAction{
			ID:        generateID(),
			Action:    "isolate_host",
			Target:    "",
			Reason:    "严重安全事件，建议隔离受影响系统",
			RiskLevel: "high",
			Status:    "pending_approval",
			CreatedAt: time.Now(),
		})

		suggestions = append(suggestions, ResponseAction{
			ID:        generateID(),
			Action:    "send_notification",
			Target:    "security_team",
			Reason:    "通知安全团队",
			RiskLevel: "low",
			Status:    "auto",
			CreatedAt: time.Now(),
		})
	}

	suggestions = append(suggestions, ResponseAction{
		ID:        generateID(),
		Action:    "create_ticket",
		Target:    event.ID,
		Reason:    "创建调查工单",
		RiskLevel: "low",
		Status:    "auto",
		CreatedAt: time.Now(),
	})

	suggestions = append(suggestions, ResponseAction{
		ID:        generateID(),
		Action:    "investigate",
		Target:    event.ID,
		Reason:    "进行深入调查",
		RiskLevel: "low",
		Status:    "pending_approval",
		CreatedAt: time.Now(),
	})

	return suggestions
}

func generateID() string {
	return time.Now().Format("20060102150405") + "-" + randomString(8)
}

func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[time.Now().UnixNano()%int64(len(letters))]
	}
	return string(b)
}

var (
	ErrApprovalNotFound         = &IntegrationError{Message: "审批记录不存在"}
	ErrApprovalAlreadyProcessed = &IntegrationError{Message: "审批已处理"}
)

type IntegrationError struct {
	Message string
}

func (e *IntegrationError) Error() string {
	return e.Message
}
