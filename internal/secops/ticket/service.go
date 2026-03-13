package ticket

import (
	"time"

	"cyberstrike-ai/internal/secops/models"
	"github.com/google/uuid"
)

type Ticket struct {
	ID          string        `json:"id"`
	EventID     string        `json:"event_id"`
	Title       string        `json:"title"`
	Description string        `json:"description"`
	Type        TicketType    `json:"type"`
	Priority    Priority      `json:"priority"`
	Status      TicketStatus  `json:"status"`
	AssigneeID  string        `json:"assignee_id"`
	CreatorID   string        `json:"creator_id"`
	ApproverID  *string       `json:"approver_id"`
	SLA         time.Duration `json:"sla"`
	DueAt       *time.Time    `json:"due_at"`
	Timeline    []Timeline    `json:"timeline"`
	Comments    []Comment     `json:"comments"`
	CreatedAt   time.Time     `json:"created_at"`
	UpdatedAt   time.Time     `json:"updated_at"`
	ResolvedAt  *time.Time    `json:"resolved_at"`
	ClosedAt    *time.Time    `json:"closed_at"`
}

type TicketType string

const (
	TicketTypeInvestigation TicketType = "investigation"
	TicketTypeResponse      TicketType = "response"
	TicketTypeApproval      TicketType = "approval"
	TicketTypeReview        TicketType = "review"
)

type Priority string

const (
	PriorityP1 Priority = "P1"
	PriorityP2 Priority = "P2"
	PriorityP3 Priority = "P3"
	PriorityP4 Priority = "P4"
)

type TicketStatus string

const (
	TicketStatusPending    TicketStatus = "pending"
	TicketStatusAssigned   TicketStatus = "assigned"
	TicketStatusInProgress TicketStatus = "in_progress"
	TicketStatusResolved   TicketStatus = "resolved"
	TicketStatusClosed     TicketStatus = "closed"
	TicketStatusCancelled  TicketStatus = "cancelled"
)

type Timeline struct {
	Action    string    `json:"action"`
	UserID    string    `json:"user_id"`
	Content   string    `json:"content"`
	CreatedAt time.Time `json:"created_at"`
}

type Comment struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Content   string    `json:"content"`
	Mentions  []string  `json:"mentions"`
	CreatedAt time.Time `json:"created_at"`
}

type TicketService struct {
	tickets map[string]*Ticket
	users   map[string]*User
	store   TicketStore
}

type TicketStore interface {
	Save(ticket *Ticket) error
	Get(id string) (*Ticket, error)
	List(filter TicketFilter) ([]*Ticket, error)
	Update(ticket *Ticket) error
	Delete(id string) error
}

type TicketFilter struct {
	Status     []TicketStatus
	Priority   []Priority
	Type       []TicketType
	AssigneeID string
	CreatorID  string
	EventID    string
	Page       int
	Limit      int
}

type User struct {
	ID     string
	Name   string
	Email  string
	Role   string
	Team   string
	Skills []string
}

func NewTicketService() *TicketService {
	return &TicketService{
		tickets: make(map[string]*Ticket),
		users:   make(map[string]*User),
	}
}

func (s *TicketService) CreateTicket(ticket *Ticket) error {
	if ticket.Title == "" {
		return ErrInvalidTicket
	}

	if ticket.ID == "" {
		ticket.ID = uuid.New().String()
	}
	now := time.Now()
	if ticket.CreatedAt.IsZero() {
		ticket.CreatedAt = now
	}
	ticket.UpdatedAt = now

	if ticket.Status == "" {
		ticket.Status = TicketStatusPending
	}
	if ticket.Priority == "" {
		ticket.Priority = PriorityP3
	}

	s.addTimeline(ticket, "created", ticket.CreatorID, "工单创建")

	s.tickets[ticket.ID] = ticket

	return nil
}

func (s *TicketService) GetTicket(id string) (*Ticket, bool) {
	ticket, ok := s.tickets[id]
	return ticket, ok
}

func (s *TicketService) ListTickets(filter TicketFilter) []*Ticket {
	results := make([]*Ticket, 0)

	for _, ticket := range s.tickets {
		if len(filter.Status) > 0 && !containsStatus(filter.Status, ticket.Status) {
			continue
		}
		if len(filter.Priority) > 0 && !containsPriority(filter.Priority, ticket.Priority) {
			continue
		}
		if filter.AssigneeID != "" && ticket.AssigneeID != filter.AssigneeID {
			continue
		}
		if filter.CreatorID != "" && ticket.CreatorID != filter.CreatorID {
			continue
		}
		if filter.EventID != "" && ticket.EventID != filter.EventID {
			continue
		}

		results = append(results, ticket)
	}

	return results
}

func (s *TicketService) UpdateTicket(ticket *Ticket) error {
	ticket.UpdatedAt = time.Now()
	s.tickets[ticket.ID] = ticket
	return nil
}

func (s *TicketService) AssignTicket(ticketID, assigneeID, operatorID string) error {
	ticket, ok := s.tickets[ticketID]
	if !ok {
		return ErrTicketNotFound
	}

	oldAssignee := ticket.AssigneeID
	ticket.AssigneeID = assigneeID
	ticket.Status = TicketStatusAssigned
	ticket.UpdatedAt = time.Now()

	msg := "工单分配"
	if oldAssignee != "" {
		msg = "工单转派"
	}
	s.addTimeline(ticket, msg, operatorID, "分配给: "+assigneeID)

	return nil
}

func (s *TicketService) TransferTicket(ticketID, toUserID, reason, operatorID string) error {
	ticket, ok := s.tickets[ticketID]
	if !ok {
		return ErrTicketNotFound
	}

	ticket.AssigneeID = toUserID
	ticket.UpdatedAt = time.Now()

	s.addTimeline(ticket, "转派", operatorID, reason)

	return nil
}

func (s *TicketService) ApproveTicket(ticketID, approverID, comment string, approved bool) error {
	ticket, ok := s.tickets[ticketID]
	if !ok {
		return ErrTicketNotFound
	}

	action := "批准"
	if !approved {
		action = "驳回"
		ticket.Status = TicketStatusInProgress
	} else {
		ticket.Status = TicketStatusInProgress
	}

	ticket.ApproverID = &approverID
	ticket.UpdatedAt = time.Now()

	s.addTimeline(ticket, action, approverID, comment)

	return nil
}

func (s *TicketService) EscalateTicket(ticketID, operatorID, reason string) error {
	ticket, ok := s.tickets[ticketID]
	if !ok {
		return ErrTicketNotFound
	}

	s.addTimeline(ticket, "升级", operatorID, reason)

	if ticket.Priority != PriorityP1 {
		newPriority := getHigherPriority(ticket.Priority)
		ticket.Priority = newPriority
	}

	ticket.UpdatedAt = time.Now()

	return nil
}

func (s *TicketService) ResolveTicket(ticketID, operatorID string) error {
	ticket, ok := s.tickets[ticketID]
	if !ok {
		return ErrTicketNotFound
	}

	ticket.Status = TicketStatusResolved
	now := time.Now()
	ticket.ResolvedAt = &now
	ticket.UpdatedAt = time.Now()

	s.addTimeline(ticket, "解决", operatorID, "工单已解决")

	return nil
}

func (s *TicketService) CloseTicket(ticketID, operatorID string) error {
	ticket, ok := s.tickets[ticketID]
	if !ok {
		return ErrTicketNotFound
	}

	ticket.Status = TicketStatusClosed
	now := time.Now()
	ticket.ClosedAt = &now
	ticket.UpdatedAt = time.Now()

	s.addTimeline(ticket, "关闭", operatorID, "工单已关闭")

	return nil
}

func (s *TicketService) AddComment(ticketID, userID, content string, mentions []string) error {
	ticket, ok := s.tickets[ticketID]
	if !ok {
		return ErrTicketNotFound
	}

	comment := Comment{
		ID:        uuid.New().String(),
		UserID:    userID,
		Content:   content,
		Mentions:  mentions,
		CreatedAt: time.Now(),
	}

	ticket.Comments = append(ticket.Comments, comment)
	ticket.UpdatedAt = time.Now()

	return nil
}

func (s *TicketService) addTimeline(ticket *Ticket, action, userID, content string) {
	entry := Timeline{
		Action:    action,
		UserID:    userID,
		Content:   content,
		CreatedAt: time.Now(),
	}
	ticket.Timeline = append(ticket.Timeline, entry)
}

func (s *TicketService) GetSLAStatus(ticketID string) (string, error) {
	ticket, ok := s.tickets[ticketID]
	if !ok {
		return "", ErrTicketNotFound
	}

	if ticket.Status == TicketStatusClosed || ticket.Status == TicketStatusResolved {
		return "closed", nil
	}

	if ticket.DueAt == nil {
		return "no_sla", nil
	}

	if time.Now().After(*ticket.DueAt) {
		return "overdue", nil
	}

	remaining := ticket.DueAt.Sub(time.Now())
	if remaining < 1*time.Hour {
		return "critical", nil
	} else if remaining < 4*time.Hour {
		return "warning", nil
	}

	return "ok", nil
}

func (s *TicketService) CreateFromEvent(event *models.SecurityEvent, creatorID string) (*Ticket, error) {
	ticket := &Ticket{
		ID:          uuid.New().String(),
		EventID:     event.ID,
		Title:       "安全事件处理: " + event.Title,
		Description: event.Description,
		Type:        TicketTypeResponse,
		Priority:    eventPriority(event.Severity),
		Status:      TicketStatusPending,
		CreatorID:   creatorID,
		Timeline:    []Timeline{},
		Comments:    []Comment{},
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	s.calculateSLA(ticket)
	s.addTimeline(ticket, "created", creatorID, "从安全事件创建工单")

	err := s.CreateTicket(ticket)
	return ticket, err
}

func (s *TicketService) calculateSLA(ticket *Ticket) {
	var sla time.Duration

	switch ticket.Priority {
	case PriorityP1:
		sla = 1 * time.Hour
	case PriorityP2:
		sla = 4 * time.Hour
	case PriorityP3:
		sla = 24 * time.Hour
	case PriorityP4:
		sla = 72 * time.Hour
	default:
		sla = 24 * time.Hour
	}

	ticket.SLA = sla
	dueAt := time.Now().Add(sla)
	ticket.DueAt = &dueAt
}

func eventPriority(severity models.Severity) Priority {
	switch severity {
	case models.SeverityCritical:
		return PriorityP1
	case models.SeverityHigh:
		return PriorityP2
	case models.SeverityMedium:
		return PriorityP3
	default:
		return PriorityP4
	}
}

func containsStatus(list []TicketStatus, status TicketStatus) bool {
	for _, s := range list {
		if s == status {
			return true
		}
	}
	return false
}

func containsPriority(list []Priority, priority Priority) bool {
	for _, p := range list {
		if p == priority {
			return true
		}
	}
	return false
}

func getHigherPriority(p Priority) Priority {
	switch p {
	case PriorityP4:
		return PriorityP3
	case PriorityP3:
		return PriorityP2
	case PriorityP2:
		return PriorityP1
	default:
		return PriorityP1
	}
}

var (
	ErrTicketNotFound = &TicketError{Message: "ticket not found"}
	ErrInvalidTicket  = &TicketError{Message: "invalid ticket"}
)

type TicketError struct {
	Message string
}

func (e *TicketError) Error() string {
	return e.Message
}
