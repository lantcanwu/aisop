package notification

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

type NotificationType string

const (
	NotificationTypeEvent  NotificationType = "event"
	NotificationTypeTicket NotificationType = "ticket"
	NotificationTypeAlert  NotificationType = "alert"
	NotificationTypeSystem NotificationType = "system"
)

type ChannelType string

const (
	ChannelTypeDingTalk ChannelType = "dingtalk"
	ChannelTypeLark     ChannelType = "lark"
	ChannelTypeEmail    ChannelType = "email"
	ChannelTypeWebhook  ChannelType = "webhook"
)

type Notification struct {
	ID         string                 `json:"id"`
	Type       NotificationType       `json:"type"`
	Channel    ChannelType            `json:"channel"`
	Title      string                 `json:"title"`
	Content    string                 `json:"content"`
	Recipients []string               `json:"recipients"`
	Metadata   map[string]interface{} `json:"metadata"`
	Status     string                 `json:"status"`
	Error      string                 `json:"error,omitempty"`
	SentAt     *time.Time             `json:"sent_at,omitempty"`
	CreatedAt  time.Time              `json:"created_at"`
}

type ChannelConfig struct {
	ID        string
	Name      string
	Type      ChannelType
	Enabled   bool
	Config    map[string]interface{}
	CreatedAt time.Time
	UpdatedAt time.Time
}

type NotificationRule struct {
	ID         string
	Name       string
	Enabled    bool
	EventTypes []string
	Severities []string
	Channels   []ChannelType
	Recipients []string
	Schedule   string
	Cooldown   time.Duration
	LastSentAt *time.Time
}

type Sender interface {
	Send(notification *Notification, config *ChannelConfig) error
	GetName() string
}

type NotificationService struct {
	channels      map[string]*ChannelConfig
	rules         map[string]*NotificationRule
	notifications map[string]*Notification
	lock          sync.RWMutex
	senders       map[ChannelType]Sender
}

func NewNotificationService() *NotificationService {
	s := &NotificationService{
		channels:      make(map[string]*ChannelConfig),
		rules:         make(map[string]*NotificationRule),
		notifications: make(map[string]*Notification),
		senders:       make(map[ChannelType]Sender),
	}

	s.registerDefaultSenders()

	return s
}

func (s *NotificationService) registerDefaultSenders() {
	s.senders[ChannelTypeDingTalk] = &DingTalkSender{}
	s.senders[ChannelTypeLark] = &LarkSender{}
	s.senders[ChannelTypeWebhook] = &WebhookSender{}
}

func (s *NotificationService) AddChannel(config *ChannelConfig) error {
	if config.ID == "" {
		config.ID = uuid.New().String()
	}
	config.CreatedAt = time.Now()
	config.UpdatedAt = time.Now()

	s.lock.Lock()
	defer s.lock.Unlock()

	s.channels[config.ID] = config
	return nil
}

func (s *NotificationService) GetChannel(id string) (*ChannelConfig, bool) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	config, ok := s.channels[id]
	return config, ok
}

func (s *NotificationService) ListChannels() []*ChannelConfig {
	s.lock.RLock()
	defer s.lock.RUnlock()

	result := make([]*ChannelConfig, 0, len(s.channels))
	for _, c := range s.channels {
		result = append(result, c)
	}
	return result
}

func (s *NotificationService) UpdateChannel(config *ChannelConfig) error {
	config.UpdatedAt = time.Now()

	s.lock.Lock()
	defer s.lock.Unlock()

	s.channels[config.ID] = config
	return nil
}

func (s *NotificationService) DeleteChannel(id string) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	delete(s.channels, id)
	return nil
}

func (s *NotificationService) SendNotification(notification *Notification) error {
	notification.ID = uuid.New().String()
	notification.CreatedAt = time.Now()
	notification.Status = "pending"

	sender, ok := s.senders[notification.Channel]
	if !ok {
		err := fmt.Errorf("no sender for channel type: %s", notification.Channel)
		notification.Status = "failed"
		notification.Error = err.Error()
		s.saveNotification(notification)
		return err
	}

	var config *ChannelConfig
	if notification.Channel == ChannelTypeWebhook {
		config = &ChannelConfig{
			Config: map[string]interface{}{
				"url": notification.Metadata["webhook_url"],
			},
		}
	}

	err := sender.Send(notification, config)
	if err != nil {
		notification.Status = "failed"
		notification.Error = err.Error()
	} else {
		notification.Status = "sent"
		now := time.Now()
		notification.SentAt = &now
	}

	s.saveNotification(notification)
	return err
}

func (s *NotificationService) saveNotification(notification *Notification) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.notifications[notification.ID] = notification
}

func (s *NotificationService) GetNotification(id string) (*Notification, bool) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	n, ok := s.notifications[id]
	return n, ok
}

func (s *NotificationService) AddRule(rule *NotificationRule) error {
	if rule.ID == "" {
		rule.ID = uuid.New().String()
	}

	s.lock.Lock()
	defer s.lock.Unlock()

	s.rules[rule.ID] = rule
	return nil
}

func (s *NotificationService) GetRule(id string) (*NotificationRule, bool) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	rule, ok := s.rules[id]
	return rule, ok
}

func (s *NotificationService) ListRules() []*NotificationRule {
	s.lock.RLock()
	defer s.lock.RUnlock()

	result := make([]*NotificationRule, 0, len(s.rules))
	for _, r := range s.rules {
		result = append(result, r)
	}
	return result
}

func (s *NotificationService) ShouldSend(rule *NotificationRule) bool {
	if !rule.Enabled {
		return false
	}

	if rule.LastSentAt != nil && rule.Cooldown > 0 {
		if time.Since(*rule.LastSentAt) < rule.Cooldown {
			return false
		}
	}

	return true
}

func (s *NotificationService) UpdateRuleSentTime(ruleID string) {
	s.lock.Lock()
	defer s.lock.Unlock()

	if rule, ok := s.rules[ruleID]; ok {
		now := time.Now()
		rule.LastSentAt = &now
	}
}

func (s *NotificationService) RegisterSender(channelType ChannelType, sender Sender) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.senders[channelType] = sender
}

type DingTalkSender struct{}

func (s *DingTalkSender) Send(notification *Notification, config *ChannelConfig) error {
	webhookURL, ok := config.Config["webhook_url"].(string)
	if !ok {
		return fmt.Errorf("dingtalk webhook_url not configured")
	}

	msg := map[string]interface{}{
		"msgtype": "markdown",
		"markdown": map[string]string{
			"title": notification.Title,
			"text":  notification.Content,
		},
	}

	body, _ := json.Marshal(msg)
	resp, err := http.Post(webhookURL, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("dingtalk webhook returned: %d", resp.StatusCode)
	}

	return nil
}

func (s *DingTalkSender) GetName() string {
	return "DingTalk"
}

type LarkSender struct{}

func (s *LarkSender) Send(notification *Notification, config *ChannelConfig) error {
	webhookURL, ok := config.Config["webhook_url"].(string)
	if !ok {
		return fmt.Errorf("lark webhook_url not configured")
	}

	msg := map[string]interface{}{
		"msg_type": "interactive",
		"card": map[string]interface{}{
			"header": map[string]string{
				"title":    notification.Title,
				"template": "red",
			},
			"elements": []map[string]interface{}{
				{
					"tag":     "markdown",
					"content": notification.Content,
				},
			},
		},
	}

	body, _ := json.Marshal(msg)
	resp, err := http.Post(webhookURL, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("lark webhook returned: %d", resp.StatusCode)
	}

	return nil
}

func (s *LarkSender) GetName() string {
	return "Lark"
}

type WebhookSender struct{}

func (s *WebhookSender) Send(notification *Notification, config *ChannelConfig) error {
	webhookURL, ok := config.Config["url"].(string)
	if !ok {
		return fmt.Errorf("webhook url not configured")
	}

	payload := map[string]interface{}{
		"type":    string(notification.Type),
		"title":   notification.Title,
		"content": notification.Content,
		"time":    notification.CreatedAt.Format(time.RFC3339),
	}

	if len(notification.Metadata) > 0 {
		payload["metadata"] = notification.Metadata
	}

	body, _ := json.Marshal(payload)
	resp, err := http.Post(webhookURL, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned: %d", resp.StatusCode)
	}

	return nil
}

func (s *WebhookSender) GetName() string {
	return "Webhook"
}

type EmailSender struct{}

func (s *EmailSender) Send(notification *Notification, config *ChannelConfig) error {
	return fmt.Errorf("email sender not implemented")
}

func (s *EmailSender) GetName() string {
	return "Email"
}

func BuildEventNotification(eventType string, severity string, title string, content string) *Notification {
	return &Notification{
		Type:    NotificationTypeEvent,
		Title:   fmt.Sprintf("[%s] %s", strings.ToUpper(severity), title),
		Content: content,
	}
}

func BuildTicketNotification(ticketType string, ticketID string, title string, action string) *Notification {
	return &Notification{
		Type:    NotificationTypeTicket,
		Title:   fmt.Sprintf("工单 %s: %s", action, ticketID),
		Content: title,
	}
}

func BuildAlertNotification(alertType string, message string) *Notification {
	return &Notification{
		Type:    NotificationTypeAlert,
		Title:   fmt.Sprintf("安全告警: %s", alertType),
		Content: message,
	}
}
