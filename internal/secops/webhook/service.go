package webhook

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"time"

	"github.com/google/uuid"
)

type SignatureType string

const (
	SignatureTypeNone   SignatureType = "none"
	SignatureTypeHMAC   SignatureType = "hmac"
	SignatureTypeBearer SignatureType = "bearer"
)

type WebhookEndpoint struct {
	ID            string                 `json:"id"`
	Name          string                 `json:"name"`
	Token         string                 `json:"token"`
	SignatureType SignatureType          `json:"signature_type"`
	SignatureKey  string                 `json:"signature_key,omitempty"`
	Enabled       bool                   `json:"enabled"`
	EventTypes    []string               `json:"event_types"`
	ParserConfig  map[string]interface{} `json:"parser_config,omitempty"`
	LastEventAt   *time.Time             `json:"last_event_at,omitempty"`
	EventsCount   int                    `json:"events_count"`
	CreatedAt     time.Time              `json:"created_at"`
	UpdatedAt     time.Time              `json:"updated_at"`
}

func (w *WebhookEndpoint) SetID() {
	if w.ID == "" {
		w.ID = uuid.New().String()
	}
}

func (w *WebhookEndpoint) GenerateToken() string {
	if w.Token == "" {
		bytes := make([]byte, 32)
		rand.Read(bytes)
		w.Token = hex.EncodeToString(bytes)
	}
	return w.Token
}

func (w *WebhookEndpoint) SetTimestamps() {
	now := time.Now()
	if w.CreatedAt.IsZero() {
		w.CreatedAt = now
	}
	w.UpdatedAt = now
}

type WebhookEvent struct {
	ID             string                 `json:"id"`
	EndpointID     string                 `json:"endpoint_id"`
	SourceIP       string                 `json:"source_ip"`
	Headers        map[string]string      `json:"headers"`
	Payload        map[string]interface{} `json:"payload"`
	SignatureValid bool                   `json:"signature_valid"`
	Processed      bool                   `json:"processed"`
	ErrorMessage   string                 `json:"error_message,omitempty"`
	ReceivedAt     time.Time              `json:"received_at"`
	ProcessedAt    *time.Time             `json:"processed_at,omitempty"`
}

type WebhookService struct{}

func NewWebhookService() *WebhookService {
	return &WebhookService{}
}

func (s *WebhookService) CreateEndpoint(endpoint *WebhookEndpoint) error {
	endpoint.SetTimestamps()
	endpoint.GenerateToken()
	if endpoint.SignatureType == "" {
		endpoint.SignatureType = SignatureTypeNone
	}
	if endpoint.Enabled {
		endpoint.Enabled = true
	}
	return nil
}

func (s *WebhookService) ValidateToken(token string, endpoint *WebhookEndpoint) bool {
	return subtle.ConstantTimeCompare([]byte(token), []byte(endpoint.Token)) == 1
}

func (s *WebhookService) ValidateSignature(payload []byte, signature string, key string) bool {
	if signature == "" || key == "" {
		return false
	}
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write(payload)
	expected := mac.Sum(nil)
	actual, err := hex.DecodeString(signature)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(expected, actual) == 1
}

func (s *WebhookService) ProcessEvent(endpoint *WebhookEndpoint, payload []byte, headers map[string]string, sourceIP string) (*WebhookEvent, error) {
	event := &WebhookEvent{
		EndpointID: endpoint.ID,
		SourceIP:   sourceIP,
		Headers:    headers,
		ReceivedAt: time.Now(),
	}

	isValid := true
	if endpoint.SignatureType == SignatureTypeHMAC {
		sigHeader := headers["X-Signature"]
		if !s.ValidateSignature(payload, sigHeader, endpoint.SignatureKey) {
			isValid = false
		}
	} else if endpoint.SignatureType == SignatureTypeBearer {
		authHeader := headers["Authorization"]
		if authHeader == "" || !s.ValidateToken(authHeader, endpoint) {
			isValid = false
		}
	}

	event.SignatureValid = isValid

	now := time.Now()
	endpoint.LastEventAt = &now
	endpoint.EventsCount++
	endpoint.UpdatedAt = time.Now()

	return event, nil
}

func (s *WebhookService) RecordEvent(event *WebhookEvent) error {
	event.ID = uuid.New().String()
	event.Processed = true
	now := time.Now()
	event.ProcessedAt = &now
	return nil
}
