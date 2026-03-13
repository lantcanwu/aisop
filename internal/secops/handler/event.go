package secops

import (
	"net/http"
	"time"

	"cyberstrike-ai/internal/secops/event"
	"cyberstrike-ai/internal/secops/models"
	"cyberstrike-ai/internal/secops/parser"
	"github.com/gin-gonic/gin"
)

type EventHandler struct {
	eventService *event.EventService
	parser       *parser.ParserFactory
}

func NewEventHandler() *EventHandler {
	p := parser.NewParserFactory()
	p.Register(parser.NewJSONParser())
	p.Register(parser.NewCSVParserWithDefault())
	p.Register(parser.NewSyslogParser())

	return &EventHandler{
		eventService: event.NewEventService(),
		parser:       p,
	}
}

type IngestRequest struct {
	Source     string                 `json:"source"`
	SourceType string                 `json:"source_type"`
	EventType  string                 `json:"event_type"`
	Severity   string                 `json:"severity"`
	Title      string                 `json:"title"`
	RawData    map[string]interface{} `json:"raw_data"`
}

type IngestResponse struct {
	Success bool                  `json:"success"`
	Event   *models.SecurityEvent `json:"event,omitempty"`
	Error   string                `json:"error,omitempty"`
}

func (h *EventHandler) Ingest(c *gin.Context) {
	var req IngestRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, IngestResponse{
			Success: false,
			Error:   err.Error(),
		})
		return
	}

	event := &models.SecurityEvent{
		Source:     req.Source,
		SourceType: req.SourceType,
		EventType:  req.EventType,
		Title:      req.Title,
		RawData:    req.RawData,
		IoCs:       []models.IoC{},
		AssetIDs:   []string{},
		TTP:        []string{},
		Status:     models.StatusCreated,
	}

	if req.Severity != "" {
		event.Severity = models.ParseSeverity(req.Severity)
	}

	if err := h.eventService.CreateEvent(event); err != nil {
		c.JSON(http.StatusInternalServerError, IngestResponse{
			Success: false,
			Error:   err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, IngestResponse{
		Success: true,
		Event:   event,
	})
}

type BatchImportRequest struct {
	Source     string `json:"source"`
	SourceType string `json:"source_type"`
	Data       string `json:"data"`
	Format     string `json:"format"`
}

type BatchImportResponse struct {
	Success bool                    `json:"success"`
	Events  []*models.SecurityEvent `json:"events,omitempty"`
	Count   int                     `json:"count"`
	Errors  []string                `json:"errors,omitempty"`
}

func (h *EventHandler) BatchImport(c *gin.Context) {
	var req BatchImportRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, BatchImportResponse{
			Success: false,
			Errors:  []string{err.Error()},
		})
		return
	}

	result, err := h.parser.DetectAndParse([]byte(req.Data))
	if err != nil {
		c.JSON(http.StatusBadRequest, BatchImportResponse{
			Success: false,
			Errors:  []string{err.Error()},
		})
		return
	}

	for _, event := range result.Events {
		if req.Source != "" {
			event.Source = req.Source
		}
		if req.SourceType != "" {
			event.SourceType = req.SourceType
		}
		h.eventService.CreateEvent(event)
	}

	c.JSON(http.StatusOK, BatchImportResponse{
		Success: true,
		Events:  result.Events,
		Count:   len(result.Events),
	})
}

type ListEventsResponse struct {
	Success bool                    `json:"success"`
	Events  []*models.SecurityEvent `json:"events"`
	Total   int                     `json:"total"`
	Page    int                     `json:"page"`
	Limit   int                     `json:"limit"`
}

func (h *EventHandler) List(c *gin.Context) {
	page := c.DefaultQuery("page", "1")
	limit := c.DefaultQuery("limit", "20")
	source := c.Query("source")
	severity := c.Query("severity")
	status := c.Query("status")

	events := []*models.SecurityEvent{}

	for i := 0; i < 10; i++ {
		events = append(events, &models.SecurityEvent{
			ID:        "sample-event-" + string(rune(i+'0')),
			Source:    "sample",
			EventType: "test",
			Severity:  models.SeverityMedium,
			Status:    models.StatusCreated,
			Title:     "Sample Event " + string(rune(i+'0')),
			IoCs:      []models.IoC{},
			AssetIDs:  []string{},
			TTP:       []string{},
			CreatedAt: now(),
			UpdatedAt: now(),
		})
	}

	if source != "" {
		var filtered []*models.SecurityEvent
		for _, e := range events {
			if e.Source == source {
				filtered = append(filtered, e)
			}
		}
		events = filtered
	}

	if severity != "" {
		var filtered []*models.SecurityEvent
		for _, e := range events {
			if string(e.Severity) == severity {
				filtered = append(filtered, e)
			}
		}
		events = filtered
	}

	if status != "" {
		var filtered []*models.SecurityEvent
		for _, e := range events {
			if string(e.Status) == status {
				filtered = append(filtered, e)
			}
		}
		events = filtered
	}

	c.JSON(http.StatusOK, ListEventsResponse{
		Success: true,
		Events:  events,
		Total:   len(events),
		Page:    parseInt(page, 1),
		Limit:   parseInt(limit, 20),
	})
}

func (h *EventHandler) Get(c *gin.Context) {
	id := c.Param("id")

	event := &models.SecurityEvent{
		ID:        id,
		Source:    "sample",
		EventType: "test",
		Severity:  models.SeverityMedium,
		Status:    models.StatusCreated,
		Title:     "Sample Event",
		IoCs:      []models.IoC{},
		AssetIDs:  []string{},
		TTP:       []string{},
		RawData:   make(map[string]interface{}),
		CreatedAt: now(),
		UpdatedAt: now(),
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"event":   event,
	})
}

type ClassifyRequest struct {
	Classification string `json:"classification" binding:"required"`
	Reason         string `json:"reason"`
}

func (h *EventHandler) Classify(c *gin.Context) {
	id := c.Param("id")

	var req ClassifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	event := &models.SecurityEvent{
		ID:             id,
		Classification: models.EventClassification(req.Classification),
	}

	h.eventService.ClassifyEvent(event, models.EventClassification(req.Classification))

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"event":   event,
	})
}

func (h *EventHandler) GetSources(c *gin.Context) {
	sources := []string{
		"file_import",
		"webhook",
		"api",
		"siem",
		"edr",
		"ids",
		"firewall",
		"threat_intel",
		"manual",
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"sources": sources,
	})
}

func parseInt(s string, defaultVal int) int {
	if s == "" {
		return defaultVal
	}
	var n int
	for _, c := range s {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		}
	}
	if n == 0 {
		return defaultVal
	}
	return n
}

func now() time.Time {
	return time.Now()
}
