package collector

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"cyberstrike-ai/internal/secops/models"
)

type STIXParser struct{}

func NewSTIXParser() *STIXParser {
	return &STIXParser{}
}

type STIXBundle struct {
	XMLName xml.Name     `xml:"bundle" json:"-"`
	Type    string       `xml:"type,attr" json:"type"`
	ID      string       `xml:"id,attr" json:"id"`
	Objects []STIXObject `xml:"objects>object" json:"objects"`
}

type STIXObject struct {
	Type            string           `xml:"type,attr" json:"type"`
	ID              string           `xml:"id,attr" json:"id"`
	Created         string           `xml:"created" json:"created"`
	Modified        string           `xml:"modified" json:"modified"`
	Pattern         string           `xml:"pattern" json:"pattern,omitempty"`
	ValidFrom       string           `xml:"valid_from" json:"valid_from,omitempty"`
	Labels          []string         `xml:"labels" json:"labels,omitempty"`
	Name            string           `xml:"name" json:"name,omitempty"`
	Description     string           `xml:"description" json:"description,omitempty"`
	PatternLang     string           `xml:"pattern_lang" json:"pattern_lang,omitempty"`
	KillChainPhases []KillChainPhase `xml:"kill_chain_phases>kill_chain_phase" json:"kill_chain_phases,omitempty"`
}

type KillChainPhase struct {
	Name  string `xml:"name" json:"name"`
	Phase string `xml:"phase_id" json:"phase_id"`
}

func (p *STIXParser) Parse(data []byte) ([]*models.SecurityEvent, error) {
	var bundle STIXBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		if err := xml.Unmarshal(data, &bundle); err != nil {
			return nil, fmt.Errorf("failed to parse STIX: %w", err)
		}
	}

	events := make([]*models.SecurityEvent, 0)
	for _, obj := range bundle.Objects {
		event := p.parseObject(obj)
		if event != nil {
			events = append(events, event)
		}
	}

	return events, nil
}

func (p *STIXParser) parseObject(obj STIXObject) *models.SecurityEvent {
	event := &models.SecurityEvent{
		Source:      "stix",
		SourceType:  "threat_intel",
		EventType:   "indicator",
		Title:       obj.Name,
		Description: obj.Description,
		IoCs:        []models.IoC{},
		AssetIDs:    []string{},
		TTP:         []string{},
		RawData:     map[string]interface{}{},
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		Status:      models.StatusCreated,
	}

	if obj.Name != "" {
		event.Title = fmt.Sprintf("STIX Indicator: %s", obj.Name)
	} else if obj.Pattern != "" {
		event.Title = "STIX Indicator Pattern"
		event.Description = obj.Pattern
	}

	if len(obj.Labels) > 0 {
		event.TTP = obj.Labels
	}

	for _, phase := range obj.KillChainPhases {
		event.TTP = append(event.TTP, fmt.Sprintf("%s:%s", phase.Name, phase.Phase))
	}

	if obj.Pattern != "" {
		ioc := p.extractIoCFromPattern(obj.Pattern)
		if ioc.Value != "" {
			event.IoCs = append(event.IoCs, ioc)
		}
	}

	event.SetID()
	return event
}

func (p *STIXParser) extractIoCFromPattern(pattern string) models.IoC {
	patterns := []struct {
		prefix  string
		iocType models.IoCType
	}{
		{"[ipv4-addr:value = '", models.IoCTypeIP},
		{"[ipv6-addr:value = '", models.IoCTypeIP},
		{"[domain-name:value = '", models.IoCTypeDomain},
		{"[hostname:value = '", models.IoCTypeDomain},
		{"[url:value = '", models.IoCTypeURL},
		{"[file:hashes.'MD5' = '", models.IoCTypeHash},
		{"[file:hashes.'SHA-1' = '", models.IoCTypeHash},
		{"[file:hashes.'SHA-256' = '", models.IoCTypeHash},
		{"[email-addr:value = '", models.IoCTypeEmail},
	}

	for _, pat := range patterns {
		if idx := strings.Index(pattern, pat.prefix); idx != -1 {
			start := idx + len(pat.prefix)
			end := strings.Index(pattern[start:], "'")
			if end > 0 {
				return models.IoC{
					Type:   pat.iocType,
					Value:  pattern[start : start+end],
					Source: "stix_pattern",
				}
			}
		}
	}

	return models.IoC{}
}

type TAXIIClient struct {
	ServerURL   string
	APIVersion  string
	Collections []string
	Auth        *TAXIIAuth
	Client      *http.Client
}

type TAXIIAuth struct {
	Username string
	Password string
	Token    string
}

func NewTAXIIClient(serverURL string) *TAXIIClient {
	return &TAXIIClient{
		ServerURL:  serverURL,
		APIVersion: "2.1",
		Client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}
}

func (c *TAXIIClient) SetBasicAuth(username, password string) {
	c.Auth = &TAXIIAuth{
		Username: username,
		Password: password,
	}
}

func (c *TAXIIClient) SetTokenAuth(token string) {
	c.Auth = &TAXIIAuth{
		Token: token,
	}
}

type TAXIICollectionsResponse struct {
	Collections []TAXIICollection `json:"collections"`
}

type TAXIICollection struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	CanRead     bool     `json:"can_read"`
	CanWrite    bool     `json:"can_write"`
	MediaTypes  []string `json:"media_types"`
}

func (c *TAXIIClient) GetCollections() ([]TAXIICollection, error) {
	url := fmt.Sprintf("%s/collections", c.ServerURL)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	if err := c.addAuth(req); err != nil {
		return nil, err
	}

	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get collections: %s", resp.Status)
	}

	var result TAXIICollectionsResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result.Collections, nil
}

type TAXIIGetObjectsResponse struct {
	Objects []json.RawMessage `json:"objects"`
}

func (c *TAXIIClient) GetObjects(collectionID string, addedAfter string) ([]json.RawMessage, error) {
	url := fmt.Sprintf("%s/collections/%s/objects", c.ServerURL, collectionID)
	if addedAfter != "" {
		url += fmt.Sprintf("?added_after=%s", addedAfter)
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	if err := c.addAuth(req); err != nil {
		return nil, err
	}

	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get objects: %s", resp.Status)
	}

	var result TAXIIGetObjectsResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result.Objects, nil
}

func (c *TAXIIClient) addAuth(req *http.Request) error {
	if c.Auth == nil {
		return nil
	}

	if c.Auth.Token != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.Auth.Token))
	} else if c.Auth.Username != "" {
		req.SetBasicAuth(c.Auth.Username, c.Auth.Password)
	}

	return nil
}

type ThreatIntelCollector struct {
	CollectorConfig
	Parser *STIXParser
	Client *TAXIIClient
}

func NewThreatIntelCollector(config CollectorConfig) *ThreatIntelCollector {
	return &ThreatIntelCollector{
		CollectorConfig: config,
		Parser:          NewSTIXParser(),
		Client:          NewTAXIIClient(getConfigString(config.Config, "server_url")),
	}
}

func (c *ThreatIntelCollector) Run() ([]*models.SecurityEvent, error) {
	authType := getConfigString(c.Config, "auth_type")
	username := getConfigString(c.Config, "username")
	password := getConfigString(c.Config, "password")
	token := getConfigString(c.Config, "token")

	switch authType {
	case "basic":
		c.Client.SetBasicAuth(username, password)
	case "token":
		c.Client.SetTokenAuth(token)
	}

	collections := getConfigSlice(c.Config, "collections")
	if len(collections) == 0 {
		cols, err := c.Client.GetCollections()
		if err != nil {
			return nil, err
		}
		for _, col := range cols {
			collections = append(collections, col.ID)
		}
	}

	allEvents := make([]*models.SecurityEvent, 0)
	for _, colID := range collections {
		objects, err := c.Client.GetObjects(colID, getLastRunTime(c.LastRun))
		if err != nil {
			continue
		}

		for _, obj := range objects {
			events, err := c.Parser.Parse(obj)
			if err != nil {
				continue
			}
			allEvents = append(allEvents, events...)
		}
	}

	return allEvents, nil
}

func getConfigString(config map[string]interface{}, key string) string {
	if v, ok := config[key].(string); ok {
		return v
	}
	return ""
}

func getConfigSlice(config map[string]interface{}, key string) []string {
	if v, ok := config[key].([]interface{}); ok {
		result := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	return nil
}

func getLastRunTime(lastRun *time.Time) string {
	if lastRun == nil {
		return ""
	}
	return lastRun.Format(time.RFC3339)
}

type SIEMCollector struct {
	CollectorConfig
	Client *http.Client
}

func NewSIEMCollector(config CollectorConfig) *SIEMCollector {
	return &SIEMCollector{
		CollectorConfig: config,
		Client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (c *SIEMCollector) Run() ([]*models.SecurityEvent, error) {
	siemType := getConfigString(c.Config, "siem_type")
	endpoint := getConfigString(c.Config, "endpoint")
	apiKey := getConfigString(c.Config, "api_key")

	var url string
	switch siemType {
	case "splunk":
		url = fmt.Sprintf("%s/services/search/jobs", endpoint)
	case "elastic":
		url = fmt.Sprintf("%s/_search", endpoint)
	case "sentinel":
		url = fmt.Sprintf("%s/api/security/alerts", endpoint)
	default:
		url = endpoint
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	if apiKey != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", apiKey))
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	events := c.parseResponse(siemType, body)
	return events, nil
}

func (c *SIEMCollector) parseResponse(siemType string, data []byte) []*models.SecurityEvent {
	events := make([]*models.SecurityEvent, 0)

	switch siemType {
	case "splunk":
		events = c.parseSplunkResponse(data)
	case "elastic":
		events = c.parseElasticResponse(data)
	case "sentinel":
		events = c.parseSentinelResponse(data)
	default:
		events = c.parseGenericResponse(data)
	}

	return events
}

func (c *SIEMCollector) parseSplunkResponse(data []byte) []*models.SecurityEvent {
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil
	}

	events := make([]*models.SecurityEvent, 0)
	results, ok := result["results"].([]interface{})
	if !ok {
		return events
	}

	for _, r := range results {
		if obj, ok := r.(map[string]interface{}); ok {
			event := &models.SecurityEvent{
				Source:     "splunk",
				SourceType: "siem",
				EventType:  "alert",
				RawData:    obj,
				IoCs:       []models.IoC{},
				AssetIDs:   []string{},
				TTP:        []string{},
				CreatedAt:  time.Now(),
				UpdatedAt:  time.Now(),
				Status:     models.StatusCreated,
			}

			if v, ok := obj["_time"].(string); ok {
				if t, err := time.Parse(time.RFC3339, v); err == nil {
					event.CreatedAt = t
					event.UpdatedAt = t
				}
			}

			if v, ok := obj["source"].(string); ok {
				event.Source = v
			}

			if v, ok := obj["_raw"].(string); ok {
				event.Title = v
				if len(v) > 200 {
					event.Title = v[:200]
					event.Description = v
				}
			}

			event.SetID()
			events = append(events, event)
		}
	}

	return events
}

func (c *SIEMCollector) parseElasticResponse(data []byte) []*models.SecurityEvent {
	var result struct {
		Hits struct {
			Hits []struct {
				Source map[string]interface{} `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}

	if err := json.Unmarshal(data, &result); err != nil {
		return nil
	}

	events := make([]*models.SecurityEvent, 0)
	for _, hit := range result.Hits.Hits {
		event := &models.SecurityEvent{
			Source:     "elastic",
			SourceType: "siem",
			EventType:  "log",
			RawData:    hit.Source,
			IoCs:       []models.IoC{},
			AssetIDs:   []string{},
			TTP:        []string{},
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
			Status:     models.StatusCreated,
		}

		if v, ok := hit.Source["message"].(string); ok {
			event.Title = v
		}

		if v, ok := hit.Source["@timestamp"].(string); ok {
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				event.CreatedAt = t
				event.UpdatedAt = t
			}
		}

		event.SetID()
		events = append(events, event)
	}

	return events
}

func (c *SIEMCollector) parseSentinelResponse(data []byte) []*models.SecurityEvent {
	var alerts []map[string]interface{}
	if err := json.Unmarshal(data, &alerts); err != nil {
		return nil
	}

	events := make([]*models.SecurityEvent, 0)
	for _, alert := range alerts {
		event := &models.SecurityEvent{
			Source:     "sentinel",
			SourceType: "siem",
			EventType:  "alert",
			RawData:    alert,
			IoCs:       []models.IoC{},
			AssetIDs:   []string{},
			TTP:        []string{},
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
			Status:     models.StatusCreated,
		}

		if v, ok := alert["AlertDisplayName"].(string); ok {
			event.Title = v
		}

		if v, ok := alert["TimeGenerated"].(string); ok {
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				event.CreatedAt = t
				event.UpdatedAt = t
			}
		}

		event.SetID()
		events = append(events, event)
	}

	return events
}

func (c *SIEMCollector) parseGenericResponse(data []byte) []*models.SecurityEvent {
	parser := NewSTIXParser()
	events, _ := parser.Parse(data)
	return events
}

type APICollector struct {
	CollectorConfig
	Client *http.Client
}

func NewAPICollector(config CollectorConfig) *APICollector {
	return &APICollector{
		CollectorConfig: config,
		Client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (c *APICollector) Run() ([]*models.SecurityEvent, error) {
	endpoint := getConfigString(c.Config, "endpoint")
	method := getConfigString(c.Config, "method")
	if method == "" {
		method = "GET"
	}

	authType := getConfigString(c.Config, "auth_type")
	apiKey := getConfigString(c.Config, "api_key")
	username := getConfigString(c.Config, "username")
	password := getConfigString(c.Config, "password")

	var body io.Reader
	if bodyStr := getConfigString(c.Config, "body"); bodyStr != "" {
		body = bytes.NewBufferString(bodyStr)
	}

	req, err := http.NewRequest(method, endpoint, body)
	if err != nil {
		return nil, err
	}

	switch authType {
	case "api_key":
		req.Header.Set("X-API-Key", apiKey)
	case "bearer":
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", apiKey))
	case "basic":
		req.SetBasicAuth(username, password)
	}

	for key, value := range c.Config {
		if strings.HasPrefix(key, "header_") {
			headerName := strings.TrimPrefix(key, "header_")
			if v, ok := value.(string); ok {
				req.Header.Set(headerName, v)
			}
		}
	}

	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	events := c.parseResponse(respBody)
	return events, nil
}

func (c *APICollector) parseResponse(data []byte) []*models.SecurityEvent {
	var rawData interface{}
	if err := json.Unmarshal(data, &rawData); err != nil {
		return nil
	}

	events := make([]*models.SecurityEvent, 0)

	switch v := rawData.(type) {
	case []interface{}:
		for _, item := range v {
			if obj, ok := item.(map[string]interface{}); ok {
				event := c.parseObject(obj)
				events = append(events, event)
			}
		}
	case map[string]interface{}:
		event := c.parseObject(v)
		events = append(events, event)
	}

	return events
}

func (c *APICollector) parseObject(obj map[string]interface{}) *models.SecurityEvent {
	event := &models.SecurityEvent{
		Source:     getConfigString(c.Config, "source"),
		SourceType: "api",
		EventType:  "api_event",
		RawData:    obj,
		IoCs:       []models.IoC{},
		AssetIDs:   []string{},
		TTP:        []string{},
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
		Status:     models.StatusCreated,
	}

	if title, ok := obj["title"].(string); ok {
		event.Title = title
	} else if msg, ok := obj["message"].(string); ok {
		event.Title = msg
	}

	if desc, ok := obj["description"].(string); ok {
		event.Description = desc
	}

	if severity, ok := obj["severity"].(string); ok {
		event.Severity = models.ParseSeverity(severity)
	}

	event.SetID()
	return event
}
