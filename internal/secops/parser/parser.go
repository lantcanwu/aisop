package parser

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"

	"cyberstrike-ai/internal/secops/models"
)

var (
	ErrEmptyData     = errors.New("empty data")
	ErrUnknownFormat = errors.New("unknown format")
)

type Parser interface {
	Parse(data []byte) ([]*models.SecurityEvent, error)
	GetType() string
}

type ParseResult struct {
	Events  []*models.SecurityEvent
	Errors  []error
	Success bool
}

type ParserFactory struct {
	parsers map[string]Parser
}

func NewParserFactory() *ParserFactory {
	return &ParserFactory{
		parsers: make(map[string]Parser),
	}
}

func (f *ParserFactory) Register(p Parser) {
	f.parsers[p.GetType()] = p
}

func (f *ParserFactory) Get(t string) Parser {
	return f.parsers[t]
}

func (f *ParserFactory) DetectAndParse(data []byte) (*ParseResult, error) {
	result := &ParseResult{
		Events:  make([]*models.SecurityEvent, 0),
		Errors:  make([]error, 0),
		Success: true,
	}

	if len(data) == 0 {
		result.Success = false
		result.Errors = append(result.Errors, ErrEmptyData)
		return result, ErrEmptyData
	}

	dataStr := string(data)

	switch {
	case isJSON(data):
		p := NewJSONParser()
		events, err := p.Parse(data)
		if err != nil {
			result.Errors = append(result.Errors, err)
			result.Success = false
		}
		result.Events = append(result.Events, events...)
	case isCSV(data):
		p := NewCSVParser(nil)
		events, err := p.Parse(data)
		if err != nil {
			result.Errors = append(result.Errors, err)
			result.Success = false
		}
		result.Events = append(result.Events, events...)
	case isSyslog(dataStr):
		p := NewSyslogParser()
		events, err := p.Parse(data)
		if err != nil {
			result.Errors = append(result.Errors, err)
			result.Success = false
		}
		result.Events = append(result.Events, events...)
	default:
		result.Success = false
		result.Errors = append(result.Errors, ErrUnknownFormat)
	}

	return result, nil
}

func isJSON(data []byte) bool {
	for _, b := range data {
		if b == '{' || b == '[' {
			return true
		}
		if b > ' ' {
			break
		}
	}
	return false
}

func isCSV(data []byte) bool {
	firstLine := findFirstLine(data)
	if firstLine == "" {
		return false
	}
	commaCount := 0
	for _, c := range firstLine {
		if c == ',' {
			commaCount++
		}
	}
	return commaCount >= 2
}

func isSyslog(data string) bool {
	return len(data) > 20 && (data[0] == '<' || isSyslogFormat(data))
}

func isSyslogFormat(data string) bool {
	syslogMarkers := []string{"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}
	for _, marker := range syslogMarkers {
		if len(data) >= len(marker) && data[:len(marker)] == marker {
			return true
		}
	}
	return false
}

func findFirstLine(data []byte) string {
	for i, b := range data {
		if b == '\n' {
			return string(data[:i])
		}
	}
	return string(data)
}

type JSONParser struct{}

func NewJSONParser() *JSONParser {
	return &JSONParser{}
}

func (p *JSONParser) GetType() string {
	return "json"
}

func (p *JSONParser) Parse(data []byte) ([]*models.SecurityEvent, error) {
	var rawData interface{}
	if err := json.Unmarshal(data, &rawData); err != nil {
		return nil, err
	}

	events := make([]*models.SecurityEvent, 0)

	switch v := rawData.(type) {
	case map[string]interface{}:
		event := p.parseObject(v)
		if event != nil {
			events = append(events, event)
		}
	case []interface{}:
		for _, item := range v {
			if obj, ok := item.(map[string]interface{}); ok {
				event := p.parseObject(obj)
				if event != nil {
					events = append(events, event)
				}
			}
		}
	}

	return events, nil
}

func (p *JSONParser) parseObject(obj map[string]interface{}) *models.SecurityEvent {
	event := &models.SecurityEvent{
		RawData:   obj,
		IoCs:      []models.IoC{},
		AssetIDs:  []string{},
		EventType: "unknown",
		Source:    "json",
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
	} else if level, ok := obj["level"].(string); ok {
		event.Severity = models.ParseSeverity(level)
	}

	p.extractIoCs(event, obj)

	if event.Title == "" {
		event.Title = "Security Event"
	}

	event.SetID()
	event.SetTimestamps()

	return event
}

func (p *JSONParser) extractIoCs(event *models.SecurityEvent, obj map[string]interface{}) {
	ipFields := []string{"src_ip", "source_ip", "dst_ip", "dest_ip", "ip", "client_ip", "attacker_ip"}
	for _, field := range ipFields {
		if ip, ok := obj[field].(string); ok && ip != "" {
			event.IoCs = append(event.IoCs, models.IoC{
				Type:   models.IoCTypeIP,
				Value:  ip,
				Source: field,
			})
		}
	}

	if domain, ok := obj["domain"].(string); ok && domain != "" {
		event.IoCs = append(event.IoCs, models.IoC{
			Type:   models.IoCTypeDomain,
			Value:  domain,
			Source: "domain",
		})
	}

	if url, ok := obj["url"].(string); ok && url != "" {
		event.IoCs = append(event.IoCs, models.IoC{
			Type:   models.IoCTypeURL,
			Value:  url,
			Source: "url",
		})
	}

	hashFields := []string{"hash", "md5", "sha1", "sha256", "file_hash"}
	for _, field := range hashFields {
		if hash, ok := obj[field].(string); ok && hash != "" {
			event.IoCs = append(event.IoCs, models.IoC{
				Type:   models.IoCTypeHash,
				Value:  hash,
				Source: field,
			})
		}
	}
}

type CSVParser struct {
	columnMapping map[string]string
	headers       []string
}

func NewCSVParser(columnMapping map[string]string) *CSVParser {
	if columnMapping == nil {
		columnMapping = make(map[string]string)
	}
	return &CSVParser{
		columnMapping: columnMapping,
	}
}

func NewCSVParserWithDefault() *CSVParser {
	return NewCSVParser(nil)
}

func (p *CSVParser) GetType() string {
	return "csv"
}

func (p *CSVParser) Parse(data []byte) ([]*models.SecurityEvent, error) {
	lines := bytes.Split(data, []byte("\n"))
	if len(lines) == 0 {
		return nil, ErrEmptyData
	}

	p.headers = p.parseCSVLine(lines[0])
	events := make([]*models.SecurityEvent, 0)

	for i := 1; i < len(lines); i++ {
		if len(bytes.TrimSpace(lines[i])) == 0 {
			continue
		}
		values := p.parseCSVLine(lines[i])
		event := p.parseRow(values)
		if event != nil {
			events = append(events, event)
		}
	}

	return events, nil
}

func (p *CSVParser) parseCSVLine(line []byte) []string {
	var values []string
	var current []byte
	inQuotes := false

	for _, b := range line {
		switch {
		case b == '"':
			inQuotes = !inQuotes
		case b == ',' && !inQuotes:
			values = append(values, string(current))
			current = nil
		default:
			current = append(current, b)
		}
	}
	values = append(values, string(current))
	return values
}

func (p *CSVParser) parseRow(values []string) *models.SecurityEvent {
	if len(values) != len(p.headers) {
		return nil
	}

	event := &models.SecurityEvent{
		IoCs:      []models.IoC{},
		AssetIDs:  []string{},
		EventType: "csv",
		Source:    "csv_import",
		RawData:   make(map[string]interface{}),
	}

	for i, header := range p.headers {
		value := values[i]
		event.RawData[header] = value

		normalizedHeader := p.normalizeHeader(header)
		switch normalizedHeader {
		case "title":
			event.Title = value
		case "description":
			event.Description = value
		case "severity":
			event.Severity = models.ParseSeverity(value)
		case "source":
			event.Source = value
		case "ip":
			event.IoCs = append(event.IoCs, models.IoC{
				Type:   models.IoCTypeIP,
				Value:  value,
				Source: "ip",
			})
		}
	}

	if event.Title == "" {
		event.Title = "CSV Import Event"
	}

	event.SetID()
	event.SetTimestamps()

	return event
}

func (p *CSVParser) normalizeHeader(header string) string {
	return strings.ToLower(header)
}

type SyslogParser struct{}

func NewSyslogParser() *SyslogParser {
	return &SyslogParser{}
}

func (p *SyslogParser) GetType() string {
	return "syslog"
}

func (p *SyslogParser) Parse(data []byte) ([]*models.SecurityEvent, error) {
	lines := bytes.Split(data, []byte("\n"))
	events := make([]*models.SecurityEvent, 0)

	for _, line := range lines {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		event := p.parseLine(string(line))
		if event != nil {
			events = append(events, event)
		}
	}

	return events, nil
}

func (p *SyslogParser) parseLine(line string) *models.SecurityEvent {
	event := &models.SecurityEvent{
		IoCs:      []models.IoC{},
		AssetIDs:  []string{},
		EventType: "syslog",
		Source:    "syslog",
		RawData:   make(map[string]interface{}),
	}

	event.Title = line
	if len(line) > 200 {
		event.Title = line[:200]
		event.Description = line
	} else {
		event.Description = line
	}

	event.Severity = models.SeverityInfo
	event.SetID()
	event.SetTimestamps()

	return event
}
