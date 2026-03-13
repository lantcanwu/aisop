package normalizer

import (
	"regexp"
	"strings"
	"time"

	"cyberstrike-ai/internal/secops/models"
)

type FieldMapping struct {
	SourceField string
	TargetField string
	Default     string
}

type Normalizer struct {
	fieldMappings map[string][]FieldMapping
}

func NewNormalizer() *Normalizer {
	return &Normalizer{
		fieldMappings: make(map[string][]FieldMapping),
	}
}

func (n *Normalizer) RegisterMapping(sourceType string, mappings []FieldMapping) {
	n.fieldMappings[sourceType] = mappings
}

func (n *Normalizer) Normalize(event *models.SecurityEvent) {
	n.normalizeSeverity(event)
	n.normalizeTimestamp(event)
	n.normalizeTitle(event)
	n.normalizeSource(event)
	n.normalizeEventType(event)
}

func (n *Normalizer) normalizeSeverity(event *models.SecurityEvent) {
	if event.Severity == "" {
		event.Severity = models.SeverityInfo
	}
}

func (n *Normalizer) normalizeTimestamp(event *models.SecurityEvent) {
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now()
	}
	if event.UpdatedAt.IsZero() {
		event.UpdatedAt = time.Now()
	}
}

func (n *Normalizer) normalizeTitle(event *models.SecurityEvent) {
	if event.Title == "" {
		event.Title = "Security Event"
	}
	event.Title = strings.TrimSpace(event.Title)
	if len(event.Title) > 500 {
		event.Title = event.Title[:500]
	}
}

func (n *Normalizer) normalizeSource(event *models.SecurityEvent) {
	if event.Source == "" {
		event.Source = "unknown"
	}
	event.Source = strings.ToLower(strings.TrimSpace(event.Source))
}

func (n *Normalizer) normalizeEventType(event *models.SecurityEvent) {
	if event.EventType == "" {
		event.EventType = "unknown"
	}
	event.EventType = strings.ToLower(strings.TrimSpace(event.EventType))
}

func (n *Normalizer) ApplyMappings(event *models.SecurityEvent, sourceType string) {
	mappings, ok := n.fieldMappings[sourceType]
	if !ok {
		return
	}

	if event.RawData == nil {
		return
	}

	for _, mapping := range mappings {
		if value, exists := event.RawData[mapping.SourceField]; exists {
			switch mapping.TargetField {
			case "title":
				if str, ok := value.(string); ok {
					event.Title = str
				}
			case "description":
				if str, ok := value.(string); ok {
					event.Description = str
				}
			case "severity":
				if str, ok := value.(string); ok {
					event.Severity = models.ParseSeverity(str)
				}
			case "source":
				if str, ok := value.(string); ok {
					event.Source = str
				}
			case "event_type":
				if str, ok := value.(string); ok {
					event.EventType = str
				}
			}
		} else if mapping.Default != "" {
			switch mapping.TargetField {
			case "title":
				event.Title = mapping.Default
			case "severity":
				event.Severity = models.ParseSeverity(mapping.Default)
			case "source":
				event.Source = mapping.Default
			case "event_type":
				event.EventType = mapping.Default
			}
		}
	}
}

type TimestampParser struct {
	formats []string
}

func NewTimestampParser() *TimestampParser {
	return &TimestampParser{
		formats: []string{
			time.RFC3339,
			time.RFC3339Nano,
			"2006-01-02T15:04:05Z07:00",
			"2006-01-02T15:04:05",
			"2006-01-02 15:04:05",
			"Jan 2, 2006 at 3:04pm (MST)",
			"02/Jan/2006:15:04:05 -0700",
			"2006/01/02 15:04:05",
		},
	}
}

func (p *TimestampParser) Parse(value string) time.Time {
	for _, format := range p.formats {
		if t, err := time.Parse(format, value); err == nil {
			return t
		}
	}
	return time.Time{}
}

func (p *TimestampParser) ExtractFromRawData(rawData map[string]interface{}) time.Time {
	timestampFields := []string{
		"timestamp",
		"time",
		"@timestamp",
		"eventTime",
		"datetime",
		"created_at",
		"date",
	}

	for _, field := range timestampFields {
		if value, ok := rawData[field]; ok {
			switch v := value.(type) {
			case string:
				return p.Parse(v)
			case float64:
				return time.Unix(int64(v), 0)
			case int64:
				return time.Unix(v, 0)
			}
		}
	}

	return time.Time{}
}

var (
	ipRegex     = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	emailRegex  = regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`)
	urlRegex    = regexp.MustCompile(`https?://[^\s]+`)
	domainRegex = regexp.MustCompile(`\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b`)
	md5Regex    = regexp.MustCompile(`\b[a-fA-F0-9]{32}\b`)
	sha1Regex   = regexp.MustCompile(`\b[a-fA-F0-9]{40}\b`)
	sha256Regex = regexp.MustCompile(`\b[a-fA-F0-9]{64}\b`)
)

type IoCExtractor struct{}

func NewIoCExtractor() *IoCExtractor {
	return &IoCExtractor{}
}

func (e *IoCExtractor) ExtractFromText(text string) []models.IoC {
	iocs := []models.IoC{}

	ipMatches := ipRegex.FindAllString(text, -1)
	for _, ip := range uniqueStrings(ipMatches) {
		if !isPrivateIP(ip) {
			iocs = append(iocs, models.IoC{
				Type:   models.IoCTypeIP,
				Value:  ip,
				Source: "regex",
			})
		}
	}

	emailMatches := emailRegex.FindAllString(text, -1)
	for _, email := range uniqueStrings(emailMatches) {
		iocs = append(iocs, models.IoC{
			Type:   models.IoCTypeEmail,
			Value:  email,
			Source: "regex",
		})
	}

	urlMatches := urlRegex.FindAllString(text, -1)
	for _, url := range uniqueStrings(urlMatches) {
		iocs = append(iocs, models.IoC{
			Type:   models.IoCTypeURL,
			Value:  url,
			Source: "regex",
		})
	}

	domainMatches := domainRegex.FindAllString(text, -1)
	for _, domain := range uniqueStrings(domainMatches) {
		if !isURL(domain) {
			iocs = append(iocs, models.IoC{
				Type:   models.IoCTypeDomain,
				Value:  domain,
				Source: "regex",
			})
		}
	}

	md5Matches := md5Regex.FindAllString(text, -1)
	for _, hash := range uniqueStrings(md5Matches) {
		iocs = append(iocs, models.IoC{
			Type:   models.IoCTypeHash,
			Value:  hash,
			Source: "regex",
		})
	}

	sha1Matches := sha1Regex.FindAllString(text, -1)
	for _, hash := range uniqueStrings(sha1Matches) {
		iocs = append(iocs, models.IoC{
			Type:   models.IoCTypeHash,
			Value:  hash,
			Source: "regex",
		})
	}

	sha256Matches := sha256Regex.FindAllString(text, -1)
	for _, hash := range uniqueStrings(sha256Matches) {
		iocs = append(iocs, models.IoC{
			Type:   models.IoCTypeHash,
			Value:  hash,
			Source: "regex",
		})
	}

	return iocs
}

func uniqueStrings(input []string) []string {
	seen := make(map[string]bool)
	result := []string{}
	for _, s := range input {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

func isPrivateIP(ip string) bool {
	privateIPs := []string{
		"10.", "172.16.", "172.17.", "172.18.", "172.19.",
		"172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
		"172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
		"172.30.", "172.31.", "192.168.",
		"127.",
	}
	for _, prefix := range privateIPs {
		if strings.HasPrefix(ip, prefix) {
			return true
		}
	}
	return false
}

func isURL(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}
