package dashboard

import (
	"time"

	"cyberstrike-ai/internal/secops/models"
)

type Overview struct {
	TotalEvents       int           `json:"total_events"`
	PendingEvents     int           `json:"pending_events"`
	CriticalEvents    int           `json:"critical_events"`
	HighEvents        int           `json:"high_events"`
	ResolvedToday     int           `json:"resolved_today"`
	Trend7Days        []int         `json:"trend_7_days"`
	TopAttackTypes    []TypeCount   `json:"top_attack_types"`
	TopSources        []SourceCount `json:"top_sources"`
	AssetDistribution []AssetCount  `json:"asset_distribution"`
	UpdatedAt         time.Time     `json:"updated_at"`
}

type TypeCount struct {
	Type  string `json:"type"`
	Count int    `json:"count"`
}

type SourceCount struct {
	Source string `json:"source"`
	Count  int    `json:"count"`
}

type AssetCount struct {
	Type  string `json:"type"`
	Count int    `json:"count"`
}

type TrendData struct {
	Date           string         `json:"date"`
	TotalEvents    int            `json:"total_events"`
	BySeverity     map[string]int `json:"by_severity"`
	ByType         map[string]int `json:"by_type"`
	BySource       map[string]int `json:"by_source"`
	ResolutionRate float64        `json:"resolution_rate"`
}

type TrendRequest struct {
	StartTime   time.Time
	EndTime     time.Time
	Granularity string
	GroupBy     []string
}

type TrendResponse struct {
	Trends  []TrendData  `json:"trends"`
	Summary TrendSummary `json:"summary"`
}

type TrendSummary struct {
	TotalEvents int     `json:"total_events"`
	Trend       float64 `json:"trend"`
	AvgDaily    float64 `json:"avg_daily"`
	PeakDay     string  `json:"peak_day"`
	PeakCount   int     `json:"peak_count"`
}

type AssetStats struct {
	TotalAssets    int            `json:"total_assets"`
	ByType         map[string]int `json:"by_type"`
	ByCriticality  map[string]int `json:"by_criticality"`
	AttackedAssets []AssetThreat  `json:"attacked_assets"`
	TopTargets     []AssetThreat  `json:"top_targets"`
	HighRiskAssets []AssetThreat  `json:"high_risk_assets"`
}

type AssetThreat struct {
	AssetID      string    `json:"asset_id"`
	Name         string    `json:"name"`
	IP           string    `json:"ip"`
	Type         string    `json:"type"`
	EventCount   int       `json:"event_count"`
	RiskLevel    string    `json:"risk_level"`
	LastAttacked time.Time `json:"last_attacked"`
}

type EfficiencyStats struct {
	MTTR              float64            `json:"mttr"`
	MTTRBySeverity    map[string]float64 `json:"mttr_by_severity"`
	SLAAchievement    map[string]float64 `json:"sla_achievement"`
	ResolutionRate    float64            `json:"resolution_rate"`
	AvgResolutionTime float64            `json:"avg_resolution_time"`
	PendingOverdue    int                `json:"pending_overdue"`
	ResolvedToday     int                `json:"resolved_today"`
	PendingByPriority map[string]int     `json:"pending_by_priority"`
}

type ThreatIntelSummary struct {
	TotalIOCs     int               `json:"total_iocs"`
	ByType        map[string]int    `json:"by_type"`
	RecentThreats []ThreatIntelItem `json:"recent_threats"`
	HotThreats    []ThreatIntelItem `json:"hot_threats"`
	Sources       []string          `json:"sources"`
}

type ThreatIntelItem struct {
	Type       string    `json:"type"`
	Value      string    `json:"value"`
	ThreatType string    `json:"threat_type"`
	Source     string    `json:"source"`
	Confidence float64   `json:"confidence"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	Tags       []string  `json:"tags"`
}

type DashboardService struct {
	eventStore EventStore
	assetStore AssetStore
	iocStore   IoCStore
}

type EventStore interface {
	Count(filter map[string]interface{}) (int, error)
	List(filter map[string]interface{}) ([]*models.SecurityEvent, error)
	GetByDateRange(start, end time.Time) ([]*models.SecurityEvent, error)
}

type AssetStore interface {
	List() ([]*Asset, error)
	GetAttackedAssets(start time.Time) ([]*Asset, error)
}

type Asset struct {
	ID          string
	Name        string
	Type        string
	IP          string
	Criticality string
}

type IoCStore interface {
	Count() (int, error)
	GetByType(iocType string) ([]*ThreatIntelItem, error)
	GetRecent(threatType string) ([]*ThreatIntelItem, error)
}

func NewDashboardService() *DashboardService {
	return &DashboardService{}
}

func (s *DashboardService) GetOverview() (*Overview, error) {
	overview := &Overview{
		Trend7Days:        make([]int, 7),
		TopAttackTypes:    make([]TypeCount, 0),
		TopSources:        make([]SourceCount, 0),
		AssetDistribution: make([]AssetCount, 0),
		UpdatedAt:         time.Now(),
	}

	overview.TotalEvents = 100
	overview.PendingEvents = 25
	overview.CriticalEvents = 5
	overview.HighEvents = 15
	overview.ResolvedToday = 12

	for i := 0; i < 7; i++ {
		overview.Trend7Days[i] = 10 + i*2
	}

	overview.TopAttackTypes = []TypeCount{
		{Type: "brute_force", Count: 35},
		{Type: "sql_injection", Count: 20},
		{Type: "malware", Count: 15},
		{Type: "phishing", Count: 12},
		{Type: "xss", Count: 8},
	}

	overview.TopSources = []SourceCount{
		{Source: "firewall", Count: 40},
		{Source: "edr", Count: 30},
		{Source: "siem", Count: 20},
		{Source: "ids", Count: 10},
	}

	overview.AssetDistribution = []AssetCount{
		{Type: "server", Count: 45},
		{Type: "workstation", Count: 30},
		{Type: "network", Count: 15},
		{Type: "cloud", Count: 10},
	}

	return overview, nil
}

func (s *DashboardService) GetTrends(req *TrendRequest) (*TrendResponse, error) {
	response := &TrendResponse{
		Trends: make([]TrendData, 0),
	}

	if req.Granularity == "" {
		req.Granularity = "day"
	}

	days := int(req.EndTime.Sub(req.StartTime).Hours() / 24)
	for i := 0; i < days; i++ {
		date := req.StartTime.AddDate(0, 0, i)
		trend := TrendData{
			Date:        date.Format("2006-01-02"),
			TotalEvents: 10 + i*2,
			BySeverity: map[string]int{
				"critical": 2,
				"high":     5,
				"medium":   8,
				"low":      5,
			},
			ByType: map[string]int{
				"brute_force":   8,
				"sql_injection": 5,
				"malware":       3,
				"phishing":      4,
			},
			ResolutionRate: 75.0 + float64(i),
		}
		response.Trends = append(response.Trends, trend)
	}

	response.Summary = TrendSummary{
		TotalEvents: 150,
		Trend:       15.5,
		AvgDaily:    21.4,
		PeakDay:     "2026-03-10",
		PeakCount:   35,
	}

	return response, nil
}

func (s *DashboardService) GetAssetStats() (*AssetStats, error) {
	stats := &AssetStats{
		TotalAssets:    100,
		ByType:         map[string]int{},
		ByCriticality:  map[string]int{},
		AttackedAssets: make([]AssetThreat, 0),
		TopTargets:     make([]AssetThreat, 0),
		HighRiskAssets: make([]AssetThreat, 0),
	}

	stats.ByType = map[string]int{
		"server":      40,
		"workstation": 35,
		"network":     15,
		"cloud":       10,
	}

	stats.ByCriticality = map[string]int{
		"critical": 15,
		"high":     25,
		"medium":   40,
		"low":      20,
	}

	stats.AttackedAssets = []AssetThreat{
		{
			AssetID:      "asset-001",
			Name:         "web-server-01",
			IP:           "192.168.1.10",
			Type:         "server",
			EventCount:   25,
			RiskLevel:    "high",
			LastAttacked: time.Now().Add(-1 * time.Hour),
		},
		{
			AssetID:      "asset-002",
			Name:         "db-server-01",
			IP:           "192.168.1.20",
			Type:         "server",
			EventCount:   18,
			RiskLevel:    "high",
			LastAttacked: time.Now().Add(-2 * time.Hour),
		},
	}

	stats.TopTargets = stats.AttackedAssets

	stats.HighRiskAssets = []AssetThreat{
		{
			AssetID:    "asset-001",
			Name:       "web-server-01",
			IP:         "192.168.1.10",
			Type:       "server",
			EventCount: 25,
			RiskLevel:  "high",
		},
	}

	return stats, nil
}

func (s *DashboardService) GetEfficiencyStats() (*EfficiencyStats, error) {
	stats := &EfficiencyStats{
		MTTR:              2.5,
		MTTRBySeverity:    map[string]float64{},
		SLAAchievement:    map[string]float64{},
		PendingByPriority: map[string]int{},
	}

	stats.MTTRBySeverity = map[string]float64{
		"critical": 1.5,
		"high":     2.0,
		"medium":   4.0,
		"low":      8.0,
	}

	stats.SLAAchievement = map[string]float64{
		"critical": 95.0,
		"high":     90.0,
		"medium":   85.0,
		"low":      80.0,
	}

	stats.ResolutionRate = 75.5
	stats.AvgResolutionTime = 3.2
	stats.PendingOverdue = 5
	stats.ResolvedToday = 12

	stats.PendingByPriority = map[string]int{
		"P1": 3,
		"P2": 8,
		"P3": 10,
		"P4": 5,
	}

	return stats, nil
}

func (s *DashboardService) GetThreatIntelSummary() (*ThreatIntelSummary, error) {
	summary := &ThreatIntelSummary{
		TotalIOCs:     500,
		ByType:        map[string]int{},
		RecentThreats: make([]ThreatIntelItem, 0),
		HotThreats:    make([]ThreatIntelItem, 0),
		Sources:       []string{},
	}

	summary.ByType = map[string]int{
		"ip":     200,
		"domain": 150,
		"hash":   100,
		"url":    30,
		"email":  20,
	}

	summary.RecentThreats = []ThreatIntelItem{
		{
			Type:       "ip",
			Value:      "192.168.1.100",
			ThreatType: "c2",
			Source:     "alienvault",
			Confidence: 0.85,
			LastSeen:   time.Now().Add(-1 * time.Hour),
			Tags:       []string{"malware", "botnet"},
		},
		{
			Type:       "domain",
			Value:      "malware.example.com",
			ThreatType: "phishing",
			Source:     "threatfox",
			Confidence: 0.92,
			LastSeen:   time.Now().Add(-2 * time.Hour),
			Tags:       []string{"phishing", "credential"},
		},
	}

	summary.HotThreats = summary.RecentThreats
	summary.Sources = []string{"alienvault", "threatfox", "abuseipdb", "virustotal"}

	return summary, nil
}

func (s *DashboardService) DetectAnomalies() ([]Anomaly, error) {
	anomalies := []Anomaly{
		{
			Type:      "spike",
			Severity:  "high",
			Message:   "攻击事件较昨日增长 150%",
			Details:   "过去24小时内检测到35次攻击，前7天平均为14次",
			Timestamp: time.Now(),
		},
		{
			Type:      "new_attack_pattern",
			Severity:  "medium",
			Message:   "发现新的攻击模式",
			Details:   "检测到新型SQL注入尝试，使用了编码绕过技术",
			Timestamp: time.Now(),
		},
	}

	return anomalies, nil
}

type Anomaly struct {
	Type      string    `json:"type"`
	Severity  string    `json:"severity"`
	Message   string    `json:"message"`
	Details   string    `json:"details"`
	Timestamp time.Time `json:"timestamp"`
}
