package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"cyberstrike-ai/internal/secops/models"
)

type AnalysisRequest struct {
	Event      *models.SecurityEvent
	Context    *AnalysisContext
	PromptType string
}

type AnalysisContext struct {
	HistoricalEvents []*models.SecurityEvent
	Assets           []map[string]interface{}
	ThreatIntel      []map[string]interface{}
	KnowledgeBase    []string
}

type AnalysisResult struct {
	Summary     string   `json:"summary"`
	AttackType  string   `json:"attack_type"`
	Confidence  float64  `json:"confidence"`
	Impact      string   `json:"impact"`
	Suggestions []string `json:"suggestions"`
	TTP         []string `json:"ttp"`
	IoCs        []string `json:"iocs"`
	RootCause   string   `json:"root_cause"`
	Timeline    []string `json:"timeline"`
	Error       string   `json:"error,omitempty"`
}

type JudgeRequest struct {
	Event   *models.SecurityEvent
	Context *AnalysisContext
}

type JudgeResult struct {
	IsRealAttack   bool     `json:"is_real_attack"`
	Confidence     float64  `json:"confidence"`
	ImpactScope    string   `json:"impact_scope"`
	Severity       string   `json:"severity"`
	Recommendation string   `json:"recommendation"`
	Reasons        []string `json:"reasons"`
}

type SuggestionRequest struct {
	Event       *models.SecurityEvent
	Context     *AnalysisContext
	ActionTypes []string
}

type SuggestionResult struct {
	RecommendedActions []RecommendedAction `json:"recommended_actions"`
	AlternativeOptions []string            `json:"alternative_options"`
	RiskAssessment     string              `json:"risk_assessment"`
	CaseReferences     []string            `json:"case_references"`
}

type RecommendedAction struct {
	Action         string `json:"action"`
	Priority       string `json:"priority"`
	Description    string `json:"description"`
	ExpectedEffect string `json:"expected_effect"`
	RiskLevel      string `json:"risk_level"`
}

type ReportRequest struct {
	EventIDs      []string
	ReportType    string
	StartTime     time.Time
	EndTime       time.Time
	IncludeCharts bool
}

type ReportResult struct {
	Title           string     `json:"title"`
	ReportType      string     `json:"report_type"`
	Summary         string     `json:"summary"`
	EventCount      int        `json:"event_count"`
	Statistics      Statistics `json:"statistics"`
	Timeline        []string   `json:"timeline"`
	Recommendations []string   `json:"recommendations"`
	Content         string     `json:"content"`
	Format          string     `json:"format"`
}

type Statistics struct {
	BySeverity  map[string]int `json:"by_severity"`
	ByType      map[string]int `json:"by_type"`
	BySource    map[string]int `json:"by_source"`
	ByStatus    map[string]int `json:"by_status"`
	MTTR        float64        `json:"mttr"`
	TotalEvents int            `json:"total_events"`
}

type AIAnalyzer struct {
	openAIClient OpenAIClient
	prompts      map[string]string
}

type OpenAIClient interface {
	Chat(ctx context.Context, messages []Message) (string, error)
}

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

func NewAIAnalyzer(client OpenAIClient) *AIAnalyzer {
	return &AIAnalyzer{
		openAIClient: client,
		prompts:      getDefaultPrompts(),
	}
}

func (a *AIAnalyzer) AnalyzeEvent(req *AnalysisRequest) (*AnalysisResult, error) {
	if req.Event == nil {
		return nil, fmt.Errorf("event is required")
	}

	result := &AnalysisResult{
		Summary:     generateSummary(req.Event),
		AttackType:  detectAttackType(req.Event),
		Confidence:  calculateConfidence(req.Event),
		Impact:      assessImpact(req.Event),
		Suggestions: generateSuggestions(req.Event),
		TTP:         matchTTP(req.Event),
		IoCs:        extractIoCStrings(req.Event),
		RootCause:   analyzeRootCause(req.Event),
		Timeline:    buildEventTimeline(req.Event),
	}

	if a.openAIClient != nil {
		prompt := a.buildAnalysisPrompt(req)
		messages := []Message{
			{Role: "system", Content: a.prompts["analysis_system"]},
			{Role: "user", Content: prompt},
		}

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		response, err := a.openAIClient.Chat(ctx, messages)
		if err == nil {
			a.parseAIResponse(response, result)
		}
	}

	return result, nil
}

func (a *AIAnalyzer) JudgeThreat(req *JudgeRequest) (*JudgeResult, error) {
	result := &JudgeResult{
		IsRealAttack: false,
		Confidence:   0.5,
		Reasons:      []string{},
	}

	if req.Event == nil {
		return nil, fmt.Errorf("event is required")
	}

	result.IsRealAttack = a.evaluateAttackLikelihood(req.Event)
	result.Confidence = calculateConfidence(req.Event)
	result.ImpactScope = a.assessImpactScope(req.Event)
	result.Severity = a.determineSeverity(req.Event)
	result.Recommendation = a.getRecommendation(req.Event)
	result.Reasons = a.generateReasons(req)

	if a.openAIClient != nil {
		prompt := a.buildJudgePrompt(req)
		messages := []Message{
			{Role: "system", Content: a.prompts["judge_system"]},
			{Role: "user", Content: prompt},
		}

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		response, err := a.openAIClient.Chat(ctx, messages)
		if err == nil {
			a.parseJudgeResponse(response, result)
		}
	}

	return result, nil
}

func (a *AIAnalyzer) GetSuggestions(req *SuggestionRequest) (*SuggestionResult, error) {
	result := &SuggestionResult{
		RecommendedActions: []RecommendedAction{},
		AlternativeOptions: []string{},
	}

	if req.Event == nil {
		return nil, fmt.Errorf("event is required")
	}

	result.RecommendedActions = a.generateRecommendedActions(req.Event)
	result.AlternativeOptions = a.getAlternativeOptions(req.Event)
	result.RiskAssessment = a.assessRisk(req.Event)
	result.CaseReferences = a.getCaseReferences(req)

	if a.openAIClient != nil {
		prompt := a.buildSuggestionPrompt(req)
		messages := []Message{
			{Role: "system", Content: a.prompts["suggestion_system"]},
			{Role: "user", Content: prompt},
		}

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		response, err := a.openAIClient.Chat(ctx, messages)
		if err == nil {
			a.parseSuggestionResponse(response, result)
		}
	}

	return result, nil
}

func (a *AIAnalyzer) GenerateReport(req *ReportRequest) (*ReportResult, error) {
	result := &ReportResult{
		Title:           getReportTitle(req.ReportType),
		ReportType:      req.ReportType,
		Timeline:        []string{},
		Recommendations: []string{},
	}

	result.Statistics = calculateStatistics(req)
	result.Summary = generateReportSummary(result.Statistics)
	result.Content = generateReportContent(req, result)
	result.Format = "markdown"

	return result, nil
}

func generateSummary(event *models.SecurityEvent) string {
	summary := fmt.Sprintf("安全事件: %s", event.Title)
	if event.EventType != "" {
		summary += fmt.Sprintf("\n事件类型: %s", event.EventType)
	}
	if event.Source != "" {
		summary += fmt.Sprintf("\n事件来源: %s", event.Source)
	}
	if event.Severity != "" {
		summary += fmt.Sprintf("\n严重程度: %s", event.Severity)
	}
	return summary
}

func detectAttackType(event *models.SecurityEvent) string {
	keywords := map[string][]string{
		"brute_force":   {"brute", "暴力", "密码", "登录失败", "failed login"},
		"sql_injection": {"sql", "injection", "注入"},
		"xss":           {"xss", "script", "cross-site"},
		"malware":       {"malware", "病毒", "恶意", "trojan"},
		"phishing":      {"phish", "钓鱼", "欺诈"},
		"ddos":          {"ddos", "dos", "攻击", "flood"},
		"data_leak":     {"leak", "泄露", "exfiltration"},
		"privilege":     {"privilege", "权限", "escalation"},
	}

	titleLower := strings.ToLower(event.Title)
	descLower := strings.ToLower(event.Description)

	for attackType, keywords := range keywords {
		for _, keyword := range keywords {
			if strings.Contains(titleLower, keyword) || strings.Contains(descLower, keyword) {
				return attackType
			}
		}
	}

	return "unknown"
}

func calculateConfidence(event *models.SecurityEvent) float64 {
	confidence := 0.5

	if len(event.IoCs) > 0 {
		confidence += 0.1
	}
	if event.Classification == models.ClassificationConfirmed {
		confidence = 0.9
	} else if event.Classification == models.ClassificationFalsePositive {
		confidence = 0.1
	}

	switch event.Severity {
	case models.SeverityCritical:
		confidence += 0.2
	case models.SeverityHigh:
		confidence += 0.1
	case models.SeverityLow:
		confidence -= 0.1
	}

	if confidence > 1.0 {
		confidence = 1.0
	}
	if confidence < 0.0 {
		confidence = 0.0
	}

	return confidence
}

func assessImpact(event *models.SecurityEvent) string {
	switch event.Severity {
	case models.SeverityCritical:
		return "严重影响 - 需要立即响应，可能导致业务中断或重大数据泄露"
	case models.SeverityHigh:
		return "高影响 - 需要优先处理，可能导致服务降级或数据风险"
	case models.SeverityMedium:
		return "中影响 - 需要关注处理，可能存在潜在风险"
	case models.SeverityLow:
		return "低影响 - 建议关注，影响范围有限"
	default:
		return "影响未知 - 需要进一步分析"
	}
}

func generateSuggestions(event *models.SecurityEvent) []string {
	suggestions := []string{}

	switch event.Severity {
	case models.SeverityCritical, models.SeverityHigh:
		suggestions = append(suggestions,
			"立即启动应急响应流程",
			"隔离受影响系统",
			"收集证据和日志",
			"通知相关人员",
		)
	case models.SeverityMedium:
		suggestions = append(suggestions,
			"安排时间进行调查分析",
			"检查相关日志",
			"评估影响范围",
		)
	default:
		suggestions = append(suggestions,
			"记录事件",
			"持续监控",
		)
	}

	attackType := detectAttackType(event)
	switch attackType {
	case "brute_force":
		suggestions = append(suggestions, "检查并限制登录尝试", "启用多因素认证")
	case "sql_injection":
		suggestions = append(suggestions, "检查输入验证", "审查数据库权限")
	case "malware":
		suggestions = append(suggestions, "进行全盘扫描", "检查可疑进程")
	}

	return suggestions
}

func matchTTP(event *models.SecurityEvent) []string {
	attackType := detectAttackType(event)
	ttpMap := map[string][]string{
		"brute_force":   {"T1110"},
		"sql_injection": {"T1190", "T1059.004"},
		"xss":           {"T1189"},
		"malware":       {"T1059", "T1566"},
		"phishing":      {"T1566", "T1598"},
		"ddos":          {"T1498"},
		"data_leak":     {"T1041"},
		"privilege":     {"T1068"},
	}

	if ttps, ok := ttpMap[attackType]; ok {
		return ttps
	}
	return []string{}
}

func extractIoCStrings(event *models.SecurityEvent) []string {
	iocs := []string{}
	for _, ioc := range event.IoCs {
		iocs = append(iocs, fmt.Sprintf("%s: %s", ioc.Type, ioc.Value))
	}
	return iocs
}

func analyzeRootCause(event *models.SecurityEvent) string {
	if len(event.IoCs) > 0 {
		return fmt.Sprintf("检测到可疑 %s: %s", event.IoCs[0].Type, event.IoCs[0].Value)
	}
	return "需要进一步分析确定根本原因"
}

func buildEventTimeline(event *models.SecurityEvent) []string {
	timeline := []string{}
	timeline = append(timeline, fmt.Sprintf("%s - 事件创建", event.CreatedAt.Format("2006-01-02 15:04:05")))
	if event.ClassifiedAt != nil {
		timeline = append(timeline, fmt.Sprintf("%s - 事件分类: %s", event.ClassifiedAt.Format("2006-01-02 15:04:05"), event.Classification))
	}
	if event.ResolvedAt != nil {
		timeline = append(timeline, fmt.Sprintf("%s - 事件解决", event.ResolvedAt.Format("2006-01-02 15:04:05")))
	}
	return timeline
}

func (a *AIAnalyzer) buildAnalysisPrompt(req *AnalysisRequest) string {
	return fmt.Sprintf("分析以下安全事件：\n%s", generateSummary(req.Event))
}

func (a *AIAnalyzer) buildJudgePrompt(req *JudgeRequest) string {
	return fmt.Sprintf("判断以下事件是否为真实攻击：\n%s", generateSummary(req.Event))
}

func (a *AIAnalyzer) buildSuggestionPrompt(req *SuggestionRequest) string {
	return fmt.Sprintf("为以下事件推荐响应措施：\n%s", generateSummary(req.Event))
}

func (a *AIAnalyzer) parseAIResponse(response string, result *AnalysisResult) {
	if json.Valid([]byte(response)) {
		json.Unmarshal([]byte(response), result)
	}
}

func (a *AIAnalyzer) parseJudgeResponse(response string, result *JudgeResult) {
	if json.Valid([]byte(response)) {
		json.Unmarshal([]byte(response), result)
	}
}

func (a *AIAnalyzer) parseSuggestionResponse(response string, result *SuggestionResult) {
	if json.Valid([]byte(response)) {
		json.Unmarshal([]byte(response), result)
	}
}

func (a *AIAnalyzer) evaluateAttackLikelihood(event *models.SecurityEvent) bool {
	return calculateConfidence(event) > 0.6
}

func (a *AIAnalyzer) assessImpactScope(event *models.SecurityEvent) string {
	if len(event.AssetIDs) > 5 {
		return "广泛 - 多个资产受影响"
	} else if len(event.AssetIDs) > 1 {
		return "中等 - 部分资产受影响"
	}
	return "有限 - 单个资产受影响"
}

func (a *AIAnalyzer) determineSeverity(event *models.SecurityEvent) string {
	return string(event.Severity)
}

func (a *AIAnalyzer) getRecommendation(event *models.SecurityEvent) string {
	if event.Severity == models.SeverityCritical {
		return "立即响应"
	}
	return "按优先级处理"
}

func (a *AIAnalyzer) generateReasons(req *JudgeRequest) []string {
	reasons := []string{}

	if len(req.Event.IoCs) > 0 {
		reasons = append(reasons, "检测到可疑指标")
	}

	if req.Event.Severity == models.SeverityCritical || req.Event.Severity == models.SeverityHigh {
		reasons = append(reasons, "高严重程度级别")
	}

	return reasons
}

func (a *AIAnalyzer) generateRecommendedActions(event *models.SecurityEvent) []RecommendedAction {
	actions := []RecommendedAction{
		{
			Action:         "investigate",
			Priority:       "high",
			Description:    "进行调查分析",
			ExpectedEffect: "确定事件性质和影响范围",
			RiskLevel:      "low",
		},
	}

	if event.Severity == models.SeverityCritical {
		actions = append(actions, RecommendedAction{
			Action:         "isolate",
			Priority:       "critical",
			Description:    "隔离受影响系统",
			ExpectedEffect: "阻止攻击扩散",
			RiskLevel:      "medium",
		})
	}

	return actions
}

func (a *AIAnalyzer) getAlternativeOptions(event *models.SecurityEvent) []string {
	return []string{
		"监控观察",
		"记录日志",
		"联系相关人员",
	}
}

func (a *AIAnalyzer) assessRisk(event *models.SecurityEvent) string {
	switch event.Severity {
	case models.SeverityCritical:
		return "高风险 - 立即采取行动"
	case models.SeverityHigh:
		return "中高风险 - 尽快处理"
	case models.SeverityMedium:
		return "中等风险 - 适当关注"
	default:
		return "低风险 - 常规处理"
	}
}

func (a *AIAnalyzer) getCaseReferences(req *SuggestionRequest) []string {
	return []string{}
}

func getReportTitle(reportType string) string {
	switch reportType {
	case "incident":
		return "安全事件分析报告"
	case "summary":
		return "安全态势总结报告"
	case "weekly":
		return "每周安全报告"
	case "monthly":
		return "每月安全报告"
	default:
		return "安全报告"
	}
}

func calculateStatistics(req *ReportRequest) Statistics {
	stats := Statistics{
		BySeverity: map[string]int{},
		ByType:     map[string]int{},
		BySource:   map[string]int{},
		ByStatus:   map[string]int{},
		MTTR:       0,
	}

	stats.BySeverity["critical"] = 0
	stats.BySeverity["high"] = 0
	stats.BySeverity["medium"] = 0
	stats.BySeverity["low"] = 0

	return stats
}

func generateReportSummary(stats Statistics) string {
	return fmt.Sprintf("报告期间共处理 %d 起安全事件", stats.TotalEvents)
}

func generateReportContent(req *ReportRequest, result *ReportResult) string {
	var sb strings.Builder
	sb.WriteString("# " + result.Title + "\n\n")
	sb.WriteString("## 概述\n")
	sb.WriteString(result.Summary + "\n\n")
	sb.WriteString("## 统计信息\n")
	sb.WriteString(fmt.Sprintf("- 总事件数: %d\n", result.EventCount))
	return sb.String()
}

func getDefaultPrompts() map[string]string {
	return map[string]string{
		"analysis_system":   "你是一个专业的安全分析师，帮助分析安全事件。",
		"judge_system":      "你是一个专业的威胁分析师，帮助判断攻击的真实性。",
		"suggestion_system": "你是一个专业的安全顾问，帮助推荐响应措施。",
	}
}
