package skills

import (
	"os"
	"path/filepath"
	"strings"
)

type Skill struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Version     string   `yaml:"version"`
	Keywords    []string `yaml:"keywords"`
	Tools       []string `yaml:"tools"`
}

type SkillsMatcher struct {
	skillIndex map[string]*Skill
	skillsDir  string
}

func NewSkillsMatcher(skillsDir string) *SkillsMatcher {
	return &SkillsMatcher{
		skillIndex: make(map[string]*Skill),
		skillsDir:  skillsDir,
	}
}

func (m *SkillsMatcher) LoadSkills() error {
	if m.skillsDir == "" {
		m.skillsDir = "skills"
	}

	entries, err := os.ReadDir(m.skillsDir)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		skillPath := filepath.Join(m.skillsDir, entry.Name(), "SKILL.md")
		skill, err := m.loadSkill(skillPath)
		if err != nil {
			continue
		}

		m.skillIndex[skill.Name] = skill
		for _, keyword := range skill.Keywords {
			m.skillIndex[strings.ToLower(keyword)] = skill
		}
	}

	return nil
}

func (m *SkillsMatcher) loadSkill(path string) (*Skill, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var skill Skill
	skill.Name = filepath.Base(filepath.Dir(path))
	skill.Description = "Security skill"

	content := string(data)
	skill.Keywords = m.extractKeywords(content)

	return &skill, nil
}

func (m *SkillsMatcher) extractKeywords(content string) []string {
	keywords := []string{}

	keywordMap := map[string][]string{
		"sql":     {"sql-injection-testing"},
		"sql注入":   {"sql-injection-testing"},
		"xss":     {"xss-testing"},
		"跨站脚本":    {"xss-testing"},
		"command": {"command-injection-testing"},
		"命令注入":    {"command-injection-testing"},
		"csrf":    {"csrf-testing"},
		"ssrf":    {"ssrf-testing"},
		"ldap":    {"ldap-injection-testing"},
		"xxe":     {"xxe-testing"},
		"api":     {"api-security-testing"},
		"文件上传":    {"file-upload-testing"},
		"文件包含":    {"file-upload-testing"},
		"业务逻辑":    {"business-logic-testing"},
		"移动应用":    {"mobile-app-security-testing"},
		"容器":      {"container-security-testing"},
		"云":       {"cloud-security-audit"},
		"渗透测试":    {"network-penetration-testing"},
		"暴力破解":    {"network-penetration-testing"},
		"应急响应":    {"incident-response"},
		"漏洞评估":    {"vulnerability-assessment"},
		"代码审计":    {"secure-code-review"},
		"安全自动化":   {"security-automation"},
		"安全意识":    {"security-awareness-training"},
		"idor":    {"idor-testing"},
		"jsonp":   {"csrf-testing"},
		"dom":     {"xss-testing"},
		"反序列化":    {"deserialization-testing"},
		"xpath":   {"xpath-injection-testing"},
	}

	for key, skillNames := range keywordMap {
		if strings.Contains(strings.ToLower(content), key) {
			keywords = append(keywords, skillNames...)
		}
	}

	return uniqueStrings(keywords)
}

func (m *SkillsMatcher) MatchSkills(eventType string, eventContent string) []*Skill {
	eventTypeLower := strings.ToLower(eventType)
	contentLower := strings.ToLower(eventContent)

	matched := make(map[string]*Skill)

	for keyword, skill := range m.skillIndex {
		if strings.Contains(eventTypeLower, keyword) || strings.Contains(contentLower, keyword) {
			matched[skill.Name] = skill
		}
	}

	result := make([]*Skill, 0, len(matched))
	for _, skill := range matched {
		result = append(result, skill)
	}

	if len(result) == 0 {
		result = append(result, m.skillIndex["incident-response"])
	}

	return result
}

func (m *SkillsMatcher) GetSkill(name string) *Skill {
	return m.skillIndex[name]
}

func (m *SkillsMatcher) ListSkills() []*Skill {
	result := make([]*Skill, 0, len(m.skillIndex))
	for _, skill := range m.skillIndex {
		result = append(result, skill)
	}
	return result
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

var defaultEventTypeMapping = map[string][]string{
	"sql_injection":       {"sql-injection-testing"},
	"sql注入":               {"sql-injection-testing"},
	"xss":                 {"xss-testing"},
	"跨站脚本":                {"xss-testing"},
	"command_injection":   {"command-injection-testing"},
	"命令注入":                {"command-injection-testing"},
	"brute_force":         {"network-penetration-testing"},
	"暴力破解":                {"network-penetration-testing"},
	"credential_stuffing": {"network-penetration-testing"},
	"钓鱼":                  {"phishing"},
	"phishing":            {"security-awareness-training"},
	"malware":             {"vulnerability-assessment"},
	"恶意软件":                {"vulnerability-assessment"},
	"ransomware":          {"incident-response"},
	"勒索软件":                {"incident-response"},
	"data_leak":           {"incident-response"},
	"数据泄露":                {"incident-response"},
	"ddos":                {"network-penetration-testing"},
	"拒绝服务":                {"network-penetration-testing"},
	"api":                 {"api-security-testing"},
	"api异常":               {"api-security-testing"},
	"文件上传":                {"file-upload-testing"},
	"文件包含":                {"file-upload-testing"},
	"ssrf":                {"ssrf-testing"},
	"服务端请求伪造":             {"ssrf-testing"},
	"csrf":                {"csrf-testing"},
	"跨站请求伪造":              {"csrf-testing"},
	"xxe":                 {"xxe-testing"},
	"xml外部实体":             {"xxe-testing"},
	"ldap":                {"ldap-injection-testing"},
	"ldap注入":              {"ldap-injection-testing"},
	"移动应用":                {"mobile-app-security-testing"},
	"android":             {"mobile-app-security-testing"},
	"ios":                 {"mobile-app-security-testing"},
	"容器":                  {"container-security-testing"},
	"docker":              {"container-security-testing"},
	"kubernetes":          {"container-security-testing"},
	"云":                   {"cloud-security-audit"},
	"aws":                 {"cloud-security-audit"},
	"azure":               {"cloud-security-audit"},
	"gcp":                 {"cloud-security-audit"},
	"代码审计":                {"secure-code-review"},
	"代码审查":                {"secure-code-review"},
	"业务逻辑":                {"business-logic-testing"},
	"越权":                  {"business-logic-testing"},
	"权限绕过":                {"business-logic-testing"},
	"unknown":             {"incident-response"},
	"未知":                  {"incident-response"},
}

func GetSkillsForEventType(eventType string) []string {
	eventTypeLower := strings.ToLower(eventType)

	if skills, ok := defaultEventTypeMapping[eventTypeLower]; ok {
		return skills
	}

	for key, skills := range defaultEventTypeMapping {
		if strings.Contains(eventTypeLower, key) {
			return skills
		}
	}

	return []string{"incident-response"}
}
