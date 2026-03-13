package knowledge

import (
	"fmt"
	"strings"
)

type QARequest struct {
	Question   string
	Context    []string
	MaxResults int
}

type QAResult struct {
	Answer     string      `json:"answer"`
	References []Reference `json:"references"`
	Confidence float64     `json:"confidence"`
}

type Reference struct {
	Title     string  `json:"title"`
	Content   string  `json:"content"`
	Relevance float64 `json:"relevance"`
	Source    string  `json:"source"`
}

type KnowledgeItem struct {
	ID       string                 `json:"id"`
	Title    string                 `json:"title"`
	Content  string                 `json:"content"`
	Category string                 `json:"category"`
	Tags     []string               `json:"tags"`
	Metadata map[string]interface{} `json:"metadata"`
}

type KnowledgeBase struct {
	items map[string]*KnowledgeItem
	index *SearchIndex
}

type SearchIndex struct {
	titleIndex    map[string][]string
	contentIndex  map[string][]string
	tagIndex      map[string][]string
	categoryIndex map[string][]string
}

func NewKnowledgeBase() *KnowledgeBase {
	return &KnowledgeBase{
		items: make(map[string]*KnowledgeItem),
		index: &SearchIndex{
			titleIndex:    make(map[string][]string),
			contentIndex:  make(map[string][]string),
			tagIndex:      make(map[string][]string),
			categoryIndex: make(map[string][]string),
		},
	}
}

func (kb *KnowledgeBase) AddItem(item *KnowledgeItem) error {
	if item.ID == "" {
		return fmt.Errorf("item ID is required")
	}

	kb.items[item.ID] = item
	kb.indexItem(item)

	return nil
}

func (kb *KnowledgeBase) GetItem(id string) (*KnowledgeItem, bool) {
	item, ok := kb.items[id]
	return item, ok
}

func (kb *KnowledgeBase) ListItems() []*KnowledgeItem {
	items := make([]*KnowledgeItem, 0, len(kb.items))
	for _, item := range kb.items {
		items = append(items, item)
	}
	return items
}

func (kb *KnowledgeBase) Search(query string, limit int) []*KnowledgeItem {
	if limit <= 0 {
		limit = 10
	}

	query = strings.ToLower(query)
	keywords := extractKeywords(query)

	var candidates []*KnowledgeItem
	seen := make(map[string]bool)

	for _, keyword := range keywords {
		if ids, ok := kb.index.titleIndex[keyword]; ok {
			for _, id := range ids {
				if !seen[id] {
					seen[id] = true
					if item, ok := kb.items[id]; ok {
						candidates = append(candidates, item)
					}
				}
			}
		}

		if ids, ok := kb.index.contentIndex[keyword]; ok {
			for _, id := range ids {
				if !seen[id] {
					seen[id] = true
					if item, ok := kb.items[id]; ok {
						candidates = append(candidates, item)
					}
				}
			}
		}

		if ids, ok := kb.index.tagIndex[keyword]; ok {
			for _, id := range ids {
				if !seen[id] {
					seen[id] = true
					if item, ok := kb.items[id]; ok {
						candidates = append(candidates, item)
					}
				}
			}
		}
	}

	if len(candidates) == 0 {
		for _, item := range kb.items {
			candidates = append(candidates, item)
		}
	}

	scored := make([]*KnowledgeItem, len(candidates))
	copy(scored, candidates)

	for i := 0; i < len(scored)-1; i++ {
		for j := i + 1; j < len(scored); j++ {
			if scoreItem(scored[i], query) < scoreItem(scored[j], query) {
				scored[i], scored[j] = scored[j], scored[i]
			}
		}
	}

	if len(scored) > limit {
		scored = scored[:limit]
	}

	return scored
}

func (kb *KnowledgeBase) SearchByCategory(category string) []*KnowledgeItem {
	results := make([]*KnowledgeItem, 0)

	category = strings.ToLower(category)
	for _, item := range kb.items {
		if strings.ToLower(item.Category) == category {
			results = append(results, item)
		}
	}

	return results
}

func (kb *KnowledgeBase) SearchByTag(tag string) []*KnowledgeItem {
	results := make([]*KnowledgeItem, 0)

	tag = strings.ToLower(tag)
	for _, item := range kb.items {
		for _, itemTag := range item.Tags {
			if strings.ToLower(itemTag) == tag {
				results = append(results, item)
				break
			}
		}
	}

	return results
}

func (kb *KnowledgeBase) indexItem(item *KnowledgeItem) {
	titleWords := extractKeywords(strings.ToLower(item.Title))
	for _, word := range titleWords {
		kb.index.titleIndex[word] = append(kb.index.titleIndex[word], item.ID)
	}

	contentWords := extractKeywords(strings.ToLower(item.Content))
	for _, word := range contentWords {
		kb.index.contentIndex[word] = append(kb.index.contentIndex[word], item.ID)
	}

	for _, tag := range item.Tags {
		tag = strings.ToLower(tag)
		kb.index.tagIndex[tag] = append(kb.index.tagIndex[tag], item.ID)
	}

	category := strings.ToLower(item.Category)
	kb.index.categoryIndex[category] = append(kb.index.categoryIndex[category], item.ID)
}

func extractKeywords(text string) []string {
	text = strings.ToLower(text)
	text = strings.ReplaceAll(text, ",", " ")
	text = strings.ReplaceAll(text, ".", " ")
	text = strings.ReplaceAll(text, "!", " ")
	text = strings.ReplaceAll(text, "?", " ")
	text = strings.ReplaceAll(text, "(", " ")
	text = strings.ReplaceAll(text, ")", " ")
	text = strings.ReplaceAll(text, "[", " ")
	text = strings.ReplaceAll(text, "]", " ")
	text = strings.ReplaceAll(text, "{", " ")
	text = strings.ReplaceAll(text, "}", " ")

	words := strings.Fields(text)

	stopWords := map[string]bool{
		"the": true, "a": true, "an": true, "is": true, "are": true,
		"was": true, "were": true, "be": true, "been": true, "being": true,
		"have": true, "has": true, "had": true, "do": true, "does": true,
		"did": true, "will": true, "would": true, "could": true, "should": true,
		"may": true, "might": true, "must": true, "shall": true, "can": true,
		"need": true, "dare": true, "ought": true, "used": true, "to": true,
		"of": true, "in": true, "for": true, "on": true, "with": true,
		"at": true, "by": true, "from": true, "as": true, "into": true,
		"through": true, "during": true, "before": true, "after": true,
		"above": true, "below": true, "between": true, "under": true,
		"again": true, "further": true, "then": true, "once": true,
		"here": true, "there": true, "when": true, "where": true, "why": true,
		"how": true, "all": true, "each": true, "few": true, "more": true,
		"most": true, "other": true, "some": true, "such": true, "no": true,
		"not": true, "only": true, "own": true, "same": true,
		"so": true, "than": true, "too": true, "very": true, "just": true,
		"and": true, "but": true, "or": true, "yet": true,
		"if": true, "else": true, "while": true, "although": true,
	}

	var keywords []string
	for _, word := range words {
		if len(word) > 2 && !stopWords[word] {
			keywords = append(keywords, word)
		}
	}

	return keywords
}

func scoreItem(item *KnowledgeItem, query string) float64 {
	score := 0.0

	queryLower := strings.ToLower(query)
	titleLower := strings.ToLower(item.Title)
	contentLower := strings.ToLower(item.Content)

	if strings.Contains(titleLower, queryLower) {
		score += 10.0
	}

	titleWords := extractKeywords(titleLower)
	queryWords := extractKeywords(queryLower)
	for _, qw := range queryWords {
		for _, tw := range titleWords {
			if tw == qw {
				score += 5.0
			}
		}
	}

	for _, qw := range queryWords {
		if strings.Contains(contentLower, qw) {
			score += 1.0
		}
	}

	for _, tag := range item.Tags {
		if strings.Contains(strings.ToLower(tag), queryLower) {
			score += 3.0
		}
	}

	return score
}

type QAService struct {
	knowledgeBase *KnowledgeBase
}

func NewQAService() *QAService {
	kb := NewKnowledgeBase()
	kb.AddItem(&KnowledgeItem{
		ID:       "1",
		Title:    "SQL Injection 防御指南",
		Content:  "SQL注入攻击防御措施：1. 使用参数化查询 2. 输入验证 3. 最小权限原则 4. 使用存储过程 5. 转义特殊字符",
		Category: "Web安全",
		Tags:     []string{"sql", "注入", "web", "安全"},
	})

	kb.AddItem(&KnowledgeItem{
		ID:       "2",
		Title:    "XSS 跨站脚本攻击防御",
		Content:  "XSS防御方法：1. 输入验证 2. 输出编码 3. 使用CSP 4. HTTPOnly Cookie 5. 验证码",
		Category: "Web安全",
		Tags:     []string{"xss", "跨站脚本", "web", "安全"},
	})

	kb.AddItem(&KnowledgeItem{
		ID:       "3",
		Title:    "暴力破解攻击防御",
		Content:  "暴力破解防御：1. 强密码策略 2. 多因素认证 3. 登录失败锁定 4. IP限制 5. 验证码",
		Category: "身份认证",
		Tags:     []string{"暴力破解", "密码", "认证", "安全"},
	})

	kb.AddItem(&KnowledgeItem{
		ID:       "4",
		Title:    "应急响应流程",
		Content:  "应急响应流程：1. 准备阶段 2. 检测阶段 3. 遏制阶段 4. 根除阶段 5. 恢复阶段 6. 总结阶段",
		Category: "应急响应",
		Tags:     []string{"应急", "响应", "事件", "处理"},
	})

	kb.AddItem(&KnowledgeItem{
		ID:       "5",
		Title:    "恶意软件分析指南",
		Content:  "恶意软件分析：1. 静态分析 2. 动态分析 3. 代码分析 4. 网络行为分析 5. 内存分析",
		Category: "恶意软件",
		Tags:     []string{"恶意软件", "病毒", "分析", "逆向"},
	})

	return &QAService{
		knowledgeBase: kb,
	}
}

func (s *QAService) Answer(req *QARequest) (*QAResult, error) {
	if req.Question == "" {
		return nil, fmt.Errorf("question is required")
	}

	if req.MaxResults <= 0 {
		req.MaxResults = 5
	}

	items := s.knowledgeBase.Search(req.Question, req.MaxResults)

	if len(items) == 0 {
		return &QAResult{
			Answer:     "抱歉，我没有找到相关的知识内容。",
			References: []Reference{},
			Confidence: 0.0,
		}, nil
	}

	references := make([]Reference, 0, len(items))
	for _, item := range items {
		ref := Reference{
			Title:     item.Title,
			Content:   item.Content,
			Relevance: scoreItem(item, req.Question),
			Source:    item.Category,
		}
		references = append(references, ref)
	}

	answer := s.generateAnswer(req.Question, items)

	confidence := 0.8
	if len(items) > 0 {
		confidence = references[0].Relevance / 10.0
		if confidence > 1.0 {
			confidence = 1.0
		}
	}

	return &QAResult{
		Answer:     answer,
		References: references,
		Confidence: confidence,
	}, nil
}

func (s *QAService) generateAnswer(question string, items []*KnowledgeItem) string {
	if len(items) == 0 {
		return "抱歉，我没有找到相关的知识内容。"
	}

	var sb strings.Builder
	sb.WriteString("根据知识库，我找到以下相关内容：\n\n")

	for i, item := range items {
		if i > 0 {
			sb.WriteString("---\n\n")
		}
		sb.WriteString(fmt.Sprintf("**%s**\n\n", item.Title))
		sb.WriteString(item.Content)
		sb.WriteString("\n")
	}

	if len(items) > 1 {
		sb.WriteString("\n建议查看上述相关文档获取更多信息。")
	}

	return sb.String()
}

func (s *QAService) AddKnowledge(item *KnowledgeItem) error {
	return s.knowledgeBase.AddItem(item)
}

func (s *QAService) GetKnowledge(id string) (*KnowledgeItem, bool) {
	return s.knowledgeBase.GetItem(id)
}

func (s *QAService) ListKnowledge() []*KnowledgeItem {
	return s.knowledgeBase.ListItems()
}
