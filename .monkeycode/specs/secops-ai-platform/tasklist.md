# Phase 1: 数据采集模块实施计划

## 阶段目标

实现安全事件数据采集核心功能，支持日志文件导入、Webhook 接收、API 定时采集、威胁情报接入。

---

- [ ] 1. 创建数据采集模块目录结构
  - [ ] 1.1 创建 internal/secops 目录结构
    - internal/secops/event - 事件接入服务
    - internal/secops/collector - 采集器管理
    - internal/secops/webhook - Webhook 服务
    - internal/secops/parser - 解析器工厂
    - internal/secops/normalizer - 数据标准化
    - internal/secops/enricher - 数据 Enricher
    - internal/database/secops - 数据库模型
    - internal/handler/secops - API 处理器
  - [ ] 1.2 定义模块初始化文件
  - [ ] 1.3 配置 config.yaml 扩展字段

- [ ] 2. 实现核心数据模型
  - [ ] 2.1 创建 SecurityEvent 事件模型
    - 参考设计文档 3.1 事件模型
    - 实现 JSON 序列化/反序列化
    - 定义 Severity 枚举 (critical/high/medium/low/info)
  - [ ] 2.2 创建 CollectorConfig 采集器配置模型
    - 参考设计文档 4.3 采集器配置模型
    - 支持类型: file/api/webhook/stix/siem
  - [ ] 2.3 创建 IoC 模型
    - 支持类型: ip/domain/hash/email/url
  - [ ] 2.4 创建 WebhookEndpoint 模型
    - 支持签名验证配置

- [ ] 3. 实现解析器工厂 (Parser Factory)
  - [ ] 3.1 创建 Parser 接口
    - ParseSyslog() 解析 Syslog 格式
    - ParseJSON() 解析 JSON 格式
    - ParseCSV() 解析 CSV 格式
  - [ ] 3.2 实现 Syslog 解析器
    - 支持 RFC 3164/5424 格式
  - [ ] 3.3 实现 JSON 解析器
    - 支持通用 JSON 格式
  - [ ] 3.4 实现 CSV 解析器
    - 支持列映射配置
  - [ ] 3.5 实现 SIEM 告警解析器
    - 支持 Splunk 格式
    - 支持 Elastic ECS 格式

- [ ] 4. 实现数据标准化器 (Normalizer)
  - [ ] 4.1 创建 Normalizer 接口
  - [ ] 4.2 实现字段映射标准化
  - [ ] 4.3 实现时间戳标准化
  - [ ] 4.4 实现严重程度标准化

- [ ] 5. 实现 Enricher 组件
  - [ ] 5.1 创建 Enricher 接口
  - [ ] 5.2 实现 IP 地理位置 Enricher
  - [ ] 5.3 实现威胁情报 Enricher (IoC 匹配)

- [ ] 6. 实现事件接入服务 (Event Ingestion Service)
  - [ ] 6.1 创建 EventService 结构
  - [ ] 6.2 实现 POST /api/v1/events/ingest 接口
    - 接收并标准化事件
    - 存储到数据库
  - [ ] 6.3 实现 POST /api/v1/events/batch-import 接口
    - 支持批量导入 10000+ 事件
    - 参考设计文档: 性能要求 < 500ms 响应
  - [ ] 6.4 实现 GET /api/v1/events/sources 接口

- [ ] 7. 实现采集器管理器 (Collector Manager)
  - [ ] 7.1 创建 CollectorService 结构
  - [ ] 7.2 实现 POST /api/v1/collectors 接口
    - 创建采集器配置
    - 验证配置有效性
  - [ ] 7.3 实现 PUT /api/v1/collectors/{id} 接口
  - [ ] 7.4 实现 DELETE /api/v1/collectors/{id} 接口
  - [ ] 7.5 实现 POST /api/v1/collectors/{id}/test 接口
    - 测试采集器连接
  - [ ] 7.6 实现 POST /api/v1/collectors/{id}/run 接口
    - 手动触发采集
  - [ ] 7.7 实现采集调度器
    - 支持 Cron 表达式调度
    - 支持定时轮询

- [ ] 8. 实现 Webhook 服务
  - [ ] 8.1 创建 WebhookService 结构
  - [ ] 8.2 实现 POST /api/v1/webhook/{token} 接口
    - 验证签名/Token
    - 解析告警内容
  - [ ] 8.3 实现 GET /api/v1/webhook/endpoints 接口
  - [ ] 8.4 实现 Webhook 端点管理
    - 生成唯一 Webhook URL
    - 配置签名密钥

- [ ] 9. 实现文件导入功能
  - [ ] 9.1 创建文件上传接口
    - 支持 POST 上传文件
    - 支持大文件分片上传
  - [ ] 9.2 实现文件解析逻辑
    - 自动检测文件格式
    - 参考设计文档: 支持 100MB+ 文件

- [ ] 10. 实现威胁情报采集 (STIX/TAXII)
  - [ ] 10.1 创建 ThreatIntelCollector 结构
  - [ ] 10.2 实现 STIX 2.1 解析器
  - [ ] 10.3 实现 TAXII 2.0/2.1 客户端
  - [ ] 10.4 实现定时轮询逻辑
  - [ ] 10.5 实现 IoC 提取和存储

- [ ] 11. 实现 API 定时采集
  - [ ] 11.1 创建 APICollector 结构
  - [ ] 11.2 实现通用 API 客户端
    - 支持自定义认证 (API Key/Bearer/OAuth)
    - 支持自定义查询条件
  - [ ] 11.3 实现定时调度逻辑

- [ ] 12. 数据库表结构设计
  - [ ] 12.1 创建 security_events 表
    - 参考设计文档 3.1 事件模型字段
  - [ ] 12.2 创建 collector_configs 表
  - [ ] 12.3 创建 webhook_endpoints 表
  - [ ] 12.4 创建 iocs 表
  - [ ] 12.5 创建 collector_jobs 表 (采集任务记录)

- [ ] 13. 错误处理和日志
  - [ ] 13.1 实现采集器错误处理
    - 参考设计文档: 自动重试 3 次
  - [ ] 13.2 实现解析失败处理
    - 记录原始数据到错误队列
  - [ ] 13.3 添加详细日志记录

- [ ] 14. 集成测试
  - [ ] 14.1 编写解析器单元测试
    - Syslog 解析测试
    - JSON 解析测试
    - CSV 解析测试
  - [ ] 14.2 编写 API 接口测试
    - 事件接入测试
    - 采集器管理测试
    - Webhook 测试

- [ ] 15. 检查点
  - 确保所有核心 API 接口可用
  - 确保解析器正确处理各格式数据
  - 确保采集器可以正常调度运行
