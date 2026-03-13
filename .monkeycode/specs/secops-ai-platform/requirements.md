# Requirements Document

## Introduction

本文档定义 AI 安全运营协作平台 (SecOps AI) 的完整需求规格。该平台基于现有 CyberStrikeAI 项目进行二次开发，将攻击性安全测试能力扩展为覆盖安全事件调查、研判、处置的全面安全运营能力。平台支持多源数据采集、智能事件分析、威胁研判、团队协作与态势感知功能。

## Glossary

- **SecOps AI**: AI 安全运营协作平台
- **SOC**: Security Operations Center，安全运营中心
- **SIEM**: Security Information and Event Management，安全信息与事件管理
- **EDR**: Endpoint Detection and Response，终端检测与响应
- **STIX/TAXII**: 威胁情报标准化格式与传输协议
- **CMDB**: Configuration Management Database，配置管理数据库
- **ITSM**: IT Service Management，IT 服务管理
- **MTTP**: Mean Time To Respond，平均响应时间
- **TTP**: Tactics, Techniques, Procedures，战术、技术和程序
- **IoC**: Indicators of Compromise，妥协指标
- **SOAR**: Security Orchestration, Automation and Response，安全编排自动化响应

## Requirements

### 1. 数据采集模块

#### 1.1 日志文件导入

**User Story:** AS 安全分析师，我想要导入多种格式的日志文件，以便将分散的安全数据集中到平台进行分析。

**Acceptance Criteria:**

1. WHEN 用户上传 Syslog 格式日志文件，系统 SHALL 自动解析并存储事件
2. WHEN 用户上传 JSON 格式日志文件，系统 SHALL 提取字段并标准化存储
3. WHEN 用户上传 CSV 格式日志文件，系统 SHALL 支持列映射配置
4. IF 导入文件格式不识别，系统 SHALL 返回错误提示并显示支持格式列表
5. IF 导入文件超过 100MB，系统 SHALL 显示分片导入进度

#### 1.2 SIEM 告警解析

**User Story:** AS 安全运营人员，我想要解析主流 SIEM 平台的告警格式，以便统一管理不同来源的安全告警。

**Acceptance Criteria:**

1. WHEN 用户配置 Splunk 告警导入，系统 SHALL 解析 Splunk 告警 JSON 格式
2. WHEN 用户配置 QRadar 告警导入，系统 SHALL 解析 QRadar AREL 格式
3. WHEN 用户配置 Elastic 告警导入，系统 SHALL 解析 Elastic Common Schema (ECS) 格式
4. WHEN 用户配置自定义告警模板，系统 SHALL 支持字段映射配置

#### 1.3 威胁情报采集

**User Story:** AS 威胁分析师，我想要接入外部威胁情报馈送，以便实时获取最新威胁信息。

**Acceptance Criteria:**

1. WHEN 用户配置 STIX 2.1 情报源，系统 SHALL 自动拉取并解析 STIX Bundle
2. WHEN 用户配置 TAXII 2.0/2.1 服务器，系统 SHALL 定时轮询获取新情报
3. WHEN 获取到新的 IoC，系统 SHALL 自动提取并存储 IoC 记录
4. IF 威胁情报获取失败，系统 SHALL 记录错误日志并发送告警通知

#### 1.4 API 定时采集

**User Story:** AS 安全运维人员，我想要配置定时从 EDR/SIEM API 拉取数据，以便实现数据自动化同步。

**Acceptance Criteria:**

1. WHEN 用户配置 API 采集任务（包含端点、认证信息、轮询间隔），系统 SHALL 按配置定时执行采集
2. WHEN 用户配置 EDR API 采集，系统 SHALL 支持常见 EDR 产品 API (如 CrowdStrike, Microsoft Defender for Endpoint)
3. WHEN 用户配置 SIEM API 采集，系统 SHALL 支持自定义查询条件的告警拉取
4. IF API 认证失败，系统 SHALL 自动重试 3 次后标记任务失败

#### 1.5 Webhook 接收

**User Story:** AS 安全集成工程师，我想要接收第三方安全工具的实时告警，以便及时响应安全事件。

**Acceptance Criteria:**

1. WHEN 用户配置 Webhook 端点，系统 SHALL 生成唯一的 Webhook URL
2. WHEN 系统收到 Webhook 请求 SHALL 验证签名/Token 有效性
3. WHEN 用户配置多个 Webhook 来源，系统 SHALL 支持分别配置告警解析规则
4. IF Webhook 请求格式无法解析，系统 SHALL 记录原始请求并标记为待处理

### 2. 事件管理模块

#### 2.1 事件接入与标准化

**User Story:** AS 安全分析师，我想要将所有采集的安全数据标准化为统一的事件格式，以便进行统一分析。

**Acceptance Criteria:**

1. WHEN 系统接入新的安全数据 SHALL 标准化为统一事件模型（包含时间戳、来源、类型、严重程度、原始数据）
2. WHEN 事件包含 IP 地址 SHALL 自动进行地理Location解析
3. WHEN 事件包含域名/Hash SHALL 自动进行威胁情报关联
4. IF 事件数据缺少必填字段 SHALL 使用默认值填充并标记数据质量

#### 2.2 事件分类

**User Story:** AS 安全分析师，我想要对安全事件进行分类，以便区分误报和真实攻击。

**Acceptance Criteria:**

1. WHEN 用户查看事件详情，系统 SHALL 提供分类选项：误报、确认攻击、待确认
2. WHEN 用户将事件标记为误报 SHALL 要求选择误报原因（规则误报、测试告警、已知可信）
3. WHEN 用户将事件标记为确认攻击 SHALL 自动创建安全事件工单
4. IF 事件 24 小时内未分类，系统 SHALL 在仪表盘显示未分类事件提醒

#### 2.3 事件状态流转

**User Story:** AS 安全运营人员，我想要管理安全事件的生命周期，以便追踪事件处理进度。

**Acceptance Criteria:**

1. WHEN 事件创建 SHALL 自动设置状态为"待处理"
2. WHEN 用户开始处理事件 SHALL 可以将状态变更为"处理中"
3. WHEN 用户完成处置 SHALL 可以将状态变更为"已处置"
4. WHEN 事件需要升级 SHALL 可以将状态变更为"待审批"并指派审批人
5. IF 事件超过 SLA 未处理，系统 SHALL 显示超时告警

#### 2.4 关联分析

**User Story:** AS 安全分析师，我想要将新事件与历史事件、资产、漏洞进行关联，以便发现攻击链。

**Acceptance Criteria:**

1. WHEN 新事件接入 SHALL 自动与过去 7 天内相似事件进行关联
2. WHEN 事件包含资产标识 SHALL 自动关联 CMDB 资产信息
3. WHEN 事件包含漏洞标识 SHALL 自动关联漏洞库信息
4. WHEN 多个事件被判定为同一攻击链 SHALL 自动生成攻击链视图

#### 2.5 响应处置

**User Story:** AS 安全响应人员，我想要执行自动化响应操作，以便快速遏制威胁。

**Acceptance Criteria:**

1. WHEN 用户触发响应动作 SHALL 支持以下操作：隔离主机、封禁 IP、强制下线用户、暂停服务
2. WHEN 用户配置自动化响应规则 SHALL 支持基于事件类型、严重程度的条件触发
3. IF 自动化响应需要审批 SHALL 生成待审批工单等待确认
4. IF 响应动作执行失败 SHALL 返回失败原因并记录执行日志

#### 2.6 事件归档与复盘

**User Story:** AS 安全主管，我想要归档已处置事件并生成复盘报告，以便总结经验教训。

**Acceptance Criteria:**

1. WHEN 事件状态为已处置超过 30 天，系统 SHALL 支持手动归档
2. WHEN 用户生成复盘报告 SHALL 自动包含事件时间线、影响范围、处置过程、根因分析
3. WHEN 归档事件 SHALL 同时归档关联的聊天记录、工具执行结果、附件

### 3. AI 分析模块

#### 3.1 事件智能分析

**User Story:** AS 安全分析师，我想要 AI 自动分析安全事件，以便快速理解事件本质。

**Acceptance Criteria:**

1. WHEN 事件接入 SHALL 自动调用 AI 进行分析
2. WHEN AI 分析 SHALL 输出：事件摘要、攻击类型判定、关键 IoC 提取、建议调查方向
3. IF AI 分析耗时超过 30 秒 SHALL 显示分析进度
4. IF AI 分析失败 SHALL 记录错误并允许用户手动触发重分析

#### 3.2 威胁研判

**User Story:** AS 安全分析师，我想要 AI 基于上下文进行威胁研判，以便判断攻击的真实性和严重程度。

**Acceptance Criteria:**

1. WHEN 用户请求威胁研判 SHALL 考虑以下上下文：历史事件模式、资产重要性、威胁情报匹配度
2. WHEN 研判完成 SHALL 输出：攻击真实性评估 (0-100%)、影响范围评估、建议响应级别
3. IF 研判置信度低于 60% SHALL 提示需要人工进一步分析

#### 3.3 智能建议

**User Story:** AS 安全分析师，我想要 AI 推荐响应处置方案，以便快速采取行动。

**Acceptance Criteria:**

1. WHEN 用户请求智能建议 SHALL 基于事件特征、资产信息、历史处置记录生成建议
2. WHEN 生成建议 SHALL 包含：推荐操作、预期效果、风险提示、相关案例参考
3. IF 存在多个可选方案 SHALL 按优先级排序显示

#### 3.4 自动化处置

**User Story:** AS 安全运营人员，我想要 AI 驱动的自动化响应，以便减少人工干预。

**Acceptance Criteria:**

1. WHEN 配置自动化处置规则 SHALL 支持设置触发条件（事件类型、严重程度、资产范围）
2. WHEN 规则触发 SHALL 自动生成处置工单并执行预设响应动作
3. IF 自动化处置需要人工审批 SHALL 生成审批工单等待确认
4. IF 自动化处置执行完成 SHALL 记录执行结果和效果评估

#### 3.5 报告生成

**User Story:** AS 安全主管，我想要自动生成事件报告，以便减少报告编写工作量。

**Acceptance Criteria:**

1. WHEN 用户请求生成报告 SHALL 支持以下类型：事件分析报告、处置总结报告、周报/月报
2. WHEN 生成报告 SHALL 自动包含：事件统计、处置情况、趋势分析、建议改进
3. WHEN 报告生成完成 SHALL 支持导出为 PDF/Markdown 格式
4. IF 报告数据量大 SHALL 显示生成进度并支持后台生成

#### 3.6 知识问答

**User Story:** AS 安全分析师，我想要通过自然语言查询安全知识库，以便辅助决策。

**Acceptance Criteria:**

1. WHEN 用户提问 SHALL 从知识库中检索相关内容并生成答案
2. WHEN 检索 SHALL 支持语义匹配和关键词匹配混合搜索
3. IF 知识库无相关内容 SHALL 提示可参考的外部资源

### 4. 态势感知模块

#### 4.1 安全态势仪表盘

**User Story:** AS 安全主管，我想要查看全局安全态势，以便快速了解安全状况。

**Acceptance Criteria:**

1. WHEN 用户访问仪表盘 SHALL 显示以下核心指标：待处理事件数、7天事件趋势、Top 5 攻击类型、资产受攻击分布
2. WHEN 仪表盘 SHALL 支持自定义布局和组件配置
3. IF 存在严重安全事件 SHALL 在仪表盘顶部显示紧急告警横幅

#### 4.2 攻击趋势分析

**User Story:** AS 安全分析师，我想要分析攻击趋势，以便发现潜在威胁。

**Acceptance Criteria:**

1. WHEN 用户查看趋势 SHALL 支持按时间粒度筛选（小时/天/周/月）
2. WHEN 展示趋势 SHALL 支持按攻击类型、来源地区、目标资产分组
3. IF 趋势出现异常波动 SHALL 标记为异常并建议关注

#### 4.3 资产态势

**User Story:** AS 安全运维人员，我想要了解资产受攻击情况，以便优先保护关键资产。

**Asset Types:**

- 服务器
- 工作站
- 网络设备
- 云资源

**Acceptance Criteria:**

1. WHEN 用户查看资产态势 SHALL 显示各资产类型的受攻击统计
2. WHEN 资产关联 SHALL 支持从 CMDB 同步资产信息
3. IF 资产受攻击频率异常 SHALL 生成资产风险告警

#### 4.4 响应效能统计

**User Story:** AS 安全主管，我想要了解团队响应效率，以便优化运营流程。

**Acceptance Criteria:**

1. WHEN 用户查看效能 SHALL 显示以下指标：MTTP 平均响应时间、事件平均处置时长、SLA 达标率
2. WHEN 统计 SHALL 支持按时间范围、人员、事件类型筛选
3. IF 响应时间超过 SLA SHALL 显示超时告警统计

#### 4.5 威胁情报展示

**User Story:** AS 威胁分析师，我想要查看威胁情报关联信息，以便评估外部威胁。

**Acceptance Criteria:**

1. WHEN 用户查看情报 SHALL 显示当前热点威胁情报
2. WHEN 事件关联 SHALL 显示匹配的情报来源和置信度
3. IF 新增高危情报 SHALL 生成告警提示

### 5. 团队协作模块

#### 5.1 工单流转

**User Story:** AS 安全运营人员，我想要通过工单管理事件处置流程，以便明确责任和进度。

**Acceptance Criteria:**

1. WHEN 事件确认或自动化触发 SHALL 自动创建处置工单
2. WHEN 工单创建 SHALL 支持设置：优先级、负责人、期望完成时间、SLA
3. WHEN 用户转派工单 SHALL 支持添加转派原因
4. WHEN 工单超时 SHALL 自动升级并通知上级

#### 5.2 多人协同调查

**User Story:** AS 安全分析师，我想要与其他分析师协同调查复杂事件，以便共享信息。

**Acceptance Criteria:**

1. WHEN 用户加入协同 SHALL 支持多人同时查看同一事件
2. WHEN 用户可以添加调查备注 SHALL 支持 @提及团队成员
3. WHEN 协同过程中 SHALL 支持实时同步分析进展

#### 5.3 审核审批

**User Story:** AS 安全主管，我想要审批重要操作，以便控制安全风险。

**Acceptance Criteria:**

1. WHEN 敏感操作需要审批 SHALL 生成审批工单
2. WHEN 审批人收到工单 SHALL 支持批准或驳回并填写原因
3. IF 审批超时 SHALL 自动升级至上级审批人

#### 5.4 通知集成

**User Story:** AS 安全运营人员，我想要接收多种渠道的通知，以便及时响应安全事件。

**Acceptance Criteria:**

1. WHEN 事件满足通知条件 SHALL 支持以下渠道：钉钉、飞书、邮件
2. WHEN 用户配置通知规则 SHALL 支持按事件类型、严重程度、人员设置不同规则
3. IF 通知发送失败 SHALL 记录失败原因并支持重试

### 6. 系统集成模块

#### 6.1 EDR 集成

**Acceptance Criteria:**

1. WHEN 配置 EDR 集成 SHALL 支持主流 EDR 产品 API 对接
2. WHEN 采集 SHALL 获取终端告警、进程信息、网络连接信息
3. WHEN 响应 SHALL 支持远程隔离、脚本执行等操作

#### 6.2 SIEM 集成

**Acceptance Criteria:**

1. WHEN 配置 SIEM 集成 SHALL 支持从 SIEM API 拉取告警
2. WHEN 展示 SHALL 支持在事件详情中关联 SIEM 原始日志

#### 6.3 防火墙/IDS/IPS 集成

**Acceptance Criteria:**

1. WHEN 配置网络设备集成 SHALL 支持获取告警日志
2. WHEN 响应 SHALL 支持 IP 封禁策略下发

#### 6.4 CMDB 集成

**Acceptance Criteria:**

1. WHEN 配置 CMDB 集成 SHALL 支持资产信息同步
2. WHEN 同步 SHALL 支持定时同步和手动触发同步

#### 6.5 ITSM 集成

**Acceptance Criteria:**

1. WHEN 配置 ITSM 集成 SHALL 支持将安全工单同步至现有工单系统
2. WHEN 同步 SHALL 支持状态双向同步

### 7. 数据存储模块

#### 7.1 关系型数据库存储

**Acceptance Criteria:**

1. WHEN 存储核心业务数据 SHALL 使用 MySQL/PostgreSQL
2. WHEN 数据 SHALL 包含：事件、工单、用户、配置、资产、处置记录
3. IF 使用 SQLite SHALL 支持中小规模部署

#### 7.2 Elasticsearch 存储

**Acceptance Criteria:**

1. WHEN 存储日志全文 SHALL 使用 Elasticsearch
2. WHEN 日志采集 SHALL 支持自动创建索引模板
3. WHEN 查询 SHALL 支持全文搜索和聚合分析
