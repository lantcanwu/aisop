// SecOps AI 前端 JavaScript

const API_BASE = '/api/secops';

// Tab 切换
document.querySelectorAll('.secops-tab').forEach(tab => {
    tab.addEventListener('click', function() {
        document.querySelectorAll('.secops-tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.secops-tab-content').forEach(c => c.style.display = 'none');
        this.classList.add('active');
        document.getElementById('tab-' + this.dataset.tab).style.display = 'block';
        
        // 加载对应数据
        loadTabData(this.dataset.tab);
    });
});

function loadTabData(tab) {
    switch(tab) {
        case 'events': loadEvents(); break;
        case 'collectors': loadCollectors(); break;
        case 'tickets': loadTickets(); break;
        case 'dashboard': loadDashboard(); break;
    }
}

// 加载安全事件
async function loadEvents() {
    try {
        const response = await fetch(API_BASE + '/events', { credentials: 'include' });
        const data = await response.json();
        
        if (data.success && data.events && data.events.length > 0) {
            renderEvents(data.events);
            document.getElementById('stat-total').textContent = data.total || data.events.length;
        } else {
            document.getElementById('events-table').innerHTML = '<tr><td colspan="6" style="text-align: center; color: #999;">暂无数据</td></tr>';
        }
    } catch (e) {
        console.error('加载事件失败:', e);
    }
}

function renderEvents(events) {
    const tbody = document.getElementById('events-table');
    tbody.innerHTML = events.map(e => `
        <tr>
            <td>${formatTime(e.created_at)}</td>
            <td>${e.title || '-'}</td>
            <td>${e.source || '-'}</td>
            <td><span class="secops-badge secops-badge-${e.severity || 'low'}">${getSeverityLabel(e.severity)}</span></td>
            <td>${getStatusLabel(e.status)}</td>
            <td class="secops-actions">
                <button class="secops-btn" onclick="viewEvent('${e.id}')">查看</button>
                <button class="secops-btn" onclick="analyzeEvent('${e.id}')">AI分析</button>
            </td>
        </tr>
    `).join('');
    
    // 更新统计
    document.getElementById('stat-total').textContent = events.length;
    document.getElementById('stat-pending').textContent = events.filter(e => e.status === 'created' || e.status === 'triaged').length;
    document.getElementById('stat-critical').textContent = events.filter(e => e.severity === 'critical' || e.severity === 'high').length;
}

// 加载采集器
async function loadCollectors() {
    try {
        const response = await fetch(API_BASE + '/collectors', { credentials: 'include' });
        const data = await response.json();
        
        if (data.success && data.collectors && data.collectors.length > 0) {
            renderCollectors(data.collectors);
        }
    } catch (e) {
        console.error('加载采集器失败:', e);
    }
}

function renderCollectors(collectors) {
    const tbody = document.getElementById('collectors-table');
    tbody.innerHTML = collectors.map(c => `
        <tr>
            <td>${c.name}</td>
            <td>${getCollectorTypeLabel(c.type)}</td>
            <td>${c.schedule || '-'}</td>
            <td>${c.enabled ? '已启用' : '已禁用'}</td>
            <td>${c.last_run ? formatTime(c.last_run) : '-'}</td>
            <td class="secops-actions">
                <button class="secops-btn" onclick="testCollector('${c.id}')">测试</button>
                <button class="secops-btn" onclick="runCollector('${c.id}')">运行</button>
            </td>
        </tr>
    `).join('');
}

// 加载工单
async function loadTickets() {
    try {
        const response = await fetch(API_BASE + '/tickets', { credentials: 'include' });
        const data = await response.json();
        
        if (data.success && data.tickets && data.tickets.length > 0) {
            renderTickets(data.tickets);
        }
    } catch (e) {
        console.error('加载工单失败:', e);
    }
}

function renderTickets(tickets) {
    const tbody = document.getElementById('tickets-table');
    tbody.innerHTML = tickets.map(t => `
        <tr>
            <td>${t.id}</td>
            <td>${t.title}</td>
            <td><span class="secops-badge secops-badge-${getPriorityClass(t.priority)}">${t.priority}</span></td>
            <td>${getTicketStatusLabel(t.status)}</td>
            <td>${t.assignee_id || '-'}</td>
            <td class="secops-actions">
                <button class="secops-btn" onclick="viewTicket('${t.id}')">查看</button>
            </td>
        </tr>
    `).join('');
}

// 加载态势感知
async function loadDashboard() {
    try {
        const response = await fetch(API_BASE + '/dashboard/overview', { credentials: 'include' });
        const data = await response.json();
        
        if (data.success) {
            document.getElementById('stat-total').textContent = data.total_events || 0;
            document.getElementById('stat-pending').textContent = data.pending_events || 0;
            document.getElementById('stat-critical').textContent = data.critical_events || 0;
            document.getElementById('stat-resolved').textContent = data.resolved_today || 0;
        }
        
        // 加载趋势
        const trendRes = await fetch(API_BASE + '/dashboard/trends', { credentials: 'include' });
        const trendData = await trendRes.json();
        if (trendData.success) {
            renderTrendChart(trendData.trends);
        }
    } catch (e) {
        console.error('加载态势感知失败:', e);
    }
}

function renderTrendChart(trends) {
    const chart = document.getElementById('trend-chart');
    if (!trends || trends.length === 0) {
        chart.innerHTML = '暂无趋势数据';
        return;
    }
    
    let html = '<div style="display: flex; align-items: flex-end; height: 200px; gap: 10px; padding: 20px;">';
    trends.forEach(t => {
        const height = Math.min(100, (t.total_events / 20) * 10);
        html += `<div style="flex: 1; text-align: center;">
            <div style="height: ${height}px; background: #1976d2; border-radius: 4px 4px 0 0;"></div>
            <div style="font-size: 12px; color: #666; margin-top: 4px;">${t.date}</div>
        </div>`;
    });
    html += '</div>';
    chart.innerHTML = html;
}

// 知识问答
async function askKnowledge() {
    const question = document.getElementById('qa-input').value;
    if (!question) return;
    
    const resultDiv = document.getElementById('qa-result');
    resultDiv.style.display = 'block';
    resultDiv.innerHTML = 'AI 正在分析...';
    
    try {
        const response = await fetch(API_BASE + '/knowledge/qa', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ question: question }),
            credentials: 'include'
        });
        const data = await response.json();
        
        if (data.success) {
            resultDiv.innerHTML = `<strong>答案:</strong><p>${data.answer}</p>`;
            if (data.references && data.references.length > 0) {
                resultDiv.innerHTML += '<p><strong>参考:</strong></p><ul>' + 
                    data.references.map(r => `<li>${r.title}</li>`).join('') + '</ul>';
            }
        } else {
            resultDiv.innerHTML = '抱歉，未能找到相关答案。';
        }
    } catch (e) {
        resultDiv.innerHTML = '问答服务暂时不可用。';
    }
}

// 手动录入事件
function showEventModal() {
    document.getElementById('event-modal').classList.add('active');
}

function closeModal(id) {
    document.getElementById(id).classList.remove('active');
}

async function submitEvent() {
    const event = {
        title: document.getElementById('event-title').value,
        source: document.getElementById('event-source').value,
        severity: document.getElementById('event-severity').value,
        description: document.getElementById('event-description').value
    };
    
    try {
        const response = await fetch(API_BASE + '/events/ingest', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(event),
            credentials: 'include'
        });
        const data = await response.json();
        
        if (data.success) {
            closeModal('event-modal');
            loadEvents();
            alert('事件录入成功！');
        } else {
            alert('录入失败: ' + data.error);
        }
    } catch (e) {
        alert('提交失败');
    }
}

// 辅助函数
function formatTime(timestamp) {
    if (!timestamp) return '-';
    const date = new Date(timestamp);
    return date.toLocaleString('zh-CN');
}

function getSeverityLabel(severity) {
    const labels = { critical: '严重', high: '高', medium: '中', low: '低', info: '信息' };
    return labels[severity] || severity;
}

function getStatusLabel(status) {
    const labels = { created: '已创建', triaged: '已分诊', in_progress: '处理中', resolved: '已解决', closed: '已关闭' };
    return labels[status] || status;
}

function getCollectorTypeLabel(type) {
    const labels = { api: 'API采集', file: '文件导入', webhook: 'Webhook', stix: 'STIX', siem: 'SIEM' };
    return labels[type] || type;
}

function getTicketStatusLabel(status) {
    const labels = { pending: '待处理', assigned: '已分配', in_progress: '处理中', resolved: '已解决', closed: '已关闭' };
    return labels[status] || status;
}

function getPriorityClass(priority) {
    const classes = { P1: 'critical', P2: 'high', P3: 'medium', P4: 'low' };
    return classes[priority] || 'low';
}

function viewEvent(id) {
    window.location.href = '/secops?event=' + id;
}

function analyzeEvent(id) {
    fetch(API_BASE + '/events/' + id + '/analyze', {
        method: 'POST',
        credentials: 'include'
    }).then(r => r.json()).then(d => {
        if (d.success) {
            alert('分析完成！');
            loadEvents();
        }
    });
}

function showCollectorModal() {
    alert('请通过 API 创建采集器');
}

function createWebhook() {
    fetch(API_BASE + '/webhooks', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'New Webhook' }),
        credentials: 'include'
    }).then(r => r.json()).then(d => {
        if (d.success) {
            alert('Webhook 创建成功！URL: /api/webhook/' + d.token);
            loadCollectors();
        }
    });
}

function testCollector(id) {
    fetch(API_BASE + '/collectors/' + id + '/test', {
        method: 'POST',
        credentials: 'include'
    }).then(r => r.json()).then(d => {
        alert(d.success ? '测试成功' : '测试失败: ' + d.message);
    });
}

function runCollector(id) {
    fetch(API_BASE + '/collectors/' + id + '/run', {
        method: 'POST',
        credentials: 'include'
    }).then(r => r.json()).then(d => {
        if (d.success) {
            alert('采集任务已启动');
            loadCollectors();
        }
    });
}

// 初始化
document.addEventListener('DOMContentLoaded', function() {
    loadEvents();
});
