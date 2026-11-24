/* =========================================================================
 * 网站访问日志可视化分析工具 —— 前端交互与 ECharts 图表
 * ========================================================================= */
'use strict';

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

const nf = new Intl.NumberFormat('zh-CN');
const fmt = (value) => nf.format(Number(value) || 0);

const LEVEL_LABELS = { high: '高危', medium: '中危', low: '低危' };
const SOURCE_LABELS = { rule: '规则命中', statistic: '统计检测' };
const RULE_TYPE_LABELS = {
  path_pattern: '路径正则',
  path_keywords: '路径关键词',
  ua_keywords: 'UA 关键词',
  ua_empty: '空 UA',
};

const THRESHOLD_LABELS = {
  high_freq_per_minute: '单 IP 每分钟请求数',
  high_freq_min_requests: '高频检测最小请求数',
  error_rate_threshold: '错误率阈值',
  error_min_requests: '错误率检测最小请求数',
  scan_404_paths: '扫描检测：不同 404 路径数',
  scan_min_404: '扫描检测：404 次数',
  bruteforce_fails: '爆破检测：失败次数',
  bruteforce_window_minutes: '爆破检测：时间窗口（分钟）',
  login_path_keywords: '登录接口路径关键词',
  login_methods: '登录接口请求方法',
  server_error_burst: '5xx 突增：每分钟次数',
  server_error_window_minutes: '5xx 突增：窗口（分钟）',
  max_events: '最多保存告警明细',
};

const state = {
  meta: null,
  stats: null,
  summary: null,
  items: [],
  page: 1,
  pageSize: 20,
  total: 0,
  pages: 1,
  filters: { level: '', source: '', category: '', keyword: '' },
};

const charts = {};

/* ------------------------------------------------------------------ */
/* 基础工具                                                            */
/* ------------------------------------------------------------------ */
function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (ch) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[ch]));
}

function truncate(text, max) {
  const value = String(text ?? '');
  return value.length > max ? value.slice(0, max) + '…' : value;
}

function withAlpha(color, alpha) {
  const value = String(color || '').trim();
  if (value.startsWith('#')) {
    let hex = value.slice(1);
    if (hex.length === 3) hex = hex.split('').map((ch) => ch + ch).join('');
    const num = parseInt(hex, 16);
    if (!Number.isNaN(num)) {
      return `rgba(${(num >> 16) & 255}, ${(num >> 8) & 255}, ${num & 255}, ${alpha})`;
    }
  }
  return value;
}

function themeColors() {
  const style = getComputedStyle(document.documentElement);
  const read = (name) => style.getPropertyValue(name).trim();
  return {
    text1: read('--text-1'),
    text2: read('--text-2'),
    text3: read('--text-3'),
    accent: read('--accent'),
    violet: read('--violet'),
    green: read('--green'),
    amber: read('--amber'),
    red: read('--red'),
    border: read('--border'),
    grid: read('--grid-line'),
    panel: read('--panel-solid'),
    panelSoft: read('--panel-soft'),
  };
}

function tooltipStyle() {
  const c = themeColors();
  return {
    backgroundColor: c.panel,
    borderColor: c.border,
    borderWidth: 1,
    padding: [8, 12],
    textStyle: { color: c.text1, fontSize: 12 },
    extraCssText: 'border-radius:10px;box-shadow:0 16px 40px -18px rgba(0,0,0,.55);',
  };
}

async function fetchJSON(url, options = {}) {
  const response = await fetch(url, {
    headers: { Accept: 'application/json' },
    ...options,
  });
  let data = null;
  try {
    data = await response.json();
  } catch (error) {
    data = null;
  }
  if (!response.ok || (data && data.ok === false)) {
    throw new Error((data && data.error) || `请求失败（HTTP ${response.status}）`);
  }
  return data;
}

let toastTimer = null;
function showToast(message, isError = false) {
  const toast = $('#toast');
  toast.textContent = message;
  toast.classList.toggle('error', isError);
  toast.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove('show'), 3600);
}

function showLoading(text) {
  $('#loadingText').textContent = text || '正在处理…';
  $('#loadingMask').classList.add('show');
}

function hideLoading() {
  $('#loadingMask').classList.remove('show');
}

function debounce(fn, wait) {
  let timer = null;
  return function debounced(...args) {
    clearTimeout(timer);
    timer = setTimeout(() => fn.apply(this, args), wait);
  };
}

/* ------------------------------------------------------------------ */
/* 图表基础                                                            */
/* ------------------------------------------------------------------ */
function chartFor(id) {
  if (!charts[id]) {
    charts[id] = echarts.init(document.getElementById(id), null, { renderer: 'canvas' });
  }
  return charts[id];
}

function resizeAllCharts() {
  Object.values(charts).forEach((chart) => chart.resize());
}

function emptyOption(text) {
  const c = themeColors();
  return {
    title: {
      text,
      left: 'center',
      top: 'middle',
      textStyle: { color: c.text3, fontSize: 13, fontWeight: 400 },
    },
    xAxis: { show: false },
    yAxis: { show: false },
    series: [],
  };
}

function axisLabel(color, size = 10) {
  return { color, fontSize: size, hideOverlap: true };
}

/* ------------------------------------------------------------------ */
/* 主题                                                                */
/* ------------------------------------------------------------------ */
const THEME_ICONS = {
  sun: '<circle cx="12" cy="12" r="4"></circle><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"></path>',
  moon: '<path d="M21 12.8A8.5 8.5 0 1111.2 3a6.5 6.5 0 009.8 9.8z"></path>',
};

function updateThemeIcon() {
  const isDark = document.documentElement.dataset.theme !== 'light';
  $('#themeIcon').innerHTML = isDark ? THEME_ICONS.sun : THEME_ICONS.moon;
}

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  localStorage.setItem('wla-theme', theme);
  updateThemeIcon();
  if (state.stats) renderStatsCharts();
  if (state.summary) renderAnomalyCharts();
}

function initTheme() {
  const queryTheme = new URLSearchParams(location.search).get('theme');
  const saved = localStorage.getItem('wla-theme');
  if (queryTheme === 'light' || queryTheme === 'dark') {
    document.documentElement.dataset.theme = queryTheme;
    localStorage.setItem('wla-theme', queryTheme);
  } else if (saved === 'light' || saved === 'dark') {
    document.documentElement.dataset.theme = saved;
  }
  updateThemeIcon();
}

/** 支持通过 URL 参数预置筛选条件，例如 /?source=statistic&level=high */
function applyInitialFilters() {
  const params = new URLSearchParams(location.search);
  const allowed = {
    level: ['high', 'medium', 'low'],
    source: ['rule', 'statistic'],
  };
  Object.entries(allowed).forEach(([key, values]) => {
    const value = params.get(key);
    if (!value || !values.includes(value)) return;
    state.filters[key] = value;
    const select = key === 'level' ? $('#levelFilter') : $('#sourceFilter');
    if (select) select.value = value;
  });
  const keyword = params.get('keyword');
  if (keyword) {
    state.filters.keyword = keyword.trim();
    $('#keywordFilter').value = keyword;
  }
}

/* ------------------------------------------------------------------ */
/* 数据加载                                                            */
/* ------------------------------------------------------------------ */
async function loadAll({ silent = false } = {}) {
  if (!silent) showLoading('正在解析日志并生成图表…');
  try {
    const statsData = await fetchJSON('/api/stats');
    state.meta = statsData.meta;
    state.stats = statsData.stats;
    renderStatsCharts();

    await loadAnomalies(1);

    renderDataset();
    renderKpis();
    renderAnomalyCharts();
    renderTable();
    renderCategoryOptions();
    updateExportLink();

    if (!silent) hideLoading();
  } catch (error) {
    if (!silent) hideLoading();
    showToast(`加载失败：${error.message}`, true);
    $('#fileName').textContent = '数据加载失败';
    $('#fileMeta').textContent = error.message;
    $('#datasetChips').innerHTML =
      '<span class="chip warn"><span class="dot"></span>点击右上角“演示数据”重试</span>';
  }
}

async function loadAnomalies(page = 1) {
  const params = new URLSearchParams({ page, page_size: state.pageSize });
  Object.entries(state.filters).forEach(([key, value]) => {
    if (value) params.set(key, value);
  });
  const data = await fetchJSON('/api/anomalies?' + params.toString());
  state.summary = data.summary;
  state.items = data.items;
  state.page = data.page;
  state.total = data.total;
  state.pages = data.pages;
}

/* ------------------------------------------------------------------ */
/* 数据集 / KPI                                                        */
/* ------------------------------------------------------------------ */
function renderDataset() {
  const meta = state.meta;
  const stats = state.stats;
  const summary = state.summary;
  if (!meta || !stats) return;

  $('#fileName').textContent =
    meta.filename + (meta.source === 'demo' ? ' · 内置演示数据' : ' · 用户上传');
  $('#fileMeta').textContent =
    `${meta.size_label} · ${String(meta.encoding).toUpperCase()} · 解析 ${meta.parse_ms} ms · ` +
    `全流程 ${meta.analyze_ms} ms · 规则 v${meta.rules_version}`;

  const formats = Object.keys(meta.format_usage || {}).join(' / ') || '—';
  const chips = [
    `<span class="chip"><span class="dot"></span><b>${fmt(meta.total_lines)}</b> 行</span>`,
    `<span class="chip ${meta.failed_lines ? 'warn' : ''}"><span class="dot"></span>失败 <b>${fmt(meta.failed_lines)}</b> 行</span>`,
    `<span class="chip">跨度 <b>${escapeHtml(stats.span_label)}</b></span>`,
    `<span class="chip">格式 <b>${escapeHtml(formats)}</b></span>`,
    `<span class="chip">告警 <b>${summary ? fmt(summary.total) : '—'}</b> 条</span>`,
  ];
  $('#datasetChips').innerHTML = chips.join('');
}

const KPI_ICONS = {
  requests:
    '<path d="M4 19V5M4 19h16"/><path d="M8 15l4-5 3 3 5-7"/>',
  users:
    '<circle cx="9" cy="8" r="3"/><path d="M3.5 19a5.5 5.5 0 0111 0"/><path d="M16 5.5a3 3 0 010 5.6"/><path d="M17 19a5.2 5.2 0 00-2-4"/>',
  zap: '<path d="M13 2L4.5 13H11l-1 9 8.5-11H12l1-9z"/>',
  alert:
    '<path d="M12 3l9 16H3l9-16z"/><path d="M12 9v5"/><path d="M12 17h.01"/>',
  shield:
    '<path d="M12 3l7 3v5c0 4.6-3 8.2-7 9.8C8 19.2 5 15.6 5 11V6l7-3z"/><path d="M9 12l2 2 4-4"/>',
  siren:
    '<path d="M6 19v-6a6 6 0 1112 0v6"/><path d="M4 19h16"/><path d="M12 3v2M4.5 6.5l1.5 1.5M19.5 6.5L18 8"/>',
};

function kpiCard(icon, label, value, sub, tone = '') {
  return `
    <article class="kpi ${tone}">
      <div class="kpi-label">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"
             stroke-linecap="round" stroke-linejoin="round">${KPI_ICONS[icon]}</svg>
        ${escapeHtml(label)}
      </div>
      <div class="kpi-value">${value}</div>
      <div class="kpi-sub">${sub}</div>
    </article>`;
}

function renderKpis() {
  const stats = state.stats;
  const meta = state.meta;
  const summary = state.summary;
  if (!stats || !meta || !summary) return;

  const errorTone = stats.error_rate >= 0.01 ? 'warn' : 'ok';
  const cards = [
    kpiCard(
      'requests',
      '总请求数',
      fmt(stats.total_requests),
      `解析 ${fmt(meta.parsed_lines)} 行 · 成功率 ${(meta.success_rate * 100).toFixed(1)}%`
    ),
    kpiCard(
      'users',
      '独立 IP',
      fmt(stats.unique_ips),
      `覆盖 ${fmt(stats.unique_urls)} 个 URL 路径`
    ),
    kpiCard(
      'zap',
      '峰值 QPS',
      fmt(stats.peak_qps),
      `平均 ${stats.avg_qps} req/s · 流量 ${escapeHtml(stats.human_bytes)}`
    ),
    kpiCard(
      'alert',
      '错误率',
      `${(stats.error_rate * 100).toFixed(2)}<small>%</small>`,
      `4xx / 5xx 共 ${fmt(stats.error_count)} 次`,
      errorTone
    ),
    kpiCard(
      'shield',
      '异常告警',
      fmt(summary.total),
      `高危 ${fmt(summary.high)} · 中危 ${fmt(summary.medium)} · 低危 ${fmt(summary.low)}`
    ),
    kpiCard(
      'siren',
      '高危告警',
      fmt(summary.high),
      `占全部告警 ${summary.total ? ((summary.high / summary.total) * 100).toFixed(1) : '0.0'}%`,
      summary.high > 0 ? 'danger' : 'ok'
    ),
  ];
  $('#kpiGrid').innerHTML = cards.join('');
}

/* ------------------------------------------------------------------ */
/* 统计图表                                                            */
/* ------------------------------------------------------------------ */
function renderStatsCharts() {
  renderTrendChart();
  renderStatusChart();
  renderTopIpChart();
  renderTopUrlChart();
  renderMethodChart();
  renderHourlyChart();
}

function renderTrendChart() {
  const chart = chartFor('trendChart');
  const stats = state.stats;
  const c = themeColors();
  const data = stats.timeline || [];
  if (!data.length) {
    chart.clear();
    chart.setOption(emptyOption('暂无访问数据'));
    return;
  }
  const hasZoom = data.length > 30;
  chart.setOption(
    {
      animationDuration: 700,
      color: [c.accent, c.amber, c.red],
      grid: { left: 10, right: 18, top: 34, bottom: hasZoom ? 56 : 8, containLabel: true },
      tooltip: {
        trigger: 'axis',
        ...tooltipStyle(),
        axisPointer: { type: 'line', lineStyle: { color: c.border } },
      },
      legend: {
        top: 0,
        right: 0,
        icon: 'roundRect',
        itemWidth: 12,
        itemHeight: 4,
        itemGap: 16,
        textStyle: { color: c.text3, fontSize: 11 },
        data: ['总访问量', '4xx 错误', '5xx 错误'],
      },
      xAxis: {
        type: 'category',
        boundaryGap: false,
        data: data.map((item) => item.time),
        axisLine: { lineStyle: { color: c.border } },
        axisTick: { show: false },
        axisLabel: {
          color: c.text3,
          fontSize: 9.5,
          rotate: data.length > 12 ? 35 : 0,
          hideOverlap: true,
          interval: data.length > 40 ? 'auto' : data.length > 14 ? 1 : 0,
        },
      },
      yAxis: {
        type: 'value',
        splitLine: { lineStyle: { color: c.grid } },
        axisLabel: axisLabel(c.text3, 10),
      },
      dataZoom: hasZoom
        ? [
            { type: 'inside', start: 0, end: 100 },
            {
              type: 'slider',
              height: 14,
              bottom: 4,
              borderColor: 'transparent',
              backgroundColor: withAlpha(c.text3, 0.08),
              fillerColor: withAlpha(c.accent, 0.18),
              handleStyle: { color: c.accent },
              moveHandleStyle: { color: c.accent },
              textStyle: { color: c.text3, fontSize: 9 },
              dataBackground: {
                lineStyle: { color: c.border },
                areaStyle: { color: withAlpha(c.accent, 0.08) },
              },
            },
          ]
        : [],
      series: [
        {
          name: '总访问量',
          type: 'line',
          smooth: true,
          symbol: 'none',
          lineStyle: { width: 2.2 },
          areaStyle: {
            color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
              { offset: 0, color: withAlpha(c.accent, 0.28) },
              { offset: 1, color: withAlpha(c.accent, 0) },
            ]),
          },
          data: data.map((item) => item.total),
        },
        {
          name: '4xx 错误',
          type: 'line',
          smooth: true,
          symbol: 'none',
          lineStyle: { width: 1.5, type: 'dashed' },
          data: data.map((item) => item.s4xx),
        },
        {
          name: '5xx 错误',
          type: 'line',
          smooth: true,
          symbol: 'none',
          lineStyle: { width: 1.5, type: 'dashed' },
          data: data.map((item) => item.s5xx),
        },
      ],
    },
    true
  );
  chart.resize();
  $('#bucketLabel').textContent = stats.bucket.label;
}

function groupStatusCodes(codes) {
  const sorted = [...codes].sort((a, b) => b.count - a.count);
  const top = sorted.slice(0, 6).map((item) => ({ ...item, name: String(item.code) }));
  const rest = sorted.slice(6);
  if (rest.length) {
    top.push({
      name: '其他',
      count: rest.reduce((sum, item) => sum + item.count, 0),
      code: '其他',
    });
  }
  return top;
}

function statusColor(code, c) {
  if (code === '其他') return c.text3;
  const digit = Math.floor(Number(code) / 100);
  return { 2: c.green, 3: c.accent, 4: c.amber, 5: c.red }[digit] || c.violet;
}

function renderStatusChart() {
  const chart = chartFor('statusChart');
  const stats = state.stats;
  const c = themeColors();
  const items = groupStatusCodes(stats.status_codes || []);
  if (!items.length) {
    chart.clear();
    chart.setOption(emptyOption('暂无状态码数据'));
    return;
  }

  chart.setOption(
    {
      animationDuration: 700,
      tooltip: {
        trigger: 'item',
        ...tooltipStyle(),
        formatter: (params) =>
          `${escapeHtml(params.name)}<br/>请求 ${fmt(params.value)} 次 · ${params.percent}%`,
      },
      legend: {
        bottom: 0,
        left: 'center',
        icon: 'circle',
        itemWidth: 8,
        itemHeight: 8,
        itemGap: 12,
        textStyle: { color: c.text3, fontSize: 11 },
        type: 'scroll',
        data: items.map((item) => item.name),
      },
      graphic: [
        {
          type: 'text',
          left: 'center',
          top: '38%',
          style: {
            text: fmt(stats.total_requests),
            fill: c.text1,
            fontSize: 23,
            fontWeight: 700,
            textAlign: 'center',
          },
        },
        {
          type: 'text',
          left: 'center',
          top: '50%',
          style: {
            text: '总请求',
            fill: c.text3,
            fontSize: 11,
            textAlign: 'center',
          },
        },
      ],
      series: [
        {
          type: 'pie',
          radius: ['52%', '72%'],
          center: ['50%', '44%'],
          avoidLabelOverlap: true,
          label: { show: false },
          labelLine: { show: false },
          itemStyle: { borderColor: c.panel, borderWidth: 3, borderRadius: 6 },
          data: items.map((item) => ({
            name: item.name,
            value: item.count,
            itemStyle: { color: statusColor(item.name, c) },
          })),
        },
      ],
    },
    true
  );
  chart.resize();
}

function barGradient(c, from, to, horizontal = true) {
  return new echarts.graphic.LinearGradient(
    horizontal ? 0 : 0,
    horizontal ? 0 : 1,
    horizontal ? 1 : 0,
    horizontal ? 0 : 0,
    [
      { offset: 0, color: withAlpha(from, 0.55) },
      { offset: 1, color: to },
    ]
  );
}

function renderTopIpChart() {
  const chart = chartFor('topIpChart');
  const stats = state.stats;
  const c = themeColors();
  const items = stats.top_ips || [];
  if (!items.length) {
    chart.clear();
    chart.setOption(emptyOption('暂无访问 IP 数据'));
    return;
  }

  chart.setOption(
    {
      animationDuration: 700,
      grid: { left: 8, right: 52, top: 6, bottom: 6, containLabel: true },
      tooltip: {
        trigger: 'axis',
        axisPointer: { type: 'shadow', shadowStyle: { color: withAlpha(c.accent, 0.06) } },
        ...tooltipStyle(),
        formatter: (params) => {
          const item = params[0].data;
          return `<b>${escapeHtml(item.ip)}</b><br/>请求 ${fmt(item.value)} 次 · ${item.percent}%<br/>其中错误 ${fmt(item.errors)} 次`;
        },
      },
      xAxis: {
        type: 'value',
        splitLine: { lineStyle: { color: c.grid } },
        axisLabel: axisLabel(c.text3, 10),
      },
      yAxis: {
        type: 'category',
        data: items.map((item) => item.ip).reverse(),
        axisTick: { show: false },
        axisLine: { lineStyle: { color: c.border } },
        axisLabel: { color: c.text2, fontSize: 10.5, fontFamily: 'Consolas, monospace' },
      },
      series: [
        {
          type: 'bar',
          barWidth: 11,
          data: items.map((item) => ({
            value: item.count,
            ip: item.ip,
            percent: item.percent,
            errors: item.errors,
          })).reverse(),
          itemStyle: {
            borderRadius: [0, 6, 6, 0],
            color: barGradient(c, c.accent, c.violet),
          },
          label: {
            show: true,
            position: 'right',
            color: c.text2,
            fontSize: 10,
            formatter: (params) => fmt(params.value),
          },
        },
      ],
    },
    true
  );
  chart.resize();
}

function renderTopUrlChart() {
  const chart = chartFor('topUrlChart');
  const stats = state.stats;
  const c = themeColors();
  const items = stats.top_urls || [];
  if (!items.length) {
    chart.clear();
    chart.setOption(emptyOption('暂无访问 URL 数据'));
    return;
  }

  chart.setOption(
    {
      animationDuration: 700,
      grid: { left: 8, right: 52, top: 6, bottom: 6, containLabel: true },
      tooltip: {
        trigger: 'axis',
        axisPointer: { type: 'shadow', shadowStyle: { color: withAlpha(c.violet, 0.06) } },
        ...tooltipStyle(),
        formatter: (params) => {
          const item = params[0].data;
          return `<b>${escapeHtml(item.url)}</b><br/>请求 ${fmt(item.value)} 次 · ${item.percent}%<br/>其中错误 ${fmt(item.errors)} 次`;
        },
      },
      xAxis: {
        type: 'value',
        splitLine: { lineStyle: { color: c.grid } },
        axisLabel: axisLabel(c.text3, 10),
      },
      yAxis: {
        type: 'category',
        data: items.map((item) => truncate(item.url, 26)).reverse(),
        axisTick: { show: false },
        axisLine: { lineStyle: { color: c.border } },
        axisLabel: { color: c.text2, fontSize: 10.5, fontFamily: 'Consolas, monospace' },
      },
      series: [
        {
          type: 'bar',
          barWidth: 11,
          data: items.map((item) => ({
            value: item.count,
            url: item.url,
            percent: item.percent,
            errors: item.errors,
          })).reverse(),
          itemStyle: {
            borderRadius: [0, 6, 6, 0],
            color: barGradient(c, c.violet, c.accent),
          },
          label: {
            show: true,
            position: 'right',
            color: c.text2,
            fontSize: 10,
            formatter: (params) => fmt(params.value),
          },
        },
      ],
    },
    true
  );
  chart.resize();
}

function renderMethodChart() {
  const chart = chartFor('methodChart');
  const stats = state.stats;
  const c = themeColors();
  const items = stats.methods || [];
  if (!items.length) {
    chart.clear();
    chart.setOption(emptyOption('暂无请求方法数据'));
    return;
  }
  const palette = [c.accent, c.violet, c.green, c.amber, c.red, c.text3];

  chart.setOption(
    {
      animationDuration: 700,
      tooltip: {
        trigger: 'item',
        ...tooltipStyle(),
        formatter: (params) =>
          `${escapeHtml(params.name)}<br/>请求 ${fmt(params.value)} 次 · ${params.percent}%`,
      },
      legend: {
        bottom: 0,
        left: 'center',
        icon: 'circle',
        itemWidth: 8,
        itemHeight: 8,
        itemGap: 12,
        textStyle: { color: c.text3, fontSize: 11 },
      },
      graphic: [
        {
          type: 'text',
          left: 'center',
          top: '36%',
          style: {
            text: fmt(stats.total_requests),
            fill: c.text1,
            fontSize: 20,
            fontWeight: 700,
            textAlign: 'center',
          },
        },
        {
          type: 'text',
          left: 'center',
          top: '47%',
          style: { text: '次请求', fill: c.text3, fontSize: 10.5, textAlign: 'center' },
        },
      ],
      series: [
        {
          type: 'pie',
          radius: ['48%', '70%'],
          center: ['50%', '42%'],
          itemStyle: { borderColor: c.panel, borderWidth: 3, borderRadius: 6 },
          label: { show: false },
          labelLine: { show: false },
          data: items.map((item, index) => ({
            name: item.method,
            value: item.count,
            itemStyle: { color: palette[index % palette.length] },
          })),
        },
      ],
    },
    true
  );
  chart.resize();
}

function renderHourlyChart() {
  const chart = chartFor('hourlyChart');
  const stats = state.stats;
  const c = themeColors();
  const items = stats.hourly || [];
  if (!items.length) {
    chart.clear();
    chart.setOption(emptyOption('暂无小时分布数据'));
    return;
  }

  chart.setOption(
    {
      animationDuration: 700,
      grid: { left: 10, right: 18, top: 18, bottom: 6, containLabel: true },
      tooltip: {
        trigger: 'axis',
        axisPointer: { type: 'shadow', shadowStyle: { color: withAlpha(c.accent, 0.06) } },
        ...tooltipStyle(),
        formatter: (params) =>
          `${params[0].axisValue}<br/>访问 ${fmt(params[0].value)} 次`,
      },
      xAxis: {
        type: 'category',
        data: items.map((item) => item.hour),
        axisLine: { lineStyle: { color: c.border } },
        axisTick: { show: false },
        axisLabel: { color: c.text3, fontSize: 10, interval: 'auto', hideOverlap: true },
      },
      yAxis: {
        type: 'value',
        splitLine: { lineStyle: { color: c.grid } },
        axisLabel: axisLabel(c.text3, 10),
      },
      series: [
        {
          type: 'bar',
          barWidth: '48%',
          data: items.map((item) => item.count),
          itemStyle: {
            borderRadius: [5, 5, 0, 0],
            color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
              { offset: 0, color: c.accent },
              { offset: 1, color: withAlpha(c.accent, 0.12) },
            ]),
          },
        },
      ],
    },
    true
  );
  chart.resize();
}

/* ------------------------------------------------------------------ */
/* 异常图表                                                            */
/* ------------------------------------------------------------------ */
function renderAnomalyCharts() {
  renderLevelChart();
  renderCategoryChart();
}

function renderLevelChart() {
  const chart = chartFor('levelChart');
  const summary = state.summary;
  const c = themeColors();
  if (!summary || !summary.total) {
    chart.clear();
    chart.setOption(emptyOption('未发现异常告警'));
    return;
  }

  const data = [
    { name: '高危', value: summary.high, color: c.red },
    { name: '中危', value: summary.medium, color: c.amber },
    { name: '低危', value: summary.low, color: c.text3 },
  ];

  chart.setOption(
    {
      animationDuration: 700,
      tooltip: {
        trigger: 'item',
        ...tooltipStyle(),
        formatter: (params) =>
          `${escapeHtml(params.name)}<br/>告警 ${fmt(params.value)} 条 · ${params.percent}%`,
      },
      legend: {
        bottom: 0,
        left: 'center',
        icon: 'circle',
        itemWidth: 8,
        itemHeight: 8,
        itemGap: 16,
        textStyle: { color: c.text3, fontSize: 11 },
      },
      graphic: [
        {
          type: 'text',
          left: 'center',
          top: '36%',
          style: {
            text: fmt(summary.total),
            fill: c.text1,
            fontSize: 20,
            fontWeight: 700,
            textAlign: 'center',
          },
        },
        {
          type: 'text',
          left: 'center',
          top: '47%',
          style: { text: '条告警', fill: c.text3, fontSize: 10.5, textAlign: 'center' },
        },
      ],
      series: [
        {
          type: 'pie',
          radius: ['48%', '70%'],
          center: ['50%', '42%'],
          itemStyle: { borderColor: c.panel, borderWidth: 3, borderRadius: 6 },
          label: { show: false },
          labelLine: { show: false },
          data: data.map((item) => ({
            name: item.name,
            value: item.value,
            itemStyle: { color: item.color },
          })),
        },
      ],
    },
    true
  );
  chart.resize();
}

function renderCategoryChart() {
  const chart = chartFor('categoryChart');
  const summary = state.summary;
  const c = themeColors();
  const items = (summary && summary.by_category ? summary.by_category : []).slice(0, 8);
  if (!items.length) {
    chart.clear();
    chart.setOption(emptyOption('未发现异常类型'));
    return;
  }

  chart.setOption(
    {
      animationDuration: 700,
      grid: { left: 8, right: 46, top: 8, bottom: 6, containLabel: true },
      tooltip: {
        trigger: 'axis',
        axisPointer: { type: 'shadow', shadowStyle: { color: withAlpha(c.red, 0.05) } },
        ...tooltipStyle(),
        formatter: (params) =>
          `${escapeHtml(params[0].axisValue)}<br/>告警 ${fmt(params[0].value)} 条`,
      },
      xAxis: {
        type: 'log',
        min: 1,
        logBase: 10,
        splitLine: { lineStyle: { color: c.grid } },
        axisLabel: { color: c.text3, fontSize: 10, formatter: (value) => (value >= 1 ? value : '') },
      },
      yAxis: {
        type: 'category',
        data: items.map((item) => item.name).reverse(),
        axisTick: { show: false },
        axisLine: { lineStyle: { color: c.border } },
        axisLabel: { color: c.text2, fontSize: 10.5 },
      },
      series: [
        {
          type: 'bar',
          barWidth: 10,
          data: items.map((item) => item.count).reverse(),
          itemStyle: {
            borderRadius: [0, 6, 6, 0],
            color: barGradient(c, c.amber, c.red),
          },
          label: {
            show: true,
            position: 'right',
            color: c.text2,
            fontSize: 10,
            formatter: (params) => fmt(params.value),
          },
        },
      ],
    },
    true
  );
  chart.resize();
}

/* ------------------------------------------------------------------ */
/* 异常明细表                                                          */
/* ------------------------------------------------------------------ */
function statusCell(status) {
  const code = Number(status) || 0;
  if (!code) return '<span class="status-code">—</span>';
  const cls = `s${Math.floor(code / 100)}`;
  return `<span class="status-code ${cls}">${code}</span>`;
}

function ruleChips(rules) {
  const items = rules || [];
  const chips = items.slice(0, 3).map(
    (rule) =>
      `<span class="rule-chip ${escapeHtml(rule.level)}" title="${escapeHtml(rule.name)}">${escapeHtml(rule.id)}</span>`
  );
  if (items.length > 3) {
    const names = items.map((rule) => rule.name).join('、');
    chips.push(`<span class="rule-chip" title="${escapeHtml(names)}">+${items.length - 3}</span>`);
  }
  return `<div class="rule-chips">${chips.join('')}</div>`;
}

function renderTable() {
  const body = $('#tableBody');
  if (!state.items.length) {
    body.innerHTML =
      '<tr><td colspan="9"><div class="empty"><strong>没有符合条件的异常记录</strong>试试调整筛选条件，或点击右上角“演示数据”重新加载</div></td></tr>';
  } else {
    body.innerHTML = state.items
      .map((event) => {
        const level = LEVEL_LABELS[event.level] || event.level;
        const source = SOURCE_LABELS[event.source] || event.source;
        return `
          <tr data-id="${event.id}" tabindex="0">
            <td class="cell-time">${escapeHtml(event.time.slice(5))}</td>
            <td><span class="badge ${escapeHtml(event.level)}">${level}</span></td>
            <td class="cell-ip">${escapeHtml(event.ip)}</td>
            <td>${escapeHtml(event.method || '—')}</td>
            <td class="cell-url" title="${escapeHtml(event.path)}">${escapeHtml(truncate(event.path, 72))}</td>
            <td>${statusCell(event.status)}</td>
            <td>${ruleChips(event.rules)}</td>
            <td><span class="badge source">${source}</span></td>
            <td class="cell-ua" title="${escapeHtml(event.ua)}">${escapeHtml(truncate(event.ua, 48))}</td>
          </tr>`;
      })
      .join('');
  }

  $('#tableCount').textContent = fmt(state.total);
  $('#pageInfo').textContent = `第 ${state.page} / ${state.pages} 页 · 共 ${fmt(state.total)} 条 · 每页 ${state.pageSize} 条`;
  $('#prevPage').disabled = state.page <= 1;
  $('#nextPage').disabled = state.page >= state.pages;
  $('#prevPage').style.opacity = state.page <= 1 ? 0.45 : 1;
  $('#nextPage').style.opacity = state.page >= state.pages ? 0.45 : 1;
}

function renderCategoryOptions() {
  const select = $('#categoryFilter');
  if (!select) return;
  const current = select.value;
  const categories = (state.summary && state.summary.by_category) || [];
  const options = ['<option value="">全部类型</option>'];
  categories.forEach((item) => {
    options.push(
      `<option value="${escapeHtml(item.category)}">${escapeHtml(item.name)}（${fmt(item.count)}）</option>`
    );
  });
  select.innerHTML = options.join('');
  if (current && categories.some((item) => item.category === current)) {
    select.value = current;
  }
}

function updateExportLink() {
  const params = new URLSearchParams();
  Object.entries(state.filters).forEach(([key, value]) => {
    if (value) params.set(key, value);
  });
  const query = params.toString();
  $('#exportBtn').href = '/api/anomalies/export' + (query ? '?' + query : '');
}

/* ------------------------------------------------------------------ */
/* 详情弹窗                                                            */
/* ------------------------------------------------------------------ */
function openDetail(event) {
  const level = LEVEL_LABELS[event.level] || event.level;
  const rules = (event.rules || [])
    .map(
      (rule) =>
        `<span class="rule-chip ${escapeHtml(rule.level)}">${escapeHtml(rule.id)} ${escapeHtml(rule.name)}</span>`
    )
    .join(' ');
  const evidence = JSON.stringify(event.evidence || [], null, 2);
  const realIp =
    event.real_ip && event.real_ip !== event.ip
      ? ` <span style="color:var(--text-3)">（真实 IP：${escapeHtml(event.real_ip)}）</span>`
      : '';

  $('#detailTitle').textContent = `${level} · ${event.ip}`;
  $('#detailBody').innerHTML = `
    <dl class="detail-grid">
      <dt>时间</dt><dd class="mono">${escapeHtml(event.time)}</dd>
      <dt>等级</dt><dd><span class="badge ${escapeHtml(event.level)}">${level}</span></dd>
      <dt>来源</dt><dd>${SOURCE_LABELS[event.source] || escapeHtml(event.source)}</dd>
      <dt>来源 IP</dt><dd class="mono">${escapeHtml(event.ip)}${realIp}</dd>
      <dt>请求</dt><dd class="mono">${escapeHtml(event.method || '—')} ${escapeHtml(event.path || '—')}</dd>
      <dt>状态码</dt><dd>${statusCell(event.status)}</dd>
      <dt>User-Agent</dt><dd class="mono">${escapeHtml(event.ua || '—')}</dd>
      <dt>命中规则</dt><dd>${rules || '—'}</dd>
      <dt>检测说明</dt><dd>${escapeHtml(event.detail || '')}</dd>
    </dl>
    <div class="evidence">${escapeHtml(evidence)}</div>`;
  $('#detailMask').classList.add('show');
  lockBodyScroll();
}

function closeDetail() {
  $('#detailMask').classList.remove('show');
  lockBodyScroll();
}

function lockBodyScroll() {
  const drawerOpen = $('#rulesDrawer').classList.contains('show');
  const modalOpen = $('#detailMask').classList.contains('show');
  document.body.style.overflow = drawerOpen || modalOpen ? 'hidden' : '';
}

/* ------------------------------------------------------------------ */
/* 规则抽屉                                                            */
/* ------------------------------------------------------------------ */
function formatThreshold(key, value) {
  if (key === 'error_rate_threshold') {
    return `${Math.round(Number(value) * 100)}%`;
  }
  if (Array.isArray(value)) return value.join(' / ');
  return String(value);
}

async function openRules() {
  $('#drawerMask').classList.add('show');
  $('#rulesDrawer').classList.add('show');
  lockBodyScroll();
  $('#rulesBody').innerHTML = '<div class="empty">正在加载规则…</div>';
  try {
    const data = await fetchJSON('/api/rules');
    renderRules(data);
  } catch (error) {
    $('#rulesBody').innerHTML = `<div class="empty"><strong>规则加载失败</strong>${escapeHtml(error.message)}</div>`;
  }
}

function closeRules() {
  $('#drawerMask').classList.remove('show');
  $('#rulesDrawer').classList.remove('show');
  lockBodyScroll();
}

function renderRules(data) {
  const thresholds = Object.entries(data.thresholds || {})
    .map(
      ([key, value]) => `
        <div class="threshold">
          <span>${escapeHtml(THRESHOLD_LABELS[key] || key)}</span>
          <b>${escapeHtml(formatThreshold(key, value))}</b>
        </div>`
    )
    .join('');

  const rules = (data.rules || [])
    .map(
      (rule) => `
        <tr>
          <td><code>${escapeHtml(rule.id)}</code></td>
          <td><span class="badge ${escapeHtml(rule.level)}">${LEVEL_LABELS[rule.level] || rule.level}</span></td>
          <td>${escapeHtml(rule.name)}
            <div class="desc">${escapeHtml(rule.description)}${rule.mitre ? ` · MITRE ${escapeHtml(rule.mitre)}` : ''}</div>
          </td>
          <td><span class="rule-chip">${escapeHtml(RULE_TYPE_LABELS[rule.type] || rule.type)}</span></td>
        </tr>`
    )
    .join('');

  const formats = (data.formats || [])
    .map(
      (item) => `
        <div class="threshold">
          <span>${escapeHtml(item.label)}</span>
          <b>${escapeHtml(item.name)}</b>
        </div>`
    )
    .join('');

  $('#rulesBody').innerHTML = `
    <h3>规则概览</h3>
    <div class="threshold-grid">
      <div class="threshold"><span>规则版本</span><b>v${escapeHtml(data.version)}</b></div>
      <div class="threshold"><span>签名规则数量</span><b>${fmt(data.rules.length)} 条</b></div>
      <div class="threshold"><span>支持日志格式</span><b>${fmt(data.formats.length)} 种</b></div>
      <div class="threshold"><span>配置文件</span><b>config/rules.json</b></div>
    </div>
    <h3>签名规则（${fmt(data.rules.length)} 条）</h3>
    <div class="table-wrap">
      <table class="rule-table">
        <thead><tr><th>编号</th><th>等级</th><th>名称与说明</th><th>类型</th></tr></thead>
        <tbody>${rules}</tbody>
      </table>
    </div>
    <h3>统计检测阈值</h3>
    <div class="threshold-grid">${thresholds}</div>
    <h3>支持的日志格式</h3>
    <div class="threshold-grid">${formats}</div>
    <p style="color:var(--text-3);font-size:12px;margin-top:18px">
      提示：修改 <code>config/rules.json</code> 后点击“重新加载规则”，服务无需重启；
      当前若为演示数据会自动重新分析，上传的日志需重新上传后生效。
    </p>`;
}

async function reloadRules() {
  const button = $('#reloadRules');
  button.disabled = true;
  button.textContent = '加载中…';
  try {
    const data = await fetchJSON('/api/rules/reload', { method: 'POST' });
    showToast(data.message);
    const fresh = await fetchJSON('/api/rules');
    renderRules(fresh);
    if (state.meta && state.meta.source === 'demo') {
      await fetchJSON('/api/demo', { method: 'POST' });
      await loadAll({ silent: true });
    }
  } catch (error) {
    showToast(`规则加载失败：${error.message}`, true);
  } finally {
    button.disabled = false;
    button.textContent = '重新加载规则';
  }
}

/* ------------------------------------------------------------------ */
/* 上传与交互                                                          */
/* ------------------------------------------------------------------ */
async function uploadFile(file) {
  if (!file) return;
  if (file.size > 64 * 1024 * 1024) {
    showToast('文件超过 64 MB 限制，请先拆分日志', true);
    return;
  }
  const form = new FormData();
  form.append('file', file);
  showLoading(`正在上传并解析 ${file.name} …`);
  try {
    const response = await fetch('/api/upload', { method: 'POST', body: form });
    let data = null;
    try {
      data = await response.json();
    } catch (error) {
      data = null;
    }
    if (!response.ok || !data || !data.ok) {
      throw new Error((data && data.error) || `上传失败（HTTP ${response.status}）`);
    }
    showToast(`已分析 ${data.meta.filename}，共 ${fmt(data.meta.parsed_lines)} 行`);
    hideLoading();
    await loadAll({ silent: true });
  } catch (error) {
    hideLoading();
    showToast(error.message, true);
  }
}

async function loadDemo() {
  showLoading('正在重新分析内置演示日志…');
  try {
    await fetchJSON('/api/demo', { method: 'POST' });
    hideLoading();
    showToast('演示日志已重新加载');
    await loadAll({ silent: true });
  } catch (error) {
    hideLoading();
    showToast(error.message, true);
  }
}

async function refreshAnomalies(page = 1) {
  try {
    await loadAnomalies(page);
    renderTable();
    renderAnomalyCharts();
    renderCategoryOptions();
    updateExportLink();
  } catch (error) {
    showToast(`筛选失败：${error.message}`, true);
  }
}

function bindEvents() {
  $('#fileInput').addEventListener('change', (event) => {
    const file = event.target.files && event.target.files[0];
    uploadFile(file);
    event.target.value = '';
  });

  $('#demoBtn').addEventListener('click', loadDemo);
  $('#themeBtn').addEventListener('click', () => {
    const next = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
    applyTheme(next);
  });

  $$('#levelFilter, #sourceFilter, #categoryFilter').forEach((select) => {
    select.addEventListener('change', () => {
      state.filters.level = $('#levelFilter').value;
      state.filters.source = $('#sourceFilter').value;
      state.filters.category = $('#categoryFilter').value;
      refreshAnomalies(1);
    });
  });

  $('#keywordFilter').addEventListener(
    'input',
    debounce((event) => {
      state.filters.keyword = event.target.value.trim();
      refreshAnomalies(1);
    }, 320)
  );

  $('#resetFilters').addEventListener('click', () => {
    state.filters = { level: '', source: '', category: '', keyword: '' };
    $('#levelFilter').value = '';
    $('#sourceFilter').value = '';
    $('#categoryFilter').value = '';
    $('#keywordFilter').value = '';
    refreshAnomalies(1);
  });

  $('#pageSize').addEventListener('change', (event) => {
    state.pageSize = Number(event.target.value) || 20;
    refreshAnomalies(1);
  });

  $('#prevPage').addEventListener('click', () => {
    if (state.page > 1) refreshAnomalies(state.page - 1);
  });
  $('#nextPage').addEventListener('click', () => {
    if (state.page < state.pages) refreshAnomalies(state.page + 1);
  });

  $('#tableBody').addEventListener('click', (event) => {
    const row = event.target.closest('tr[data-id]');
    if (!row) return;
    const item = state.items.find((entry) => String(entry.id) === row.dataset.id);
    if (item) openDetail(item);
  });
  $('#tableBody').addEventListener('keydown', (event) => {
    if (event.key !== 'Enter') return;
    const row = event.target.closest('tr[data-id]');
    if (!row) return;
    const item = state.items.find((entry) => String(entry.id) === row.dataset.id);
    if (item) openDetail(item);
  });

  $('#rulesBtn').addEventListener('click', openRules);
  $('#closeDrawer').addEventListener('click', closeRules);
  $('#closeDrawer2').addEventListener('click', closeRules);
  $('#drawerMask').addEventListener('click', closeRules);
  $('#reloadRules').addEventListener('click', reloadRules);

  $('#closeDetail').addEventListener('click', closeDetail);
  $('#detailMask').addEventListener('click', (event) => {
    if (event.target === $('#detailMask')) closeDetail();
  });

  document.addEventListener('keydown', (event) => {
    if (event.key !== 'Escape') return;
    if ($('#detailMask').classList.contains('show')) closeDetail();
    else if ($('#rulesDrawer').classList.contains('show')) closeRules();
  });

  const dropZone = $('#dropZone');
  ['dragenter', 'dragover'].forEach((type) => {
    dropZone.addEventListener(type, (event) => {
      event.preventDefault();
      dropZone.classList.add('dragover');
    });
  });
  ['dragleave', 'drop'].forEach((type) => {
    dropZone.addEventListener(type, (event) => {
      event.preventDefault();
      dropZone.classList.remove('dragover');
    });
  });
  dropZone.addEventListener('drop', (event) => {
    const file = event.dataTransfer && event.dataTransfer.files && event.dataTransfer.files[0];
    uploadFile(file);
  });

  window.addEventListener('resize', debounce(resizeAllCharts, 160));
}

/* ------------------------------------------------------------------ */
/* 启动                                                                */
/* ------------------------------------------------------------------ */
document.addEventListener('DOMContentLoaded', () => {
  initTheme();

  if (typeof echarts === 'undefined') {
    showToast('ECharts 资源加载失败，请检查 static/vendor/echarts.min.js', true);
    return;
  }

  bindEvents();
  applyInitialFilters();
  loadAll();

  // 支持 /#rules 直接打开规则说明面板
  if (location.hash === '#rules') openRules();

  if (window.ResizeObserver) {
    const observer = new ResizeObserver(() => resizeAllCharts());
    $$('.chart').forEach((element) => observer.observe(element));
  }
});
