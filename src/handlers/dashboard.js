import { verifyJWT } from '../utils/security.js';

export async function handleDashboard(request, env, corsHeaders) {
  const url = new URL(request.url);
  const path = url.pathname;
  
  if (path === '/dashboard' && request.method === 'GET') {
    return await serveDashboardPage();
  }
  
  if (path === '/api/dashboard/overview' && request.method === 'GET') {
    return await handleDashboardOverview(request, env, corsHeaders);
  }
  
  if (path === '/api/dashboard/metrics' && request.method === 'GET') {
    return await handleDashboardMetrics(request, env, corsHeaders);
  }
  
  if (path === '/api/dashboard/recent-scans' && request.method === 'GET') {
    return await handleRecentScans(request, env, corsHeaders);
  }
  
  if (path === '/api/dashboard/security-score' && request.method === 'GET') {
    return await handleSecurityScore(request, env, corsHeaders);
  }
  
  if (path === '/api/dashboard/vulnerability-trends' && request.method === 'GET') {
    return await handleVulnerabilityTrends(request, env, corsHeaders);
  }
  
  return new Response('Ruta no encontrada', { 
    status: 404, 
    headers: corsHeaders 
  });
}

async function handleDashboardOverview(request, env, corsHeaders) {
  try {
    const token = request.headers.get('Authorization')?.replace('Bearer ', '');
    const payload = await verifyJWT(token);
    
    // Obtener estadísticas generales
    const stats = await getDashboardStats(payload.userId, env);
    
    return new Response(JSON.stringify({ 
      success: true, 
      stats
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    console.error('Error en overview del dashboard:', error);
    return new Response(JSON.stringify({ 
      success: false, 
      message: 'Error al obtener overview del dashboard' 
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

async function getDashboardStats(userId, env) {
  // Contar dominios
  const domainsCount = await env.DB.prepare(
    'SELECT COUNT(*) as count FROM domains WHERE user_id = ?'
  ).bind(userId).first();
  
  // Contar escaneos totales
  const scansCount = await env.DB.prepare(
    `SELECT COUNT(*) as count FROM scans s 
     JOIN domains d ON s.domain_id = d.id 
     WHERE d.user_id = ?`
  ).bind(userId).first();
  
  // Contar escaneos activos
  const activeScansCount = await env.DB.prepare(
    `SELECT COUNT(*) as count FROM scans s 
     JOIN domains d ON s.domain_id = d.id 
     WHERE d.user_id = ? AND s.status = 'running'`
  ).bind(userId).first();
  
  // Contar vulnerabilidades por severidad
  const vulnerabilities = await env.DB.prepare(
    `SELECT f.severity, COUNT(*) as count 
     FROM findings f 
     JOIN scans s ON f.scan_id = s.id 
     JOIN domains d ON s.domain_id = d.id 
     WHERE d.user_id = ? 
     GROUP BY f.severity`
  ).bind(userId).all();
  
  const vulnStats = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0
  };
  
  vulnerabilities.results.forEach(vuln => {
    vulnStats[vuln.severity] = vuln.count;
  });
  
  // Calcular puntuación de seguridad promedio
  const securityScore = calculateSecurityScore(vulnStats);
  
  // Obtener escaneos recientes
  const recentScans = await env.DB.prepare(
    `SELECT s.*, d.domain_name 
     FROM scans s 
     JOIN domains d ON s.domain_id = d.id 
     WHERE d.user_id = ? 
     ORDER BY s.created_at DESC 
     LIMIT 5`
  ).bind(userId).all();
  
  return {
    domains: domainsCount.count,
    total_scans: scansCount.count,
    active_scans: activeScansCount.count,
    vulnerabilities: vulnStats,
    security_score: securityScore,
    recent_scans: recentScans.results.map(scan => ({
      id: scan.id,
      domain: scan.domain_name,
      status: scan.status,
      created_at: scan.created_at,
      completed_at: scan.completed_at,
      results: scan.results ? JSON.parse(scan.results) : null
    }))
  };
}

function calculateSecurityScore(vulnerabilities) {
  const weights = {
    critical: -25,
    high: -15,
    medium: -8,
    low: -3,
    info: -1
  };
  
  let score = 100;
  
  Object.keys(weights).forEach(severity => {
    score += vulnerabilities[severity] * weights[severity];
  });
  
  return Math.max(0, Math.min(100, score));
}

async function handleDashboardMetrics(request, env, corsHeaders) {
  try {
    const token = request.headers.get('Authorization')?.replace('Bearer ', '');
    const payload = await verifyJWT(token);
    const url = new URL(request.url);
    const timeRange = url.searchParams.get('range') || '30d';
    
    const metrics = await getDashboardMetrics(payload.userId, timeRange, env);
    
    return new Response(JSON.stringify({ 
      success: true, 
      metrics
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    console.error('Error en métricas del dashboard:', error);
    return new Response(JSON.stringify({ 
      success: false, 
      message: 'Error al obtener métricas del dashboard' 
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

async function getDashboardMetrics(userId, timeRange, env) {
  const days = timeRange === '7d' ? 7 : timeRange === '30d' ? 30 : 90;
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - days);
  
  // Escaneos por día
  const scansByDay = await env.DB.prepare(
    `SELECT DATE(s.created_at) as date, COUNT(*) as count 
     FROM scans s 
     JOIN domains d ON s.domain_id = d.id 
     WHERE d.user_id = ? AND s.created_at >= ? 
     GROUP BY DATE(s.created_at) 
     ORDER BY date`
  ).bind(userId, startDate.toISOString()).all();
  
  // Vulnerabilidades por tipo
  const vulnsByType = await env.DB.prepare(
    `SELECT f.vulnerability_type, COUNT(*) as count 
     FROM findings f 
     JOIN scans s ON f.scan_id = s.id 
     JOIN domains d ON s.domain_id = d.id 
     WHERE d.user_id = ? AND f.created_at >= ? 
     GROUP BY f.vulnerability_type 
     ORDER BY count DESC 
     LIMIT 10`
  ).bind(userId, startDate.toISOString()).all();
  
  // Dominios con más vulnerabilidades
  const topVulnDomains = await env.DB.prepare(
    `SELECT d.domain_name, COUNT(*) as vuln_count 
     FROM findings f 
     JOIN scans s ON f.scan_id = s.id 
     JOIN domains d ON s.domain_id = d.id 
     WHERE d.user_id = ? AND f.created_at >= ? 
     GROUP BY d.id, d.domain_name 
     ORDER BY vuln_count DESC 
     LIMIT 5`
  ).bind(userId, startDate.toISOString()).all();
  
  // Tendencia de puntuación de seguridad
  const securityTrend = await getSecurityScoreTrend(userId, days, env);
  
  return {
    scans_by_day: scansByDay.results,
    vulnerabilities_by_type: vulnsByType.results,
    top_vulnerable_domains: topVulnDomains.results,
    security_score_trend: securityTrend,
    time_range: timeRange
  };
}

async function getSecurityScoreTrend(userId, days, env) {
  const trend = [];
  
  for (let i = days; i >= 0; i--) {
    const date = new Date();
    date.setDate(date.getDate() - i);
    const dateStr = date.toISOString().split('T')[0];
    
    // Obtener vulnerabilidades hasta esa fecha
    const vulns = await env.DB.prepare(
      `SELECT f.severity, COUNT(*) as count 
       FROM findings f 
       JOIN scans s ON f.scan_id = s.id 
       JOIN domains d ON s.domain_id = d.id 
       WHERE d.user_id = ? AND DATE(f.created_at) <= ? 
       GROUP BY f.severity`
    ).bind(userId, dateStr).all();
    
    const vulnStats = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0
    };
    
    vulns.results.forEach(vuln => {
      vulnStats[vuln.severity] = vuln.count;
    });
    
    const score = calculateSecurityScore(vulnStats);
    
    trend.push({
      date: dateStr,
      score: score
    });
  }
  
  return trend;
}

async function handleRecentScans(request, env, corsHeaders) {
  try {
    const token = request.headers.get('Authorization')?.replace('Bearer ', '');
    const payload = await verifyJWT(token);
    const url = new URL(request.url);
    const limit = parseInt(url.searchParams.get('limit')) || 10;
    
    const recentScans = await env.DB.prepare(
      `SELECT s.*, d.domain_name, d.display_name 
       FROM scans s 
       JOIN domains d ON s.domain_id = d.id 
       WHERE d.user_id = ? 
       ORDER BY s.created_at DESC 
       LIMIT ?`
    ).bind(payload.userId, limit).all();
    
    const scansWithFindings = await Promise.all(
      recentScans.results.map(async (scan) => {
        const findings = await env.DB.prepare(
          'SELECT COUNT(*) as count, severity FROM findings WHERE scan_id = ? GROUP BY severity'
        ).bind(scan.id).all();
        
        const findingsSummary = {
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          info: 0
        };
        
        findings.results.forEach(finding => {
          findingsSummary[finding.severity] = finding.count;
        });
        
        return {
          ...scan,
          findings_summary: findingsSummary,
          results: scan.results ? JSON.parse(scan.results) : null
        };
      })
    );
    
    return new Response(JSON.stringify({ 
      success: true, 
      scans: scansWithFindings
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    console.error('Error al obtener escaneos recientes:', error);
    return new Response(JSON.stringify({ 
      success: false, 
      message: 'Error al obtener escaneos recientes' 
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

async function handleSecurityScore(request, env, corsHeaders) {
  try {
    const token = request.headers.get('Authorization')?.replace('Bearer ', '');
    const payload = await verifyJWT(token);
    const url = new URL(request.url);
    const domainId = url.searchParams.get('domainId');
    
    let whereClause = 'd.user_id = ?';
    let params = [payload.userId];
    
    if (domainId) {
      whereClause += ' AND d.id = ?';
      params.push(domainId);
    }
    
    const vulnerabilities = await env.DB.prepare(
      `SELECT f.severity, COUNT(*) as count 
       FROM findings f 
       JOIN scans s ON f.scan_id = s.id 
       JOIN domains d ON s.domain_id = d.id 
       WHERE ${whereClause} 
       GROUP BY f.severity`
    ).bind(...params).all();
    
    const vulnStats = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0
    };
    
    vulnerabilities.results.forEach(vuln => {
      vulnStats[vuln.severity] = vuln.count;
    });
    
    const score = calculateSecurityScore(vulnStats);
    const grade = getSecurityGrade(score);
    
    return new Response(JSON.stringify({ 
      success: true, 
      security_score: {
        score: score,
        grade: grade,
        vulnerabilities: vulnStats,
        recommendations: getScoreRecommendations(vulnStats)
      }
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    console.error('Error al calcular puntuación de seguridad:', error);
    return new Response(JSON.stringify({ 
      success: false, 
      message: 'Error al calcular puntuación de seguridad' 
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

function getSecurityGrade(score) {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
}

function getScoreRecommendations(vulnerabilities) {
  const recommendations = [];
  
  if (vulnerabilities.critical > 0) {
    recommendations.push('Corregir inmediatamente las vulnerabilidades críticas');
  }
  
  if (vulnerabilities.high > 5) {
    recommendations.push('Priorizar la corrección de vulnerabilidades de alta severidad');
  }
  
  if (vulnerabilities.medium > 10) {
    recommendations.push('Planificar la corrección de vulnerabilidades de severidad media');
  }
  
  if (recommendations.length === 0) {
    recommendations.push('Mantener las buenas prácticas de seguridad actuales');
  }
  
  return recommendations;
}

async function handleVulnerabilityTrends(request, env, corsHeaders) {
  try {
    const token = request.headers.get('Authorization')?.replace('Bearer ', '');
    const payload = await verifyJWT(token);
    
    const trends = await getVulnerabilityTrends(payload.userId, env);
    
    return new Response(JSON.stringify({ 
      success: true, 
      trends
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    console.error('Error en tendencias de vulnerabilidades:', error);
    return new Response(JSON.stringify({ 
      success: false, 
      message: 'Error al obtener tendencias de vulnerabilidades' 
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

async function getVulnerabilityTrends(userId, env) {
  const last30Days = [];
  
  for (let i = 29; i >= 0; i--) {
    const date = new Date();
    date.setDate(date.getDate() - i);
    const dateStr = date.toISOString().split('T')[0];
    
    const dailyVulns = await env.DB.prepare(
      `SELECT f.severity, COUNT(*) as count 
       FROM findings f 
       JOIN scans s ON f.scan_id = s.id 
       JOIN domains d ON s.domain_id = d.id 
       WHERE d.user_id = ? AND DATE(f.created_at) = ? 
       GROUP BY f.severity`
    ).bind(userId, dateStr).all();
    
    const dayData = {
      date: dateStr,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0
    };
    
    dailyVulns.results.forEach(vuln => {
      dayData[vuln.severity] = vuln.count;
    });
    
    last30Days.push(dayData);
  }
  
  return {
    daily_trends: last30Days,
    period: '30 días'
  };
}

async function serveDashboardPage() {
  const dashboardHTML = `
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - CyberSecurity Scanner</title>
    <link rel="stylesheet" href="/static/css/main.css">
    <link rel="stylesheet" href="/static/css/dashboard.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <div class="dashboard-container">
        <nav class="sidebar">
            <div class="logo">
                <h2>CyberSecurity Scanner</h2>
            </div>
            <ul class="nav-menu">
                <li><a href="#overview" class="nav-link active">Overview</a></li>
                <li><a href="#domains" class="nav-link">Dominios</a></li>
                <li><a href="#scans" class="nav-link">Escaneos</a></li>
                <li><a href="#vulnerabilities" class="nav-link">Vulnerabilidades</a></li>
                <li><a href="#reports" class="nav-link">Reportes</a></li>
                <li><a href="#settings" class="nav-link">Configuración</a></li>
            </ul>
            <div class="user-info">
                <button id="logoutBtn">Cerrar Sesión</button>
            </div>
        </nav>
        
        <main class="main-content">
            <div id="overview-section" class="content-section active">
                <h1>Dashboard Overview</h1>
                
                <div class="stats-grid">
                    <div class="stat-card">
                        <h3>Dominios</h3>
                        <div class="stat-number" id="domainsCount">-</div>
                    </div>
                    <div class="stat-card">
                        <h3>Escaneos Totales</h3>
                        <div class="stat-number" id="scansCount">-</div>
                    </div>
                    <div class="stat-card">
                        <h3>Escaneos Activos</h3>
                        <div class="stat-number" id="activeScansCount">-</div>
                    </div>
                    <div class="stat-card">
                        <h3>Puntuación de Seguridad</h3>
                        <div class="stat-number" id="securityScore">-</div>
                    </div>
                </div>
                
                <div class="charts-grid">
                    <div class="chart-container">
                        <h3>Vulnerabilidades por Severidad</h3>
                        <canvas id="vulnerabilitiesChart"></canvas>
                    </div>
                    <div class="chart-container">
                        <h3>Tendencia de Escaneos</h3>
                        <canvas id="scansChart"></canvas>
                    </div>
                </div>
                
                <div class="recent-scans">
                    <h3>Escaneos Recientes</h3>
                    <div id="recentScansList"></div>
                </div>
            </div>
            
            <div id="domains-section" class="content-section">
                <h1>Gestión de Dominios</h1>
                <button id="addDomainBtn" class="btn-primary">Agregar Dominio</button>
                <div id="domainsList"></div>
            </div>
            
            <div id="scans-section" class="content-section">
                <h1>Historial de Escaneos</h1>
                <div id="scansList"></div>
            </div>
            
            <div id="vulnerabilities-section" class="content-section">
                <h1>Vulnerabilidades Encontradas</h1>
                <div id="vulnerabilitiesList"></div>
            </div>
        </main>
    </div>
    
    <script src="/static/js/dashboard.js"></script>
</body>
</html>`;
  
  return new Response(dashboardHTML, {
    headers: { 'Content-Type': 'text/html' }
  });
}
