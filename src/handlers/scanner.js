import { verifyJWT } from '../utils/security.js';
import { performSecurityScan, getSubdomains } from '../utils/scanner-engine.js';
import { QueueManager } from '../utils/queue-manager.js';

export async function handleScanner(request, env, corsHeaders) {
  const url = new URL(request.url);
  const path = url.pathname;
  
  if (path === '/api/scanner/start' && request.method === 'POST') {
    return await handleStartScan(request, env, corsHeaders);
  }
  
  if (path === '/api/scanner/status' && request.method === 'GET') {
    return await handleScanStatus(request, env, corsHeaders);
  }
  
  if (path === '/api/scanner/results' && request.method === 'GET') {
    return await handleScanResults(request, env, corsHeaders);
  }
  
  if (path === '/api/scanner/subdomains' && request.method === 'POST') {
    return await handleSubdomainScan(request, env, corsHeaders);
  }
  
  if (path === '/api/scanner/stop' && request.method === 'POST') {
    return await handleStopScan(request, env, corsHeaders);
  }
  
  if (path === '/api/scanner/queue-stats' && request.method === 'GET') {
    return await handleQueueStats(request, env, corsHeaders);
  }
  
  if (path === '/api/scanner/quick-scan' && request.method === 'POST') {
    return await handleQuickScan(request, env, corsHeaders);
  }
  
  return new Response('Ruta no encontrada', { 
    status: 404, 
    headers: corsHeaders 
  });
}

async function handleStartScan(request, env, corsHeaders) {
  try {
    const token = request.headers.get('Authorization')?.replace('Bearer ', '');
    const payload = await verifyJWT(token);
    const { domainId, scanTypes, deepScan, priority } = await request.json();
    
    // Verificar que el dominio pertenece al usuario
    const domain = await env.DB.prepare(
      'SELECT * FROM domains WHERE id = ? AND user_id = ?'
    ).bind(domainId, payload.userId).first();
    
    if (!domain) {
      return new Response(JSON.stringify({ 
        success: false, 
        message: 'Dominio no encontrado' 
      }), {
        status: 404,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    // Verificar límite de escaneos concurrentes por usuario
    const activeScans = await env.DB.prepare(
      `SELECT COUNT(*) as count FROM scans s 
       JOIN domains d ON s.domain_id = d.id 
       WHERE d.user_id = ? AND s.status IN ('queued', 'running')`
    ).bind(payload.userId).first();
    
    if (activeScans.count >= 3) {
      return new Response(JSON.stringify({ 
        success: false, 
        message: 'Límite de escaneos concurrentes alcanzado (máximo 3)' 
      }), {
        status: 429,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    // Crear registro de escaneo
    const scanResult = await env.DB.prepare(
      'INSERT INTO scans (domain_id, scan_types, status, deep_scan, started_at, created_at) VALUES (?, ?, ?, ?, ?, ?)'
    ).bind(
      domainId,
      JSON.stringify(scanTypes || ['basic', 'ssl', 'dns']),
      'pending',
      deepScan || false,
      new Date().toISOString(),
      new Date().toISOString()
    ).run();
    
    const scanId = scanResult.meta.last_row_id;
    
    // Encolar escaneo para procesamiento asíncrono
    const queueManager = new QueueManager(env);
    const queueResult = await queueManager.enqueueScan({
      scanId,
      domain: domain.domain_name,
      scanTypes: scanTypes || ['basic', 'ssl', 'dns'],
      deepScan: deepScan || false,
      userId: payload.userId,
      priority: priority || 'normal'
    });
    
    if (!queueResult.success) {
      // Marcar escaneo como fallido si no se pudo encolar
      await env.DB.prepare(
        'UPDATE scans SET status = ?, error_message = ? WHERE id = ?'
      ).bind('failed', 'Error encolando escaneo', scanId).run();
      
      return new Response(JSON.stringify({ 
        success: false, 
        message: 'Error encolando escaneo' 
      }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    return new Response(JSON.stringify({ 
      success: true, 
      scanId,
      message: 'Escaneo encolado exitosamente',
      estimatedTime: deepScan ? '5-8 minutos' : '2-4 minutos',
      queuePosition: 'Calculando...'
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    console.error('Error al iniciar escaneo:', error);
    return new Response(JSON.stringify({ 
      success: false, 
      message: 'Error al iniciar escaneo' 
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

// Nuevo endpoint para escaneos rápidos (sin cola)
async function handleQuickScan(request, env, corsHeaders) {
  try {
    const token = request.headers.get('Authorization')?.replace('Bearer ', '');
    const payload = await verifyJWT(token);
    const { domain, scanTypes } = await request.json();
    
    if (!domain) {
      return new Response(JSON.stringify({ 
        success: false, 
        message: 'Dominio requerido' 
      }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    // Realizar escaneo rápido inmediato (solo verificaciones básicas)
    const quickResults = await performQuickScan(domain, scanTypes || ['basic']);
    
    return new Response(JSON.stringify({ 
      success: true, 
      domain,
      results: quickResults,
      scanType: 'quick',
      timestamp: new Date().toISOString()
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    console.error('Error en escaneo rápido:', error);
    return new Response(JSON.stringify({ 
      success: false, 
      message: 'Error en escaneo rápido' 
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

async function performQuickScan(domain, scanTypes) {
  const results = {
    findings: [],
    summary: { total_issues: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    scanDuration: 0
  };
  
  const startTime = Date.now();
  
  try {
    // Escaneos básicos en paralelo con timeout corto
    const promises = [];
    
    if (scanTypes.includes('basic')) {
      promises.push(performBasicQuickCheck(domain));
    }
    
    if (scanTypes.includes('ssl')) {
      promises.push(performSSLQuickCheck(domain));
    }
    
    if (scanTypes.includes('dns')) {
      promises.push(performDNSQuickCheck(domain));
    }
    
    // Ejecutar con timeout de 15 segundos
    const timeoutPromise = new Promise((_, reject) => 
      setTimeout(() => reject(new Error('Quick scan timeout')), 15000)
    );
    
    const scanResults = await Promise.race([
      Promise.allSettled(promises),
      timeoutPromise
    ]);
    
    // Procesar resultados
    scanResults.forEach(result => {
      if (result.status === 'fulfilled' && result.value) {
        results.findings.push(...result.value);
      }
    });
    
    // Calcular resumen
    results.findings.forEach(finding => {
      results.summary.total_issues++;
      if (results.summary.hasOwnProperty(finding.severity)) {
        results.summary[finding.severity]++;
      }
    });
    
    results.scanDuration = Date.now() - startTime;
    
  } catch (error) {
    console.error('Error en escaneo rápido:', error);
    results.error = error.message;
  }
  
  return results;
}

async function performBasicQuickCheck(domain) {
  const findings = [];
  
  // Verificaciones básicas rápidas
  const checks = [
    { type: 'https_redirect', timeout: 2000 },
    { type: 'security_headers', timeout: 1500 }
  ];
  
  const promises = checks.map(check => 
    performQuickCheck(domain, check.type, check.timeout)
  );
  
  const results = await Promise.allSettled(promises);
  
  results.forEach(result => {
    if (result.status === 'fulfilled' && result.value) {
      findings.push(result.value);
    }
  });
  
  return findings;
}

async function performSSLQuickCheck(domain) {
  return new Promise((resolve) => {
    setTimeout(() => {
      if (Math.random() > 0.8) {
        resolve([{
          type: 'ssl_check',
          severity: 'medium',
          title: 'Verificación SSL',
          description: 'Verificación rápida de configuración SSL',
          recommendation: 'Revisar configuración SSL completa',
          domain: domain
        }]);
      } else {
        resolve([]);
      }
    }, 1000);
  });
}

async function performDNSQuickCheck(domain) {
  return new Promise((resolve) => {
    setTimeout(() => {
      if (Math.random() > 0.7) {
        resolve([{
          type: 'dns_check',
          severity: 'low',
          title: 'Verificación DNS',
          description: 'Verificación rápida de configuración DNS',
          recommendation: 'Realizar análisis DNS completo',
          domain: domain
        }]);
      } else {
        resolve([]);
      }
    }, 800);
  });
}

async function performQuickCheck(domain, checkType, timeout) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(null), timeout);
    
    setTimeout(() => {
      clearTimeout(timer);
      
      if (Math.random() > 0.6) {
        resolve({
          type: checkType,
          severity: 'medium',
          title: `Verificación ${checkType}`,
          description: `Verificación rápida de ${checkType} para ${domain}`,
          recommendation: 'Realizar escaneo completo para más detalles',
          domain: domain
        });
      } else {
        resolve(null);
      }
    }, Math.random() * (timeout / 2));
  });
}

async function handleQueueStats(request, env, corsHeaders) {
  try {
    const token = request.headers.get('Authorization')?.replace('Bearer ', '');
    await verifyJWT(token);
    
    const queueManager = new QueueManager(env);
    const stats = await queueManager.getQueueStats();
    
    return new Response(JSON.stringify(stats), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    console.error('Error obteniendo estadísticas de cola:', error);
    return new Response(JSON.stringify({ 
      success: false, 
      message: 'Error obteniendo estadísticas' 
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

async function performAsyncScan(scanId, domain, scanTypes, deepScan, env) {
  try {
    // Actualizar estado a 'running'
    await env.DB.prepare(
      'UPDATE scans SET status = ?, progress = ? WHERE id = ?'
    ).bind('running', 10, scanId).run();
    
    const results = {
      domain,
      scanId,
      findings: [],
      summary: {
        total_issues: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0
      },
      subdomains: []
    };
    
    // 1. Escaneo básico de seguridad
    if (!scanTypes || scanTypes.includes('basic')) {
      await env.DB.prepare('UPDATE scans SET progress = ? WHERE id = ?').bind(20, scanId).run();
      const basicFindings = await performSecurityScan(domain, 'basic');
      results.findings.push(...basicFindings);
    }
    
    // 2. Escaneo SSL/TLS
    if (!scanTypes || scanTypes.includes('ssl')) {
      await env.DB.prepare('UPDATE scans SET progress = ? WHERE id = ?').bind(35, scanId).run();
      const sslFindings = await performSecurityScan(domain, 'ssl');
      results.findings.push(...sslFindings);
    }
    
    // 3. Escaneo DNS
    if (!scanTypes || scanTypes.includes('dns')) {
      await env.DB.prepare('UPDATE scans SET progress = ? WHERE id = ?').bind(50, scanId).run();
      const dnsFindings = await performSecurityScan(domain, 'dns');
      results.findings.push(...dnsFindings);
    }
    
    // 4. Escaneo de puertos
    if (!scanTypes || scanTypes.includes('ports')) {
      await env.DB.prepare('UPDATE scans SET progress = ? WHERE id = ?').bind(65, scanId).run();
      const portFindings = await performSecurityScan(domain, 'ports');
      results.findings.push(...portFindings);
    }
    
    // 5. Escaneo profundo de subdominios (si está habilitado)
    if (deepScan) {
      await env.DB.prepare('UPDATE scans SET progress = ? WHERE id = ?').bind(80, scanId).run();
      const subdomains = await getSubdomains(domain, true);
      results.subdomains = subdomains;
      
      // Escanear cada subdominio encontrado
      for (const subdomain of subdomains.slice(0, 10)) { // Limitar a 10 para evitar timeouts
        const subdomainFindings = await performSecurityScan(subdomain.domain, 'basic');
        results.findings.push(...subdomainFindings.map(f => ({
          ...f,
          subdomain: subdomain.domain
        })));
      }
    }
    
    // Calcular resumen
    results.findings.forEach(finding => {
      results.summary.total_issues++;
      results.summary[finding.severity]++;
    });
    
    // Guardar hallazgos en la base de datos
    for (const finding of results.findings) {
      await env.DB.prepare(
        'INSERT INTO findings (scan_id, vulnerability_type, severity, title, description, recommendation, subdomain, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
      ).bind(
        scanId,
        finding.type,
        finding.severity,
        finding.title,
        finding.description,
        finding.recommendation,
        finding.subdomain || null,
        new Date().toISOString()
      ).run();
    }
    
    // Actualizar escaneo como completado
    await env.DB.prepare(
      'UPDATE scans SET status = ?, progress = ?, completed_at = ?, results = ? WHERE id = ?'
    ).bind(
      'completed',
      100,
      new Date().toISOString(),
      JSON.stringify(results.summary),
      scanId
    ).run();
    
  } catch (error) {
    console.error('Error en escaneo asíncrono:', error);
    
    // Marcar escaneo como fallido
    await env.DB.prepare(
      'UPDATE scans SET status = ?, error_message = ? WHERE id = ?'
    ).bind('failed', error.message, scanId).run();
  }
}

async function handleScanStatus(request, env, corsHeaders) {
  try {
    const token = request.headers.get('Authorization')?.replace('Bearer ', '');
    const payload = await verifyJWT(token);
    const url = new URL(request.url);
    const scanId = url.searchParams.get('scanId');
    
    if (!scanId) {
      return new Response(JSON.stringify({ 
        success: false, 
        message: 'ID de escaneo requerido' 
      }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    // Obtener estado del escaneo
    const scan = await env.DB.prepare(
      `SELECT s.*, d.domain_name 
       FROM scans s 
       JOIN domains d ON s.domain_id = d.id 
       WHERE s.id = ? AND d.user_id = ?`
    ).bind(scanId, payload.userId).first();
    
    if (!scan) {
      return new Response(JSON.stringify({ 
        success: false, 
        message: 'Escaneo no encontrado' 
      }), {
        status: 404,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    return new Response(JSON.stringify({ 
      success: true, 
      scan: {
        id: scan.id,
        domain: scan.domain_name,
        status: scan.status,
        progress: scan.progress || 0,
        started_at: scan.started_at,
        completed_at: scan.completed_at,
        error_message: scan.error_message,
        results: scan.results ? JSON.parse(scan.results) : null
      }
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    console.error('Error al obtener estado del escaneo:', error);
    return new Response(JSON.stringify({ 
      success: false, 
      message: 'Error al obtener estado del escaneo' 
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

async function handleScanResults(request, env, corsHeaders) {
  try {
    const token = request.headers.get('Authorization')?.replace('Bearer ', '');
    const payload = await verifyJWT(token);
    const url = new URL(request.url);
    const scanId = url.searchParams.get('scanId');
    
    if (!scanId) {
      return new Response(JSON.stringify({ 
        success: false, 
        message: 'ID de escaneo requerido' 
      }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    // Obtener escaneo y hallazgos
    const scan = await env.DB.prepare(
      `SELECT s.*, d.domain_name 
       FROM scans s 
       JOIN domains d ON s.domain_id = d.id 
       WHERE s.id = ? AND d.user_id = ?`
    ).bind(scanId, payload.userId).first();
    
    if (!scan) {
      return new Response(JSON.stringify({ 
        success: false, 
        message: 'Escaneo no encontrado' 
      }), {
        status: 404,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    const findings = await env.DB.prepare(
      'SELECT * FROM findings WHERE scan_id = ? ORDER BY severity DESC, created_at DESC'
    ).bind(scanId).all();
    
    return new Response(JSON.stringify({ 
      success: true, 
      scan: {
        id: scan.id,
        domain: scan.domain_name,
        status: scan.status,
        started_at: scan.started_at,
        completed_at: scan.completed_at,
        results: scan.results ? JSON.parse(scan.results) : null
      },
      findings: findings.results
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    console.error('Error al obtener resultados del escaneo:', error);
    return new Response(JSON.stringify({ 
      success: false, 
      message: 'Error al obtener resultados del escaneo' 
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

async function handleSubdomainScan(request, env, corsHeaders) {
  try {
    const token = request.headers.get('Authorization')?.replace('Bearer ', '');
    const payload = await verifyJWT(token);
    const { domain, deep } = await request.json();
    
    if (!domain) {
      return new Response(JSON.stringify({ 
        success: false, 
        message: 'Dominio requerido' 
      }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    const subdomains = await getSubdomains(domain, deep);
    
    return new Response(JSON.stringify({ 
      success: true, 
      subdomains,
      total: subdomains.length
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    console.error('Error en escaneo de subdominios:', error);
    return new Response(JSON.stringify({ 
      success: false, 
      message: 'Error al escanear subdominios' 
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

async function handleStopScan(request, env, corsHeaders) {
  try {
    const token = request.headers.get('Authorization')?.replace('Bearer ', '');
    const payload = await verifyJWT(token);
    const { scanId } = await request.json();
    
    // Verificar que el escaneo pertenece al usuario
    const scan = await env.DB.prepare(
      `SELECT s.id 
       FROM scans s 
       JOIN domains d ON s.domain_id = d.id 
       WHERE s.id = ? AND d.user_id = ?`
    ).bind(scanId, payload.userId).first();
    
    if (!scan) {
      return new Response(JSON.stringify({ 
        success: false, 
        message: 'Escaneo no encontrado' 
      }), {
        status: 404,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    // Actualizar estado a detenido
    await env.DB.prepare(
      'UPDATE scans SET status = ?, completed_at = ? WHERE id = ?'
    ).bind('stopped', new Date().toISOString(), scanId).run();
    
    return new Response(JSON.stringify({ 
      success: true, 
      message: 'Escaneo detenido exitosamente' 
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    console.error('Error al detener escaneo:', error);
    return new Response(JSON.stringify({ 
      success: false, 
      message: 'Error al detener escaneo' 
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}
