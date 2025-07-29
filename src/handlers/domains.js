import { verifyJWT } from '../utils/security.js';

export async function handleDomains(request, env, corsHeaders) {
  const url = new URL(request.url);
  const path = url.pathname;
  
  if (path === '/api/domains/search' && request.method === 'POST') {
    return await handleDomainSearch(request, env, corsHeaders);
  }
  
  if (path === '/api/domains/add' && request.method === 'POST') {
    return await handleAddDomain(request, env, corsHeaders);
  }
  
  if (path === '/api/domains/list' && request.method === 'GET') {
    return await handleListDomains(request, env, corsHeaders);
  }
  
  if (path === '/api/domains/delete' && request.method === 'DELETE') {
    return await handleDeleteDomain(request, env, corsHeaders);
  }
  
  if (path === '/api/domains/validate' && request.method === 'POST') {
    return await handleValidateDomain(request, env, corsHeaders);
  }
  
  return new Response('Ruta no encontrada', { 
    status: 404, 
    headers: corsHeaders 
  });
}

async function handleDomainSearch(request, env, corsHeaders) {
  try {
    const token = request.headers.get('Authorization')?.replace('Bearer ', '');
    const payload = await verifyJWT(token);
    const { query } = await request.json();
    
    if (!query || query.length < 2) {
      return new Response(JSON.stringify({ 
        success: false, 
        message: 'La consulta debe tener al menos 2 caracteres' 
      }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    // Buscar dominios relacionados usando múltiples fuentes
    const domains = await searchDomains(query);
    
    return new Response(JSON.stringify({ 
      success: true, 
      domains,
      total: domains.length
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    console.error('Error en búsqueda de dominios:', error);
    return new Response(JSON.stringify({ 
      success: false, 
      message: 'Error al buscar dominios' 
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

async function searchDomains(query) {
  const domains = [];
  
  // 1. Búsqueda directa del dominio
  const mainDomain = query.toLowerCase().replace(/[^a-z0-9.-]/g, '');
  if (isValidDomain(mainDomain)) {
    domains.push({
      domain: mainDomain,
      type: 'main',
      source: 'direct',
      verified: false
    });
  }
  
  // 2. Variaciones comunes del dominio
  const variations = generateDomainVariations(mainDomain);
  variations.forEach(variation => {
    if (isValidDomain(variation)) {
      domains.push({
        domain: variation,
        type: 'variation',
        source: 'generated',
        verified: false
      });
    }
  });
  
  // 3. Búsqueda en Certificate Transparency Logs (simulado)
  const ctDomains = await searchCertificateTransparency(query);
  ctDomains.forEach(domain => {
    domains.push({
      domain: domain,
      type: 'certificate',
      source: 'ct_logs',
      verified: false
    });
  });
  
  // 4. Búsqueda DNS reversa (simulado)
  const reverseDomains = await searchReverseDNS(query);
  reverseDomains.forEach(domain => {
    domains.push({
      domain: domain,
      type: 'reverse_dns',
      source: 'dns',
      verified: false
    });
  });
  
  // Eliminar duplicados y limitar resultados
  const uniqueDomains = domains.filter((domain, index, self) => 
    index === self.findIndex(d => d.domain === domain.domain)
  ).slice(0, 50);
  
  return uniqueDomains;
}

function generateDomainVariations(domain) {
  const variations = [];
  const parts = domain.split('.');
  
  if (parts.length >= 2) {
    const name = parts[0];
    const tld = parts.slice(1).join('.');
    
    // TLDs comunes
    const commonTlds = ['com', 'net', 'org', 'info', 'biz', 'co', 'io', 'app'];
    commonTlds.forEach(newTld => {
      if (newTld !== tld) {
        variations.push(`${name}.${newTld}`);
      }
    });
    
    // Prefijos y sufijos comunes
    const prefixes = ['www', 'mail', 'ftp', 'admin', 'api', 'app', 'dev', 'test'];
    const suffixes = ['app', 'api', 'web', 'site', 'online', 'digital'];
    
    prefixes.forEach(prefix => {
      variations.push(`${prefix}.${domain}`);
    });
    
    suffixes.forEach(suffix => {
      variations.push(`${name}-${suffix}.${tld}`);
      variations.push(`${name}${suffix}.${tld}`);
    });
  }
  
  return variations;
}

async function searchCertificateTransparency(query) {
  // En un entorno real, esto consultaría APIs como crt.sh
  // Por ahora, simulamos algunos resultados
  const mockResults = [
    `*.${query}`,
    `mail.${query}`,
    `www.${query}`,
    `api.${query}`,
    `admin.${query}`
  ];
  
  return mockResults.filter(domain => isValidDomain(domain.replace('*.', '')));
}

async function searchReverseDNS(query) {
  // En un entorno real, esto haría búsquedas DNS reversas
  // Por ahora, simulamos algunos resultados
  const mockResults = [
    `${query.split('.')[0]}.example.com`,
    `${query.split('.')[0]}-backup.com`,
    `old-${query}`
  ];
  
  return mockResults.filter(domain => isValidDomain(domain));
}

function isValidDomain(domain) {
  const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
  return domainRegex.test(domain) && domain.length <= 253;
}

async function handleAddDomain(request, env, corsHeaders) {
  try {
    const token = request.headers.get('Authorization')?.replace('Bearer ', '');
    const payload = await verifyJWT(token);
    const { domain, name } = await request.json();
    
    if (!domain || !isValidDomain(domain)) {
      return new Response(JSON.stringify({ 
        success: false, 
        message: 'Dominio inválido' 
      }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    // Verificar si el dominio ya existe para este usuario
    const existingDomain = await env.DB.prepare(
      'SELECT id FROM domains WHERE user_id = ? AND domain_name = ?'
    ).bind(payload.userId, domain).first();
    
    if (existingDomain) {
      return new Response(JSON.stringify({ 
        success: false, 
        message: 'El dominio ya está agregado' 
      }), {
        status: 409,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    // Validar dominio antes de agregarlo
    const validation = await validateDomainOwnership(domain);
    
    // Agregar dominio a la base de datos
    const result = await env.DB.prepare(
      'INSERT INTO domains (user_id, domain_name, display_name, status, validation_status, created_at) VALUES (?, ?, ?, ?, ?, ?)'
    ).bind(
      payload.userId, 
      domain, 
      name || domain, 
      'active',
      validation.valid ? 'verified' : 'pending',
      new Date().toISOString()
    ).run();
    
    return new Response(JSON.stringify({ 
      success: true, 
      message: 'Dominio agregado exitosamente',
      domainId: result.meta.last_row_id,
      validation
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    console.error('Error al agregar dominio:', error);
    return new Response(JSON.stringify({ 
      success: false, 
      message: 'Error al agregar dominio' 
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

async function handleListDomains(request, env, corsHeaders) {
  try {
    const token = request.headers.get('Authorization')?.replace('Bearer ', '');
    const payload = await verifyJWT(token);
    
    const domains = await env.DB.prepare(
      'SELECT * FROM domains WHERE user_id = ? ORDER BY created_at DESC'
    ).bind(payload.userId).all();
    
    return new Response(JSON.stringify({ 
      success: true, 
      domains: domains.results
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    console.error('Error al listar dominios:', error);
    return new Response(JSON.stringify({ 
      success: false, 
      message: 'Error al obtener dominios' 
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

async function handleDeleteDomain(request, env, corsHeaders) {
  try {
    const token = request.headers.get('Authorization')?.replace('Bearer ', '');
    const payload = await verifyJWT(token);
    const { domainId } = await request.json();
    
    // Verificar que el dominio pertenece al usuario
    const domain = await env.DB.prepare(
      'SELECT id FROM domains WHERE id = ? AND user_id = ?'
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
    
    // Eliminar dominio y sus escaneos relacionados
    await env.DB.prepare('DELETE FROM findings WHERE scan_id IN (SELECT id FROM scans WHERE domain_id = ?)').bind(domainId).run();
    await env.DB.prepare('DELETE FROM scans WHERE domain_id = ?').bind(domainId).run();
    await env.DB.prepare('DELETE FROM domains WHERE id = ?').bind(domainId).run();
    
    return new Response(JSON.stringify({ 
      success: true, 
      message: 'Dominio eliminado exitosamente' 
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    console.error('Error al eliminar dominio:', error);
    return new Response(JSON.stringify({ 
      success: false, 
      message: 'Error al eliminar dominio' 
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

async function handleValidateDomain(request, env, corsHeaders) {
  try {
    const { domain } = await request.json();
    
    if (!domain || !isValidDomain(domain)) {
      return new Response(JSON.stringify({ 
        success: false, 
        message: 'Dominio inválido' 
      }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    const validation = await validateDomainOwnership(domain);
    
    return new Response(JSON.stringify({ 
      success: true, 
      validation
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    console.error('Error al validar dominio:', error);
    return new Response(JSON.stringify({ 
      success: false, 
      message: 'Error al validar dominio' 
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

async function validateDomainOwnership(domain) {
  try {
    // En un entorno real, esto haría verificaciones DNS reales
    // Por ahora, simulamos la validación
    
    const validation = {
      valid: true,
      accessible: true,
      ssl_valid: true,
      dns_records: {
        a: ['192.168.1.1'],
        mx: ['mail.' + domain],
        ns: ['ns1.' + domain, 'ns2.' + domain]
      },
      whois: {
        registrar: 'Example Registrar',
        creation_date: '2020-01-01',
        expiration_date: '2025-01-01'
      },
      security_headers: {
        hsts: false,
        csp: false,
        x_frame_options: true
      }
    };
    
    // Simular algunas validaciones que podrían fallar
    if (domain.includes('invalid')) {
      validation.valid = false;
      validation.accessible = false;
    }
    
    return validation;
    
  } catch (error) {
    return {
      valid: false,
      accessible: false,
      error: error.message
    };
  }
}
