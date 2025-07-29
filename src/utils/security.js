import bcrypt from 'bcryptjs';

// Configuración JWT (en un entorno real, esto debería estar en variables de entorno)
const JWT_SECRET = 'your-super-secret-jwt-key-change-this-in-production';
const JWT_EXPIRY = '24h';

export async function hashPassword(password) {
  const saltRounds = 12;
  return await bcrypt.hash(password, saltRounds);
}

export async function verifyPassword(password, hash) {
  return await bcrypt.compare(password, hash);
}

export async function generateJWT(payload) {
  const header = {
    alg: 'HS256',
    typ: 'JWT'
  };
  
  const now = Math.floor(Date.now() / 1000);
  const jwtPayload = {
    ...payload,
    iat: now,
    exp: now + (24 * 60 * 60) // 24 horas
  };
  
  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(jwtPayload));
  
  const signature = await sign(`${encodedHeader}.${encodedPayload}`, JWT_SECRET);
  
  return `${encodedHeader}.${encodedPayload}.${signature}`;
}

export async function verifyJWT(token) {
  if (!token) {
    throw new Error('Token no proporcionado');
  }
  
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error('Token JWT inválido');
  }
  
  const [encodedHeader, encodedPayload, signature] = parts;
  
  // Verificar firma
  const expectedSignature = await sign(`${encodedHeader}.${encodedPayload}`, JWT_SECRET);
  if (signature !== expectedSignature) {
    throw new Error('Firma JWT inválida');
  }
  
  // Decodificar payload
  const payload = JSON.parse(base64UrlDecode(encodedPayload));
  
  // Verificar expiración
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp && payload.exp < now) {
    throw new Error('Token JWT expirado');
  }
  
  return payload;
}

export async function validateSession(request, sessionsKV) {
  try {
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return false;
    }
    
    const token = authHeader.replace('Bearer ', '');
    const payload = await verifyJWT(token);
    
    // Verificar que la sesión existe en KV
    const sessionToken = await sessionsKV.get(`session_${payload.userId}`);
    if (!sessionToken || sessionToken !== token) {
      return false;
    }
    
    return true;
  } catch (error) {
    console.error('Error validando sesión:', error);
    return false;
  }
}

export function generateSecureToken(length = 32) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  
  return result;
}

export function sanitizeInput(input) {
  if (typeof input !== 'string') {
    return input;
  }
  
  return input
    .replace(/[<>]/g, '') // Remover caracteres HTML básicos
    .replace(/javascript:/gi, '') // Remover javascript:
    .replace(/on\w+=/gi, '') // Remover event handlers
    .trim();
}

export function validateEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

export function validatePassword(password) {
  // Al menos 8 caracteres, una mayúscula, una minúscula, un número
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d@$!%*?&]{8,}$/;
  return passwordRegex.test(password);
}

export function rateLimitKey(ip, endpoint) {
  return `ratelimit:${ip}:${endpoint}`;
}

export async function checkRateLimit(key, limit, window, kv) {
  const current = await kv.get(key);
  const count = current ? parseInt(current) : 0;
  
  if (count >= limit) {
    return false;
  }
  
  await kv.put(key, (count + 1).toString(), { expirationTtl: window });
  return true;
}

export function getClientIP(request) {
  return request.headers.get('CF-Connecting-IP') || 
         request.headers.get('X-Forwarded-For') || 
         request.headers.get('X-Real-IP') || 
         '127.0.0.1';
}

export function generateCSPHeader() {
  return "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self'; font-src 'self' https:; object-src 'none'; media-src 'self'; frame-src 'none';";
}

export function securityHeaders() {
  return {
    'Content-Security-Policy': generateCSPHeader(),
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
  };
}

// Funciones auxiliares para JWT
function base64UrlEncode(str) {
  return btoa(str)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

function base64UrlDecode(str) {
  str += '='.repeat((4 - str.length % 4) % 4);
  return atob(str.replace(/-/g, '+').replace(/_/g, '/'));
}

async function sign(data, secret) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
  return base64UrlEncode(String.fromCharCode(...new Uint8Array(signature)));
}

// Utilidades para validación de dominios
export function isValidDomain(domain) {
  const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
  return domainRegex.test(domain) && domain.length <= 253;
}

export function isValidIP(ip) {
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
  return ipv4Regex.test(ip) || ipv6Regex.test(ip);
}

export function sanitizeDomain(domain) {
  return domain
    .toLowerCase()
    .replace(/[^a-z0-9.-]/g, '')
    .replace(/^\.+|\.+$/g, '');
}

// Utilidades para logging de seguridad
export function logSecurityEvent(event, details, env) {
  const logEntry = {
    timestamp: new Date().toISOString(),
    event: event,
    details: details,
    severity: getSeverityLevel(event)
  };
  
  console.log('SECURITY_EVENT:', JSON.stringify(logEntry));
  
  // En un entorno real, esto se enviaría a un sistema de logging centralizado
  return logEntry;
}

function getSeverityLevel(event) {
  const severityMap = {
    'login_failed': 'medium',
    'login_success': 'info',
    'mfa_failed': 'high',
    'token_expired': 'low',
    'rate_limit_exceeded': 'medium',
    'suspicious_activity': 'high',
    'unauthorized_access': 'critical'
  };
  
  return severityMap[event] || 'info';
}

// Utilidades para encriptación adicional
export async function encryptSensitiveData(data, key) {
  const encoder = new TextEncoder();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    encoder.encode(key),
    'AES-GCM',
    false,
    ['encrypt']
  );
  
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    cryptoKey,
    encoder.encode(data)
  );
  
  return {
    encrypted: Array.from(new Uint8Array(encrypted)),
    iv: Array.from(iv)
  };
}

export async function decryptSensitiveData(encryptedData, key) {
  const decoder = new TextDecoder();
  const encoder = new TextEncoder();
  
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    encoder.encode(key),
    'AES-GCM',
    false,
    ['decrypt']
  );
  
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: new Uint8Array(encryptedData.iv) },
    cryptoKey,
    new Uint8Array(encryptedData.encrypted)
  );
  
  return decoder.decode(decrypted);
}
