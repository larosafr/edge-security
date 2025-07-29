import { hashPassword, verifyPassword, generateJWT, verifyJWT } from '../utils/security.js';
import { authenticator } from 'otplib';
import QRCode from 'qrcode';

export async function handleAuth(request, env, corsHeaders) {
  const url = new URL(request.url);
  const path = url.pathname;
  
  if (path === '/auth/login' && request.method === 'POST') {
    return await handleLogin(request, env, corsHeaders);
  }
  
  if (path === '/auth/register' && request.method === 'POST') {
    return await handleRegister(request, env, corsHeaders);
  }
  
  if (path === '/auth/setup-mfa' && request.method === 'POST') {
    return await handleSetupMFA(request, env, corsHeaders);
  }
  
  if (path === '/auth/verify-mfa' && request.method === 'POST') {
    return await handleVerifyMFA(request, env, corsHeaders);
  }
  
  if (path === '/auth/logout' && request.method === 'POST') {
    return await handleLogout(request, env, corsHeaders);
  }
  
  if (path === '/register') {
    return await serveRegisterPage();
  }
  
  return new Response('Ruta no encontrada', { 
    status: 404, 
    headers: corsHeaders 
  });
}

async function handleLogin(request, env, corsHeaders) {
  try {
    const { email, password, mfaCode } = await request.json();
    
    // Buscar usuario en la base de datos
    const user = await env.DB.prepare(
      'SELECT * FROM users WHERE email = ?'
    ).bind(email).first();
    
    if (!user) {
      return new Response(JSON.stringify({ 
        success: false, 
        message: 'Credenciales inválidas' 
      }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    // Verificar contraseña
    const passwordValid = await verifyPassword(password, user.password_hash);
    if (!passwordValid) {
      return new Response(JSON.stringify({ 
        success: false, 
        message: 'Credenciales inválidas' 
      }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    // Si el usuario tiene MFA habilitado, verificar código
    if (user.mfa_secret) {
      if (!mfaCode) {
        return new Response(JSON.stringify({ 
          success: false, 
          requiresMFA: true,
          message: 'Se requiere código MFA' 
        }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }
      
      const mfaValid = authenticator.verify({
        token: mfaCode,
        secret: user.mfa_secret
      });
      
      if (!mfaValid) {
        return new Response(JSON.stringify({ 
          success: false, 
          message: 'Código MFA inválido' 
        }), {
          status: 401,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }
    }
    
    // Generar JWT
    const token = await generateJWT({ 
      userId: user.id, 
      email: user.email 
    });
    
    // Guardar sesión en KV
    await env.SESSIONS.put(`session_${user.id}`, token, { expirationTtl: 86400 });
    
    return new Response(JSON.stringify({ 
      success: true, 
      token,
      user: {
        id: user.id,
        email: user.email,
        username: user.username
      }
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    console.error('Error en login:', error);
    return new Response(JSON.stringify({ 
      success: false, 
      message: 'Error interno del servidor' 
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

async function handleRegister(request, env, corsHeaders) {
  try {
    const { username, email, password } = await request.json();
    
    // Validar datos
    if (!username || !email || !password) {
      return new Response(JSON.stringify({ 
        success: false, 
        message: 'Todos los campos son requeridos' 
      }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    // Verificar si el usuario ya existe
    const existingUser = await env.DB.prepare(
      'SELECT id FROM users WHERE email = ?'
    ).bind(email).first();
    
    if (existingUser) {
      return new Response(JSON.stringify({ 
        success: false, 
        message: 'El usuario ya existe' 
      }), {
        status: 409,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    // Hash de la contraseña
    const passwordHash = await hashPassword(password);
    
    // Crear usuario
    const result = await env.DB.prepare(
      'INSERT INTO users (username, email, password_hash, created_at) VALUES (?, ?, ?, ?)'
    ).bind(username, email, passwordHash, new Date().toISOString()).run();
    
    return new Response(JSON.stringify({ 
      success: true, 
      message: 'Usuario creado exitosamente',
      userId: result.meta.last_row_id
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    console.error('Error en registro:', error);
    return new Response(JSON.stringify({ 
      success: false, 
      message: 'Error interno del servidor' 
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

async function handleSetupMFA(request, env, corsHeaders) {
  try {
    const token = request.headers.get('Authorization')?.replace('Bearer ', '');
    const payload = await verifyJWT(token);
    
    // Generar secreto MFA
    const secret = authenticator.generateSecret();
    const service = 'CyberSecurity Scanner';
    const account = payload.email;
    
    const otpauth = authenticator.keyuri(account, service, secret);
    const qrCode = await QRCode.toDataURL(otpauth);
    
    // Guardar secreto temporalmente (se confirmará con verify-mfa)
    await env.CACHE.put(`mfa_setup_${payload.userId}`, secret, { expirationTtl: 300 });
    
    return new Response(JSON.stringify({ 
      success: true, 
      secret,
      qrCode,
      manualEntryKey: secret
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    console.error('Error en setup MFA:', error);
    return new Response(JSON.stringify({ 
      success: false, 
      message: 'Error al configurar MFA' 
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

async function handleVerifyMFA(request, env, corsHeaders) {
  try {
    const token = request.headers.get('Authorization')?.replace('Bearer ', '');
    const payload = await verifyJWT(token);
    const { code } = await request.json();
    
    // Obtener secreto temporal
    const secret = await env.CACHE.get(`mfa_setup_${payload.userId}`);
    if (!secret) {
      return new Response(JSON.stringify({ 
        success: false, 
        message: 'Sesión de configuración MFA expirada' 
      }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    // Verificar código
    const isValid = authenticator.verify({
      token: code,
      secret: secret
    });
    
    if (!isValid) {
      return new Response(JSON.stringify({ 
        success: false, 
        message: 'Código MFA inválido' 
      }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    // Guardar secreto en la base de datos
    await env.DB.prepare(
      'UPDATE users SET mfa_secret = ? WHERE id = ?'
    ).bind(secret, payload.userId).run();
    
    // Limpiar caché temporal
    await env.CACHE.delete(`mfa_setup_${payload.userId}`);
    
    return new Response(JSON.stringify({ 
      success: true, 
      message: 'MFA configurado exitosamente' 
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    console.error('Error en verificación MFA:', error);
    return new Response(JSON.stringify({ 
      success: false, 
      message: 'Error al verificar MFA' 
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

async function handleLogout(request, env, corsHeaders) {
  try {
    const token = request.headers.get('Authorization')?.replace('Bearer ', '');
    const payload = await verifyJWT(token);
    
    // Eliminar sesión
    await env.SESSIONS.delete(`session_${payload.userId}`);
    
    return new Response(JSON.stringify({ 
      success: true, 
      message: 'Sesión cerrada exitosamente' 
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    return new Response(JSON.stringify({ 
      success: true, 
      message: 'Sesión cerrada' 
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

async function serveRegisterPage() {
  const registerHTML = `
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberSecurity Scanner - Registro</title>
    <link rel="stylesheet" href="/static/css/main.css">
</head>
<body>
    <div class="login-container">
        <div class="login-form">
            <h1>Crear Cuenta</h1>
            <p>Únete a CyberSecurity Scanner</p>
            <form id="registerForm">
                <input type="text" id="username" placeholder="Nombre de usuario" required>
                <input type="email" id="email" placeholder="Email" required>
                <input type="password" id="password" placeholder="Contraseña" required>
                <button type="submit">Registrarse</button>
            </form>
            <p><a href="/login">¿Ya tienes cuenta? Inicia sesión</a></p>
        </div>
    </div>
    <script src="/static/js/auth.js"></script>
</body>
</html>`;
  
  return new Response(registerHTML, {
    headers: { 'Content-Type': 'text/html' }
  });
}
