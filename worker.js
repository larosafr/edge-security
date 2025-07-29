import { handleAuth } from './src/handlers/auth.js';
import { handleDomains } from './src/handlers/domains.js';
import { handleScanner } from './src/handlers/scanner.js';
import { handleDashboard } from './src/handlers/dashboard.js';
import { initDatabase } from './src/utils/database.js';
import { validateSession } from './src/utils/security.js';
import { QueueManager } from './src/utils/queue-manager.js';

export default {
  async fetch(request, env, ctx) {
    try {
      // Inicializar base de datos
      await initDatabase(env.DB);
      
      const url = new URL(request.url);
      const path = url.pathname;
      
      // Configurar CORS
      const corsHeaders = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      };
      
      if (request.method === 'OPTIONS') {
        return new Response(null, { headers: corsHeaders });
      }
      
      // Rutas públicas (no requieren autenticación)
      const publicRoutes = ['/login', '/register', '/static/', '/'];
      const isPublicRoute = publicRoutes.some(route => path.startsWith(route));
      
      // Validar sesión para rutas protegidas
      if (!isPublicRoute) {
        const sessionValid = await validateSession(request, env.SESSIONS);
        if (!sessionValid) {
          return new Response('No autorizado', { 
            status: 401,
            headers: corsHeaders 
          });
        }
      }
      
      // Enrutamiento
      if (path.startsWith('/auth/') || path === '/login' || path === '/register') {
        return await handleAuth(request, env, corsHeaders);
      }
      
      if (path.startsWith('/api/domains/')) {
        return await handleDomains(request, env, corsHeaders);
      }
      
      if (path.startsWith('/api/scanner/')) {
        return await handleScanner(request, env, corsHeaders);
      }
      
      if (path.startsWith('/api/dashboard/') || path === '/dashboard') {
        return await handleDashboard(request, env, corsHeaders);
      }
      
      if (path.startsWith('/static/')) {
        return await handleStaticFiles(path, env);
      }
      
      // Página principal
      if (path === '/') {
        return await serveLoginPage();
      }
      
      // 404 para rutas no encontradas
      return new Response('No encontrado', { 
        status: 404,
        headers: corsHeaders 
      });
      
    } catch (error) {
      console.error('Error en worker:', error);
      return new Response('Error interno del servidor', { 
        status: 500,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Content-Type': 'text/plain'
        }
      });
    }
  },

  // Manejador de colas para procesamiento asíncrono de escaneos
  async queue(batch, env) {
    const queueManager = new QueueManager(env);
    
    try {
      console.log(`Procesando batch de ${batch.messages.length} escaneos`);
      
      const results = await queueManager.processScanBatch(batch.messages);
      
      // Log de resultados para monitoreo
      const successful = results.filter(r => r.status === 'fulfilled').length;
      const failed = results.filter(r => r.status === 'rejected').length;
      
      console.log(`Batch completado: ${successful} exitosos, ${failed} fallidos`);
      
      // Marcar mensajes como procesados
      batch.messages.forEach(message => {
        message.ack();
      });
      
    } catch (error) {
      console.error('Error procesando batch de escaneos:', error);
      
      // Marcar mensajes como fallidos para reintento
      batch.messages.forEach(message => {
        message.retry();
      });
    }
  }
};

async function handleStaticFiles(path, env) {
  // Servir archivos estáticos
  const filePath = path.replace('/static/', '');
  
  // Determinar tipo de contenido
  let contentType = 'text/plain';
  if (filePath.endsWith('.css')) contentType = 'text/css';
  if (filePath.endsWith('.js')) contentType = 'application/javascript';
  if (filePath.endsWith('.png')) contentType = 'image/png';
  if (filePath.endsWith('.jpg') || filePath.endsWith('.jpeg')) contentType = 'image/jpeg';
  if (filePath.endsWith('.svg')) contentType = 'image/svg+xml';
  
  // En un entorno real, los archivos estáticos se servirían desde KV o R2
  return new Response('Archivo estático no encontrado', { 
    status: 404,
    headers: { 'Content-Type': contentType }
  });
}

async function serveLoginPage() {
  const loginHTML = `
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberSecurity Scanner - Login</title>
    <link rel="stylesheet" href="/static/css/main.css">
</head>
<body>
    <div class="login-container">
        <div class="login-form">
            <h1>CyberSecurity Scanner</h1>
            <p>Análisis de seguridad de dominios</p>
            <form id="loginForm">
                <input type="email" id="email" placeholder="Email" required>
                <input type="password" id="password" placeholder="Contraseña" required>
                <button type="submit">Iniciar Sesión</button>
            </form>
            <p><a href="/register">¿No tienes cuenta? Regístrate</a></p>
        </div>
    </div>
    <script src="/static/js/auth.js"></script>
</body>
</html>`;
  
  return new Response(loginHTML, {
    headers: { 'Content-Type': 'text/html' }
  });
}
