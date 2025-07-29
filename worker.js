// Aplicación de CyberSecurity Scanner para Cloudflare Workers
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
  const filePath = path.replace('/static/', '');
  
  // Determinar tipo de contenido
  let contentType = 'text/plain';
  if (filePath.endsWith('.css')) contentType = 'text/css';
  if (filePath.endsWith('.js')) contentType = 'application/javascript';
  if (filePath.endsWith('.png')) contentType = 'image/png';
  if (filePath.endsWith('.jpg') || filePath.endsWith('.jpeg')) contentType = 'image/jpeg';
  if (filePath.endsWith('.svg')) contentType = 'image/svg+xml';
  
  // Servir archivos estáticos incrustados
  if (filePath === 'css/main.css') {
    return new Response(getMainCSS(), {
      headers: { 
        'Content-Type': 'text/css',
        'Cache-Control': 'public, max-age=3600'
      }
    });
  }
  
  if (filePath === 'js/auth.js') {
    return new Response(getAuthJS(), {
      headers: { 
        'Content-Type': 'application/javascript',
        'Cache-Control': 'public, max-age=3600'
      }
    });
  }
  
  if (filePath === 'css/dashboard.css') {
    return new Response(getDashboardCSS(), {
      headers: { 
        'Content-Type': 'text/css',
        'Cache-Control': 'public, max-age=3600'
      }
    });
  }
  
  if (filePath === 'js/dashboard.js') {
    return new Response(getDashboardJS(), {
      headers: { 
        'Content-Type': 'application/javascript',
        'Cache-Control': 'public, max-age=3600'
      }
    });
  }
  
  return new Response('Archivo no encontrado', { 
    status: 404,
    headers: { 'Content-Type': contentType }
  });
}

// CSS incrustado
function getMainCSS() {
  return `
/* Estilos principales para CyberSecurity Scanner */
:root {
  --primary-color: #2563eb;
  --primary-dark: #1d4ed8;
  --secondary-color: #64748b;
  --success-color: #10b981;
  --warning-color: #f59e0b;
  --error-color: #ef4444;
  --critical-color: #dc2626;
  --background-color: #f8fafc;
  --surface-color: #ffffff;
  --text-primary: #1e293b;
  --text-secondary: #64748b;
  --border-color: #e2e8f0;
  --shadow-sm: 0 1px 2px 0 rgb(0 0 0 / 0.05);
  --shadow-md: 0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1);
  --shadow-lg: 0 10px 15px -3px rgb(0 0 0 / 0.1), 0 4px 6px -4px rgb(0 0 0 / 0.1);
  --radius-sm: 0.375rem;
  --radius-md: 0.5rem;
  --radius-lg: 0.75rem;
}

* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  color: var(--text-primary);
  line-height: 1.6;
  min-height: 100vh;
}

.login-container {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 100vh;
  padding: 1rem;
}

.login-form {
  background-color: var(--surface-color);
  padding: 2rem;
  border-radius: var(--radius-lg);
  box-shadow: var(--shadow-lg);
  width: 100%;
  max-width: 400px;
  text-align: center;
}

.login-form h1 {
  color: var(--primary-color);
  margin-bottom: 0.5rem;
  font-size: 1.875rem;
  font-weight: 700;
}

.login-form p {
  color: var(--text-secondary);
  margin-bottom: 2rem;
}

.login-form input {
  width: 100%;
  padding: 0.75rem;
  margin-bottom: 1rem;
  border: 1px solid var(--border-color);
  border-radius: var(--radius-md);
  font-size: 0.875rem;
  transition: border-color 0.2s ease, box-shadow 0.2s ease;
}

.login-form input:focus {
  outline: none;
  border-color: var(--primary-color);
  box-shadow: 0 0 0 3px rgb(37 99 235 / 0.1);
}

.login-form button {
  width: 100%;
  padding: 0.75rem;
  background-color: var(--primary-color);
  color: white;
  border: none;
  border-radius: var(--radius-md);
  font-size: 0.875rem;
  font-weight: 500;
  cursor: pointer;
  transition: background-color 0.2s ease, transform 0.1s ease;
  margin-bottom: 1rem;
}

.login-form button:hover {
  background-color: var(--primary-dark);
  transform: translateY(-1px);
}

.login-form button:active {
  transform: translateY(0);
}

.login-form a {
  color: var(--primary-color);
  text-decoration: none;
  font-size: 0.875rem;
}

.login-form a:hover {
  text-decoration: underline;
}

.alert {
  padding: 0.75rem;
  border-radius: var(--radius-md);
  margin-bottom: 1rem;
  border: 1px solid;
  font-size: 0.875rem;
}

.alert-success {
  background-color: #f0fdf4;
  border-color: #bbf7d0;
  color: #166534;
}

.alert-error {
  background-color: #fef2f2;
  border-color: #fecaca;
  color: #991b1b;
}

.loading-message {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  padding: 0.75rem;
  background-color: #eff6ff;
  border: 1px solid #bfdbfe;
  border-radius: var(--radius-md);
  color: #1e40af;
  margin-bottom: 1rem;
}

.spinner {
  display: inline-block;
  width: 1rem;
  height: 1rem;
  border: 2px solid var(--border-color);
  border-radius: 50%;
  border-top-color: var(--primary-color);
  animation: spin 1s ease-in-out infinite;
}

@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}

.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background-color: rgba(0, 0, 0, 0.5);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
}

.modal {
  background-color: var(--surface-color);
  border-radius: var(--radius-lg);
  box-shadow: var(--shadow-lg);
  max-width: 500px;
  width: 90%;
  max-height: 90vh;
  overflow-y: auto;
}

.modal-header {
  padding: 1.5rem;
  border-bottom: 1px solid var(--border-color);
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.modal-title {
  font-size: 1.25rem;
  font-weight: 600;
  margin: 0;
}

.modal-close {
  background: none;
  border: none;
  font-size: 1.5rem;
  cursor: pointer;
  color: var(--text-secondary);
}

.modal-body {
  padding: 1.5rem;
}

@media (max-width: 480px) {
  .login-form {
    padding: 1.5rem;
  }
  
  .modal {
    width: 95%;
  }
}
`;
}

// JavaScript incrustado
function getAuthJS() {
  return `
// Funcionalidad de autenticación
class AuthManager {
  constructor() {
    this.token = localStorage.getItem('auth_token');
    this.user = JSON.parse(localStorage.getItem('user') || 'null');
    this.init();
  }
  
  init() {
    this.setupLoginForm();
    this.setupRegisterForm();
    this.setupMFAForm();
    
    if (this.token && window.location.pathname === '/') {
      window.location.href = '/dashboard';
    }
  }
  
  setupLoginForm() {
    const loginForm = document.getElementById('loginForm');
    if (!loginForm) return;
    
    loginForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      await this.handleLogin(e.target);
    });
  }
  
  setupRegisterForm() {
    const registerForm = document.getElementById('registerForm');
    if (!registerForm) return;
    
    registerForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      await this.handleRegister(e.target);
    });
  }
  
  setupMFAForm() {
    const mfaForm = document.getElementById('mfaForm');
    if (!mfaForm) return;
    
    mfaForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      await this.handleMFAVerification(e.target);
    });
  }
  
  async handleLogin(form) {
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    const mfaCode = document.getElementById('mfaCode')?.value;
    
    if (!email || !password) {
      this.showError('Por favor, completa todos los campos');
      return;
    }
    
    this.showLoading('Iniciando sesión...');
    
    try {
      const response = await fetch('/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          email,
          password,
          mfaCode
        })
      });
      
      const data = await response.json();
      
      if (data.success) {
        this.token = data.token;
        this.user = data.user;
        
        localStorage.setItem('auth_token', this.token);
        localStorage.setItem('user', JSON.stringify(this.user));
        
        this.showSuccess('¡Inicio de sesión exitoso!');
        
        setTimeout(() => {
          window.location.href = '/dashboard';
        }, 1000);
        
      } else if (data.requiresMFA) {
        this.showMFAForm();
      } else {
        this.showError(data.message || 'Error al iniciar sesión');
      }
      
    } catch (error) {
      console.error('Error en login:', error);
      this.showError('Error de conexión. Inténtalo de nuevo.');
    } finally {
      this.hideLoading();
    }
  }
  
  async handleRegister(form) {
    const username = document.getElementById('username').value;
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    
    if (!username || !email || !password) {
      this.showError('Por favor, completa todos los campos');
      return;
    }
    
    if (!this.validateEmail(email)) {
      this.showError('Por favor, ingresa un email válido');
      return;
    }
    
    if (password.length < 6) {
      this.showError('La contraseña debe tener al menos 6 caracteres');
      return;
    }
    
    this.showLoading('Creando cuenta...');
    
    try {
      const response = await fetch('/auth/register', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          username,
          email,
          password
        })
      });
      
      const data = await response.json();
      
      if (data.success) {
        this.showSuccess('¡Cuenta creada exitosamente! Ahora puedes iniciar sesión.');
        
        setTimeout(() => {
          window.location.href = '/';
        }, 2000);
        
      } else {
        this.showError(data.message || 'Error al crear la cuenta');
      }
      
    } catch (error) {
      console.error('Error en registro:', error);
      this.showError('Error de conexión. Inténtalo de nuevo.');
    } finally {
      this.hideLoading();
    }
  }
  
  showMFAForm() {
    const loginForm = document.querySelector('.login-form');
    if (!loginForm) return;
    
    loginForm.innerHTML = \`
      <h1>Verificación MFA</h1>
      <p>Ingresa el código de tu aplicación de autenticación</p>
      <form id="mfaForm">
        <input type="text" id="mfaCode" placeholder="Código MFA (6 dígitos)" maxlength="6" required>
        <button type="submit">Verificar</button>
      </form>
      <p><a href="/" onclick="location.reload()">Volver al login</a></p>
    \`;
    
    this.setupMFAForm();
  }
  
  validateEmail(email) {
    const emailRegex = /^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/;
    return emailRegex.test(email);
  }
  
  showLoading(message) {
    this.removeMessages();
    const container = document.querySelector('.login-form');
    const loading = document.createElement('div');
    loading.className = 'loading-message';
    loading.innerHTML = \`
      <div class="spinner"></div>
      <span>\${message}</span>
    \`;
    container.appendChild(loading);
  }
  
  hideLoading() {
    const loading = document.querySelector('.loading-message');
    if (loading) loading.remove();
  }
  
  showError(message) {
    this.removeMessages();
    const container = document.querySelector('.login-form');
    const error = document.createElement('div');
    error.className = 'alert alert-error';
    error.textContent = message;
    container.appendChild(error);
    
    setTimeout(() => error.remove(), 5000);
  }
  
  showSuccess(message) {
    this.removeMessages();
    const container = document.querySelector('.login-form');
    const success = document.createElement('div');
    success.className = 'alert alert-success';
    success.textContent = message;
    container.appendChild(success);
    
    setTimeout(() => success.remove(), 5000);
  }
  
  removeMessages() {
    const messages = document.querySelectorAll('.alert, .loading-message');
    messages.forEach(msg => msg.remove());
  }
}

// Crear instancia global del gestor de autenticación
const authManager = new AuthManager();
window.authManager = authManager;
`;
}

// CSS del dashboard
function getDashboardCSS() {
  return `
/* Estilos del Dashboard */
.dashboard-container {
  display: flex;
  min-height: 100vh;
  background-color: var(--background-color);
}

.sidebar {
  width: 250px;
  background-color: var(--surface-color);
  border-right: 1px solid var(--border-color);
  padding: 1rem;
}

.main-content {
  flex: 1;
  padding: 2rem;
}

.dashboard-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 2rem;
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 1rem;
  margin-bottom: 2rem;
}

.stat-card {
  background-color: var(--surface-color);
  padding: 1.5rem;
  border-radius: var(--radius-lg);
  box-shadow: var(--shadow-sm);
  border: 1px solid var(--border-color);
}

.stat-value {
  font-size: 2rem;
  font-weight: 700;
  color: var(--primary-color);
}

.stat-label {
  color: var(--text-secondary);
  font-size: 0.875rem;
}

.chart-container {
  background-color: var(--surface-color);
  padding: 1.5rem;
  border-radius: var(--radius-lg);
  box-shadow: var(--shadow-sm);
  border: 1px solid var(--border-color);
  margin-bottom: 2rem;
}
`;
}

// JavaScript del dashboard
function getDashboardJS() {
  return `
// Funcionalidad del Dashboard
class DashboardManager {
  constructor() {
    this.init();
  }
  
  init() {
    this.loadDashboardData();
    this.setupEventListeners();
  }
  
  async loadDashboardData() {
    try {
      const response = await authManager.authenticatedFetch('/api/dashboard/stats');
      const data = await response.json();
      
      if (data.success) {
        this.updateStats(data.stats);
        this.updateCharts(data.charts);
      }
    } catch (error) {
      console.error('Error cargando datos del dashboard:', error);
    }
  }
  
  updateStats(stats) {
    // Actualizar estadísticas en la interfaz
    console.log('Actualizando estadísticas:', stats);
  }
  
  updateCharts(charts) {
    // Actualizar gráficos
    console.log('Actualizando gráficos:', charts);
  }
  
  setupEventListeners() {
    // Configurar event listeners
    console.log('Dashboard inicializado');
  }
}

// Inicializar dashboard cuando la página esté lista
document.addEventListener('DOMContentLoaded', () => {
  if (window.location.pathname === '/dashboard') {
    new DashboardManager();
  }
});
`;
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
