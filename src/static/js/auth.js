// Funcionalidad de autenticación

class AuthManager {
  constructor() {
    this.token = localStorage.getItem('auth_token');
    this.user = JSON.parse(localStorage.getItem('user') || 'null');
    this.init();
  }
  
  init() {
    // Configurar formularios de login y registro
    this.setupLoginForm();
    this.setupRegisterForm();
    this.setupMFAForm();
    
    // Verificar si ya está autenticado
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
    const formData = new FormData(form);
    const email = formData.get('email') || document.getElementById('email').value;
    const password = formData.get('password') || document.getElementById('password').value;
    const mfaCode = formData.get('mfaCode') || document.getElementById('mfaCode')?.value;
    
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
    const formData = new FormData(form);
    const username = formData.get('username') || document.getElementById('username').value;
    const email = formData.get('email') || document.getElementById('email').value;
    const password = formData.get('password') || document.getElementById('password').value;
    
    if (!username || !email || !password) {
      this.showError('Por favor, completa todos los campos');
      return;
    }
    
    if (!this.validateEmail(email)) {
      this.showError('Por favor, ingresa un email válido');
      return;
    }
    
    if (!this.validatePassword(password)) {
      this.showError('La contraseña debe tener al menos 8 caracteres, una mayúscula, una minúscula y un número');
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
  
  async handleMFAVerification(form) {
    const formData = new FormData(form);
    const mfaCode = formData.get('mfaCode') || document.getElementById('mfaCode').value;
    
    if (!mfaCode) {
      this.showError('Por favor, ingresa el código MFA');
      return;
    }
    
    // Reenviar login con código MFA
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    
    await this.handleLogin({ 
      querySelector: (selector) => {
        if (selector === '#email') return { value: email };
        if (selector === '#password') return { value: password };
        if (selector === '#mfaCode') return { value: mfaCode };
        return null;
      }
    });
  }
  
  showMFAForm() {
    const loginForm = document.querySelector('.login-form');
    if (!loginForm) return;
    
    loginForm.innerHTML = `
      <h1>Verificación MFA</h1>
      <p>Ingresa el código de tu aplicación de autenticación</p>
      <form id="mfaForm">
        <input type="text" id="mfaCode" placeholder="Código MFA (6 dígitos)" maxlength="6" required>
        <button type="submit">Verificar</button>
      </form>
      <p><a href="/" onclick="location.reload()">Volver al login</a></p>
    `;
    
    this.setupMFAForm();
  }
  
  async logout() {
    try {
      if (this.token) {
        await fetch('/auth/logout', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${this.token}`,
            'Content-Type': 'application/json',
          }
        });
      }
    } catch (error) {
      console.error('Error en logout:', error);
    } finally {
      this.token = null;
      this.user = null;
      localStorage.removeItem('auth_token');
      localStorage.removeItem('user');
      window.location.href = '/';
    }
  }
  
  async setupMFA() {
    if (!this.token) {
      this.showError('Debes estar autenticado para configurar MFA');
      return;
    }
    
    try {
      const response = await fetch('/auth/setup-mfa', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${this.token}`,
          'Content-Type': 'application/json',
        }
      });
      
      const data = await response.json();
      
      if (data.success) {
        this.showMFASetup(data.qrCode, data.secret);
      } else {
        this.showError(data.message || 'Error al configurar MFA');
      }
      
    } catch (error) {
      console.error('Error configurando MFA:', error);
      this.showError('Error de conexión. Inténtalo de nuevo.');
    }
  }
  
  showMFASetup(qrCode, secret) {
    const modal = this.createModal('Configurar MFA', `
      <div class="mfa-setup">
        <p>Escanea este código QR con tu aplicación de autenticación:</p>
        <div class="qr-code">
          <img src="${qrCode}" alt="Código QR MFA">
        </div>
        <p>O ingresa manualmente esta clave:</p>
        <div class="manual-key">
          <code>${secret}</code>
          <button onclick="navigator.clipboard.writeText('${secret}')">Copiar</button>
        </div>
        <form id="verifyMFAForm">
          <input type="text" id="verifyMFACode" placeholder="Código de verificación" maxlength="6" required>
          <button type="submit">Verificar y Activar</button>
        </form>
      </div>
    `);
    
    document.getElementById('verifyMFAForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      await this.verifyMFASetup(document.getElementById('verifyMFACode').value);
      modal.remove();
    });
  }
  
  async verifyMFASetup(code) {
    try {
      const response = await fetch('/auth/verify-mfa', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${this.token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ code })
      });
      
      const data = await response.json();
      
      if (data.success) {
        this.showSuccess('¡MFA configurado exitosamente!');
      } else {
        this.showError(data.message || 'Código MFA inválido');
      }
      
    } catch (error) {
      console.error('Error verificando MFA:', error);
      this.showError('Error de conexión. Inténtalo de nuevo.');
    }
  }
  
  validateEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }
  
  validatePassword(password) {
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d@$!%*?&]{8,}$/;
    return passwordRegex.test(password);
  }
  
  showLoading(message) {
    this.removeMessages();
    const container = document.querySelector('.login-form') || document.body;
    const loading = document.createElement('div');
    loading.className = 'loading-message';
    loading.innerHTML = `
      <div class="spinner"></div>
      <span>${message}</span>
    `;
    container.appendChild(loading);
  }
  
  hideLoading() {
    const loading = document.querySelector('.loading-message');
    if (loading) loading.remove();
  }
  
  showError(message) {
    this.removeMessages();
    const container = document.querySelector('.login-form') || document.body;
    const error = document.createElement('div');
    error.className = 'alert alert-error';
    error.textContent = message;
    container.appendChild(error);
    
    setTimeout(() => error.remove(), 5000);
  }
  
  showSuccess(message) {
    this.removeMessages();
    const container = document.querySelector('.login-form') || document.body;
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
  
  createModal(title, content) {
    const modal = document.createElement('div');
    modal.className = 'modal-overlay';
    modal.innerHTML = `
      <div class="modal">
        <div class="modal-header">
          <h3 class="modal-title">${title}</h3>
          <button class="modal-close">&times;</button>
        </div>
        <div class="modal-body">
          ${content}
        </div>
      </div>
    `;
    
    modal.querySelector('.modal-close').addEventListener('click', () => {
      modal.remove();
    });
    
    modal.addEventListener('click', (e) => {
      if (e.target === modal) {
        modal.remove();
      }
    });
    
    document.body.appendChild(modal);
    return modal;
  }
  
  // Método para hacer peticiones autenticadas
  async authenticatedFetch(url, options = {}) {
    if (!this.token) {
      throw new Error('No hay token de autenticación');
    }
    
    const defaultOptions = {
      headers: {
        'Authorization': `Bearer ${this.token}`,
        'Content-Type': 'application/json',
        ...options.headers
      }
    };
    
    const response = await fetch(url, { ...options, ...defaultOptions });
    
    if (response.status === 401) {
      // Token expirado o inválido
      this.logout();
      throw new Error('Sesión expirada');
    }
    
    return response;
  }
  
  // Verificar si el usuario está autenticado
  isAuthenticated() {
    return !!this.token;
  }
  
  // Obtener información del usuario actual
  getCurrentUser() {
    return this.user;
  }
  
  // Actualizar información del usuario
  updateUser(userData) {
    this.user = { ...this.user, ...userData };
    localStorage.setItem('user', JSON.stringify(this.user));
  }
}

// Crear instancia global del gestor de autenticación
const authManager = new AuthManager();

// Configurar logout button si existe
document.addEventListener('DOMContentLoaded', () => {
  const logoutBtn = document.getElementById('logoutBtn');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', () => {
      authManager.logout();
    });
  }
  
  // Configurar botón de MFA si existe
  const setupMFABtn = document.getElementById('setupMFABtn');
  if (setupMFABtn) {
    setupMFABtn.addEventListener('click', () => {
      authManager.setupMFA();
    });
  }
});

// Exportar para uso en otros archivos
window.authManager = authManager;
