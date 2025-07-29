// Funcionalidad principal del dashboard

class Dashboard {
  constructor() {
    this.currentSection = 'overview';
    this.charts = {};
    this.refreshInterval = null;
    this.init();
  }
  
  init() {
    // Verificar autenticación
    if (!authManager.isAuthenticated()) {
      window.location.href = '/';
      return;
    }
    
    this.setupNavigation();
    this.setupMobileMenu();
    this.loadDashboardData();
    this.startAutoRefresh();
    
    // Configurar event listeners
    this.setupEventListeners();
  }
  
  setupNavigation() {
    const navLinks = document.querySelectorAll('.nav-link');
    
    navLinks.forEach(link => {
      link.addEventListener('click', (e) => {
        e.preventDefault();
        const sectionId = link.getAttribute('href').substring(1);
        this.showSection(sectionId);
        
        // Actualizar navegación activa
        navLinks.forEach(l => l.classList.remove('active'));
        link.classList.add('active');
      });
    });
  }
  
  setupMobileMenu() {
    // Crear botón de menú móvil si no existe
    if (!document.querySelector('.mobile-menu-toggle')) {
      const toggleBtn = document.createElement('button');
      toggleBtn.className = 'mobile-menu-toggle';
      toggleBtn.innerHTML = '☰';
      document.body.appendChild(toggleBtn);
      
      toggleBtn.addEventListener('click', () => {
        const sidebar = document.querySelector('.sidebar');
        sidebar.classList.toggle('open');
      });
    }
  }
  
  setupEventListeners() {
    // Botón para agregar dominio
    const addDomainBtn = document.getElementById('addDomainBtn');
    if (addDomainBtn) {
      addDomainBtn.addEventListener('click', () => {
        this.showAddDomainModal();
      });
    }
    
    // Configurar logout
    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) {
      logoutBtn.addEventListener('click', () => {
        authManager.logout();
      });
    }
  }
  
  showSection(sectionId) {
    // Ocultar todas las secciones
    const sections = document.querySelectorAll('.content-section');
    sections.forEach(section => {
      section.classList.remove('active');
    });
    
    // Mostrar sección seleccionada
    const targetSection = document.getElementById(`${sectionId}-section`);
    if (targetSection) {
      targetSection.classList.add('active');
      this.currentSection = sectionId;
      
      // Cargar datos específicos de la sección
      this.loadSectionData(sectionId);
    }
  }
  
  async loadDashboardData() {
    try {
      this.showLoading();
      
      // Cargar datos del overview
      await this.loadOverviewData();
      
      // Cargar datos de la sección actual
      if (this.currentSection !== 'overview') {
        await this.loadSectionData(this.currentSection);
      }
      
    } catch (error) {
      console.error('Error cargando datos del dashboard:', error);
      this.showError('Error al cargar los datos del dashboard');
    } finally {
      this.hideLoading();
    }
  }
  
  async loadOverviewData() {
    try {
      const response = await authManager.authenticatedFetch('/api/dashboard/overview');
      const data = await response.json();
      
      if (data.success) {
        this.updateOverviewStats(data.stats);
        this.updateRecentScans(data.stats.recent_scans);
        await this.loadCharts();
      }
      
    } catch (error) {
      console.error('Error cargando overview:', error);
    }
  }
  
  updateOverviewStats(stats) {
    // Actualizar contadores principales
    this.updateStatCard('domainsCount', stats.domains);
    this.updateStatCard('scansCount', stats.total_scans);
    this.updateStatCard('activeScansCount', stats.active_scans);
    this.updateStatCard('securityScore', `${stats.security_score}/100`);
    
    // Actualizar grado de seguridad
    const scoreElement = document.getElementById('securityScore');
    if (scoreElement) {
      const grade = this.getSecurityGrade(stats.security_score);
      scoreElement.className = `stat-number score-grade ${grade}`;
    }
  }
  
  updateStatCard(elementId, value) {
    const element = document.getElementById(elementId);
    if (element) {
      element.textContent = value;
      element.classList.add('fade-in');
    }
  }
  
  getSecurityGrade(score) {
    if (score >= 90) return 'A';
    if (score >= 80) return 'B';
    if (score >= 70) return 'C';
    if (score >= 60) return 'D';
    return 'F';
  }
  
  updateRecentScans(scans) {
    const container = document.getElementById('recentScansList');
    if (!container) return;
    
    if (!scans || scans.length === 0) {
      container.innerHTML = `
        <div class="empty-state">
          <p>No hay escaneos recientes</p>
          <button class="btn btn-primary" onclick="dashboard.showSection('domains')">
            Agregar Dominio
          </button>
        </div>
      `;
      return;
    }
    
    container.innerHTML = scans.map(scan => `
      <div class="scan-item">
        <div class="scan-info">
          <div class="scan-domain">${scan.domain}</div>
          <div class="scan-meta">
            <span class="scan-date">${this.formatDate(scan.created_at)}</span>
            <div class="scan-status">
              <span class="status-indicator ${scan.status}"></span>
              <span>${this.getStatusText(scan.status)}</span>
            </div>
          </div>
        </div>
        <div class="scan-results">
          ${this.renderVulnerabilitySummary(scan.results)}
        </div>
      </div>
    `).join('');
  }
  
  renderVulnerabilitySummary(results) {
    if (!results) return '<span class="text-secondary">Procesando...</span>';
    
    const total = results.total_issues || 0;
    if (total === 0) return '<span class="text-success">Sin problemas</span>';
    
    return `
      <div class="vuln-summary">
        ${results.critical ? `<span class="badge badge-critical">${results.critical}</span>` : ''}
        ${results.high ? `<span class="badge badge-high">${results.high}</span>` : ''}
        ${results.medium ? `<span class="badge badge-medium">${results.medium}</span>` : ''}
        ${results.low ? `<span class="badge badge-low">${results.low}</span>` : ''}
      </div>
    `;
  }
  
  async loadCharts() {
    try {
      const response = await authManager.authenticatedFetch('/api/dashboard/metrics?range=30d');
      const data = await response.json();
      
      if (data.success) {
        this.createVulnerabilitiesChart(data.metrics.vulnerabilities_by_type);
        this.createScansChart(data.metrics.scans_by_day);
      }
      
    } catch (error) {
      console.error('Error cargando gráficos:', error);
    }
  }
  
  createVulnerabilitiesChart(data) {
    const ctx = document.getElementById('vulnerabilitiesChart');
    if (!ctx || !data) return;
    
    // Destruir gráfico existente si existe
    if (this.charts.vulnerabilities) {
      this.charts.vulnerabilities.destroy();
    }
    
    this.charts.vulnerabilities = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: data.map(item => item.vulnerability_type),
        datasets: [{
          data: data.map(item => item.count),
          backgroundColor: [
            '#ef4444', // Critical
            '#f97316', // High
            '#f59e0b', // Medium
            '#3b82f6', // Low
            '#6b7280'  // Info
          ],
          borderWidth: 2,
          borderColor: '#ffffff'
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'bottom',
            labels: {
              padding: 20,
              usePointStyle: true
            }
          }
        }
      }
    });
  }
  
  createScansChart(data) {
    const ctx = document.getElementById('scansChart');
    if (!ctx || !data) return;
    
    // Destruir gráfico existente si existe
    if (this.charts.scans) {
      this.charts.scans.destroy();
    }
    
    this.charts.scans = new Chart(ctx, {
      type: 'line',
      data: {
        labels: data.map(item => this.formatDate(item.date)),
        datasets: [{
          label: 'Escaneos',
          data: data.map(item => item.count),
          borderColor: '#3b82f6',
          backgroundColor: 'rgba(59, 130, 246, 0.1)',
          borderWidth: 2,
          fill: true,
          tension: 0.4
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          y: {
            beginAtZero: true,
            ticks: {
              stepSize: 1
            }
          }
        },
        plugins: {
          legend: {
            display: false
          }
        }
      }
    });
  }
  
  async loadSectionData(sectionId) {
    switch (sectionId) {
      case 'domains':
        await this.loadDomainsData();
        break;
      case 'scans':
        await this.loadScansData();
        break;
      case 'vulnerabilities':
        await this.loadVulnerabilitiesData();
        break;
    }
  }
  
  async loadDomainsData() {
    try {
      const response = await authManager.authenticatedFetch('/api/domains/list');
      const data = await response.json();
      
      if (data.success) {
        this.renderDomainsList(data.domains);
      }
      
    } catch (error) {
      console.error('Error cargando dominios:', error);
    }
  }
  
  renderDomainsList(domains) {
    const container = document.getElementById('domainsList');
    if (!container) return;
    
    if (!domains || domains.length === 0) {
      container.innerHTML = `
        <div class="empty-state">
          <div class="empty-state-icon">🌐</div>
          <h3 class="empty-state-title">No hay dominios agregados</h3>
          <p class="empty-state-description">Agrega tu primer dominio para comenzar a escanearlo</p>
          <button class="btn btn-primary" onclick="dashboard.showAddDomainModal()">
            Agregar Dominio
          </button>
        </div>
      `;
      return;
    }
    
    container.innerHTML = `
      <div class="domain-grid">
        ${domains.map(domain => this.renderDomainCard(domain)).join('')}
      </div>
    `;
  }
  
  renderDomainCard(domain) {
    return `
      <div class="domain-card">
        <div class="domain-header">
          <div class="domain-name">${domain.display_name || domain.domain_name}</div>
          <div class="domain-actions">
            <button class="btn btn-sm btn-primary" onclick="dashboard.startScan(${domain.id})">
              Escanear
            </button>
            <button class="btn btn-sm btn-outline" onclick="dashboard.showDomainDetails(${domain.id})">
              Ver
            </button>
            <button class="btn btn-sm btn-error" onclick="dashboard.deleteDomain(${domain.id})">
              Eliminar
            </button>
          </div>
        </div>
        <div class="domain-meta">
          <div>Dominio: ${domain.domain_name}</div>
          <div>Estado: <span class="badge badge-${domain.status === 'active' ? 'success' : 'warning'}">${domain.status}</span></div>
        </div>
        <div class="domain-stats">
          <div class="last-scan">
            ${domain.last_scan_at ? `Último escaneo: ${this.formatDate(domain.last_scan_at)}` : 'Sin escaneos'}
          </div>
        </div>
      </div>
    `;
  }
  
  showAddDomainModal() {
    const modal = this.createModal('Agregar Dominio', `
      <form id="addDomainForm">
        <div class="form-group">
          <label class="form-label">Buscar Dominios</label>
          <input type="text" id="domainSearch" class="form-input" placeholder="Ingresa nombre o empresa">
          <button type="button" id="searchDomainsBtn" class="btn btn-secondary mt-2">Buscar</button>
        </div>
        
        <div id="searchResults" class="hidden">
          <h4>Dominios Encontrados:</h4>
          <div id="domainResults"></div>
        </div>
        
        <div class="form-group">
          <label class="form-label">O agregar dominio específico:</label>
          <input type="text" id="specificDomain" class="form-input" placeholder="ejemplo.com">
        </div>
        
        <div class="form-group">
          <label class="form-label">Nombre para mostrar (opcional)</label>
          <input type="text" id="displayName" class="form-input" placeholder="Mi Empresa">
        </div>
      </form>
    `, [
      { text: 'Cancelar', class: 'btn-secondary', action: 'close' },
      { text: 'Agregar', class: 'btn-primary', action: 'submit' }
    ]);
    
    // Configurar búsqueda de dominios
    document.getElementById('searchDomainsBtn').addEventListener('click', async () => {
      const query = document.getElementById('domainSearch').value;
      if (query) {
        await this.searchDomains(query);
      }
    });
    
    // Configurar envío del formulario
    modal.querySelector('.btn-primary').addEventListener('click', async () => {
      await this.addDomain();
      modal.remove();
    });
  }
  
  async searchDomains(query) {
    try {
      this.showLoading('Buscando dominios...');
      
      const response = await authManager.authenticatedFetch('/api/domains/search', {
        method: 'POST',
        body: JSON.stringify({ query })
      });
      
      const data = await response.json();
      
      if (data.success) {
        this.displaySearchResults(data.domains);
      } else {
        this.showError(data.message);
      }
      
    } catch (error) {
      console.error('Error buscando dominios:', error);
      this.showError('Error al buscar dominios');
    } finally {
      this.hideLoading();
    }
  }
  
  displaySearchResults(domains) {
    const resultsContainer = document.getElementById('domainResults');
    const searchResults = document.getElementById('searchResults');
    
    if (!domains || domains.length === 0) {
      resultsContainer.innerHTML = '<p>No se encontraron dominios</p>';
      searchResults.classList.remove('hidden');
      return;
    }
    
    resultsContainer.innerHTML = domains.map(domain => `
      <div class="domain-result">
        <label class="form-checkbox">
          <input type="checkbox" name="selectedDomains" value="${domain.domain}">
          <span>${domain.domain}</span>
          <small class="text-secondary">(${domain.type} - ${domain.source})</small>
        </label>
      </div>
    `).join('');
    
    searchResults.classList.remove('hidden');
  }
  
  async addDomain() {
    const selectedDomains = Array.from(document.querySelectorAll('input[name="selectedDomains"]:checked'))
      .map(cb => cb.value);
    
    const specificDomain = document.getElementById('specificDomain').value;
    const displayName = document.getElementById('displayName').value;
    
    const domainsToAdd = selectedDomains.length > 0 ? selectedDomains : 
      specificDomain ? [specificDomain] : [];
    
    if (domainsToAdd.length === 0) {
      this.showError('Selecciona al menos un dominio');
      return;
    }
    
    try {
      this.showLoading('Agregando dominios...');
      
      for (const domain of domainsToAdd) {
        const response = await authManager.authenticatedFetch('/api/domains/add', {
          method: 'POST',
          body: JSON.stringify({
            domain: domain,
            name: displayName || domain
          })
        });
        
        const data = await response.json();
        if (!data.success) {
          console.error(`Error agregando ${domain}:`, data.message);
        }
      }
      
      this.showSuccess('Dominios agregados exitosamente');
      await this.loadDomainsData();
      
    } catch (error) {
      console.error('Error agregando dominios:', error);
      this.showError('Error al agregar dominios');
    } finally {
      this.hideLoading();
    }
  }
  
  async startScan(domainId) {
    const modal = this.createModal('Configurar Escaneo', `
      <form id="scanConfigForm">
        <div class="form-group">
          <label class="form-label">Tipos de escaneo:</label>
          <div class="form-checkbox">
            <input type="checkbox" id="basicScan" checked>
            <label for="basicScan">Escaneo básico de seguridad</label>
          </div>
          <div class="form-checkbox">
            <input type="checkbox" id="sslScan" checked>
            <label for="sslScan">Análisis SSL/TLS</label>
          </div>
          <div class="form-checkbox">
            <input type="checkbox" id="dnsScan" checked>
            <label for="dnsScan">Análisis DNS</label>
          </div>
          <div class="form-checkbox">
            <input type="checkbox" id="portScan">
            <label for="portScan">Escaneo de puertos</label>
          </div>
        </div>
        
        <div class="form-group">
          <div class="form-checkbox">
            <input type="checkbox" id="deepScan">
            <label for="deepScan">Escaneo profundo de subdominios (toma más tiempo)</label>
          </div>
        </div>
      </form>
    `, [
      { text: 'Cancelar', class: 'btn-secondary', action: 'close' },
      { text: 'Iniciar Escaneo', class: 'btn-primary', action: 'submit' }
    ]);
    
    modal.querySelector('.btn-primary').addEventListener('click', async () => {
      await this.executeScan(domainId);
      modal.remove();
    });
  }
  
  async executeScan(domainId) {
    const scanTypes = [];
    if (document.getElementById('basicScan').checked) scanTypes.push('basic');
    if (document.getElementById('sslScan').checked) scanTypes.push('ssl');
    if (document.getElementById('dnsScan').checked) scanTypes.push('dns');
    if (document.getElementById('portScan').checked) scanTypes.push('ports');
    
    const deepScan = document.getElementById('deepScan').checked;
    
    try {
      const response = await authManager.authenticatedFetch('/api/scanner/start', {
        method: 'POST',
        body: JSON.stringify({
          domainId,
          scanTypes,
          deepScan
        })
      });
      
      const data = await response.json();
      
      if (data.success) {
        this.showSuccess(`Escaneo iniciado. Tiempo estimado: ${data.estimatedTime}`);
        this.monitorScan(data.scanId);
      } else {
        this.showError(data.message);
      }
      
    } catch (error) {
      console.error('Error iniciando escaneo:', error);
      this.showError('Error al iniciar el escaneo');
    }
  }
  
  async monitorScan(scanId) {
    const modal = this.createModal('Escaneo en Progreso', `
      <div class="scan-progress">
        <div class="scan-progress-bar">
          <div class="scan-progress-fill" id="progressFill" style="width: 0%"></div>
        </div>
        <div class="scan-progress-text" id="progressText">Iniciando escaneo...</div>
      </div>
      <div id="scanLogs"></div>
    `, [
      { text: 'Ejecutar en segundo plano', class: 'btn-secondary', action: 'close' }
    ]);
    
    const checkProgress = async () => {
      try {
        const response = await authManager.authenticatedFetch(`/api/scanner/status?scanId=${scanId}`);
        const data = await response.json();
        
        if (data.success) {
          const scan = data.scan;
          const progressFill = document.getElementById('progressFill');
          const progressText = document.getElementById('progressText');
          
          if (progressFill) {
            progressFill.style.width = `${scan.progress || 0}%`;
          }
          
          if (progressText) {
            progressText.textContent = `${scan.progress || 0}% - ${this.getStatusText(scan.status)}`;
          }
          
          if (scan.status === 'completed') {
            this.showSuccess('¡Escaneo completado!');
            modal.remove();
            await this.loadDashboardData();
          } else if (scan.status === 'failed') {
            this.showError('El escaneo falló: ' + scan.error_message);
            modal.remove();
          } else {
            setTimeout(checkProgress, 2000);
          }
        }
        
      } catch (error) {
        console.error('Error monitoreando escaneo:', error);
        modal.remove();
      }
    };
    
    checkProgress();
  }
  
  getStatusText(status) {
    const statusMap = {
      'pending': 'Pendiente',
      'running': 'Ejecutándose',
      'completed': 'Completado',
      'failed': 'Fallido',
      'stopped': 'Detenido'
    };
    return statusMap[status] || status;
  }
  
  formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString('es-ES', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  }
  
  startAutoRefresh() {
    // Refrescar datos cada 30 segundos
    this.refreshInterval = setInterval(() => {
      if (this.currentSection === 'overview') {
        this.loadOverviewData();
      }
    }, 30000);
  }
  
  stopAutoRefresh() {
    if (this.refreshInterval) {
      clearInterval(this.refreshInterval);
      this.refreshInterval = null;
    }
  }
  
  // Métodos de utilidad para UI
  showLoading(message = 'Cargando...') {
    const loading = document.createElement('div');
    loading.id = 'globalLoading';
    loading.className = 'loading-container';
    loading.innerHTML = `
      <div class="loading-spinner"></div>
      <div class="loading-text">${message}</div>
    `;
    document.body.appendChild(loading);
  }
  
  hideLoading() {
    const loading = document.getElementById('globalLoading');
    if (loading) loading.remove();
  }
  
  showError(message) {
    this.showToast(message, 'error');
  }
  
  showSuccess(message) {
    this.showToast(message, 'success');
  }
  
  showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    
    document.body.appendChild(toast);
    
    setTimeout(() => {
      toast.remove();
    }, 5000);
  }
  
  createModal(title, content, buttons = []) {
    const modal = document.createElement('div');
    modal.className = 'modal-overlay';
    
    const buttonsHtml = buttons.map(btn => 
      `<button class="btn ${btn.class}" data-action="${btn.action}">${btn.text}</button>`
    ).join('');
    
    modal.innerHTML = `
      <div class="modal">
        <div class="modal-header">
          <h3 class="modal-title">${title}</h3>
          <button class="modal-close">&times;</button>
        </div>
        <div class="modal-body">
          ${content}
        </div>
        ${buttons.length > 0 ? `<div class="modal-footer">${buttonsHtml}</div>` : ''}
      </div>
    `;
    
    // Configurar cierre del modal
    modal.querySelector('.modal-close').addEventListener('click', () => {
      modal.remove();
    });
    
    modal.addEventListener('click', (e) => {
      if (e.target === modal) {
        modal.remove();
      }
    });
    
    // Configurar botones
    buttons.forEach(btn => {
      if (btn.action === 'close') {
        modal.querySelector(`[data-action="${btn.action}"]`).addEventListener('click', () => {
          modal.remove();
        });
      }
    });
    
    document.body.appendChild(modal);
    return modal;
  }
  
  // Cleanup al salir
  destroy() {
    this.stopAutoRefresh();
    
    // Destruir gráficos
    Object.values(this.charts).forEach(chart => {
      if (chart && typeof chart.destroy === 'function') {
        chart.destroy();
      }
    });
  }
}

// Inicializar dashboard cuando el DOM esté listo
document.addEventListener('DOMContentLoaded', () => {
  window.dashboard = new Dashboard();
});

// Cleanup al salir de la página
window.addEventListener('beforeunload', () => {
  if (window.dashboard) {
    window.dashboard.destroy();
  }
});
