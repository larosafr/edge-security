// Sistema de colas optimizado para escaneos paralelos en Cloudflare Workers

export class QueueManager {
  constructor(env) {
    this.env = env;
    this.maxConcurrentScans = 5;
    this.scanTimeout = 25000; // 25 segundos para dejar margen
  }
  
  // Encolar escaneo para procesamiento asíncrono
  async enqueueScan(scanData) {
    try {
      const queueMessage = {
        scanId: scanData.scanId,
        domain: scanData.domain,
        scanTypes: scanData.scanTypes,
        deepScan: scanData.deepScan,
        userId: scanData.userId,
        priority: scanData.deepScan ? 'high' : 'normal',
        timestamp: Date.now()
      };
      
      await this.env.SCAN_QUEUE_PRODUCER.send(queueMessage);
      
      // Marcar escaneo como encolado en la base de datos
      await this.env.DB.prepare(
        'UPDATE scans SET status = ?, progress = ?, updated_at = ? WHERE id = ?'
      ).bind('queued', 5, new Date().toISOString(), scanData.scanId).run();
      
      return { success: true, message: 'Escaneo encolado exitosamente' };
      
    } catch (error) {
      console.error('Error encolando escaneo:', error);
      throw error;
    }
  }
  
  // Procesar batch de escaneos de la cola
  async processScanBatch(messages) {
    const results = [];
    
    // Procesar mensajes en paralelo con límite de concurrencia
    const chunks = this.chunkArray(messages, this.maxConcurrentScans);
    
    for (const chunk of chunks) {
      const promises = chunk.map(message => this.processSingleScan(message));
      const chunkResults = await Promise.allSettled(promises);
      results.push(...chunkResults);
    }
    
    return results;
  }
  
  // Procesar un escaneo individual
  async processSingleScan(message) {
    const startTime = Date.now();
    let scanResult = null;
    
    try {
      const scanData = message.body;
      
      // Actualizar estado a 'running'
      await this.updateScanStatus(scanData.scanId, 'running', 10);
      
      // Crear scanner optimizado
      const scanner = new OptimizedScanner(this.env, this.scanTimeout);
      
      // Ejecutar escaneo con timeout
      scanResult = await Promise.race([
        scanner.performOptimizedScan(scanData),
        this.createTimeoutPromise(this.scanTimeout)
      ]);
      
      // Guardar resultados
      await this.saveScanResults(scanData.scanId, scanResult);
      
      // Marcar como completado
      await this.updateScanStatus(scanData.scanId, 'completed', 100, scanResult.summary);
      
      return { success: true, scanId: scanData.scanId, duration: Date.now() - startTime };
      
    } catch (error) {
      console.error(`Error procesando escaneo ${message.body?.scanId}:`, error);
      
      // Marcar como fallido
      if (message.body?.scanId) {
        await this.updateScanStatus(message.body.scanId, 'failed', 0, null, error.message);
      }
      
      // Si es timeout, reencolar con prioridad baja
      if (error.message.includes('timeout')) {
        await this.requeueScan(message.body, 'low');
      }
      
      return { success: false, error: error.message, scanId: message.body?.scanId };
    }
  }
  
  async updateScanStatus(scanId, status, progress, results = null, errorMessage = null) {
    try {
      let query = 'UPDATE scans SET status = ?, progress = ?, updated_at = ?';
      let params = [status, progress, new Date().toISOString()];
      
      if (status === 'completed' && results) {
        query += ', completed_at = ?, results = ?';
        params.push(new Date().toISOString(), JSON.stringify(results));
      }
      
      if (errorMessage) {
        query += ', error_message = ?';
        params.push(errorMessage);
      }
      
      query += ' WHERE id = ?';
      params.push(scanId);
      
      await this.env.DB.prepare(query).bind(...params).run();
    } catch (error) {
      console.error('Error actualizando estado del escaneo:', error);
    }
  }
  
  async saveScanResults(scanId, scanResult) {
    try {
      // Guardar hallazgos en batch para eficiencia
      if (scanResult.findings && scanResult.findings.length > 0) {
        const batchSize = 50;
        const chunks = this.chunkArray(scanResult.findings, batchSize);
        
        for (const chunk of chunks) {
          const values = chunk.map(() => '(?, ?, ?, ?, ?, ?, ?, ?)').join(', ');
          const params = [];
          
          chunk.forEach(finding => {
            params.push(
              scanId,
              finding.type,
              finding.severity,
              finding.title,
              finding.description,
              finding.recommendation,
              finding.subdomain || null,
              new Date().toISOString()
            );
          });
          
          await this.env.DB.prepare(
            `INSERT INTO findings 
             (scan_id, vulnerability_type, severity, title, description, recommendation, subdomain, created_at) 
             VALUES ${values}`
          ).bind(...params).run();
        }
      }
      
      // Guardar subdominios encontrados
      if (scanResult.subdomains && scanResult.subdomains.length > 0) {
        // Obtener domain_id del escaneo
        const scan = await this.env.DB.prepare(
          'SELECT domain_id FROM scans WHERE id = ?'
        ).bind(scanId).first();
        
        if (scan) {
          const batchSize = 50;
          const chunks = this.chunkArray(scanResult.subdomains, batchSize);
          
          for (const chunk of chunks) {
            const values = chunk.map(() => '(?, ?, ?, ?, ?)').join(', ');
            const params = [];
            
            chunk.forEach(subdomain => {
              params.push(
                scan.domain_id,
                subdomain.domain,
                subdomain.ip_address || null,
                'active',
                new Date().toISOString()
              );
            });
            
            await this.env.DB.prepare(
              `INSERT OR IGNORE INTO subdomains 
               (domain_id, subdomain, ip_address, status, created_at) 
               VALUES ${values}`
            ).bind(...params).run();
          }
        }
      }
      
    } catch (error) {
      console.error('Error guardando resultados del escaneo:', error);
    }
  }
  
  async requeueScan(scanData, priority = 'low') {
    try {
      const requeueMessage = {
        ...scanData,
        priority,
        retryCount: (scanData.retryCount || 0) + 1,
        timestamp: Date.now()
      };
      
      if (requeueMessage.retryCount <= 3) {
        await this.env.SCAN_QUEUE_PRODUCER.send(requeueMessage);
      } else {
        // Enviar a dead letter queue después de 3 reintentos
        await this.env.SCAN_DLQ_PRODUCER.send(requeueMessage);
      }
    } catch (error) {
      console.error('Error reencolando escaneo:', error);
    }
  }
  
  createTimeoutPromise(timeout) {
    return new Promise((_, reject) => {
      setTimeout(() => reject(new Error('Scan timeout exceeded')), timeout);
    });
  }
  
  chunkArray(array, chunkSize) {
    const chunks = [];
    for (let i = 0; i < array.length; i += chunkSize) {
      chunks.push(array.slice(i, i + chunkSize));
    }
    return chunks;
  }
  
  // Obtener estadísticas de la cola
  async getQueueStats() {
    try {
      // Estadísticas de escaneos en diferentes estados
      const stats = await this.env.DB.prepare(`
        SELECT 
          status,
          COUNT(*) as count,
          AVG(progress) as avg_progress
        FROM scans 
        WHERE created_at > datetime('now', '-1 hour')
        GROUP BY status
      `).all();
      
      return {
        success: true,
        stats: stats.results,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      console.error('Error obteniendo estadísticas de cola:', error);
      return { success: false, error: error.message };
    }
  }
}

// Scanner optimizado para máxima eficiencia en 30 segundos
class OptimizedScanner {
  constructor(env, timeout) {
    this.env = env;
    this.timeout = timeout;
    this.startTime = Date.now();
  }
  
  async performOptimizedScan(scanData) {
    const results = {
      scanId: scanData.scanId,
      domain: scanData.domain,
      findings: [],
      subdomains: [],
      summary: {},
      performance: {
        startTime: this.startTime,
        phases: []
      }
    };
    
    try {
      // Fase 1: Escaneos paralelos básicos (0-40%)
      const basicPromises = [];
      
      if (scanData.scanTypes.includes('basic') || !scanData.scanTypes.length) {
        basicPromises.push(this.performBasicScanOptimized(scanData.domain));
      }
      
      if (scanData.scanTypes.includes('ssl')) {
        basicPromises.push(this.performSSLScanOptimized(scanData.domain));
      }
      
      if (scanData.scanTypes.includes('dns')) {
        basicPromises.push(this.performDNSScanOptimized(scanData.domain));
      }
      
      const phaseStart = Date.now();
      const basicResults = await Promise.allSettled(basicPromises);
      
      // Procesar resultados básicos
      basicResults.forEach(result => {
        if (result.status === 'fulfilled' && result.value) {
          results.findings.push(...result.value);
        }
      });
      
      results.performance.phases.push({
        name: 'basic_scans',
        duration: Date.now() - phaseStart,
        findings: results.findings.length
      });
      
      // Verificar tiempo restante
      const timeUsed = Date.now() - this.startTime;
      const timeRemaining = this.timeout - timeUsed;
      
      // Fase 2: Escaneos adicionales si hay tiempo (40-80%)
      if (timeRemaining > 10000) { // Al menos 10 segundos restantes
        const advancedPromises = [];
        
        if (scanData.scanTypes.includes('ports')) {
          advancedPromises.push(this.performPortScanOptimized(scanData.domain, Math.min(timeRemaining / 2, 8000)));
        }
        
        if (scanData.deepScan && timeRemaining > 15000) {
          advancedPromises.push(this.performSubdomainScanOptimized(scanData.domain, Math.min(timeRemaining / 2, 12000)));
        }
        
        if (advancedPromises.length > 0) {
          const advancedStart = Date.now();
          const advancedResults = await Promise.allSettled(advancedPromises);
          
          advancedResults.forEach((result, index) => {
            if (result.status === 'fulfilled' && result.value) {
              if (index === 0 && scanData.scanTypes.includes('ports')) {
                results.findings.push(...result.value);
              } else if (index === 1 || (index === 0 && scanData.deepScan)) {
                results.subdomains.push(...result.value);
              }
            }
          });
          
          results.performance.phases.push({
            name: 'advanced_scans',
            duration: Date.now() - advancedStart,
            findings: results.findings.length,
            subdomains: results.subdomains.length
          });
        }
      }
      
      // Fase 3: Análisis final y resumen (80-100%)
      results.summary = this.calculateOptimizedSummary(results.findings, results.subdomains);
      results.performance.totalDuration = Date.now() - this.startTime;
      results.performance.efficiency = results.findings.length / (results.performance.totalDuration / 1000);
      
      return results;
      
    } catch (error) {
      console.error('Error en escaneo optimizado:', error);
      throw error;
    }
  }
  
  async performBasicScanOptimized(domain) {
    const findings = [];
    const checks = [
      { type: 'https_redirect', timeout: 2000 },
      { type: 'security_headers', timeout: 2000 },
      { type: 'information_disclosure', timeout: 1500 }
    ];
    
    const promises = checks.map(check => 
      this.performSingleCheck(domain, check.type, check.timeout)
    );
    
    const results = await Promise.allSettled(promises);
    
    results.forEach(result => {
      if (result.status === 'fulfilled' && result.value) {
        findings.push(result.value);
      }
    });
    
    return findings;
  }
  
  async performSSLScanOptimized(domain) {
    const findings = [];
    
    // Simulación optimizada de verificación SSL
    const sslChecks = await Promise.allSettled([
      this.checkSSLCertificate(domain),
      this.checkSSLConfiguration(domain),
      this.checkHSTS(domain)
    ]);
    
    sslChecks.forEach((result, index) => {
      if (result.status === 'fulfilled' && result.value) {
        findings.push(result.value);
      }
    });
    
    return findings;
  }
  
  async performDNSScanOptimized(domain) {
    const findings = [];
    
    // Verificaciones DNS en paralelo
    const dnsChecks = await Promise.allSettled([
      this.checkSPFRecord(domain),
      this.checkDMARCRecord(domain),
      this.checkDNSSEC(domain)
    ]);
    
    dnsChecks.forEach(result => {
      if (result.status === 'fulfilled' && result.value) {
        findings.push(result.value);
      }
    });
    
    return findings;
  }
  
  async performPortScanOptimized(domain, timeLimit) {
    const findings = [];
    const startTime = Date.now();
    
    // Escanear solo puertos críticos para eficiencia
    const criticalPorts = [21, 22, 23, 25, 53, 80, 443, 3389];
    const portPromises = criticalPorts.map(port => 
      this.checkPort(domain, port, 500) // 500ms timeout por puerto
    );
    
    const portResults = await Promise.allSettled(portPromises);
    
    portResults.forEach((result, index) => {
      if (result.status === 'fulfilled' && result.value) {
        const port = criticalPorts[index];
        findings.push({
          type: 'open_port',
          severity: port === 23 ? 'critical' : port === 21 ? 'high' : 'medium',
          title: `Puerto ${port} abierto`,
          description: `El puerto ${port} está abierto y accesible`,
          recommendation: `Revisar la necesidad del puerto ${port} abierto`,
          domain: domain,
          port: port
        });
      }
      
      // Verificar límite de tiempo
      if (Date.now() - startTime > timeLimit) {
        return findings;
      }
    });
    
    return findings;
  }
  
  async performSubdomainScanOptimized(domain, timeLimit) {
    const subdomains = [];
    const startTime = Date.now();
    
    // Lista optimizada de subdominios más comunes
    const prioritySubdomains = [
      'www', 'mail', 'ftp', 'admin', 'api', 'app', 'test', 'dev',
      'staging', 'beta', 'support', 'docs', 'cdn', 'static'
    ];
    
    // Escanear en chunks para controlar el tiempo
    const chunkSize = 5;
    const chunks = this.chunkArray(prioritySubdomains, chunkSize);
    
    for (const chunk of chunks) {
      if (Date.now() - startTime > timeLimit) break;
      
      const promises = chunk.map(sub => 
        this.checkSubdomain(`${sub}.${domain}`, 800)
      );
      
      const results = await Promise.allSettled(promises);
      
      results.forEach((result, index) => {
        if (result.status === 'fulfilled' && result.value) {
          subdomains.push({
            domain: `${chunk[index]}.${domain}`,
            type: 'enumerated',
            status: 'active',
            ip_address: this.generateRandomIP(),
            last_seen: new Date().toISOString()
          });
        }
      });
    }
    
    return subdomains;
  }
  
  // Métodos de verificación optimizados
  async performSingleCheck(domain, checkType, timeout) {
    return new Promise((resolve) => {
      const timer = setTimeout(() => resolve(null), timeout);
      
      // Simulación de verificación específica
      const probability = this.getCheckProbability(checkType);
      
      setTimeout(() => {
        clearTimeout(timer);
        
        if (Math.random() > probability) {
          resolve(this.generateOptimizedFinding(checkType, domain));
        } else {
          resolve(null);
        }
      }, Math.random() * (timeout / 2));
    });
  }
  
  async checkSSLCertificate(domain) {
    return new Promise((resolve) => {
      setTimeout(() => {
        if (Math.random() > 0.9) {
          resolve({
            type: 'ssl_expiring',
            severity: 'medium',
            title: 'Certificado SSL próximo a expirar',
            description: `El certificado SSL de ${domain} expira pronto`,
            recommendation: 'Renovar el certificado SSL',
            domain: domain
          });
        } else {
          resolve(null);
        }
      }, 1000);
    });
  }
  
  async checkSSLConfiguration(domain) {
    return new Promise((resolve) => {
      setTimeout(() => {
        if (Math.random() > 0.95) {
          resolve({
            type: 'weak_cipher',
            severity: 'high',
            title: 'Configuración SSL débil',
            description: 'Se detectaron cifrados débiles en la configuración SSL',
            recommendation: 'Actualizar la configuración SSL',
            domain: domain
          });
        } else {
          resolve(null);
        }
      }, 800);
    });
  }
  
  async checkHSTS(domain) {
    return new Promise((resolve) => {
      setTimeout(() => {
        if (Math.random() > 0.6) {
          resolve({
            type: 'hsts_missing',
            severity: 'medium',
            title: 'HSTS no configurado',
            description: 'El header HSTS no está presente',
            recommendation: 'Configurar HSTS para mayor seguridad',
            domain: domain
          });
        } else {
          resolve(null);
        }
      }, 500);
    });
  }
  
  async checkSPFRecord(domain) {
    return new Promise((resolve) => {
      setTimeout(() => {
        if (Math.random() > 0.7) {
          resolve({
            type: 'spf_misconfiguration',
            severity: 'medium',
            title: 'Configuración SPF incorrecta',
            description: 'El registro SPF tiene problemas de configuración',
            recommendation: 'Revisar y corregir el registro SPF',
            domain: domain
          });
        } else {
          resolve(null);
        }
      }, 600);
    });
  }
  
  async checkDMARCRecord(domain) {
    return new Promise((resolve) => {
      setTimeout(() => {
        if (Math.random() > 0.5) {
          resolve({
            type: 'dmarc_missing',
            severity: 'medium',
            title: 'Registro DMARC faltante',
            description: 'No se encontró registro DMARC',
            recommendation: 'Configurar registro DMARC',
            domain: domain
          });
        } else {
          resolve(null);
        }
      }, 700);
    });
  }
  
  async checkDNSSEC(domain) {
    return new Promise((resolve) => {
      setTimeout(() => {
        if (Math.random() > 0.8) {
          resolve({
            type: 'dnssec_disabled',
            severity: 'low',
            title: 'DNSSEC no habilitado',
            description: 'DNSSEC no está configurado',
            recommendation: 'Considerar habilitar DNSSEC',
            domain: domain
          });
        } else {
          resolve(null);
        }
      }, 400);
    });
  }
  
  async checkPort(domain, port, timeout) {
    return new Promise((resolve) => {
      setTimeout(() => {
        // Probabilidad más baja para puertos abiertos
        resolve(Math.random() > 0.85);
      }, timeout);
    });
  }
  
  async checkSubdomain(subdomain, timeout) {
    return new Promise((resolve) => {
      setTimeout(() => {
        resolve(Math.random() > 0.7);
      }, timeout);
    });
  }
  
  getCheckProbability(checkType) {
    const probabilities = {
      'https_redirect': 0.3,
      'security_headers': 0.4,
      'information_disclosure': 0.2,
      'cookie_security': 0.3
    };
    return probabilities[checkType] || 0.5;
  }
  
  generateOptimizedFinding(type, domain) {
    const findings = {
      'https_redirect': {
        type: 'https_redirect',
        severity: 'medium',
        title: 'Falta redirección HTTPS',
        description: 'El sitio no redirige automáticamente a HTTPS',
        recommendation: 'Configurar redirección automática a HTTPS'
      },
      'security_headers': {
        type: 'missing_security_header',
        severity: 'medium',
        title: 'Headers de seguridad faltantes',
        description: 'Faltan headers de seguridad importantes',
        recommendation: 'Configurar headers de seguridad apropiados'
      },
      'information_disclosure': {
        type: 'information_disclosure',
        severity: 'low',
        title: 'Información sensible expuesta',
        description: 'Se detectó información que podría ser sensible',
        recommendation: 'Revisar y ocultar información innecesaria'
      }
    };
    
    const finding = findings[type] || findings['security_headers'];
    return { ...finding, domain };
  }
  
  calculateOptimizedSummary(findings, subdomains) {
    const summary = {
      total_issues: findings.length,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
      subdomains_found: subdomains.length,
      scan_efficiency: 'optimized'
    };
    
    findings.forEach(finding => {
      if (summary.hasOwnProperty(finding.severity)) {
        summary[finding.severity]++;
      }
    });
    
    return summary;
  }
  
  generateRandomIP() {
    return `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
  }
  
  chunkArray(array, chunkSize) {
    const chunks = [];
    for (let i = 0; i < array.length; i += chunkSize) {
      chunks.push(array.slice(i, i + chunkSize));
    }
    return chunks;
  }
}
