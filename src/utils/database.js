export async function initDatabase(db) {
  try {
    // Crear tabla de usuarios
    await db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        mfa_secret TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
        last_login TEXT,
        is_active BOOLEAN DEFAULT 1
      )
    `);
    
    // Crear tabla de dominios
    await db.exec(`
      CREATE TABLE IF NOT EXISTS domains (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        domain_name TEXT NOT NULL,
        display_name TEXT,
        status TEXT DEFAULT 'active',
        validation_status TEXT DEFAULT 'pending',
        created_at TEXT NOT NULL,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
        last_scan_at TEXT,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
        UNIQUE(user_id, domain_name)
      )
    `);
    
    // Crear tabla de escaneos
    await db.exec(`
      CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain_id INTEGER NOT NULL,
        scan_types TEXT NOT NULL,
        status TEXT DEFAULT 'pending',
        progress INTEGER DEFAULT 0,
        deep_scan BOOLEAN DEFAULT 0,
        started_at TEXT,
        completed_at TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
        results TEXT,
        error_message TEXT,
        FOREIGN KEY (domain_id) REFERENCES domains (id) ON DELETE CASCADE
      )
    `);
    
    // Crear tabla de hallazgos/vulnerabilidades
    await db.exec(`
      CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER NOT NULL,
        vulnerability_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT,
        recommendation TEXT,
        subdomain TEXT,
        port INTEGER,
        service TEXT,
        cvss_score REAL,
        cve_id TEXT,
        status TEXT DEFAULT 'open',
        created_at TEXT NOT NULL,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
        resolved_at TEXT,
        FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
      )
    `);
    
    // Crear tabla de subdominios
    await db.exec(`
      CREATE TABLE IF NOT EXISTS subdomains (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain_id INTEGER NOT NULL,
        subdomain TEXT NOT NULL,
        ip_address TEXT,
        status TEXT DEFAULT 'active',
        last_seen TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (domain_id) REFERENCES domains (id) ON DELETE CASCADE,
        UNIQUE(domain_id, subdomain)
      )
    `);
    
    // Crear tabla de configuraciones de usuario
    await db.exec(`
      CREATE TABLE IF NOT EXISTS user_settings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        setting_key TEXT NOT NULL,
        setting_value TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
        UNIQUE(user_id, setting_key)
      )
    `);
    
    // Crear tabla de notificaciones
    await db.exec(`
      CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        type TEXT NOT NULL,
        title TEXT NOT NULL,
        message TEXT,
        is_read BOOLEAN DEFAULT 0,
        created_at TEXT NOT NULL,
        read_at TEXT,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
      )
    `);
    
    // Crear tabla de logs de actividad
    await db.exec(`
      CREATE TABLE IF NOT EXISTS activity_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        resource_type TEXT,
        resource_id INTEGER,
        details TEXT,
        ip_address TEXT,
        user_agent TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
      )
    `);
    
    // Crear índices para mejorar el rendimiento
    await createIndexes(db);
    
    console.log('Base de datos inicializada correctamente');
    
  } catch (error) {
    console.error('Error inicializando base de datos:', error);
    throw error;
  }
}

async function createIndexes(db) {
  const indexes = [
    'CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)',
    'CREATE INDEX IF NOT EXISTS idx_domains_user_id ON domains(user_id)',
    'CREATE INDEX IF NOT EXISTS idx_domains_domain_name ON domains(domain_name)',
    'CREATE INDEX IF NOT EXISTS idx_scans_domain_id ON scans(domain_id)',
    'CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status)',
    'CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at)',
    'CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id)',
    'CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)',
    'CREATE INDEX IF NOT EXISTS idx_findings_vulnerability_type ON findings(vulnerability_type)',
    'CREATE INDEX IF NOT EXISTS idx_subdomains_domain_id ON subdomains(domain_id)',
    'CREATE INDEX IF NOT EXISTS idx_notifications_user_id ON notifications(user_id)',
    'CREATE INDEX IF NOT EXISTS idx_notifications_is_read ON notifications(is_read)',
    'CREATE INDEX IF NOT EXISTS idx_activity_logs_user_id ON activity_logs(user_id)',
    'CREATE INDEX IF NOT EXISTS idx_activity_logs_created_at ON activity_logs(created_at)'
  ];
  
  for (const indexQuery of indexes) {
    try {
      await db.exec(indexQuery);
    } catch (error) {
      console.error('Error creando índice:', indexQuery, error);
    }
  }
}

// Utilidades para operaciones comunes de base de datos
export class DatabaseUtils {
  constructor(db) {
    this.db = db;
  }
  
  async getUserById(userId) {
    return await this.db.prepare(
      'SELECT id, username, email, created_at, last_login, is_active FROM users WHERE id = ?'
    ).bind(userId).first();
  }
  
  async getUserByEmail(email) {
    return await this.db.prepare(
      'SELECT * FROM users WHERE email = ?'
    ).bind(email).first();
  }
  
  async updateUserLastLogin(userId) {
    return await this.db.prepare(
      'UPDATE users SET last_login = ? WHERE id = ?'
    ).bind(new Date().toISOString(), userId).run();
  }
  
  async getDomainsByUser(userId) {
    return await this.db.prepare(
      'SELECT * FROM domains WHERE user_id = ? ORDER BY created_at DESC'
    ).bind(userId).all();
  }
  
  async getDomainById(domainId, userId) {
    return await this.db.prepare(
      'SELECT * FROM domains WHERE id = ? AND user_id = ?'
    ).bind(domainId, userId).first();
  }
  
  async getActiveScansByUser(userId) {
    return await this.db.prepare(
      `SELECT s.*, d.domain_name 
       FROM scans s 
       JOIN domains d ON s.domain_id = d.id 
       WHERE d.user_id = ? AND s.status IN ('pending', 'running') 
       ORDER BY s.created_at DESC`
    ).bind(userId).all();
  }
  
  async getScanById(scanId, userId) {
    return await this.db.prepare(
      `SELECT s.*, d.domain_name 
       FROM scans s 
       JOIN domains d ON s.domain_id = d.id 
       WHERE s.id = ? AND d.user_id = ?`
    ).bind(scanId, userId).first();
  }
  
  async getFindingsByScan(scanId) {
    return await this.db.prepare(
      'SELECT * FROM findings WHERE scan_id = ? ORDER BY severity DESC, created_at DESC'
    ).bind(scanId).all();
  }
  
  async getVulnerabilityStats(userId) {
    return await this.db.prepare(
      `SELECT f.severity, COUNT(*) as count 
       FROM findings f 
       JOIN scans s ON f.scan_id = s.id 
       JOIN domains d ON s.domain_id = d.id 
       WHERE d.user_id = ? 
       GROUP BY f.severity`
    ).bind(userId).all();
  }
  
  async getRecentFindings(userId, limit = 10) {
    return await this.db.prepare(
      `SELECT f.*, s.id as scan_id, d.domain_name 
       FROM findings f 
       JOIN scans s ON f.scan_id = s.id 
       JOIN domains d ON s.domain_id = d.id 
       WHERE d.user_id = ? 
       ORDER BY f.created_at DESC 
       LIMIT ?`
    ).bind(userId, limit).all();
  }
  
  async logActivity(userId, action, resourceType, resourceId, details, ipAddress, userAgent) {
    return await this.db.prepare(
      `INSERT INTO activity_logs 
       (user_id, action, resource_type, resource_id, details, ip_address, user_agent, created_at) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      userId,
      action,
      resourceType,
      resourceId,
      details,
      ipAddress,
      userAgent,
      new Date().toISOString()
    ).run();
  }
  
  async createNotification(userId, type, title, message) {
    return await this.db.prepare(
      'INSERT INTO notifications (user_id, type, title, message, created_at) VALUES (?, ?, ?, ?, ?)'
    ).bind(userId, type, title, message, new Date().toISOString()).run();
  }
  
  async getUnreadNotifications(userId) {
    return await this.db.prepare(
      'SELECT * FROM notifications WHERE user_id = ? AND is_read = 0 ORDER BY created_at DESC'
    ).bind(userId).all();
  }
  
  async markNotificationAsRead(notificationId, userId) {
    return await this.db.prepare(
      'UPDATE notifications SET is_read = 1, read_at = ? WHERE id = ? AND user_id = ?'
    ).bind(new Date().toISOString(), notificationId, userId).run();
  }
  
  async getUserSetting(userId, key) {
    const result = await this.db.prepare(
      'SELECT setting_value FROM user_settings WHERE user_id = ? AND setting_key = ?'
    ).bind(userId, key).first();
    
    return result ? result.setting_value : null;
  }
  
  async setUserSetting(userId, key, value) {
    return await this.db.prepare(
      `INSERT INTO user_settings (user_id, setting_key, setting_value, created_at) 
       VALUES (?, ?, ?, ?) 
       ON CONFLICT(user_id, setting_key) 
       DO UPDATE SET setting_value = ?, updated_at = CURRENT_TIMESTAMP`
    ).bind(userId, key, value, new Date().toISOString(), value).run();
  }
  
  async cleanupOldData(daysToKeep = 90) {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - daysToKeep);
    const cutoffISO = cutoffDate.toISOString();
    
    // Limpiar logs de actividad antiguos
    await this.db.prepare(
      'DELETE FROM activity_logs WHERE created_at < ?'
    ).bind(cutoffISO).run();
    
    // Limpiar notificaciones leídas antiguas
    await this.db.prepare(
      'DELETE FROM notifications WHERE is_read = 1 AND read_at < ?'
    ).bind(cutoffISO).run();
    
    // Limpiar escaneos fallidos antiguos
    await this.db.prepare(
      'DELETE FROM scans WHERE status = "failed" AND created_at < ?'
    ).bind(cutoffISO).run();
    
    console.log(`Limpieza de datos completada. Eliminados registros anteriores a ${cutoffISO}`);
  }
  
  async getSystemStats() {
    const stats = {};
    
    // Contar usuarios activos
    const activeUsers = await this.db.prepare(
      'SELECT COUNT(*) as count FROM users WHERE is_active = 1'
    ).first();
    stats.active_users = activeUsers.count;
    
    // Contar dominios totales
    const totalDomains = await this.db.prepare(
      'SELECT COUNT(*) as count FROM domains'
    ).first();
    stats.total_domains = totalDomains.count;
    
    // Contar escaneos del último mes
    const lastMonth = new Date();
    lastMonth.setMonth(lastMonth.getMonth() - 1);
    const recentScans = await this.db.prepare(
      'SELECT COUNT(*) as count FROM scans WHERE created_at > ?'
    ).bind(lastMonth.toISOString()).first();
    stats.recent_scans = recentScans.count;
    
    // Contar vulnerabilidades por severidad
    const vulnStats = await this.db.prepare(
      'SELECT severity, COUNT(*) as count FROM findings GROUP BY severity'
    ).all();
    stats.vulnerabilities = {};
    vulnStats.results.forEach(vuln => {
      stats.vulnerabilities[vuln.severity] = vuln.count;
    });
    
    return stats;
  }
}

// Funciones de migración para actualizaciones futuras
export async function runMigrations(db) {
  try {
    // Verificar si existe tabla de migraciones
    await db.exec(`
      CREATE TABLE IF NOT EXISTS migrations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        version TEXT UNIQUE NOT NULL,
        applied_at TEXT NOT NULL
      )
    `);
    
    const migrations = [
      {
        version: '1.0.0',
        sql: `
          -- Migración inicial ya aplicada en initDatabase
          SELECT 1;
        `
      },
      {
        version: '1.1.0',
        sql: `
          -- Agregar columna para tracking de IP en findings
          ALTER TABLE findings ADD COLUMN source_ip TEXT;
          ALTER TABLE findings ADD COLUMN confidence_level INTEGER DEFAULT 100;
        `
      }
    ];
    
    for (const migration of migrations) {
      const existing = await db.prepare(
        'SELECT version FROM migrations WHERE version = ?'
      ).bind(migration.version).first();
      
      if (!existing) {
        await db.exec(migration.sql);
        await db.prepare(
          'INSERT INTO migrations (version, applied_at) VALUES (?, ?)'
        ).bind(migration.version, new Date().toISOString()).run();
        
        console.log(`Migración ${migration.version} aplicada exitosamente`);
      }
    }
    
  } catch (error) {
    console.error('Error ejecutando migraciones:', error);
    throw error;
  }
}

// Utilidad para backup de datos críticos
export async function backupCriticalData(db) {
  try {
    const backup = {
      timestamp: new Date().toISOString(),
      users: [],
      domains: [],
      recent_scans: []
    };
    
    // Backup de usuarios (sin contraseñas)
    const users = await db.prepare(
      'SELECT id, username, email, created_at, last_login FROM users WHERE is_active = 1'
    ).all();
    backup.users = users.results;
    
    // Backup de dominios
    const domains = await db.prepare(
      'SELECT * FROM domains WHERE status = "active"'
    ).all();
    backup.domains = domains.results;
    
    // Backup de escaneos recientes (último mes)
    const lastMonth = new Date();
    lastMonth.setMonth(lastMonth.getMonth() - 1);
    const recentScans = await db.prepare(
      'SELECT * FROM scans WHERE created_at > ? AND status = "completed"'
    ).bind(lastMonth.toISOString()).all();
    backup.recent_scans = recentScans.results;
    
    return backup;
    
  } catch (error) {
    console.error('Error creando backup:', error);
    throw error;
  }
}
