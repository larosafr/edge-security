# 🛡️ CyberSecurity Scanner

Una aplicación web avanzada de ciberseguridad similar a SecurityScorecard.com, optimizada para Cloudflare Workers con sistema de colas asíncronas y procesamiento paralelo. Permite realizar análisis de seguridad completos de dominios con máxima eficiencia.

## ✨ Características Principales

- **🔐 Autenticación Segura**: Login con MFA (TOTP) usando Google Authenticator
- **🔍 Búsqueda Inteligente**: Encuentra dominios relacionados con empresas usando múltiples fuentes
- **⚡ Escaneos Optimizados**: Sistema de colas asíncronas para procesamiento paralelo
- **📊 Dashboard Interactivo**: Métricas en tiempo real con gráficos dinámicos
- **📋 Reportes Detallados**: Análisis completo con recomendaciones de corrección
- **🎨 Diseño Moderno**: Interfaz responsive con tema oscuro/claro
- **🚀 Alta Performance**: Optimizado para máxima eficiencia en 30 segundos

## 🛠️ Stack Tecnológico

- **Backend**: Cloudflare Workers (JavaScript) + Sistema de Colas Optimizado
- **Base de Datos**: Cloudflare D1 (SQLite) con migraciones automáticas
- **Almacenamiento**: Cloudflare KV (4 namespaces) + Cloudflare Queues
- **Frontend**: HTML5, CSS3, JavaScript Vanilla con componentes modulares
- **Visualización**: Chart.js para gráficos interactivos
- **Autenticación**: JWT + TOTP (OTPLib) con sesiones seguras
- **Procesamiento**: Colas asíncronas con paralelización inteligente

## 📋 Requisitos Previos

- Node.js (v16 o superior)
- Cuenta de Cloudflare
- Wrangler CLI instalado globalmente

```bash
npm install -g wrangler
```

## 🔧 Instalación y Configuración

### 1. Preparación del Proyecto
```bash
# Clonar el repositorio
git clone <tu-repositorio>
cd cybersecurity-scanner

# Instalar dependencias
npm install

# Autenticarse con Cloudflare
wrangler login
```

### 2. Crear Recursos de Cloudflare
```bash
# Crear base de datos D1
wrangler d1 create cybersecurity_db

# Crear todos los namespaces KV necesarios
wrangler kv:namespace create "SESSIONS"
wrangler kv:namespace create "CACHE" 
wrangler kv:namespace create "SCAN_QUEUE"
wrangler kv:namespace create "SCAN_RESULTS"

# Crear colas para procesamiento asíncrono
wrangler queues create scan-queue
wrangler queues create scan-dlq
```

### 3. Configurar wrangler.toml
Actualiza el archivo `wrangler.toml` con todos los IDs generados:

```toml
name = "cybersecurity-scanner"
main = "worker.js"
compatibility_date = "2024-01-01"

[vars]
ENVIRONMENT = "production"

[[d1_databases]]
binding = "DB"
database_name = "cybersecurity_db"
database_id = "tu-database-id-aqui"

[[kv_namespaces]]
binding = "SESSIONS"
id = "tu-sessions-kv-id-aqui"

[[kv_namespaces]]
binding = "CACHE"
id = "tu-cache-kv-id-aqui"

[[kv_namespaces]]
binding = "SCAN_QUEUE"
id = "tu-scan-queue-kv-id-aqui"

[[kv_namespaces]]
binding = "SCAN_RESULTS"
id = "tu-scan-results-kv-id-aqui"

# Configuración de colas
[[queues.producers]]
queue = "scan-queue"
binding = "SCAN_QUEUE_PRODUCER"

[[queues.consumers]]
queue = "scan-queue"
max_batch_size = 10
max_batch_timeout = 5
max_retries = 3
dead_letter_queue = "scan-dlq"

[[queues.producers]]
queue = "scan-dlq"
binding = "SCAN_DLQ_PRODUCER"
```

### 4. Configurar Variables de Entorno
```bash
# Configurar secretos de seguridad
wrangler secret put JWT_SECRET
# Ingresa una clave secreta fuerte (ej: openssl rand -base64 32)

wrangler secret put ENCRYPTION_KEY
# Ingresa otra clave para encriptación adicional
```

### 5. Inicializar Base de Datos
```bash
# Aplicar migraciones
wrangler d1 migrations apply cybersecurity_db

# Verificar que las tablas se crearon correctamente
wrangler d1 execute cybersecurity_db --command "SELECT name FROM sqlite_master WHERE type='table';"
```

## 🚀 Desarrollo y Testing

### Comandos de Desarrollo
```bash
# Ejecutar en modo desarrollo local
npm run dev
# Servidor disponible en http://localhost:8787

# Ejecutar con logs detallados
wrangler dev --local --log-level debug

# Ver logs en tiempo real (producción)
wrangler tail

# Ejecutar tests de base de datos
wrangler d1 execute cybersecurity_db --local --command "SELECT * FROM users LIMIT 5;"
```

### Comandos de Despliegue
```bash
# Desplegar a producción
npm run deploy

# Desplegar con preview (staging)
wrangler deploy --env preview

# Verificar estado del deployment
wrangler deployments list
```

### Testing y Debugging
```bash
# Probar endpoints localmente
curl -X POST http://localhost:8787/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"test","email":"test@example.com","password":"Test123!"}'

# Verificar colas
wrangler queues list

# Monitorear métricas
wrangler analytics
```

### Scripts Útiles
```bash
# Limpiar base de datos (desarrollo)
wrangler d1 execute cybersecurity_db --command "DELETE FROM scans; DELETE FROM findings;"

# Backup de base de datos
wrangler d1 backup create cybersecurity_db

# Ver estadísticas de KV
wrangler kv:key list --binding SESSIONS
```

## 📁 Estructura del Proyecto

```
cybersecurity-scanner/
├── src/
│   ├── handlers/              # 🎯 Manejadores de rutas optimizados
│   │   ├── auth.js           # 🔐 Autenticación JWT + MFA (TOTP)
│   │   ├── domains.js        # 🌐 Gestión y búsqueda de dominios
│   │   ├── scanner.js        # ⚡ Motor de escaneo con colas
│   │   └── dashboard.js      # 📊 Dashboard y métricas en tiempo real
│   ├── utils/                # 🛠️ Utilidades del sistema
│   │   ├── security.js       # 🔒 Funciones de seguridad y JWT
│   │   ├── database.js       # 🗄️ Gestión de D1 y migraciones
│   │   ├── scanner-engine.js # 🔍 Motor de escaneo de vulnerabilidades
│   │   └── queue-manager.js  # 🔄 Sistema de colas asíncronas
│   ├── static/               # 🎨 Archivos estáticos del frontend
│   │   ├── css/              # 💅 Estilos CSS modulares
│   │   │   ├── main.css      # Estilos base y componentes
│   │   │   ├── dashboard.css # Estilos específicos del dashboard
│   │   │   └── login.css     # Estilos de autenticación
│   │   ├── js/               # ⚙️ JavaScript frontend
│   │   │   ├── auth.js       # Lógica de autenticación
│   │   │   └── dashboard.js  # Funcionalidad del dashboard
│   │   └── assets/           # 🖼️ Recursos estáticos
│   └── templates/            # 📄 Plantillas HTML (futuro)
├── migrations/               # 🗃️ Migraciones de base de datos
│   └── 0001_initial.sql     # Migración inicial con todas las tablas
├── worker.js                 # 🚀 Punto de entrada principal con colas
├── wrangler.toml            # ⚙️ Configuración completa de Cloudflare
├── package.json             # 📦 Dependencias y scripts npm
├── .gitignore               # 🚫 Archivos ignorados por Git
└── README.md               # 📖 Documentación completa
```

### 🏗️ Arquitectura del Sistema

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Frontend      │    │   Cloudflare     │    │   Cloudflare    │
│   (Static)      │◄──►│   Workers        │◄──►│   D1 Database   │
│                 │    │   (Main App)     │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                              │
                              ▼
                    ┌──────────────────┐
                    │  Cloudflare      │
                    │  Queues          │
                    │  (Async Scans)   │
                    └──────────────────┘
                              │
                              ▼
                    ┌──────────────────┐
                    │  KV Storage      │
                    │  (4 Namespaces)  │
                    │  • Sessions      │
                    │  • Cache         │
                    │  • Scan Queue    │
                    │  • Scan Results  │
                    └──────────────────┘
```

## 🔐 Configuración de Seguridad

### Variables de Entorno
Configura las siguientes variables en Cloudflare Workers:

```bash
wrangler secret put JWT_SECRET
wrangler secret put ENCRYPTION_KEY
```

### Headers de Seguridad
La aplicación incluye headers de seguridad automáticos:
- Content Security Policy (CSP)
- X-Frame-Options
- X-Content-Type-Options
- Strict-Transport-Security (HSTS)

## 📊 Funcionalidades del Scanner

### Tipos de Escaneo

1. **Escaneo Básico**
   - Verificación de accesibilidad
   - Redirección HTTPS
   - Headers de seguridad básicos
   - Información sensible expuesta

2. **Análisis SSL/TLS**
   - Validez del certificado
   - Fecha de expiración
   - Algoritmos de cifrado
   - Configuración HSTS

3. **Análisis DNS**
   - Registros DNS faltantes
   - Configuración SPF
   - Registro DMARC
   - DNSSEC

4. **Escaneo de Puertos**
   - Puertos abiertos
   - Servicios vulnerables
   - Versiones de software

5. **Escaneo de Subdominios**
   - Enumeración de subdominios
   - Certificate Transparency Logs
   - DNS reverso
   - Subdominios activos

### Modos de Escaneo

- **Escaneo Rápido**: Verificaciones básicas en <15 segundos
- **Escaneo Completo**: Análisis profundo vía cola asíncrona
- **Escaneo Profundo**: Incluye enumeración exhaustiva de subdominios

### Severidades de Vulnerabilidades

- **Crítica**: Requiere atención inmediata
- **Alta**: Debe corregirse pronto
- **Media**: Planificar corrección
- **Baja**: Mejorar cuando sea posible
- **Info**: Información general

## ⚡ Optimizaciones Implementadas

### Sistema de Colas Asíncronas
- **Cloudflare Queues**: Procesamiento en background de escaneos largos
- **Batch Processing**: Hasta 10 escaneos simultáneos por batch
- **Rate Limiting**: Máximo 3 escaneos concurrentes por usuario
- **Dead Letter Queue**: Manejo de escaneos fallidos con reintentos

### Paralelización Inteligente
- **Escaneos Paralelos**: Múltiples verificaciones simultáneas
- **Timeout Optimizado**: 25 segundos máximo por escaneo
- **Chunking**: División de subdominios en grupos para eficiencia
- **Promise.allSettled**: Manejo robusto de fallos parciales

### Caché y Almacenamiento
- **KV Storage**: Resultados de escaneos y estado de colas
- **Database Batching**: Inserción eficiente de hallazgos
- **Result Caching**: Evita escaneos duplicados recientes

### Monitoreo y Estadísticas
- **Queue Stats**: Métricas en tiempo real de procesamiento
- **Performance Tracking**: Duración y eficiencia de escaneos
- **Error Handling**: Logging detallado para debugging

## 🎨 Personalización

### Temas y Estilos
Los estilos están organizados en:
- `main.css`: Estilos base y componentes
- `dashboard.css`: Estilos específicos del dashboard

### Configuración de Gráficos
Los gráficos utilizan Chart.js y pueden personalizarse en `dashboard.js`

## 🔍 API Endpoints

### Autenticación
- `POST /auth/login` - Iniciar sesión
- `POST /auth/register` - Registrar usuario
- `POST /auth/setup-mfa` - Configurar MFA
- `POST /auth/verify-mfa` - Verificar MFA
- `POST /auth/logout` - Cerrar sesión

### Dominios
- `POST /api/domains/search` - Buscar dominios
- `POST /api/domains/add` - Agregar dominio
- `GET /api/domains/list` - Listar dominios
- `DELETE /api/domains/delete` - Eliminar dominio

### Scanner
- `POST /api/scanner/start` - Iniciar escaneo (encolado)
- `POST /api/scanner/quick-scan` - Escaneo rápido inmediato
- `GET /api/scanner/status` - Estado del escaneo
- `GET /api/scanner/results` - Resultados del escaneo
- `GET /api/scanner/queue-stats` - Estadísticas de la cola
- `POST /api/scanner/stop` - Detener escaneo

### Dashboard
- `GET /api/dashboard/overview` - Resumen general
- `GET /api/dashboard/metrics` - Métricas y gráficos
- `GET /api/dashboard/recent-scans` - Escaneos recientes

## 🐛 Solución de Problemas

### Errores Comunes

#### 1. **Error de Base de Datos**
```bash
# Reaplicar migraciones
wrangler d1 migrations apply cybersecurity_db

# Verificar conexión
wrangler d1 execute cybersecurity_db --command "SELECT 1;"

# Recrear base de datos si es necesario
wrangler d1 create cybersecurity_db --force
```

#### 2. **Error de KV Namespaces**
```bash
# Verificar namespaces existentes
wrangler kv:namespace list

# Recrear namespace específico
wrangler kv:namespace create "SESSIONS" --preview false

# Verificar configuración en wrangler.toml
```

#### 3. **Error de Colas**
```bash
# Verificar colas existentes
wrangler queues list

# Recrear cola si es necesario
wrangler queues create scan-queue

# Ver mensajes en cola
wrangler queues consumer scan-queue
```

#### 4. **Error de Autenticación**
```bash
# Verificar secretos configurados
wrangler secret list

# Reconfigurar JWT_SECRET
wrangler secret put JWT_SECRET

# Limpiar sesiones en desarrollo
wrangler kv:key delete --binding SESSIONS "session_1"
```

#### 5. **Error de Despliegue**
```bash
# Verificar sintaxis
wrangler validate

# Desplegar con logs detallados
wrangler deploy --log-level debug

# Rollback si es necesario
wrangler rollback
```

### Debugging Avanzado

#### Logs y Monitoreo
```bash
# Ver logs en tiempo real con filtros
wrangler tail --format pretty --status error

# Logs específicos de colas
wrangler tail --search "queue"

# Métricas de rendimiento
wrangler analytics --since 1h
```

#### Testing de Endpoints
```bash
# Test completo de autenticación
curl -X POST http://localhost:8787/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","email":"test@example.com","password":"SecurePass123!"}'

# Test de escaneo rápido
curl -X POST http://localhost:8787/api/scanner/quick-scan \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{"domain":"example.com","scanTypes":["basic"]}'

# Test de estadísticas de cola
curl -X GET http://localhost:8787/api/scanner/queue-stats \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

#### Verificación de Estado del Sistema
```bash
# Estado de todos los recursos
wrangler whoami
wrangler kv:namespace list
wrangler queues list
wrangler d1 list

# Verificar límites y uso
wrangler analytics --since 24h
```

## 🚀 Despliegue en Producción

### Pre-despliegue
1. Verificar todas las variables de entorno
2. Ejecutar tests (si están configurados)
3. Verificar configuración de dominio personalizado

### Despliegue
```bash
npm run deploy
```

### Post-despliegue
1. Verificar funcionalidad básica
2. Probar autenticación y MFA
3. Ejecutar escaneo de prueba
4. Verificar métricas del dashboard

## 🔒 Consideraciones de Seguridad

- Cambiar JWT_SECRET en producción
- Configurar dominio personalizado con SSL
- Implementar rate limiting adicional si es necesario
- Monitorear logs de seguridad
- Actualizar dependencias regularmente

## 📈 Monitoreo y Métricas

La aplicación incluye:
- Métricas de uso en el dashboard
- Logs de actividad de usuarios
- Estadísticas de escaneos
- Alertas de vulnerabilidades críticas

## 🤝 Contribución

1. Fork el proyecto
2. Crear rama de feature (`git checkout -b feature/nueva-funcionalidad`)
3. Commit cambios (`git commit -am 'Agregar nueva funcionalidad'`)
4. Push a la rama (`git push origin feature/nueva-funcionalidad`)
5. Crear Pull Request

## 📄 Licencia

Este proyecto está bajo la Licencia MIT. Ver el archivo `LICENSE` para más detalles.

## 🆘 Soporte

Para soporte y preguntas:
- Crear un issue en GitHub
- Revisar la documentación
- Verificar logs de Cloudflare Workers

## 🔄 Actualizaciones

Para mantener la aplicación actualizada:

```bash
# Actualizar dependencias
npm update

# Verificar vulnerabilidades
npm audit

# Aplicar parches de seguridad
npm audit fix
```

## 💡 Ejemplos de Uso

### Flujo Completo de Usuario
```javascript
// 1. Registro de usuario
const registerResponse = await fetch('/auth/register', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    username: 'security_analyst',
    email: 'analyst@company.com',
    password: 'SecurePass123!'
  })
});

// 2. Login con MFA
const loginResponse = await fetch('/auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    email: 'analyst@company.com',
    password: 'SecurePass123!',
    mfaCode: '123456'
  })
});

// 3. Agregar dominio para escaneo
const addDomainResponse = await fetch('/api/domains/add', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${token}`
  },
  body: JSON.stringify({
    domain: 'example.com',
    name: 'Mi Empresa'
  })
});

// 4. Iniciar escaneo completo
const scanResponse = await fetch('/api/scanner/start', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${token}`
  },
  body: JSON.stringify({
    domainId: 1,
    scanTypes: ['basic', 'ssl', 'dns', 'ports'],
    deepScan: true,
    priority: 'high'
  })
});
```

### Monitoreo de Escaneos
```javascript
// Monitorear progreso del escaneo
const monitorScan = async (scanId) => {
  const interval = setInterval(async () => {
    const response = await fetch(`/api/scanner/status?scanId=${scanId}`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    
    const data = await response.json();
    
    if (data.scan.status === 'completed') {
      clearInterval(interval);
      console.log('Escaneo completado:', data.scan.results);
    } else if (data.scan.status === 'failed') {
      clearInterval(interval);
      console.error('Escaneo falló:', data.scan.error_message);
    } else {
      console.log(`Progreso: ${data.scan.progress}% - ${data.scan.currentPhase}`);
    }
  }, 2000);
};
```

## 🎯 Mejores Prácticas

### Seguridad
- ✅ Cambiar `JWT_SECRET` en producción con una clave de 256 bits
- ✅ Habilitar MFA para todos los usuarios administrativos
- ✅ Implementar rate limiting por IP en endpoints críticos
- ✅ Monitorear logs de seguridad regularmente
- ✅ Usar HTTPS exclusivamente en producción

### Performance
- ✅ Usar escaneos rápidos para verificaciones inmediatas
- ✅ Implementar caché para resultados de escaneos recientes
- ✅ Optimizar consultas de base de datos con índices
- ✅ Monitorear métricas de cola para ajustar batch sizes
- ✅ Implementar cleanup automático de datos antiguos

### Escalabilidad
- ✅ Configurar múltiples colas para diferentes tipos de escaneo
- ✅ Implementar sharding de base de datos para grandes volúmenes
- ✅ Usar CDN para archivos estáticos
- ✅ Implementar circuit breakers para servicios externos
- ✅ Monitorear límites de Cloudflare Workers

## 📊 Métricas y KPIs

### Métricas de Sistema
- **Throughput**: Escaneos completados por hora
- **Latencia**: Tiempo promedio de respuesta de APIs
- **Error Rate**: Porcentaje de escaneos fallidos
- **Queue Depth**: Número de escaneos pendientes
- **Resource Usage**: Uso de CPU, memoria y almacenamiento

### Métricas de Negocio
- **Usuarios Activos**: Usuarios únicos por día/mes
- **Dominios Escaneados**: Total de dominios bajo monitoreo
- **Vulnerabilidades Detectadas**: Por severidad y tipo
- **Tiempo de Resolución**: Tiempo promedio para corregir vulnerabilidades
- **Cobertura de Escaneo**: Porcentaje de dominios escaneados regularmente

## 🔄 Roadmap y Futuras Mejoras

### Versión 2.0 (Próxima)
- [ ] Integración con APIs externas de threat intelligence
- [ ] Escaneos programados automáticos
- [ ] Notificaciones por email/Slack
- [ ] Exportación de reportes en PDF
- [ ] API pública para integraciones

### Versión 3.0 (Futuro)
- [ ] Machine Learning para detección de anomalías
- [ ] Integración con SIEM systems
- [ ] Compliance reporting (SOC2, ISO27001)
- [ ] Multi-tenancy para empresas
- [ ] Mobile app para monitoreo

## 📚 Recursos Adicionales

### Documentación Oficial
- [Cloudflare Workers](https://developers.cloudflare.com/workers/)
- [Cloudflare D1 Database](https://developers.cloudflare.com/d1/)
- [Cloudflare Queues](https://developers.cloudflare.com/queues/)
- [Cloudflare KV](https://developers.cloudflare.com/kv/)

### Herramientas y Librerías
- [Chart.js Documentation](https://www.chartjs.org/docs/)
- [OTPLib Documentation](https://github.com/yeojz/otplib)
- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/)

### Seguridad y Compliance
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CIS Controls](https://www.cisecurity.org/controls/)

---

## ⚠️ Disclaimer

**Esta aplicación está diseñada para fines educativos y de demostración.** Para uso en producción:

- Implementa medidas de seguridad adicionales según tu contexto
- Cumple con regulaciones locales de ciberseguridad y privacidad
- Realiza auditorías de seguridad regulares
- Mantén todas las dependencias actualizadas
- Implementa monitoreo y alertas apropiados

**Licencia**: MIT - Ver archivo LICENSE para más detalles.
# edge-security
