import {
	Router,
	error,
	json
} from 'itty-router';

// Inicializa enrutadores separados para la API y las páginas/vistas
const apiRouter = Router({
	base: '/api'
});
const pageRouter = Router();

// --- LÓGICA DEL MOTOR DE ESCANEO (Mejorada) ---
async function scanDomain(domain) {
	const results = {
		headers: {},
		recommendations: [],
		score: 100, // Puntuación inicial
	};
	let response;
	try {
		// Intenta HTTPS primero, que es el estándar preferido.
		try {
			response = await fetch(`https://${domain}`, {
				redirect: 'manual',
				headers: {
					'User-Agent': 'CSE-Security-Scanner/1.0'
				}
			});
		} catch (e) {
			console.log(`HTTPS failed for ${domain}, trying HTTP. Error: ${e.message}`);
			results.recommendations.push("El sitio no es accesible a través de HTTPS. Se recomienda encarecidamente configurar SSL/TLS.");
			results.score -= 25;
			response = await fetch(`http://${domain}`, {
				redirect: 'manual',
				headers: {
					'User-Agent': 'CSE-Security-Scanner/1.0'
				}
			});
		}
		results.status_code = response.status;
		results.url = response.url;
		const requiredHeaders = {
			'Content-Security-Policy': {
				description: 'Protege contra ataques XSS y de inyección de datos.',
				penalty: 15
			},
			'Strict-Transport-Security': {
				description: 'Asegura que el navegador solo se comunique usando HTTPS.',
				penalty: 10
			},
			'X-Frame-Options': {
				description: 'Protege contra ataques de clickjacking.',
				penalty: 5
			},
			'X-Content-Type-Options': {
				description: 'Evita que el navegador interprete archivos con un tipo MIME diferente al declarado.',
				penalty: 5
			},
			'Referrer-Policy': {
				description: 'Controla cuánta información de referencia se incluye con las solicitudes.',
				penalty: 2
			},
			'Permissions-Policy': {
				description: 'Controla qué características y APIs del navegador pueden ser usadas en la página.',
				penalty: 3
			}
		};
		for (const [header, details] of Object.entries(requiredHeaders)) {
			const lowerCaseHeader = header.toLowerCase();
			if (response.headers.has(lowerCaseHeader)) {
				results.headers[header] = {
					present: true,
					value: response.headers.get(lowerCaseHeader)
				};
			} else {
				results.headers[header] = {
					present: false,
					value: null
				};
				results.recommendations.push(`Cabecera de seguridad ausente: '${header}'. ${details.description}`);
				results.score -= details.penalty;
			}
		}

	} catch (e) {
		console.error(`Failed to scan domain ${domain}: ${e.message}`);
		results.error = `No se pudo conectar al dominio. Puede que esté offline o bloqueando las solicitudes. Error: ${e.message}`;
		results.recommendations.push("Verifica que el dominio esté activo y accesible desde internet.");
		results.score = 0;
	}

	results.score = Math.max(0, results.score); // Asegura que la puntuación no sea negativa
	return results;
}

// --- GESTIÓN DE LA BASE DE DATOS (D1) - AHORA CON API NATIVA ---
const updateDomainStatus = async (db, domain, status, webSocket) => {
	await db.prepare('UPDATE domains SET status = ?1 WHERE name = ?2')
		.bind(status, domain)
		.run();

	if (webSocket && webSocket.readyState === WebSocket.OPEN) {
		webSocket.send(JSON.stringify({
			type: 'statusUpdate',
			domain,
			status
		}));
	}
};

const saveScanResults = async (db, domain, results, webSocket) => {
	const scan_data = JSON.stringify(results);
	const timestamp = new Date().toISOString();
	const newStatus = results.error ? 'failed' : 'completed';

	await db.prepare('INSERT INTO scans (domain_name, scan_date, scan_data) VALUES (?1, ?2, ?3)')
		.bind(domain, timestamp, scan_data)
		.run();

	await db.prepare('UPDATE domains SET last_scanned = ?1, status = ?2 WHERE name = ?3')
		.bind(timestamp, newStatus, domain)
		.run();

	console.log(`Successfully saved scan results for ${domain}`);
	if (webSocket && webSocket.readyState === WebSocket.OPEN) {
		webSocket.send(JSON.stringify({
			type: 'scanCompleted',
			domain,
			status: newStatus,
			last_scanned: timestamp
		}));
	}
};

// --- PLANTILLAS HTML (Sin cambios) ---
const AppShell = (data) => `
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CSE Security Scanner</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: 'Inter', sans-serif; }
        .status-dot { width: 10px; height: 10px; border-radius: 50%; display: inline-block; }
        .status-completed { background-color: #22c55e; }
        .status-queued { background-color: #f59e0b; }
        .status-scanning { background-color: #3b82f6; }
        .status-failed { background-color: #ef4444; }
        .status-pending { background-color: #6b7280; }
    </style>
</head>
<body class="bg-gray-100">
    <div id="app" class="flex h-screen bg-gray-200">
        <!-- Barra lateral -->
        <div class="fixed inset-y-0 left-0 transform w-64 bg-gray-900 text-white p-4 space-y-6 flex flex-col">
            <h1 class="text-2xl font-bold text-white">CSE Scanner</h1>
            <nav class="flex-grow">
                <a href="/dashboard" class="nav-link flex items-center py-2.5 px-4 rounded transition duration-200 hover:bg-gray-700">Dashboard</a>
                <a href="/domains" class="nav-link flex items-center py-2.5 px-4 rounded transition duration-200 hover:bg-gray-700">Dominios</a>
            </nav>
            <div class="mt-auto">
                 <form action="/logout" method="post">
                    <button type="submit" class="w-full text-left flex items-center py-2.5 px-4 rounded transition duration-200 hover:bg-red-700">Cerrar Sesión</button>
                </form>
            </div>
        </div>

        <!-- Contenido principal -->
        <main class="flex-1 p-10 ml-64 overflow-y-auto">
            <div id="view-content">
                <!-- El contenido de la vista se renderizará aquí -->
            </div>
        </main>
    </div>
    
    <!-- Modal para resultados de escaneo -->
    <div id="scan-modal" class="fixed inset-0 bg-black bg-opacity-50 hidden items-center justify-center p-4 z-50">
        <div class="bg-white rounded-xl shadow-2xl p-6 w-full max-w-2xl max-h-[90vh] overflow-y-auto">
            <div class="flex justify-between items-center mb-4">
                <h2 id="modal-title" class="text-xl font-bold">Resultados del Escaneo</h2>
                <button onclick="App.closeModal()" class="text-gray-500 hover:text-gray-800 text-2xl font-bold">&times;</button>
            </div>
            <div id="modal-content" class="text-sm">Cargando...</div>
        </div>
    </div>

    <!-- Datos iniciales para la app -->
    <script>
        window.initialData = ${JSON.stringify(data)};
    </script>
    <script src="/static/js/app.js"></script>
</body>
</html>`;

const loginPage = (error = '') => `
<!DOCTYPE html>
<html lang="es"><head><meta charset="UTF-8"><title>Login</title><script src="https://cdn.tailwindcss.com"></script></head>
<body class="bg-gray-100 flex items-center justify-center h-screen">
    <div class="max-w-md w-full bg-white p-8 rounded-xl shadow-md">
        <h1 class="text-2xl font-bold text-center mb-6">Acceso al Escáner</h1>
        <form action="/login" method="post" class="space-y-6">
            <div>
                <label for="password" class="block text-sm font-medium text-gray-700">Contraseña</label>
                <input type="password" name="password" id="password" required class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500">
            </div>
            ${error ? `<p class="text-red-500 text-sm text-center">${error}</p>` : ''}
            <button type="submit" class="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700">Entrar</button>
        </form>
    </div>
</body></html>`;


// --- MIDDLEWARE ---
const authMiddleware = (request, env) => {
	if (!env.AUTH_TOKEN || !env.PASSWORD) {
		console.error("AUTH_TOKEN and PASSWORD secrets are not set.");
		return error(500, "Server configuration error.");
	}
	const cookie = request.headers.get('cookie');
	if (!cookie || !cookie.includes(`auth_token=${env.AUTH_TOKEN}`)) {
		const url = new URL(request.url);
		if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/ws')) {
			return error(401, 'Unauthorized');
		}
		return Response.redirect(`${url.origin}/login`, 302);
	}
};

// --- RUTAS DE LA API ---
apiRouter
	.get('/domains', authMiddleware, async (request, {
		DB
	}) => {
		const {
			results
		} = await DB.prepare('SELECT * FROM domains ORDER BY added_date DESC').all();
		return json(results);
	})
	.post('/domains', authMiddleware, async (request, {
		DB,
		SCANNER_QUEUE
	}) => {
		try {
			const {
				domain
			} = await request.json();
			if (!domain || !/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(domain)) {
				return error(400, 'Invalid domain name.');
			}
			const added_date = new Date().toISOString();
			const inserted = await DB.prepare('INSERT INTO domains (name, added_date, status) VALUES (?1, ?2, ?3) RETURNING *')
				.bind(domain, added_date, 'queued')
				.first();

			await SCANNER_QUEUE.send({
				domain
			});
			return json(inserted);
		} catch (e) {
			if (e.message.includes('UNIQUE constraint failed')) {
				return error(409, 'Domain already exists.');
			}
			console.error("Error adding domain:", e);
			return error(500, 'Internal server error.');
		}
	})
	.post('/scanner', authMiddleware, async (request, {
		DB,
		SCANNER_QUEUE
	}) => {
		const {
			domain
		} = await request.json();
		if (!domain) return error(400, 'Domain required.');
		await updateDomainStatus(DB, domain, 'queued', request.WEBSOCKET);
		await SCANNER_QUEUE.send({
			domain
		});
		return json({
			message: 'Scan queued.'
		});
	})
	.get('/scans/:domain', authMiddleware, async ({
		params
	}, {
		DB
	}) => {
		const lastScan = await DB.prepare('SELECT * FROM scans WHERE domain_name = ?1 ORDER BY scan_date DESC LIMIT 1')
			.bind(params.domain)
			.first();

		if (lastScan) {
			return new Response(lastScan.scan_data, {
				headers: {
					'Content-Type': 'application/json'
				}
			});
		}
		return error(404, 'No scans found for this domain.');
	});


// --- RUTAS DE PÁGINAS Y WORKER PRINCIPAL ---
pageRouter
	.get('/login', () => new Response(loginPage(), {
		headers: {
			'Content-Type': 'text/html'
		}
	}))
	.post('/login', async (request, {
		PASSWORD,
		AUTH_TOKEN
	}) => {
		const formData = await request.formData();
		if (formData.get('password') === PASSWORD) {
			return new Response(null, {
				status: 302,
				headers: {
					'Location': '/dashboard',
					'Set-Cookie': `auth_token=${AUTH_TOKEN}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=86400`
				}
			});
		}
		return new Response(loginPage("Contraseña incorrecta."), {
			status: 401,
			headers: {
				'Content-Type': 'text/html'
			}
		});
	})
	.post('/logout', () => new Response(null, {
		status: 302,
		headers: {
			'Location': '/login',
			'Set-Cookie': 'auth_token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT'
		}
	}))
	.get('/static/js/app.js', () => new Response(FRONTEND_JS, {
		headers: {
			'Content-Type': 'application/javascript'
		}
	}))
	.get('/favicon.ico', () => new Response(
		`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M12 1.998c-5.524 0-10 4.476-10 10s4.476 10 10 10 10-4.476 10-10-4.476-10-10-10zm-3.293 14.293l-3.293-3.293 1.414-1.414 1.879 1.879 5.657-5.657 1.414 1.414-7.071 7.071z" fill-rule="evenodd" clip-rule="evenodd" fill="currentColor"/></svg>`, {
			headers: {
				'Content-Type': 'image/svg+xml'
			}
		}
	))
	// WebSocket handler
	.get('/ws', authMiddleware, (request, env) => {
		const pair = new WebSocketPair();
		const [client, server] = Object.values(pair);
		env.WEBSOCKET = server;
		server.accept();
		server.addEventListener('close', () => {
			env.WEBSOCKET = null;
		});
		server.addEventListener('error', (err) => {
			env.WEBSOCKET = null;
		});

		return new Response(null, {
			status: 101,
			webSocket: client
		});
	})
	// Ruta comodín para la SPA: sirve la aplicación principal para cualquier ruta no reconocida.
	.get('*', authMiddleware, async (request, {
		DB
	}) => {
		const {
			results
		} = await DB.prepare('SELECT * FROM domains ORDER BY added_date DESC').all();
		const data = {
			domains: results || []
		};
		return new Response(AppShell(data), {
			headers: {
				'Content-Type': 'text/html'
			}
		});
	});


export default {
	async fetch(request, env, ctx) {
		const url = new URL(request.url);
		if (url.pathname.startsWith('/api/')) {
			return apiRouter.handle(request, env, ctx).catch(err => error(err.status || 500, err.message));
		}
		return pageRouter.handle(request, env, ctx).catch(err => error(err.status || 500, err.message));
	},

	async queue(batch, env, ctx) {
		console.log(`Processing a batch of ${batch.messages.length} messages.`);
		for (const msg of batch.messages) {
			const {
				domain
			} = msg.body;
			if (!domain) {
				msg.ack();
				continue;
			}
			try {
				await updateDomainStatus(env.DB, domain, 'scanning', env.WEBSOCKET);
				const results = await scanDomain(domain);
				await saveScanResults(env.DB, domain, results, env.WEBSOCKET);
				msg.ack();
			} catch (err) {
				console.error(`Error scanning ${domain}: ${err.message}`);
				await updateDomainStatus(env.DB, domain, 'failed', env.WEBSOCKET);
				msg.ack();
			}
		}
	}
};

// --- CÓDIGO JAVASCRIPT DEL FRONTEND (Sin cambios) ---
const FRONTEND_JS = `
const App = {
    // Estado global de la aplicación
    state: {
        domains: [],
        currentView: 'dashboard',
    },
    // Elementos del DOM cacheados
    elements: {
        viewContent: null,
        navLinks: null,
        modal: null,
        modalTitle: null,
        modalContent: null,
    },
    // WebSocket
    ws: null,

    // Inicialización de la aplicación
    init() {
        // Cargar datos iniciales desde el HTML
        this.state.domains = window.initialData.domains || [];
        
        // Cachear elementos del DOM
        this.elements.viewContent = document.getElementById('view-content');
        this.elements.navLinks = document.querySelectorAll('.nav-link');
        this.elements.modal = document.getElementById('scan-modal');
        this.elements.modalTitle = document.getElementById('modal-title');
        this.elements.modalContent = document.getElementById('modal-content');

        this.setupRouting();
        this.connectWebSocket();
        
        // Renderizar la vista inicial basada en la URL actual
        const path = window.location.pathname.replace('/', '') || 'dashboard';
        this.navigateTo(path, false); // false para no crear una nueva entrada en el historial
    },

    // Configurar el enrutamiento del lado del cliente
    setupRouting() {
        // Escuchar cambios en el historial del navegador (botones atrás/adelante)
        window.addEventListener('popstate', (e) => {
            const path = e.state?.path || 'dashboard';
            this.renderView(path);
        });

        // Añadir listeners a los enlaces de navegación
        this.elements.navLinks.forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const path = new URL(e.currentTarget.href).pathname.substring(1);
                this.navigateTo(path);
            });
        });
    },
    
    // Navegar a una nueva vista
    navigateTo(path, addToHistory = true) {
        if (addToHistory) {
            // Añadir una nueva entrada al historial del navegador
            history.pushState({ path }, '', '/' + path);
        }
        this.renderView(path);
    },

    // Renderizar la vista actual en el DOM
    renderView(path) {
        this.state.currentView = path;
        
        // Resaltar el enlace de navegación activo
        this.elements.navLinks.forEach(l => {
            l.classList.toggle('bg-gray-700', l.pathname.endsWith(path));
        });

        // Renderizar la plantilla correspondiente
        switch (path) {
            case 'dashboard':
                this.elements.viewContent.innerHTML = this.templates.dashboard();
                this.renderCharts();
                break;
            case 'domains':
                this.elements.viewContent.innerHTML = this.templates.domainsPage(this.state.domains);
                this.setupDomainPageEventListeners();
                break;
            default:
                this.navigateTo('dashboard'); // Redirigir a dashboard si la ruta no existe
        }
    },
    
    // Configurar listeners para la página de dominios
    setupDomainPageEventListeners() {
        const form = document.getElementById('add-domain-form');
        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            const input = document.getElementById('domain-input');
            const domain = input.value.trim();
            if (!domain) return;

            const button = e.submitter;
            button.disabled = true;
            button.textContent = 'Añadiendo...';

            const messageEl = document.getElementById('form-message');
            messageEl.textContent = '';

            try {
                const response = await fetch('/api/domains', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ domain }),
                });
                const newDomain = await response.json();
                if (!response.ok) throw new Error(newDomain.error || 'Error desconocido');

                this.state.domains.unshift(newDomain);
                this.renderView('domains'); // Re-renderizar para mostrar el nuevo dominio
                
            } catch (error) {
                messageEl.textContent = \`Error: \${error.message}\`;
                messageEl.className = 'mt-3 text-sm text-red-600';
                button.disabled = false;
                button.textContent = 'Añadir';
            }
        });
    },
    
    // Conectar WebSocket para actualizaciones en tiempo real
    connectWebSocket() {
        const url = new URL(window.location.href);
        url.protocol = url.protocol.replace('http', 'ws');
        url.pathname = '/ws';
        
        this.ws = new WebSocket(url.toString());

        this.ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            console.log('WS Message:', data);
            
            const domainToUpdate = this.state.domains.find(d => d.name === data.domain);
            if (domainToUpdate) {
                domainToUpdate.status = data.status;
                if(data.last_scanned) {
                    domainToUpdate.last_scanned = data.last_scanned;
                }
                // Si estamos en la vista de dominios, la re-renderizamos para mostrar el cambio
                if (this.state.currentView === 'domains') {
                    this.renderView('domains');
                }
            }
        };

        this.ws.onclose = () => {
            console.log('WebSocket disconnected. Reconnecting in 5s...');
            setTimeout(() => this.connectWebSocket(), 5000);
        };
        
        this.ws.onerror = (err) => {
            console.error('WebSocket error:', err);
            this.ws.close();
        };
    },

    // Renderizar gráficos en el dashboard
    renderCharts() {
        const ctx = document.getElementById('securityScoreChart')?.getContext('2d');
        if (!ctx) return;
        new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Seguro', 'Vulnerable'],
                datasets: [{
                    data: [85, 15], // Datos de ejemplo
                    backgroundColor: ['#22c55e', '#ef4444'],
                    borderColor: '#fff',
                    borderWidth: 4,
                }]
            },
            options: { responsive: true, maintainAspectRatio: false, cutout: '70%' }
        });
    },

    // Plantillas HTML para las vistas
    templates: {
        dashboard() {
            const completedScans = App.state.domains.filter(d => d.status === 'completed').length;
            const failedScans = App.state.domains.filter(d => d.status === 'failed').length;
            return \`
                <h1 class="text-3xl font-bold mb-6">Dashboard</h1>
                <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                    <div class="bg-white p-6 rounded-xl shadow">
                        <h2 class="text-gray-500 text-sm font-medium">Dominios Totales</h2>
                        <p class="text-3xl font-bold">\${App.state.domains.length}</p>
                    </div>
                    <div class="bg-white p-6 rounded-xl shadow">
                        <h2 class="text-gray-500 text-sm font-medium">Escaneos Completados</h2>
                        <p class="text-3xl font-bold text-green-600">\${completedScans}</p>
                    </div>
                    <div class="bg-white p-6 rounded-xl shadow">
                        <h2 class="text-gray-500 text-sm font-medium">Escaneos Fallidos</h2>
                        <p class="text-3xl font-bold text-red-600">\${failedScans}</p>
                    </div>
                </div>
                <div class="mt-8 bg-white p-6 rounded-xl shadow" style="height: 300px;">
                    <h2 class="text-xl font-semibold mb-4">Puntuación de Seguridad General</h2>
                    <canvas id="securityScoreChart"></canvas>
                </div>
            \`;
        },
        domainsPage(domains) {
            return \`
                <h1 class="text-3xl font-bold mb-6">Dominios</h1>
                <div class="bg-white p-6 rounded-xl shadow-md mb-8">
                    <h2 class="text-xl font-semibold mb-4">Añadir Dominio</h2>
                    <form id="add-domain-form" class="flex flex-col sm:flex-row gap-4">
                        <input type="text" id="domain-input" placeholder="ejemplo.com" class="flex-grow p-3 border rounded-lg" required>
                        <button type="submit" class="bg-blue-600 hover:bg-blue-700 text-white font-bold py-3 px-6 rounded-lg transition-colors">Añadir</button>
                    </form>
                    <p id="form-message" class="mt-3 text-sm"></p>
                </div>
                <div class="bg-white p-6 rounded-xl shadow-md">
                    <h2 class="text-xl font-semibold mb-4">Dominios Monitorizados</h2>
                    <div id="domains-list" class="space-y-4">
                        \${domains.length > 0 ? domains.map(this.domainCard).join('') : '<p class="text-gray-500">No hay dominios todavía. Añade uno para empezar.</p>'}
                    </div>
                </div>
            \`;
        },
        domainCard(domain) {
            const statusText = domain.status ? (domain.status.charAt(0).toUpperCase() + domain.status.slice(1)) : 'Pendiente';
            const lastScannedText = domain.last_scanned ? new Date(domain.last_scanned).toLocaleString('es-ES') : 'Nunca';
            return \`
            <div class="p-4 border rounded-lg flex flex-col sm:flex-row justify-between items-center gap-4">
                <div class="flex-grow">
                    <h3 class="font-bold text-lg">\${domain.name}</h3>
                    <p class="text-sm text-gray-500">
                        <span class="status-dot status-\${domain.status || 'pending'} inline-block align-middle"></span>
                        <span class="font-semibold align-middle">\${statusText}</span>
                        | Último escaneo: \${lastScannedText}
                    </p>
                </div>
                <div class="flex gap-2 flex-shrink-0">
                     <button onclick="App.viewScan('\${domain.name}')" class="bg-green-500 hover:bg-green-600 text-white font-semibold py-2 px-4 rounded-lg text-sm" \${!domain.last_scanned ? 'disabled' : ''}>Ver</button>
                     <button onclick="App.rescanDomain(this, '\${domain.name}')" class="bg-gray-200 hover:bg-gray-300 font-semibold py-2 px-4 rounded-lg text-sm">Re-escanear</button>
                </div>
            </div>\`;
        },
        formatScanResults(results) {
            if (results.error) {
                return \`<div class="text-red-500 font-bold">Error de Escaneo: \${results.error}</div>
                        <div class="mt-2 text-gray-600">\${results.recommendations.join('<br>')}</div>\`;
            }

            let html = \`<div class="space-y-4">
                <div class="text-center mb-4">
                    <h3 class="text-lg font-medium">Puntuación de Seguridad</h3>
                    <p class="text-5xl font-bold \${results.score > 80 ? 'text-green-600' : results.score > 50 ? 'text-yellow-500' : 'text-red-600'}">\${results.score} / 100</p>
                </div>
                <div>
                    <h4 class="font-bold text-md mb-2">Cabeceras de Seguridad</h4>
                    <ul class="space-y-2">
            \`;
            
            Object.entries(results.headers).forEach(([header, data]) => {
                html += \`<li class="font-mono p-2 rounded-md \${data.present ? 'bg-green-50' : 'bg-red-50'}">
                    <strong class="mr-2">\${header}:</strong> 
                    \${data.present 
                        ? '<span class="text-green-700 font-semibold">Presente</span>' 
                        : '<span class="text-red-700 font-semibold">Ausente</span>'}
                </li>\`;
            });

            html += \`</ul></div>\`;

            if (results.recommendations && results.recommendations.length > 0) {
                html += \`<div>
                    <h4 class="font-bold text-md mt-4 mb-2">Recomendaciones</h4>
                    <ul class="list-disc list-inside space-y-2 text-gray-700">
                \`;
                results.recommendations.forEach(rec => {
                    html += \`<li>\${rec}</li>\`;
                });
                html += \`</ul></div>\`;
            }

            html += '</div>';
            return html;
        }
    },

    // Acciones de la aplicación
    async rescanDomain(button, domain) {
        button.textContent = 'Encolando...';
        button.disabled = true;
        try {
            await fetch('/api/scanner', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ domain })
            });
            // La actualización de la UI se manejará por WebSocket, pero podemos hacer una actualización optimista.
            const domainState = this.state.domains.find(d => d.name === domain);
            if(domainState) {
                domainState.status = 'queued';
                this.renderView('domains');
            }
        } catch (error) {
            console.error('Error al re-escanear:', error);
            alert('No se pudo iniciar el escaneo.');
            button.textContent = 'Re-escanear';
            button.disabled = false;
        }
    },

    async viewScan(domain) {
        this.elements.modalTitle.textContent = \`Resultados para \${domain}\`;
        this.elements.modalContent.innerHTML = '<p>Cargando...</p>';
        this.elements.modal.classList.remove('hidden');
        this.elements.modal.classList.add('flex');

        try {
            const response = await fetch(\`/api/scans/\${domain}\`);
            if (!response.ok) {
                const err = await response.json();
                throw new Error(err.error || 'No se pudieron obtener los resultados.');
            }
            const results = await response.json();
            this.elements.modalContent.innerHTML = this.templates.formatScanResults(results);
        } catch (error) {
            this.elements.modalContent.innerHTML = \`<p class="text-red-500">Error: \${error.message}</p>\`;
        }
    },

    closeModal() {
        this.elements.modal.classList.add('hidden');
        this.elements.modal.classList.remove('flex');
    }
};

document.addEventListener('DOMContentLoaded', () => App.init());
`;
