/**
 * TacLink HF — API de control de acceso
 * Tiwin Developers · X Prog. GE - 2026
 *
 * Endpoints públicos:
 *   GET  /verify/:id          → verifica si un equipo está autorizado
 *   POST /request             → registra una solicitud de acceso nueva
 *
 * Endpoints de administración (requieren ADMIN_TOKEN):
 *   GET  /admin               → panel web de administración
 *   GET  /admin/api/devices   → lista todos los equipos
 *   POST /admin/api/approve   → aprueba un equipo
 *   POST /admin/api/revoke    → revoca un equipo
 *   DELETE /admin/api/device  → elimina un equipo del registro
 *   GET  /admin/api/log       → log de actividad
 */

const express = require("express");
const fs      = require("fs");
const path    = require("path");
const crypto  = require("crypto");

const app  = express();
const PORT = process.env.PORT || 3001;

// ── Configuración desde variables de entorno ──────────────────────────────────
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "cambiar-este-token-ahora";
const APP_NAME    = "TacLink HF";
const DB_FILE     = path.join(__dirname, "data", "devices.json");

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(express.json());
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-Admin-Token");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

// ── Base de datos (JSON en disco) ─────────────────────────────────────────────
function loadDB() {
  try {
    if (!fs.existsSync(path.dirname(DB_FILE))) {
      fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });
    }
    if (!fs.existsSync(DB_FILE)) {
      const initial = { devices: [], log: [] };
      fs.writeFileSync(DB_FILE, JSON.stringify(initial, null, 2));
      return initial;
    }
    return JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
  } catch (e) {
    console.error("Error leyendo DB:", e.message);
    return { devices: [], log: [] };
  }
}

function saveDB(db) {
  try {
    if (!fs.existsSync(path.dirname(DB_FILE))) {
      fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });
    }
    fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
  } catch (e) {
    console.error("Error guardando DB:", e.message);
  }
}

function addLog(db, evento, machineId, detalle = "") {
  db.log.unshift({
    ts: new Date().toISOString(),
    evento,
    machineId: machineId || "—",
    detalle,
    ip: ""
  });
  if (db.log.length > 500) db.log = db.log.slice(0, 500);
}

// ── Middleware de autenticación admin ─────────────────────────────────────────
function requireAdmin(req, res, next) {
  const token = req.headers["x-admin-token"] || req.query.token;
  if (!token || token !== ADMIN_TOKEN) {
    return res.status(401).json({ error: "No autorizado" });
  }
  next();
}

// ══════════════════════════════════════════════════════════════════════════════
// ENDPOINTS PÚBLICOS (usados por la extensión)
// ══════════════════════════════════════════════════════════════════════════════

// Verificar si un equipo está autorizado
app.get("/verify/:id", (req, res) => {
  const { id } = req.params;
  if (!id || !/^[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}$/i.test(id)) {
    return res.json({ autorizado: false, razon: "ID inválido" });
  }

  const db     = loadDB();
  const device = db.devices.find(d => d.id === id.toUpperCase());

  if (device) {
    // Actualizar última conexión
    device.ultimaConexion = new Date().toISOString();
    device.conexiones = (device.conexiones || 0) + 1;
    addLog(db, "VERIFICACION", id, device.autorizado ? "AUTORIZADO" : "DENEGADO");
    saveDB(db);
    return res.json({ autorizado: device.autorizado, nombre: device.nombre || "" });
  }

  // Equipo nuevo — registrarlo como pendiente
  db.devices.push({
    id: id.toUpperCase(),
    autorizado: false,
    estado: "pendiente",
    nombre: "",
    fechaSolicitud: new Date().toISOString(),
    ultimaConexion: new Date().toISOString(),
    conexiones: 1,
    notas: ""
  });
  addLog(db, "EQUIPO_NUEVO", id, "Primer intento de acceso");
  saveDB(db);

  return res.json({ autorizado: false, razon: "Pendiente de autorización" });
});

// Registrar solicitud (cuando el usuario toca "Contactar admin")
app.post("/request", (req, res) => {
  const { id, mensaje } = req.body;
  if (!id) return res.status(400).json({ error: "ID requerido" });

  const db     = loadDB();
  const device = db.devices.find(d => d.id === id.toUpperCase());

  if (device) {
    device.solicitudEnviada = new Date().toISOString();
    device.mensajeSolicitud = mensaje || "";
  } else {
    db.devices.push({
      id: id.toUpperCase(),
      autorizado: false,
      estado: "pendiente",
      nombre: "",
      fechaSolicitud: new Date().toISOString(),
      ultimaConexion: new Date().toISOString(),
      conexiones: 0,
      solicitudEnviada: new Date().toISOString(),
      mensajeSolicitud: mensaje || ""
    });
  }
  addLog(db, "SOLICITUD_ENVIADA", id, "Usuario contactó al administrador");
  saveDB(db);

  return res.json({ ok: true });
});


// Ping / registro de conexión activa (llamado por la extensión al iniciar)
app.post("/devices/ping", (req, res) => {
  const { machineId } = req.body;
  if (!machineId) return res.json({ ok: false });
  const db     = loadDB();
  const device = db.devices.find(d => d.id === (machineId||"").toUpperCase());
  if (device && device.autorizado) {
    device.ultimaConexion = new Date().toISOString();
    device.conexiones = (device.conexiones || 0) + 1;
    addLog(db, "PING", machineId, "Conexión activa");
    saveDB(db);
    return res.json({ ok: true });
  }
  res.json({ ok: false });
});

// Alias POST /devices/check (compatibilidad con versiones anteriores de la extensión)
app.post("/devices/check", (req, res) => {
  const { machineId } = req.body;
  if (!machineId) return res.json({ authorized: false, status: "invalid" });
  const db     = loadDB();
  const device = db.devices.find(d => d.id === (machineId||"").toUpperCase());
  if (device) {
    device.ultimaConexion = new Date().toISOString();
    device.conexiones = (device.conexiones || 0) + 1;
    saveDB(db);
    return res.json({ authorized: device.autorizado, status: device.estado || (device.autorizado ? "active" : "unauthorized") });
  }
  // Nuevo equipo: registrar como pendiente
  db.devices.push({
    id: (machineId||"").toUpperCase(),
    autorizado: false, estado: "pendiente", nombre: "",
    fechaSolicitud: new Date().toISOString(),
    ultimaConexion: new Date().toISOString(),
    conexiones: 1, notas: ""
  });
  addLog(db, "EQUIPO_NUEVO", machineId, "Acceso via /devices/check");
  saveDB(db);
  res.json({ authorized: false, status: "pending" });
});

// ══════════════════════════════════════════════════════════════════════════════
// ENDPOINTS DE ADMINISTRACIÓN
// ══════════════════════════════════════════════════════════════════════════════

// Lista de equipos
app.get("/admin/api/devices", requireAdmin, (req, res) => {
  const db = loadDB();
  res.json({ devices: db.devices, total: db.devices.length });
});

// Aprobar equipo
app.post("/admin/api/approve", requireAdmin, (req, res) => {
  const { id, nombre, notas } = req.body;
  if (!id) return res.status(400).json({ error: "ID requerido" });

  const db     = loadDB();
  const device = db.devices.find(d => d.id === id.toUpperCase());

  if (device) {
    device.autorizado   = true;
    device.estado       = "autorizado";
    device.nombre       = nombre || device.nombre || "";
    device.notas        = notas  || device.notas  || "";
    device.fechaAprobacion = new Date().toISOString();
  } else {
    db.devices.push({
      id: id.toUpperCase(),
      autorizado: true,
      estado: "autorizado",
      nombre: nombre || "",
      notas: notas || "",
      fechaSolicitud: new Date().toISOString(),
      fechaAprobacion: new Date().toISOString(),
      ultimaConexion: null,
      conexiones: 0
    });
  }
  addLog(db, "EQUIPO_APROBADO", id, nombre || "sin nombre");
  saveDB(db);
  res.json({ ok: true });
});

// Revocar equipo
app.post("/admin/api/revoke", requireAdmin, (req, res) => {
  const { id, motivo } = req.body;
  if (!id) return res.status(400).json({ error: "ID requerido" });

  const db     = loadDB();
  const device = db.devices.find(d => d.id === id.toUpperCase());

  if (device) {
    device.autorizado = false;
    device.estado     = "revocado";
    device.motivoRevocacion = motivo || "";
    device.fechaRevocacion  = new Date().toISOString();
    addLog(db, "EQUIPO_REVOCADO", id, motivo || "sin motivo");
    saveDB(db);
    return res.json({ ok: true });
  }
  res.status(404).json({ error: "Equipo no encontrado" });
});

// Eliminar equipo
app.delete("/admin/api/device", requireAdmin, (req, res) => {
  const { id } = req.body;
  if (!id) return res.status(400).json({ error: "ID requerido" });

  const db  = loadDB();
  const idx = db.devices.findIndex(d => d.id === id.toUpperCase());
  if (idx === -1) return res.status(404).json({ error: "No encontrado" });

  db.devices.splice(idx, 1);
  addLog(db, "EQUIPO_ELIMINADO", id);
  saveDB(db);
  res.json({ ok: true });
});

// Actualizar nombre/notas de un equipo
app.post("/admin/api/update", requireAdmin, (req, res) => {
  const { id, nombre, notas } = req.body;
  if (!id) return res.status(400).json({ error: "ID requerido" });

  const db     = loadDB();
  const device = db.devices.find(d => d.id === id.toUpperCase());
  if (!device) return res.status(404).json({ error: "No encontrado" });

  device.nombre = nombre ?? device.nombre;
  device.notas  = notas  ?? device.notas;
  saveDB(db);
  res.json({ ok: true });
});

// Log de actividad
app.get("/admin/api/log", requireAdmin, (req, res) => {
  const db    = loadDB();
  const limit = parseInt(req.query.limit) || 100;
  res.json({ log: db.log.slice(0, limit) });
});

// Estadísticas
app.get("/admin/api/stats", requireAdmin, (req, res) => {
  const db = loadDB();
  res.json({
    total:      db.devices.length,
    autorizados: db.devices.filter(d => d.autorizado).length,
    pendientes:  db.devices.filter(d => !d.autorizado && d.estado === "pendiente").length,
    revocados:   db.devices.filter(d => d.estado === "revocado").length,
    logTotal:    db.log.length
  });
});

// ── Panel de administración (HTML) ────────────────────────────────────────────
app.get("/admin", (req, res) => {
  res.send(ADMIN_HTML);
});

// Ruta raíz — health check
app.get("/", (req, res) => {
  res.json({
    app: "TacLink HF API",
    version: "1.0.0",
    status: "ok",
    ts: new Date().toISOString()
  });
});

// ── Arranque ──────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`TacLink HF API corriendo en puerto ${PORT}`);
  console.log(`Panel admin: http://localhost:${PORT}/admin`);
  console.log(`Admin token: ${ADMIN_TOKEN === "cambiar-este-token-ahora" ? "⚠ CAMBIAR EN VARIABLE DE ENTORNO" : "configurado"}`);
});

// ══════════════════════════════════════════════════════════════════════════════
// PANEL HTML DE ADMINISTRACIÓN
// ══════════════════════════════════════════════════════════════════════════════
const ADMIN_HTML = `<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>TacLink HF — Panel Admin</title>
<style>
:root{
  --blue:#185FA5;--blue2:#0C447C;--blue3:#E6F1FB;--cyan:#378ADD;
  --green:#0F6E56;--green2:#1D9E75;--greenbg:#E1F5EE;
  --text:#1e293b;--muted:#64748b;--border:#e2e8f0;
  --bg:#f8fafc;--card:#fff;
  --warn:#dc2626;--warnbg:#fee2e2;
  --amber:#d97706;--amberbg:#fef3c7;
  --purple:#7c3aed;--purplebg:#ede9fe;
}
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;font-size:13px;color:var(--text);background:var(--bg);min-height:100vh;}

/* Login */
#login-screen{display:flex;align-items:center;justify-content:center;min-height:100vh;}
.login-card{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:32px;width:360px;text-align:center;}
.login-logo{font-size:22px;font-weight:700;color:var(--blue);letter-spacing:.08em;margin-bottom:4px;}
.login-sub{font-size:11px;color:var(--muted);margin-bottom:24px;}
.login-card input{width:100%;height:40px;padding:0 12px;border:1px solid var(--border);border-radius:8px;font-size:13px;margin-bottom:12px;}
.login-card input:focus{outline:none;border-color:var(--cyan);}
.login-card button{width:100%;height:40px;background:var(--blue);color:#fff;border:none;border-radius:8px;font-size:13px;font-weight:600;cursor:pointer;}
.login-card button:hover{background:var(--blue2);}
.login-err{color:var(--warn);font-size:12px;margin-top:8px;}

/* App */
#app{display:none;}
.topbar{background:var(--blue2);padding:12px 24px;display:flex;align-items:center;gap:12px;}
.topbar-logo{color:#fff;font-weight:700;font-size:15px;letter-spacing:.08em;}
.topbar-sub{color:#b5d4f4;font-size:11px;}
.topbar-logout{margin-left:auto;background:rgba(255,255,255,.15);color:#e2e8f0;border:1px solid rgba(255,255,255,.2);border-radius:6px;padding:5px 12px;font-size:11px;cursor:pointer;}
.topbar-logout:hover{background:rgba(255,255,255,.25);}

.container{max-width:1100px;margin:0 auto;padding:20px;}

/* Stats */
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px;}
.stat{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:14px 16px;}
.stat-val{font-size:28px;font-weight:600;color:var(--blue);margin-bottom:2px;}
.stat-lbl{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;}

/* Tabs */
.tabs{display:flex;gap:4px;margin-bottom:16px;}
.tab{padding:7px 16px;border-radius:8px;cursor:pointer;font-size:12px;color:var(--muted);border:1px solid transparent;}
.tab.active{background:var(--blue3);color:var(--blue);border-color:#b5d4f4;font-weight:500;}
.tab:hover:not(.active){background:var(--bg);border-color:var(--border);}

/* Panels */
.panel{display:none;}
.panel.active{display:block;}

/* Filters */
.filters{display:flex;gap:8px;margin-bottom:14px;flex-wrap:wrap;}
.filters input,.filters select{height:34px;padding:0 10px;border:1px solid var(--border);border-radius:7px;font-size:12px;background:#fff;color:var(--text);}
.filters input{flex:1;min-width:180px;}
.filters input:focus,.filters select:focus{outline:none;border-color:var(--cyan);}

/* Add device form */
.add-form{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:14px 16px;margin-bottom:14px;display:flex;gap:8px;flex-wrap:wrap;align-items:flex-end;}
.add-form label{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;display:block;margin-bottom:3px;}
.add-form input{height:34px;padding:0 10px;border:1px solid var(--border);border-radius:7px;font-size:12px;width:200px;}
.add-form input.wide{width:260px;}
.add-form input:focus{outline:none;border-color:var(--cyan);}
.btn-add{height:34px;padding:0 16px;background:var(--green2);color:#fff;border:none;border-radius:7px;font-size:12px;font-weight:600;cursor:pointer;white-space:nowrap;}
.btn-add:hover{background:var(--green);}

/* Devices table */
.devices-table{background:var(--card);border:1px solid var(--border);border-radius:10px;overflow:hidden;}
table{width:100%;border-collapse:collapse;}
th{text-align:left;font-size:10px;color:var(--muted);padding:10px 14px;border-bottom:1px solid var(--border);text-transform:uppercase;letter-spacing:.06em;background:var(--bg);white-space:nowrap;}
td{padding:10px 14px;border-bottom:1px solid #f1f5f9;vertical-align:middle;}
tr:last-child td{border:none;}
tr:hover td{background:#fafbfc;}

.id-cell{font-family:'Courier New',monospace;font-size:12px;color:var(--blue);letter-spacing:.04em;}
.name-cell{font-weight:500;color:var(--text);}
.date-cell{font-size:11px;color:var(--muted);}
.conn-cell{font-size:12px;color:var(--text);text-align:center;}

.badge{font-size:10px;padding:2px 8px;border-radius:10px;font-weight:500;white-space:nowrap;}
.badge-auth{background:var(--greenbg);color:var(--green);border:1px solid #9fe1cb;}
.badge-pend{background:var(--amberbg);color:var(--amber);border:1px solid #fcd34d;}
.badge-rev{background:var(--warnbg);color:var(--warn);border:1px solid #fca5a5;}

.actions{display:flex;gap:5px;}
.btn-approve{padding:4px 10px;background:var(--greenbg);color:var(--green);border:1px solid #9fe1cb;border-radius:5px;font-size:11px;cursor:pointer;white-space:nowrap;}
.btn-approve:hover{background:#c6f0dc;}
.btn-revoke{padding:4px 10px;background:var(--amberbg);color:var(--amber);border:1px solid #fcd34d;border-radius:5px;font-size:11px;cursor:pointer;}
.btn-revoke:hover{background:#fde68a;}
.btn-delete{padding:4px 10px;background:var(--warnbg);color:var(--warn);border:1px solid #fca5a5;border-radius:5px;font-size:11px;cursor:pointer;}
.btn-delete:hover{background:#fecaca;}

.notes-input{border:1px solid var(--border);border-radius:5px;padding:3px 7px;font-size:11px;width:120px;}
.notes-input:focus{outline:none;border-color:var(--cyan);}

/* Log */
.log-table{background:var(--card);border:1px solid var(--border);border-radius:10px;overflow:hidden;max-height:600px;overflow-y:auto;}
.log-row{display:flex;gap:12px;padding:8px 14px;border-bottom:1px solid #f1f5f9;font-size:11px;align-items:center;}
.log-row:last-child{border:none;}
.log-ts{color:var(--muted);font-family:'Courier New',monospace;flex-shrink:0;width:130px;}
.log-ev{font-weight:500;width:160px;flex-shrink:0;}
.log-id{color:var(--blue);font-family:'Courier New',monospace;font-size:10px;width:160px;}
.log-det{color:var(--muted);}
.ev-VERIFICACION{color:var(--blue);}
.ev-EQUIPO_NUEVO{color:var(--amber);}
.ev-EQUIPO_APROBADO{color:var(--green2);}
.ev-EQUIPO_REVOCADO,.ev-EQUIPO_ELIMINADO{color:var(--warn);}
.ev-SOLICITUD_ENVIADA{color:var(--purple);}

.empty{text-align:center;padding:40px;color:var(--muted);}
.refresh-btn{padding:6px 14px;background:var(--card);border:1px solid var(--border);border-radius:7px;font-size:12px;cursor:pointer;color:var(--muted);}
.refresh-btn:hover{border-color:var(--cyan);color:var(--cyan);}
.toolbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;}
.toolbar-title{font-size:13px;font-weight:500;color:var(--text);}

.modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.4);z-index:100;align-items:center;justify-content:center;}
.modal-overlay.open{display:flex;}
.modal{background:#fff;border-radius:12px;padding:24px;width:380px;max-width:95vw;}
.modal h3{font-size:15px;margin-bottom:12px;color:var(--text);}
.modal input,.modal textarea{width:100%;border:1px solid var(--border);border-radius:7px;padding:8px 10px;font-size:13px;margin-bottom:10px;font-family:inherit;}
.modal input:focus,.modal textarea:focus{outline:none;border-color:var(--cyan);}
.modal-btns{display:flex;gap:8px;justify-content:flex-end;}
.modal-cancel{padding:7px 16px;border:1px solid var(--border);border-radius:7px;background:#fff;cursor:pointer;font-size:12px;}
.modal-confirm{padding:7px 16px;background:var(--blue);color:#fff;border:none;border-radius:7px;cursor:pointer;font-size:12px;font-weight:600;}
</style>
</head>
<body>

<!-- LOGIN -->
<div id="login-screen">
  <div class="login-card">
    <div class="login-logo">TacLink HF</div>
    <div class="login-sub">Panel de Administración · Tiwin Developers</div>
    <input type="password" id="token-input" placeholder="Token de administrador" onkeydown="if(event.key==='Enter')login()">
    <button onclick="login()">Ingresar</button>
    <div class="login-err" id="login-err"></div>
  </div>
</div>

<!-- APP -->
<div id="app">
  <div class="topbar">
    <div class="topbar-logo">TacLink HF</div>
    <div class="topbar-sub">Panel de Administración · X Prog. GE - 2026</div>
    <button class="topbar-logout" onclick="logout()">Cerrar sesión</button>
  </div>

  <div class="container">
    <!-- Stats -->
    <div class="stats" id="stats-grid">
      <div class="stat"><div class="stat-val" id="s-total">—</div><div class="stat-lbl">Total equipos</div></div>
      <div class="stat"><div class="stat-val" id="s-auth" style="color:var(--green2)">—</div><div class="stat-lbl">Autorizados</div></div>
      <div class="stat"><div class="stat-val" id="s-pend" style="color:var(--amber)">—</div><div class="stat-lbl">Pendientes</div></div>
      <div class="stat"><div class="stat-val" id="s-rev" style="color:var(--warn)">—</div><div class="stat-lbl">Revocados</div></div>
    </div>

    <!-- Tabs -->
    <div class="tabs">
      <div class="tab active" onclick="showPanel('devices',this)">Equipos</div>
      <div class="tab" onclick="showPanel('log',this)">Log de actividad</div>
    </div>

    <!-- PANEL: EQUIPOS -->
    <div class="panel active" id="panel-devices">
      <!-- Agregar manualmente -->
      <div class="add-form">
        <div>
          <label>Machine ID</label>
          <input type="text" id="new-id" class="wide" placeholder="XXXX-XXXX-XXXX-XXXX" maxlength="19">
        </div>
        <div>
          <label>Nombre / Descripción</label>
          <input type="text" id="new-name" placeholder="Ej: Sargento López - PC Comando">
        </div>
        <button class="btn-add" onclick="aprobarManual()">+ Autorizar equipo</button>
      </div>

      <!-- Filtros -->
      <div class="filters">
        <input type="text" id="search" placeholder="Buscar por ID, nombre o notas..." oninput="renderDevices()">
        <select id="filter-estado" onchange="renderDevices()">
          <option value="">Todos los estados</option>
          <option value="autorizado">Autorizados</option>
          <option value="pendiente">Pendientes</option>
          <option value="revocado">Revocados</option>
        </select>
        <button class="refresh-btn" onclick="loadData()">↻ Actualizar</button>
      </div>

      <!-- Tabla -->
      <div class="devices-table">
        <table>
          <thead>
            <tr>
              <th>Machine ID</th>
              <th>Nombre</th>
              <th>Estado</th>
              <th>Última conexión</th>
              <th style="text-align:center">Conexiones</th>
              <th>Notas</th>
              <th>Acciones</th>
            </tr>
          </thead>
          <tbody id="devices-tbody"></tbody>
        </table>
      </div>
    </div>

    <!-- PANEL: LOG -->
    <div class="panel" id="panel-log">
      <div class="toolbar">
        <div class="toolbar-title">Últimas 100 entradas</div>
        <button class="refresh-btn" onclick="loadLog()">↻ Actualizar</button>
      </div>
      <div class="log-table" id="log-container"></div>
    </div>
  </div>
</div>

<!-- MODAL APROBAR -->
<div class="modal-overlay" id="modal-approve">
  <div class="modal">
    <h3>Autorizar equipo</h3>
    <input type="text" id="modal-id" placeholder="Machine ID (XXXX-XXXX-XXXX-XXXX)" maxlength="19">
    <input type="text" id="modal-name" placeholder="Nombre del usuario / unidad">
    <textarea id="modal-notes" rows="2" placeholder="Notas internas (opcional)"></textarea>
    <div class="modal-btns">
      <button class="modal-cancel" onclick="closeModal('modal-approve')">Cancelar</button>
      <button class="modal-confirm" onclick="confirmarAprobacion()">Autorizar</button>
    </div>
  </div>
</div>

<script>
let adminToken = "";
let allDevices = [];

// ── Autenticación ──────────────────────────────────────────────────────────────
async function login() {
  const token = document.getElementById("token-input").value.trim();
  if (!token) return;
  try {
    const r = await fetch("/admin/api/stats", { headers: { "x-admin-token": token } });
    if (!r.ok) { document.getElementById("login-err").textContent = "Token incorrecto"; return; }
    adminToken = token;
    sessionStorage.setItem("taclink_token", token);
    document.getElementById("login-screen").style.display = "none";
    document.getElementById("app").style.display = "block";
    loadData();
  } catch { document.getElementById("login-err").textContent = "Error de conexión"; }
}

function logout() {
  adminToken = "";
  sessionStorage.removeItem("taclink_token");
  document.getElementById("login-screen").style.display = "flex";
  document.getElementById("app").style.display = "none";
  document.getElementById("token-input").value = "";
}

// Restaurar sesión si existe
window.addEventListener("load", () => {
  const saved = sessionStorage.getItem("taclink_token");
  if (saved) { document.getElementById("token-input").value = saved; login(); }
});

// ── Datos ──────────────────────────────────────────────────────────────────────
async function loadData() {
  await Promise.all([loadDevices(), loadStats(), loadLog()]);
}

async function loadStats() {
  const r = await fetch("/admin/api/stats", { headers: { "x-admin-token": adminToken } });
  const d = await r.json();
  document.getElementById("s-total").textContent = d.total;
  document.getElementById("s-auth").textContent  = d.autorizados;
  document.getElementById("s-pend").textContent  = d.pendientes;
  document.getElementById("s-rev").textContent   = d.revocados;
}

async function loadDevices() {
  const r = await fetch("/admin/api/devices", { headers: { "x-admin-token": adminToken } });
  const d = await r.json();
  allDevices = d.devices || [];
  renderDevices();
}

function renderDevices() {
  const q     = document.getElementById("search").value.toLowerCase();
  const estado = document.getElementById("filter-estado").value;
  const tbody = document.getElementById("devices-tbody");

  let filtered = allDevices.filter(d => {
    const matchQ = !q || d.id.toLowerCase().includes(q) ||
                   (d.nombre||"").toLowerCase().includes(q) ||
                   (d.notas||"").toLowerCase().includes(q);
    const matchE = !estado || d.estado === estado;
    return matchQ && matchE;
  });

  if (!filtered.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="empty">No hay equipos que mostrar.</td></tr>';
    return;
  }

  tbody.innerHTML = filtered.map(d => {
    const badge = d.autorizado
      ? '<span class="badge badge-auth">Autorizado</span>'
      : d.estado === "revocado"
        ? '<span class="badge badge-rev">Revocado</span>'
        : '<span class="badge badge-pend">Pendiente</span>';

    const fecha = d.ultimaConexion
      ? new Date(d.ultimaConexion).toLocaleString("es-PE",{day:"2-digit",month:"2-digit",year:"2-digit",hour:"2-digit",minute:"2-digit"})
      : "—";

    const approveBtn = !d.autorizado
      ? \`<button class="btn-approve" onclick="aprobar('\${d.id}','\${(d.nombre||'').replace(/'/g,'')}')" >Aprobar</button>\`
      : \`<button class="btn-revoke" onclick="revocar('\${d.id}')">Revocar</button>\`;

    return \`<tr>
      <td class="id-cell">\${d.id}</td>
      <td class="name-cell">
        <input class="notes-input" value="\${d.nombre||''}" onblur="updateNombre('\${d.id}',this.value)" placeholder="Sin nombre">
      </td>
      <td>\${badge}</td>
      <td class="date-cell">\${fecha}</td>
      <td class="conn-cell">\${d.conexiones||0}</td>
      <td><input class="notes-input" value="\${d.notas||''}" onblur="updateNotas('\${d.id}',this.value)" placeholder="—"></td>
      <td><div class="actions">\${approveBtn}
        <button class="btn-delete" onclick="eliminar('\${d.id}')">✕</button>
      </div></td>
    </tr>\`;
  }).join("");
}

async function loadLog() {
  const r = await fetch("/admin/api/log?limit=100", { headers: { "x-admin-token": adminToken } });
  const d = await r.json();
  const el = document.getElementById("log-container");
  if (!d.log?.length) { el.innerHTML = '<div class="empty">Log vacío.</div>'; return; }
  el.innerHTML = d.log.map(e => {
    const ts = new Date(e.ts).toLocaleString("es-PE",{day:"2-digit",month:"2-digit",hour:"2-digit",minute:"2-digit",second:"2-digit"});
    return \`<div class="log-row">
      <div class="log-ts">\${ts}</div>
      <div class="log-ev ev-\${e.evento}">\${e.evento}</div>
      <div class="log-id">\${e.machineId}</div>
      <div class="log-det">\${e.detalle||''}</div>
    </div>\`;
  }).join("");
}

// ── Acciones ───────────────────────────────────────────────────────────────────
async function aprobar(id, nombre) {
  document.getElementById("modal-id").value   = id || "";
  document.getElementById("modal-name").value = nombre || "";
  document.getElementById("modal-notes").value = allDevices.find(d=>d.id===id)?.notas || "";
  document.getElementById("modal-approve").classList.add("open");
}

async function confirmarAprobacion() {
  const id     = document.getElementById("modal-id").value.trim().toUpperCase();
  const nombre = document.getElementById("modal-name").value.trim();
  const notas  = document.getElementById("modal-notes").value.trim();
  if (!id) return alert("Ingresa un ID válido");
  await fetch("/admin/api/approve", {
    method:"POST", headers:{"Content-Type":"application/json","x-admin-token":adminToken},
    body: JSON.stringify({id,nombre,notas})
  });
  closeModal("modal-approve");
  loadData();
}

async function aprobarManual() {
  const id     = document.getElementById("new-id").value.trim().toUpperCase();
  const nombre = document.getElementById("new-name").value.trim();
  if (!id) return alert("Ingresa un Machine ID");
  await fetch("/admin/api/approve", {
    method:"POST", headers:{"Content-Type":"application/json","x-admin-token":adminToken},
    body: JSON.stringify({id,nombre})
  });
  document.getElementById("new-id").value = "";
  document.getElementById("new-name").value = "";
  loadData();
}

async function revocar(id) {
  const motivo = prompt("Motivo de revocación (opcional):") ?? "";
  if (motivo === null) return;
  await fetch("/admin/api/revoke", {
    method:"POST", headers:{"Content-Type":"application/json","x-admin-token":adminToken},
    body: JSON.stringify({id,motivo})
  });
  loadData();
}

async function eliminar(id) {
  if (!confirm(\`¿Eliminar el equipo \${id} del registro?\`)) return;
  await fetch("/admin/api/device", {
    method:"DELETE", headers:{"Content-Type":"application/json","x-admin-token":adminToken},
    body: JSON.stringify({id})
  });
  loadData();
}

async function updateNombre(id, nombre) {
  await fetch("/admin/api/update", {
    method:"POST", headers:{"Content-Type":"application/json","x-admin-token":adminToken},
    body: JSON.stringify({id,nombre})
  });
}

async function updateNotas(id, notas) {
  await fetch("/admin/api/update", {
    method:"POST", headers:{"Content-Type":"application/json","x-admin-token":adminToken},
    body: JSON.stringify({id,notas})
  });
}

function showPanel(name, el) {
  document.querySelectorAll(".tab").forEach(t=>t.classList.remove("active"));
  document.querySelectorAll(".panel").forEach(p=>p.classList.remove("active"));
  el.classList.add("active");
  document.getElementById("panel-"+name).classList.add("active");
  if(name==="log") loadLog();
}

function closeModal(id) { document.getElementById(id).classList.remove("open"); }

// Auto-actualizar cada 30 segundos
setInterval(() => { if(adminToken) loadData(); }, 30000);
</script>
</body>
</html>`;
