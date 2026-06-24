/**
 * SentinelX Backend Server
 * Express.js REST API for vulnerability scanning platform
 */

require("dotenv").config();
const connectDB = require("./config/db");
const express = require('express');
const cors = require('cors');
const http = require('http');
const { Server } = require('socket.io');
const { v4: uuidv4 } = require('uuid');
const swaggerUi = require("swagger-ui-express");
const swaggerJsdoc = require("swagger-jsdoc");



const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST', 'DELETE', 'PATCH'] }
});

app.use(cors());

app.use(express.static('../frontend/public'));

// ─── IN-MEMORY DATABASE ───────────────────────────────────────────────────────
const db = {
  scans: [],
  vulnerabilities: [],
  reports: [],
  scanHistory: []
};

// ─── VULNERABILITY TEMPLATES ──────────────────────────────────────────────────
const VULN_TEMPLATES = [
  {
    name: 'SQL Injection',
    description: 'Error-based SQL injection allows unauthenticated extraction of database contents.',
    severity: 'critical',
    cvss: 9.8,
    cve: 'CVE-2024-3412',
    cwe: 'CWE-89',
    category: 'Injection',
    remediation: 'Use parameterized queries or prepared statements. Validate and sanitize all user input.',
    references: ['https://owasp.org/www-community/attacks/SQL_Injection', 'https://cwe.mitre.org/data/definitions/89.html']
  },
  {
    name: 'Remote Code Execution via Deserialization',
    description: 'Unsafe deserialization allows remote attackers to execute arbitrary OS commands.',
    severity: 'critical',
    cvss: 9.6,
    cve: 'CVE-2024-1887',
    cwe: 'CWE-502',
    category: 'Injection',
    remediation: 'Avoid deserializing data from untrusted sources. Use allowlists for permitted classes.',
    references: ['https://owasp.org/www-project-top-ten/2017/A8_2017-Insecure_Deserialization']
  },
  {
    name: 'Default Admin Credentials',
    description: 'Admin panel accepts factory-default credentials granting full system access.',
    severity: 'critical',
    cvss: 9.1,
    cve: 'CVE-2023-9981',
    cwe: 'CWE-798',
    category: 'Broken Authentication',
    remediation: 'Change all default credentials immediately. Enforce strong password policy.',
    references: ['https://owasp.org/www-project-top-ten/2021/A07_2021-Identification_and_Authentication_Failures']
  },
  {
    name: 'SSL/TLS Weak Cipher Suites (RC4)',
    description: 'Server supports deprecated TLS 1.0 and RC4 ciphers enabling BEAST attacks.',
    severity: 'high',
    cvss: 7.4,
    cve: 'CVE-2011-3389',
    cwe: 'CWE-326',
    category: 'Cryptographic Failures',
    remediation: 'Disable TLS 1.0/1.1 and RC4. Enable TLS 1.2+ with AEAD cipher suites only.',
    references: ['https://www.openssl.org/news/secadv/20110906.txt']
  },
  {
    name: 'Outdated Apache httpd',
    description: 'Running end-of-life Apache version with 24 publicly known CVEs.',
    severity: 'high',
    cvss: 7.1,
    cve: 'CVE-2021-41773',
    cwe: 'CWE-22',
    category: 'Vulnerable Components',
    remediation: 'Upgrade Apache to the latest stable release (2.4.58+). Apply all security patches.',
    references: ['https://httpd.apache.org/security/vulnerabilities_24.html']
  },
  {
    name: 'Missing Security Headers',
    description: 'X-Frame-Options, CSP, and HSTS headers are absent exposing users to clickjacking.',
    severity: 'medium',
    cvss: 5.3,
    cve: null,
    cwe: 'CWE-693',
    category: 'Security Misconfiguration',
    remediation: 'Add Content-Security-Policy, X-Frame-Options: DENY, Strict-Transport-Security headers.',
    references: ['https://owasp.org/www-project-secure-headers/']
  },
  {
    name: 'Directory Listing Enabled',
    description: 'Apache autoindex enabled on /uploads/ and /static/ exposing file structure.',
    severity: 'low',
    cvss: 3.1,
    cve: null,
    cwe: 'CWE-548',
    category: 'Information Disclosure',
    remediation: 'Disable Options Indexes in Apache configuration. Restrict directory access.',
    references: ['https://httpd.apache.org/docs/2.4/mod/mod_autoindex.html']
  },
  {
    name: 'Open Redis Port Without Authentication',
    description: 'Redis 6.2 is exposed on port 6379 without password authentication.',
    severity: 'high',
    cvss: 7.5,
    cve: 'CVE-2022-0543',
    cwe: 'CWE-306',
    category: 'Broken Authentication',
    remediation: 'Set requirepass in redis.conf. Bind to localhost or use firewall rules.',
    references: ['https://redis.io/docs/manual/security/']
  },
  {
    name: 'Cross-Site Scripting (Reflected)',
    description: 'Search parameter reflects user input without sanitization enabling XSS.',
    severity: 'medium',
    cvss: 6.1,
    cve: null,
    cwe: 'CWE-79',
    category: 'Injection',
    remediation: 'Encode all user-supplied data before output. Implement a strict Content-Security-Policy.',
    references: ['https://owasp.org/www-community/attacks/xss/']
  },
  {
    name: 'CSRF Token Missing on State-Changing Endpoints',
    description: 'POST endpoints that modify data do not validate CSRF tokens.',
    severity: 'medium',
    cvss: 5.8,
    cve: null,
    cwe: 'CWE-352',
    category: 'Broken Access Control',
    remediation: 'Implement synchronizer token pattern or SameSite cookie attribute.',
    references: ['https://owasp.org/www-community/attacks/csrf']
  }
];

const PORT_TEMPLATES = [
  { port: 22,   service: 'SSH',       version: 'OpenSSH 7.4',   state: 'open',     risk: 'medium' },
  { port: 80,   service: 'HTTP',      version: 'Apache 2.4.29', state: 'open',     risk: 'high' },
  { port: 443,  service: 'HTTPS',     version: 'OpenSSL 1.0.2', state: 'open',     risk: 'medium' },
  { port: 3306, service: 'MySQL',     version: 'MySQL 8.0.32',  state: 'filtered', risk: 'low' },
  { port: 6379, service: 'Redis',     version: 'Redis 6.2.11',  state: 'open',     risk: 'critical' },
  { port: 8080, service: 'HTTP-Alt',  version: 'Tomcat 9.0',    state: 'open',     risk: 'critical' },
  { port: 8443, service: 'HTTPS-Alt', version: 'Nginx 1.18',    state: 'filtered', risk: 'low' },
  { port: 25,   service: 'SMTP',      version: 'Postfix 3.4',   state: 'open',     risk: 'medium' },
  { port: 53,   service: 'DNS',       version: 'BIND 9.11',     state: 'open',     risk: 'medium' },
  { port: 111,  service: 'RPC',       version: 'rpcbind 0.2',   state: 'open',     risk: 'high' },
  { port: 2049, service: 'NFS',       version: 'NFS 4.0',       state: 'filtered', risk: 'high' },
  { port: 5432, service: 'PostgreSQL',version: 'PG 14.5',       state: 'filtered', risk: 'low' }
];

const SCAN_LOG_SEQUENCE = (target) => [
  { delay: 300,  msg: `Initializing SentinelX scan engine v2.4.1`, type: 'info' },
  { delay: 600,  msg: `Target: ${target}`, type: 'info' },
  { delay: 900,  msg: 'Resolving DNS records...', type: 'info' },
  { delay: 1400, msg: `Host resolved successfully`, type: 'success' },
  { delay: 1800, msg: 'Starting SYN port scan (top 1000 ports)...', type: 'info' },
  { delay: 2400, msg: 'Discovered 12 open/filtered ports', type: 'success' },
  { delay: 2800, msg: 'Running service fingerprinting...', type: 'info' },
  { delay: 3400, msg: 'Service detection complete', type: 'success' },
  { delay: 3800, msg: 'Starting SSL/TLS audit...', type: 'info' },
  { delay: 4200, msg: '⚠ TLS 1.0 detected on port 443', type: 'warning' },
  { delay: 4600, msg: '⚠ RC4 cipher suite enabled — BEAST attack possible', type: 'warning' },
  { delay: 5000, msg: 'SSL audit complete', type: 'success' },
  { delay: 5400, msg: 'Running vulnerability checks (10 modules)...', type: 'info' },
  { delay: 6000, msg: '✗ SQL injection confirmed — /api/v1/users/search', type: 'error' },
  { delay: 6500, msg: '✗ Default credentials accepted on /admin panel', type: 'error' },
  { delay: 7200, msg: '✗ Unauthenticated Redis exposure on port 6379', type: 'error' },
  { delay: 7800, msg: '✗ RCE via deserialization on port 8080', type: 'error' },
  { delay: 8400, msg: '⚠ Missing security headers (CSP, HSTS, X-Frame-Options)', type: 'warning' },
  { delay: 9000, msg: '⚠ Directory listing enabled on /uploads/', type: 'warning' },
  { delay: 9600, msg: 'Vulnerability scan complete — 10 findings', type: 'success' },
  { delay: 10200,msg: 'Querying NVD CVE database...', type: 'info' },
  { delay: 11000,msg: 'CVE cross-reference complete — 31 CVEs mapped', type: 'success' },
  { delay: 11600,msg: 'Calculating risk score...', type: 'info' },
  { delay: 12200,msg: 'Risk score: 7.8/10 (HIGH)', type: 'warning' },
  { delay: 12800,msg: 'Generating security assessment report...', type: 'info' },
  { delay: 13400,msg: 'Scan complete. Report ready.', type: 'success' }
];

// ─── HELPERS ──────────────────────────────────────────────────────────────────
function calcRiskScore(vulns) {
  if (!vulns.length) return 0;
  const weights = { critical: 10, high: 7, medium: 4, low: 1 };
  const score = vulns.reduce((acc, v) => acc + (weights[v.severity] || 0), 0);
  return Math.min(10, parseFloat((score / (vulns.length * 3)).toFixed(1)));
}

function getRiskLevel(score) {
  if (score >= 9)   return 'Critical';
  if (score >= 7)   return 'High';
  if (score >= 4)   return 'Medium';
  if (score >= 1)   return 'Low';
  return 'None';
}

function pickVulns() {
  const shuffled = [...VULN_TEMPLATES].sort(() => Math.random() - 0.5);
  const count = Math.floor(Math.random() * 4) + 5;
  return shuffled.slice(0, count).map((t, i) => ({
    id: uuidv4(),
    ...t,
    endpoint: ['/', '/api/v1/users', '/admin', '/login', '/search', '/upload'][i % 6],
    parameter: ['id', 'search', 'username', 'redirect', 'file'][i % 5],
    discoveredAt: new Date().toISOString(),
    status: 'open'
  }));
}

const options = {
  definition: {
    openapi: "3.0.0",
    info: {
      title: "Vulnerability Scanner API",
      version: "1.0.0",
      description: "Backend API for Vulnerability Scanner"
    },
    servers: [
      {
        url: "http://localhost:5000"
      }
    ]
  },
  apis: ["./server.js"]
};

const swaggerSpec = swaggerJsdoc(options);

// ─── ROUTES ───────────────────────────────────────────────────────────────────

/**
 * @swagger
 * /api/scans:
 *   get:
 *     summary: Get all scans
 *     description: Returns all vulnerability scans with pagination.
 *     parameters:
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: List of scans
 */

app.get("/api/scans", async (req, res) => {

    const scans = await Scan.find().sort({ createdAt: -1 });

    res.json(scans);

});

// Health
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', version: '2.4.1', uptime: process.uptime() });
});

// Dashboard summary
app.get('/api/dashboard', (req, res) => {
  const allVulns = db.vulnerabilities;
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  allVulns.forEach(v => { if (counts[v.severity] !== undefined) counts[v.severity]++; });
  const riskScore = calcRiskScore(allVulns);

  res.json({
    totalScans: db.scans.length,
    activeScans: db.scans.filter(s => s.status === 'running').length,
    totalVulnerabilities: allVulns.length,
    severityCounts: counts,
    riskScore,
    riskLevel: getRiskLevel(riskScore),
    openPorts: PORT_TEMPLATES.length,
    riskyPorts: PORT_TEMPLATES.filter(p => p.risk === 'critical' || p.risk === 'high').length,
    lastScan: db.scans.at(-1) || null,
    recentVulnerabilities: allVulns.slice(-5).reverse()
  });
});

// ── SCANS ──
app.get('/api/scans', async (req, res) => {

    try {

        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;

        const scans = await Scan.find()
            .sort({ createdAt: -1 })
            .skip((page - 1) * limit)
            .limit(limit);

        const total = await Scan.countDocuments();

        res.json({
            scans,
            total,
            page,
            limit
        });

    } catch (err) {

        res.status(500).json({
            error: err.message
        });

    }

});

/**
 * @swagger
 * /api/scans:
 *   post:
 *     summary: Create a new scan
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               target:
 *                 type: string
 *               scanType:
 *                 type: string
 *                 example: quick
 *     responses:
 *       201:
 *         description: Scan created successfully
 */

app.post('/api/scans', async (req, res) => {
  const { target, scanType = 'quick' } = req.body;
  if (!target || target.trim() === "") {
    return res.status(400).json({
        success: false,
        error: "Target is required"
    });
}
const allowedTypes = ["quick", "full"];

if (!allowedTypes.includes(scanType)) {
    return res.status(400).json({
        success: false,
        error: "Invalid scan type"
    });
}
  const scan = {
    id: uuidv4(),
    target,
    scanType,
    status: 'running',
    progress: 0,
    startedAt: new Date().toISOString(),
    completedAt: null,
    vulnerabilities: [],
    ports: [],
    riskScore: null,
    logs: []
  };

  const dbScan = new Scan({
    target: scan.target,
    scanType: scan.scanType,
    status: scan.status,
    progress: scan.progress,
    riskScore: scan.riskScore,
    vulnerabilities: [],
    startedAt: new Date(scan.startedAt)
});

await dbScan.save();
  res.status(201).json({
    scanId: dbScan._id,
    message: 'Scan started',
    scan: dbScan
});

  // Emit real-time updates via WebSocket
  runScanSimulation(scan);
});

app.get('/api/scans/:id', (req, res) => {
  const scan = db.scans.find(s => s.id === req.params.id);
  if (!scan) {
    return res.status(404).json({
        success: false,
        error: "Scan not found"
    });
}
  res.json(scan);
});

app.delete('/api/scans/:id', (req, res) => {
  const idx = db.scans.findIndex(s => s.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Scan not found' });
  db.scans.splice(idx, 1);
  res.json({ message: 'Scan deleted' });
});

// ── VULNERABILITIES ──
app.get('/api/vulnerabilities', (req, res) => {
  const { severity, status, scanId } = req.query;
  let vulns = [...db.vulnerabilities];
  if (severity) vulns = vulns.filter(v => v.severity === severity);
  if (status)   vulns = vulns.filter(v => v.status === status);
  if (scanId)   vulns = vulns.filter(v => v.scanId === scanId);
  res.json({ vulnerabilities: vulns, total: vulns.length });
});

app.get('/api/vulnerabilities/:id', (req, res) => {
  const vuln = db.vulnerabilities.find(v => v.id === req.params.id);
  if (!vuln) return res.status(404).json({ error: 'Vulnerability not found' });
  res.json(vuln);
});

app.patch('/api/vulnerabilities/:id', (req, res) => {
  const vuln = db.vulnerabilities.find(v => v.id === req.params.id);
  if (!vuln) return res.status(404).json({ error: 'Vulnerability not found' });
  const allowed = ['status', 'notes', 'assignedTo'];
  allowed.forEach(k => { if (req.body[k] !== undefined) vuln[k] = req.body[k]; });
  vuln.updatedAt = new Date().toISOString();
  res.json(vuln);
});

// ── PORTS ──
app.get('/api/ports', (req, res) => {
  const { scanId } = req.query;
  if (scanId) {
    const scan = db.scans.find(s => s.id === scanId);
    return res.json({ ports: scan ? scan.ports : [] });
  }
  res.json({ ports: PORT_TEMPLATES });
});

// ── REPORTS ──
app.get('/api/reports', (req, res) => {
  res.json({ reports: db.reports, total: db.reports.length });
});

app.post('/api/reports', (req, res) => {
  const { scanId, format = 'json' } = req.body;
  const scan = db.scans.find(s => s.id === scanId);
  if (!scan) return res.status(404).json({ error: 'Scan not found' });

  const vulns = db.vulnerabilities.filter(v => v.scanId === scanId);
  const report = {
    id: uuidv4(),
    scanId,
    target: scan.target,
    format,
    generatedAt: new Date().toISOString(),
    summary: {
      riskScore: scan.riskScore,
      riskLevel: getRiskLevel(scan.riskScore),
      totalVulnerabilities: vulns.length,
      critical: vulns.filter(v => v.severity === 'critical').length,
      high:     vulns.filter(v => v.severity === 'high').length,
      medium:   vulns.filter(v => v.severity === 'medium').length,
      low:      vulns.filter(v => v.severity === 'low').length
    },
    vulnerabilities: vulns,
    ports: scan.ports,
    recommendations: [
      'Immediately patch critical SQL injection and RCE vulnerabilities',
      'Change all default credentials and enforce MFA on admin panels',
      'Upgrade Apache, OpenSSL, and PHP to latest stable versions',
      'Disable TLS 1.0/1.1 and weak cipher suites',
      'Implement all missing HTTP security headers',
      'Restrict Redis to localhost or add authentication',
      'Disable directory listing on all web directories'
    ]
  };

  db.reports.push(report);
  res.status(201).json(report);
});

app.get('/api/reports/:id', (req, res) => {
  const report = db.reports.find(r => r.id === req.params.id);
  if (!report) return res.status(404).json({ error: 'Report not found' });
  res.json(report);
});

// ── ANALYTICS ──
app.get('/api/analytics', (req, res) => {
  const allVulns = db.vulnerabilities;
  const severityDist = {
    critical: allVulns.filter(v => v.severity === 'critical').length,
    high:     allVulns.filter(v => v.severity === 'high').length,
    medium:   allVulns.filter(v => v.severity === 'medium').length,
    low:      allVulns.filter(v => v.severity === 'low').length
  };

  const categoryDist = {};
  allVulns.forEach(v => {
    categoryDist[v.category] = (categoryDist[v.category] || 0) + 1;
  });

  const riskTrend = db.scans.slice(-8).map(s => ({
    scanId: s.id,
    target: s.target,
    date: s.completedAt || s.startedAt,
    riskScore: s.riskScore || 0
  }));

  res.json({ severityDist, categoryDist, riskTrend, totalScans: db.scans.length });
});

// ── SSL CHECK ──
app.post('/api/ssl-check', (req, res) => {
  const { host } = req.body;
  if (!host) return res.status(400).json({ error: 'host is required' });

  // Simulated SSL analysis
  res.json({
    host,
    grade: 'C',
    issues: [
      { severity: 'high',   issue: 'TLS 1.0 enabled' },
      { severity: 'high',   issue: 'RC4 cipher suite supported' },
      { severity: 'medium', issue: 'Certificate expires in 21 days' },
      { severity: 'low',    issue: 'OCSP stapling not enabled' }
    ],
    certificate: {
      subject: `CN=${host}`,
      issuer: 'Let\'s Encrypt Authority X3',
      validFrom: '2024-01-01',
      validTo: '2024-12-31',
      daysRemaining: 21,
      keySize: 2048,
      signatureAlgorithm: 'SHA256withRSA'
    },
    supportedProtocols: ['TLSv1.0', 'TLSv1.2', 'TLSv1.3'],
    weakCiphers: ['TLS_RSA_WITH_RC4_128_SHA', 'TLS_RSA_WITH_RC4_128_MD5'],
    checkedAt: new Date().toISOString()
  });
});

// ── DNS ANALYZER ──
app.post('/api/dns', (req, res) => {
  const { host } = req.body;
  if (!host) return res.status(400).json({ error: 'host is required' });

  res.json({
    host,
    records: {
      A:    ['192.168.1.100'],
      MX:   [`mail.${host}`],
      NS:   [`ns1.${host}`, `ns2.${host}`],
      TXT:  ['v=spf1 include:_spf.google.com ~all'],
      AAAA: []
    },
    issues: [
      { severity: 'medium', issue: 'SPF record present but permissive (~all)' },
      { severity: 'high',   issue: 'DMARC record not found' },
      { severity: 'low',    issue: 'DKIM record not configured' }
    ],
    checkedAt: new Date().toISOString()
  });
});

// ─── WEBSOCKET ────────────────────────────────────────────────────────────────
io.on('connection', (socket) => {
  console.log('Client connected:', socket.id);

  socket.on('subscribe:scan', (scanId) => {
    socket.join(`scan:${scanId}`);
    const scan = db.scans.find(s => s.id === scanId);
    if (scan) socket.emit('scan:update', scan);
  });

  socket.on('disconnect', () => {
    console.log('Client disconnected:', socket.id);
  });
});

// ─── SCAN SIMULATION ──────────────────────────────────────────────────────────
function runScanSimulation(scan) {
  const logSeq = SCAN_LOG_SEQUENCE(scan.target);
  const totalDuration = logSeq.at(-1).delay + 500;
  const vulns = pickVulns();
  const ports = [...PORT_TEMPLATES];

  // Emit log entries on schedule
  logSeq.forEach(({ delay, msg, type }) => {
    setTimeout(() => {
      const logEntry = { timestamp: new Date().toISOString(), message: msg, type };
      scan.logs.push(logEntry);
      scan.progress = Math.round((delay / totalDuration) * 100);
      io.to(`scan:${scan.id}`).emit('scan:log', logEntry);
      io.to(`scan:${scan.id}`).emit('scan:progress', { progress: scan.progress });
    }, delay);
  });

  // Emit vulnerabilities mid-scan
  const vulnRevealTimes = [5500, 6200, 7000, 7500, 8200, 9000, 9400];
  vulns.forEach((v, i) => {
    const t = vulnRevealTimes[i] || 9000 + i * 300;
    setTimeout(() => {
      const vuln = { ...v, scanId: scan.id };
      db.vulnerabilities.push(vuln);
      scan.vulnerabilities.push(vuln.id);
      io.to(`scan:${scan.id}`).emit('scan:vulnerability', vuln);
    }, t);
  });

  // Complete scan
  setTimeout(() => {
    scan.ports = ports;
    scan.riskScore = calcRiskScore(vulns);
    scan.status = 'completed';
    scan.progress = 100;
    scan.completedAt = new Date().toISOString();

    db.scanHistory.push({
      id: scan.id,
      target: scan.target,
      completedAt: scan.completedAt,
      riskScore: scan.riskScore,
      vulnCount: vulns.length
    });

    io.to(`scan:${scan.id}`).emit('scan:complete', scan);
    console.log(`Scan ${scan.id} completed for ${scan.target}`);
  }, totalDuration);
}

app.get("/", (req, res) => {
    res.send("SentinelX Backend is Running 🚀");
});

app.get("/api", (req, res) => {
    res.json({
        success: true,
        message: "SentinelX API is Running",
        version: "2.4.1"
    });
});

connectDB();

app.get("/api/test-db", async (req, res) => {

    try {

        const scan = await Scan.create({

            target: "google.com",

            scanType: "quick",

            status: "completed",

            progress: 100,

            riskScore: 15,

            startedAt: new Date(),

            completedAt: new Date()

        });

        res.json(scan);

    } catch (err) {

        res.status(500).json({
            error: err.message
        });

    }

});

app.get("/api/scans", async (req, res) => {

    try {

        const scans = await Scan.find().sort({ createdAt: -1 });

        res.json(scans);

    } catch (err) {

        res.status(500).json({
            error: err.message
        });

    }

});

function runScanSimulation(scan) {
  let progress = 0;

  const interval = setInterval(() => {

    progress += 10;
    scan.progress = progress;

    const messages = [
  "Resolving target...",
  "Checking DNS...",
  "Scanning open ports...",
  "Enumerating services...",
  "Checking HTTP headers...",
  "Searching vulnerabilities...",
  "Generating report...",
  "Finishing..."
];

scan.logs.push({
  time: new Date().toISOString(),
  message: messages[Math.floor(progress / 15)] || "Scanning..."
});

    io.emit("scan:update", scan);
console.log(`Progress: ${scan.progress}%`);
    if (progress >= 100) {

      clearInterval(interval);

      scan.status = "completed";
      scan.completedAt = new Date().toISOString();

      scan.ports = [22, 80, 443];

      scan.vulnerabilities = [
        {
          id: uuidv4(),
          title: "SQL Injection",
          severity: "High"
        },
        {
          id: uuidv4(),
          title: "XSS",
          severity: "Medium"
        }
      ];

      scan.riskScore = 82;

      io.emit("scan:completed", scan);
    }

  }, 1000);
}



app.use((err, req, res, next) => {
    console.error(err.stack);

    res.status(500).json({
        success: false,
        error: "Internal Server Error"
    });
});

// ── DASHBOARD ──
app.get("/api/dashboard", (req, res) => {

    const totalScans = db.scans.length;

    const runningScans = db.scans.filter(
        scan => scan.status === "running"
    ).length;

    const completedScans = db.scans.filter(
        scan => scan.status === "completed"
    ).length;

    const failedScans = db.scans.filter(
        scan => scan.status === "failed"
    ).length;

    const highRisk = db.scans.filter(
        scan => scan.riskScore >= 70
    ).length;

    const mediumRisk = db.scans.filter(
        scan => scan.riskScore >= 40 && scan.riskScore < 70
    ).length;

    const lowRisk = db.scans.filter(
        scan => scan.riskScore !== null && scan.riskScore < 40
    ).length;

    res.json({
        totalScans,
        runningScans,
        completedScans,
        failedScans,
        highRisk,
        mediumRisk,
        lowRisk
    });

});

app.use(
  "/api-docs",
  swaggerUi.serve,
  swaggerUi.setup(swaggerSpec)
);
// ─── START ────────────────────────────────────────────────────────────────────

app.get("/api/test-db", async (req, res) => {
    try {

        const scan = await Scan.create({
            target: "google.com",
            scanType: "quick",
            status: "completed",
            progress: 100,
            riskScore: 15,
            startedAt: new Date(),
            completedAt: new Date()
        });

        res.json(scan);

    } catch (err) {

        res.status(500).json({
            error: err.message
        });

    }
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log("================================");
console.log("🚀 Vulnerability Scanner API");
console.log(`🌐 Running on http://localhost:${PORT}`);
console.log(`📄 Swagger: http://localhost:${PORT}/api-docs`);
console.log("================================");
});

module.exports = { app, server };