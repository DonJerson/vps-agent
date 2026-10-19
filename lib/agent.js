#!/usr/bin/env node
/**
 * vps-remote-agent — self-hosted remote shell agent (Node port).
 *
 * Runs on your VPS. Exposes an HTTPS endpoint that executes shell commands
 * for a single authorized client. No third parties: no relay servers,
 * no telemetry, no vendor backends. Zero npm dependencies — Node stdlib only.
 *
 * Security model (read this before running):
 *   - Bearer token auth: a 256-bit token is generated on first run, printed
 *     ONCE, and only its SHA-256 hash is stored on disk. The client must send
 *     `Authorization: Bearer <token>`. Comparisons are timing-safe.
 *   - TLS with a self-signed certificate generated on first run (openssl CLI).
 *     The client pins the certificate's SHA-256 fingerprint, so even a network
 *     attacker with a valid CA cert cannot impersonate the server.
 *   - This is FULL shell access by design (same as SSH). Anyone holding the
 *     token can run arbitrary commands as the user running this agent.
 *     Protect the token like an SSH private key.
 *   - Every command is appended to an audit log (command text, timestamp,
 *     exit code) so the machine owner can review what was run.
 *
 * Requirements: node >= 18 + openssl CLI (first run only, for cert gen).
 *
 * Usage:
 *   vps-remote-agent                  # first run: generates token + cert, prints token once
 *   vps-remote-agent --port 8443      # start the agent
 *   vps-remote-agent --print-service  # print a systemd unit for this install
 *
 * Files (in ~/.vps-agent/, mode 0700):
 *   token.sha256   SHA-256 hex of the bearer token (token itself never stored)
 *   server.crt     self-signed certificate (public)
 *   server.key     private key (mode 0600)
 *   audit.log      append-only log of executed commands
 */

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const https = require('https');
const { spawn, spawnSync, execSync } = require('child_process');

const CONFIG_DIR = path.join(os.homedir(), '.vps-agent');
const TOKEN_HASH_FILE = path.join(CONFIG_DIR, 'token.sha256');
const CERT_FILE = path.join(CONFIG_DIR, 'server.crt');
const KEY_FILE = path.join(CONFIG_DIR, 'server.key');
const AUDIT_LOG = path.join(CONFIG_DIR, 'audit.log');

const DEFAULT_PORT = 8443;
const MAX_BODY_BYTES = 64 * 1024;          // max JSON request body
const MAX_OUTPUT_BYTES = 1 * 1024 * 1024;  // cap per stream (stdout/stderr)
const DEFAULT_TIMEOUT = 120;               // seconds per command
const MAX_TIMEOUT = 600;
const KILL_GRACE_MS = 5000;

function log(msg) {
  const ts = new Date().toISOString().replace(/\.\d+Z$/, 'Z');
  console.log(`[${ts}] ${msg}`);
}

function ensureConfigDir() {
  fs.mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
  fs.chmodSync(CONFIG_DIR, 0o700);
}

function sha256Hex(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}

function certFingerprint() {
  const pem = fs.readFileSync(CERT_FILE, 'utf8');
  const b64 = pem.replace(/-----(BEGIN|END) CERTIFICATE-----/g, '').replace(/\s+/g, '');
  const der = Buffer.from(b64, 'base64');
  return crypto.createHash('sha256').update(der).digest('hex');
}

function firstRunSetup() {
  ensureConfigDir();

  // --- token (256 bits, printed once, only the hash is stored) ---
  const token = crypto.randomBytes(32).toString('base64url');
  fs.writeFileSync(TOKEN_HASH_FILE, sha256Hex(token) + '\n', { mode: 0o600 });
  fs.chmodSync(TOKEN_HASH_FILE, 0o600);

  // --- self-signed cert via openssl (10-year validity) ---
  if (!(fs.existsSync(CERT_FILE) && fs.existsSync(KEY_FILE))) {
    const r = spawnSync('openssl', [
      'req', '-x509', '-newkey', 'rsa:2048',
      '-keyout', KEY_FILE, '-out', CERT_FILE,
      '-days', '3650', '-nodes',
      '-subj', '/CN=vps-remote-agent',
    ], { encoding: 'utf8' });
    if (r.status !== 0) {
      console.error('ERROR: openssl cert generation failed:', (r.stderr || '').trim());
      console.error('Install openssl and re-run.');
      process.exit(1);
    }
    fs.chmodSync(KEY_FILE, 0o600);
    fs.chmodSync(CERT_FILE, 0o644);
  }

  const fingerprint = certFingerprint();

  console.log();
  console.log('='.repeat(64));
  console.log('FIRST RUN COMPLETE — SAVE THESE NOW (shown only once)');
  console.log('='.repeat(64));
  console.log();
  console.log('BEARER TOKEN:');
  console.log(token);
  console.log();
  console.log('CERTIFICATE SHA-256 FINGERPRINT (client pins this):');
  console.log(fingerprint);
  console.log();
  console.log('Give BOTH to your client through a secure channel (never chat).');
  console.log('The token is not stored anywhere — if you lose it, delete');
  console.log('~/.vps-agent/token.sha256 and re-run to generate a new one.');
  console.log('='.repeat(64));
  console.log();
  console.log('Setup done. Start the agent with: vps-remote-agent');
  console.log('(Or install the systemd unit — see README.md.)');
}

function loadTokenHash() {
  return fs.readFileSync(TOKEN_HASH_FILE, 'utf8').trim();
}

function audit(cmd, code, clientIp) {
  try {
    const ts = new Date().toISOString().replace(/\.\d+Z$/, 'Z');
    const short = cmd.length <= 500 ? cmd : cmd.slice(0, 500) + '...[truncated]';
    fs.appendFileSync(AUDIT_LOG, `${ts} from=${clientIp} exit=${code} cmd=${short}\n`);
  } catch (_) { /* audit must never crash the server */ }
}

function timingSafeEqualHex(a, b) {
  const ba = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
}

function authorized(req, tokenHash) {
  const auth = req.headers['authorization'] || '';
  if (!auth.startsWith('Bearer ')) return false;
  const presented = auth.slice('Bearer '.length).trim();
  if (!presented) return false;
  return timingSafeEqualHex(sha256Hex(presented), tokenHash);
}

function sendJson(res, code, obj) {
  const body = Buffer.from(JSON.stringify(obj));
  res.writeHead(code, {
    'Content-Type': 'application/json',
    'Content-Length': body.length,
  });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let tooBig = false;
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY_BYTES) { tooBig = true; return; }
      chunks.push(c);
    });
    req.on('end', () => {
      if (tooBig) reject(Object.assign(new Error('body too large'), { status: 400 }));
      else resolve(Buffer.concat(chunks).toString('utf8'));
    });
    req.on('error', reject);
  });
}

function runCommand(cmd, timeoutSec) {
  return new Promise((resolve) => {
    const child = spawn(cmd, {
      shell: '/bin/sh',
      env: {
        PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
        HOME: os.homedir(),
        LANG: 'C.UTF-8',
      },
    });
    const out = [];
    const err = [];
    let outBytes = 0, errBytes = 0, truncated = false;
    let timedOut = false;

    const collect = (chunk, store, counter) => {
      if (counter.bytes + chunk.length > MAX_OUTPUT_BYTES) {
        truncated = true;
        const room = MAX_OUTPUT_BYTES - counter.bytes;
        if (room > 0) { store.push(chunk.slice(0, room)); counter.bytes = MAX_OUTPUT_BYTES; }
      } else {
        store.push(chunk);
        counter.bytes += chunk.length;
      }
    };
    const outCounter = { bytes: 0 };
    const errCounter = { bytes: 0 };
    child.stdout.on('data', (c) => collect(c, out, outCounter));
    child.stderr.on('data', (c) => collect(c, err, errCounter));

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGTERM');
      setTimeout(() => { try { child.kill('SIGKILL'); } catch (_) {} }, KILL_GRACE_MS);
    }, timeoutSec * 1000);
    timer.unref();

    child.on('error', () => { /* handled via close */ });
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      if (timedOut) {
        err.push(Buffer.from('\n[TIMED OUT]'));
        resolve({ code: 124, stdout: Buffer.concat(out), stderr: Buffer.concat(err), truncated });
      } else {
        resolve({
          code: code === null ? 127 : code,
          stdout: Buffer.concat(out),
          stderr: Buffer.concat(err),
          truncated,
        });
      }
    });
  });
}

async function handleExec(req, res, tokenHash) {
  let payload;
  try {
    const raw = await readBody(req);
    payload = JSON.parse(raw);
  } catch (e) {
    sendJson(res, e.status || 400, { error: e.status ? 'bad request size' : 'invalid json' });
    return;
  }
  const cmd = payload.cmd;
  if (typeof cmd !== 'string' || !cmd.trim()) {
    sendJson(res, 400, { error: 'missing cmd' });
    return;
  }
  let timeout = parseInt(payload.timeout, 10);
  if (!Number.isFinite(timeout)) timeout = DEFAULT_TIMEOUT;
  timeout = Math.max(1, Math.min(timeout, MAX_TIMEOUT));

  const clientIp = req.socket.remoteAddress || '?';
  log(`exec from ${clientIp}: ${cmd.slice(0, 120)}`);

  const r = await runCommand(cmd, timeout);
  audit(cmd, r.code, clientIp);
  sendJson(res, 200, {
    code: r.code,
    stdout: r.stdout.toString('utf8'),
    stderr: r.stderr.toString('utf8'),
    truncated: r.truncated,
  });
}

function startServer(port) {
  const tokenHash = loadTokenHash();
  const server = https.createServer(
    { key: fs.readFileSync(KEY_FILE), cert: fs.readFileSync(CERT_FILE) },
    (req, res) => {
      (async () => {
        if (req.method === 'GET' && req.url === '/health') {
          if (!authorized(req, tokenHash)) { sendJson(res, 401, { error: 'unauthorized' }); return; }
          sendJson(res, 200, { ok: true, time: Date.now() / 1000 });
          return;
        }
        if (req.method === 'POST' && req.url === '/exec') {
          if (!authorized(req, tokenHash)) { sendJson(res, 401, { error: 'unauthorized' }); return; }
          await handleExec(req, res, tokenHash);
          return;
        }
        sendJson(res, 404, { error: 'not found' });
      })().catch(() => {
        try { sendJson(res, 500, { error: 'internal error' }); } catch (_) {}
      });
    }
  );
  server.listen(port, '0.0.0.0', () => {
    log(`vps-remote-agent listening on 0.0.0.0:${port} (TLS, token auth)`);
    log(`audit log: ${AUDIT_LOG}`);
  });
  server.on('error', (e) => {
    console.error('server error:', e.message);
    process.exit(1);
  });
}

function printService() {
  // Resolve where this package's bin lives so the unit survives reboots.
  const selfPath = process.argv[1];
  let binPath = selfPath;
  let note = '';
  if (selfPath.includes('_npx')) {
    try {
      const root = execSync('npm root -g', { encoding: 'utf8' }).trim();
      binPath = path.join(root, 'vps-remote-agent', 'bin', 'vps-remote-agent.js');
      note = '# NOTE: you ran this from the npx cache. Install globally first:\n#   npm i -g vps-remote-agent\n';
    } catch (_) {
      note = '# WARNING: could not resolve global npm root — install with `npm i -g vps-remote-agent` and fix ExecStart.\n';
    }
  }
  const nodePath = process.execPath;
  console.log(`${note}[Unit]
Description=vps-remote-agent — self-hosted remote shell
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=vpsagent
WorkingDirectory=/opt/vps-remote-agent
ExecStart=${nodePath} ${binPath} --port 8443
Restart=on-failure
RestartSec=5
# Hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/home/vpsagent/.vps-agent /opt/vps-remote-agent

[Install]
WantedBy=multi-user.target
`);
}

function printHelp() {
  console.log(`vps-remote-agent — self-hosted remote shell agent

Usage:
  vps-remote-agent [--port 8443]   start the agent (first run prints token + fingerprint)
  vps-remote-agent --print-service  print a systemd unit for this install
  vps-remote-agent --help           this help
  vps-remote-agent --version        version

First run generates a 256-bit bearer token (printed once) and a self-signed
TLS certificate. The client pins the certificate fingerprint.`);
}

function main() {
  const args = process.argv.slice(2);
  if (args.includes('--help') || args.includes('-h')) { printHelp(); return; }
  if (args.includes('--version') || args.includes('-v')) {
    console.log(require('../package.json').version);
    return;
  }
  if (args.includes('--print-service')) { printService(); return; }

  let port = DEFAULT_PORT;
  const pi = args.indexOf('--port');
  if (pi !== -1 && args[pi + 1]) {
    const p = parseInt(args[pi + 1], 10);
    if (Number.isFinite(p) && p > 0 && p < 65536) port = p;
  }

  ensureConfigDir();
  if (!fs.existsSync(TOKEN_HASH_FILE)) {
    firstRunSetup();
    return;
  }
  startServer(port);
}

main();
