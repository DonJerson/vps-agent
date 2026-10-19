# vps-remote-agent

Your own remote shell agent for your own VPS. Run it with npx, pair it once,
then run commands on the box from anywhere. **No vendor servers, no telemetry,
no third parties, no accounts.** You can read every line — it's one file
(`lib/agent.js`), Node stdlib only, zero npm dependencies.

## Why this exists

Remote-access tools that relay your shell through someone else's servers mean
your commands, file contents, and outputs pass through infrastructure you
don't control, encrypted only in transit to *their* backend. This agent talks
directly to your VPS public IP: TLS with a certificate *you* generated, a
token *you* generated, and a client that pins the certificate fingerprint
before the token ever leaves your machine.

## Install (on the VPS, ~5 minutes)

```bash
# needs: node >= 18, openssl (first run only)
npm i -g vps-remote-agent

# 1. unprivileged user
sudo useradd -r -m -s /usr/sbin/nologin vpsagent

# 2. FIRST RUN — prints your BEARER TOKEN + CERT FINGERPRINT (shown once, save them!)
sudo -u vpsagent vps-remote-agent
# → copy both into your password manager, then Ctrl-C

# 3. install as a service (prints a unit with the right paths for this machine)
sudo vps-remote-agent --print-service > /etc/systemd/system/vps-remote-agent.service
sudo systemctl daemon-reload
sudo systemctl enable --now vps-remote-agent
sudo systemctl status vps-remote-agent   # should show active (running)

# 4. open the port (if ufw is active)
sudo ufw allow 8443/tcp
```

## Pairing a client

The client needs three things: the VPS host, the bearer token, and the
certificate SHA-256 fingerprint. The client **verifies the fingerprint before
sending the token** — if the cert ever changes unexpectedly, it refuses to
connect. That's the pinning doing its job.

A minimal client is ~40 lines (see the Python reference in the repo):
POST JSON `{"cmd": "uptime", "timeout": 120}` to `https://<host>:8443/exec`
with header `Authorization: Bearer <token>`, over TLS with certificate
checking disabled but fingerprint-verified against the pinned value.

## Rotating / revoking

- New token: `sudo rm /home/vpsagent/.vps-agent/token.sha256`, re-run step 2,
  update the client.
- Revoke instantly: `sudo systemctl stop vps-remote-agent` — no process, no access.
- Full removal: stop the service, delete `/home/vpsagent/.vps-agent` and the
  `vpsagent` user, `npm rm -g vps-remote-agent`.

## Security model

- **Token auth**: 256-bit token, only its SHA-256 hash stored on disk,
  timing-safe comparison.
- **Pinned self-signed TLS**: 2048-bit RSA cert generated on first run
  (10-year validity). No CA involved, nothing to trust except the two
  secrets you generated.
- **Full shell by design** (same as SSH). Anyone holding the token can run
  arbitrary commands as the `vpsagent` user. Guard the token like an SSH key.
- **Audit log**: every command is appended to `~/.vps-agent/audit.log`
  (timestamp, source IP, exit code, command text) so you can review what ran.
- **Sandboxed execution**: minimal environment (`PATH`, `HOME`, `LANG`),
  64KB request cap, 1MB per-stream output cap, 120s default timeout
  (max 600s).

## What it does NOT do

- No file-browser UI, no MCP wrappers — just shell. Shell covers everything.
- No connection dashboard — systemd `Restart=on-failure` handles crashes,
  and the service starts on boot.
- No vendor relay — the client connects straight to your VPS public IP.
  Your firewall + the token are the entire perimeter.

## License

MIT — do whatever you want with it.
