# HNG Anomaly Detection Engine

A real-time HTTP traffic anomaly detection daemon built for HNG cloud.ng — a Nextcloud-powered cloud storage platform. This engine watches all incoming traffic, learns what normal looks like, and automatically blocks threats the moment they deviate.

<br>
🌐 Live Deployment
ResourceURLLive Metrics Dashboardhttp://3.239.20.208:8080/Nextcloud (IP only)http://3.239.20.208/Server IP3.239.20.208
Internet Traffic
      │
      ▼  port 80
┌─────────────┐      JSON logs      ┌──────────────────────────┐
│    Nginx    │ ──────────────────▶ │   HNG-nginx-logs volume  │
│  (Reverse   │                     │  /var/log/nginx/          │
│   Proxy)    │                     │  hng-access.log          │
└──────┬──────┘                     └────────────┬─────────────┘
       │                                         │ (read-only mount)
       ▼                                         ▼
  ┌──────────┐                    ┌──────────────────────────────┐
  │Nextcloud │                    │     Detector Daemon          │
  │(HNG img) │                    │                              │
  └──────────┘                    │  monitor.py  → tails log     │
                                  │  baseline.py → rolling mean  │
                                  │  detector.py → z-score check │
                                  │  blocker.py  → iptables DROP │
                                  │  unbanner.py → backoff unban │
                                  │  notifier.py → Slack alerts  │
                                  │  dashboard.py→ live UI :8080 │
                                  └──────────────────────────────┘
                                         │          │
                               ┌─────────┘          └──────────┐
                               ▼                               ▼
                          iptables                           Slack
                         DROP rules                         Webhooks
Why Python?
Python was chosen for three reasons:
1. asyncio — The entire daemon runs as a single async process. The log tailer, baseline recalculator, unbanner loop, Slack notifier, and HTTP dashboard all run concurrently without threads. This makes the code simple, predictable, and easy to reason about.
2. collections.deque — Python's built-in double-ended queue is the perfect structure for a sliding window. O(1) appends on the right and O(1) pops from the left mean eviction is essentially free, with no background cleanup needed.
3. aiohttp — A single library handles both the async HTTP dashboard server and the async Slack webhook client, keeping dependencies minimal.
<br>
🔄 How the Sliding Window Works
Each window is a collections.deque containing Unix timestamps — one float per request.
pythonfrom collections import deque

class SlidingWindowCounter:
    def __init__(self, window_seconds: int):
        self.window_seconds = window_seconds
        self._dq = deque()          # timestamps, newest on the RIGHT

    def add(self, ts: float) -> None:
        self._dq.append(ts)         # O(1) — append to right
        self._evict(ts)

    def _evict(self, now: float) -> None:
        cutoff = now - self.window_seconds
        while self._dq and self._dq[0] < cutoff:
            self._dq.popleft()      # O(1) — pop from left

    def rate(self) -> float:
        return len(self._dq) / self.window_seconds
Eviction is lazy. No background timer runs to clean old data. Instead, every time a new event is recorded, we pop stale timestamps from the LEFT until deque[0] >= (now - window_seconds). Each timestamp is added once and removed once — O(1) amortized.
Two windows run in parallel:

per_ip_windows[ip] — tracks one IP's requests over 60 seconds
global_window — tracks all requests over 60 seconds

<br>
📊 How the Baseline Works
Window Size & Recalculation Interval

Rolling window: 30 minutes of per-second request counts (up to 1,800 data points)
Recalculation: Every 60 seconds

Per-Hour Slot Logic
The baseline maintains a dict[hour_of_day → deque[counts]]. This means traffic at 3am is compared against other 3am readings, not against the peak-hour average. The current hour's slot is preferred when it has at least 30 samples; otherwise the full 30-minute rolling window is used.
pythonhour = int(time.strftime("%H"))
hourly_samples = hourly_slots[hour]

samples = hourly_samples if len(hourly_samples) >= 30 else rolling_window
Floor Values
To prevent division-by-zero and over-sensitivity during quiet periods:
yamlfloor_mean:   1.0   # effective_mean never drops below 1.0 req/s
floor_stddev: 0.5   # effective_stddev never drops below 0.5
These are configurable in detector/config.yaml.
<br>
🚨 How Detection Works
Two Conditions (fires whichever triggers first)
Condition 1 — Z-score:
zscore = (current_rate - effective_mean) / effective_stddev
if zscore > 3.0 → ANOMALY
Condition 2 — Rate multiplier:
if current_rate > effective_mean × 5.0 → ANOMALY
Error Surge Tightening
If an IP's 4xx/5xx rate exceeds baseline_error_rate × 3.0, thresholds tighten automatically to catch scanners and credential-stuffers earlier:
ThresholdNormalError SurgeZ-score3.02.0Rate multiplier5×3×
Response

Per-IP anomaly → iptables -I INPUT -s <IP> -j DROP + Slack alert (within 10 seconds)
Global anomaly → Slack alert only (can't block the internet)

<br>
⏱️ Auto-Unban Backoff Schedule
Each IP gets progressively longer bans on repeat offences:
OffenceBan Duration1st10 minutes2nd30 minutes3rd2 hours4th+Permanent
The unbanner loop checks every 30 seconds and sends a Slack notification on every release.
<br>
📋 Audit Log Format
Every ban, unban, and baseline recalculation writes a structured line to /var/log/hng-detector/audit.log:
[2026-04-29T18:16:44] BAN ip=172.18.0.1 | condition=zscore=3.03 > threshold=3.0 | rate=2.517 | baseline=1.000 | duration=10m
[2026-04-29T18:26:44] UNBAN ip=172.18.0.1 | condition=zscore=3.03 > threshold=3.0 | rate=2.517 | baseline=1.000 | duration=10m
[2026-04-29T18:16:52] BASELINE_RECALC ip=ALL | condition=recalc | rate=13.200 | baseline=13.200 | stddev=16.980 | samples=15 | source=rolling
<br>
📁 Repository Structure
hng-anomaly-system/
├── detector/
│   ├── main.py          # Entry point — wires all modules, handles shutdown
│   ├── monitor.py       # Nginx log tailer + deque sliding windows
│   ├── baseline.py      # 30-min rolling baseline, per-hour slots
│   ├── detector.py      # Z-score + rate multiplier anomaly logic
│   ├── blocker.py       # iptables ban management + audit logging
│   ├── unbanner.py      # Backoff schedule auto-release
│   ├── notifier.py      # Slack webhook alerts
│   ├── dashboard.py     # Live metrics web UI at :8080/
│   ├── config.yaml      # All thresholds — nothing hardcoded in logic
│   ├── requirements.txt # Python dependencies
│   └── Dockerfile       # Container definition
├── nginx/
│   └── nginx.conf       # JSON access logs + X-Forwarded-For config
├── docs/
│   └── architecture.png # System architecture diagram
├── screenshots/
│   ├── Tool-running.png
│   ├── Ban-slack.png
│   ├── Unban-slack.png
│   ├── Global-alert-slack.png
│   ├── Iptables-banned.png
│   ├── Audit-log.png
│   └── Baseline-graph.png
├── docker-compose.yml   # Full 4-container stack definition
├── .env.example         # Environment variable template
└── README.md
<br>
⚙️ Configuration Reference
All thresholds live in detector/config.yaml — nothing is hardcoded in the logic files:
yamlsliding_window:
  per_ip_seconds: 60       # Track per-IP rate over this window
  global_seconds: 60       # Track global rate over this window

baseline:
  window_minutes: 30       # Rolling window for mean/stddev
  recalc_interval_seconds: 60
  min_samples: 30          # Minimum before hourly slot is preferred
  floor_mean: 1.0
  floor_stddev: 0.5

detection:
  zscore_threshold: 3.0
  rate_multiplier: 5.0
  error_rate_multiplier: 3.0   # Error surge trigger
  tightened_zscore: 2.0
  tightened_multiplier: 3.0

blocking:
  ban_alert_timeout_seconds: 10
  backoff_schedule_minutes: [10, 30, 120, -1]
<br>
🚀 Setup: Fresh Ubuntu Server to Running Stack
Prerequisites

Ubuntu 22.04 LTS VPS — minimum 2 vCPU, 2 GB RAM (AWS t3.small or equivalent)
A Slack Incoming Webhook URL
Ports 80 and 8080 open in your firewall/security group

Step 1 — Install Docker
bashsudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install -y ca-certificates curl gnupg git
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
sudo usermod -aG docker $USER && newgrp docker
Step 2 — Clone the Repository
bashgit clone https://github.com/YOUR_USERNAME/hng-anomaly-system.git
cd hng-anomaly-system
Step 3 — Configure Environment
bashcp .env.example .env
nano .env
Fill in your values:
envMYSQL_ROOT_PASSWORD=your_strong_root_password
MYSQL_DATABASE=nextcloud
MYSQL_USER=nextcloud
MYSQL_PASSWORD=your_strong_db_password
NEXTCLOUD_ADMIN_USER=admin
NEXTCLOUD_ADMIN_PASSWORD=your_strong_admin_password
SERVER_IP=your_server_public_ip
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
Step 4 — Build and Launch
bashdocker compose build detector
docker compose up -d
Step 5 — Verify
bash# All 4 containers should show "Up"
docker compose ps

# Watch the detector start up
docker compose logs -f detector

# Test Nextcloud is reachable
curl -I http://localhost/

# Open the dashboard
# http://YOUR_SERVER_IP:8080/
Step 6 — Test Detection
bash# Simulate an attack flood
for i in $(seq 1 200); do curl -s http://localhost/ > /dev/null & done; wait

# Watch the ban fire
docker compose logs --tail=20 detector

# Confirm iptables block
sudo iptables -L INPUT -n

# Check audit log
docker compose exec detector cat /var/log/hng-detector/audit.log
<br>
🛠️ Useful Commands
bash# Start the stack
docker compose up -d

# Stop the stack
docker compose down

# Restart just the detector (after config changes)
docker compose restart detector

# Watch live detector logs
docker compose logs -f detector

# View current iptables bans
sudo iptables -L INPUT -n

# Manually remove a ban
sudo iptables -D INPUT -s 1.2.3.4 -j DROP

# View the audit log live
docker compose exec detector tail -f /var/log/hng-detector/audit.log

# Check dashboard API
curl http://localhost:8080/api/stats
<br>
🔒 Security Notes

The detector container runs with NET_ADMIN capability so it can modify iptables rules on the host. This is required by design.
The Slack webhook URL is injected via environment variable and never stored in code.
Nginx is configured to trust Docker bridge network ranges for X-Forwarded-For so real client IPs are correctly identified behind the proxy.
The HNG-nginx-logs Docker volume is mounted read-write by Nginx and read-only by the detector — the detector can never write to or corrupt the log source.

<br>
📦 Tech Stack
ComponentTechnologyCloud StorageNextcloud (kefaslungu/hng-nextcloud)Reverse ProxyNginx 1.25 AlpineDatabaseMariaDB 10.11Detection DaemonPython 3.12 + asyncioContainerisationDocker + Docker ComposeAlertingSlack Incoming WebhooksFirewalliptables (Linux kernel)