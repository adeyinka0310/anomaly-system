import asyncio, json, logging, time
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Deque, Dict, Optional

log = logging.getLogger('hng.monitor')

@dataclass
class LogEntry:
    source_ip: str
    timestamp: float
    method: str
    path: str
    status: int
    response_size: int
    raw: str = ''

class SlidingWindowCounter:
    def __init__(self, window_seconds):
        self.window_seconds = window_seconds
        self._dq: Deque[float] = deque()
    def add(self, ts):
        self._dq.append(ts)
        self._evict(ts)
    def _evict(self, now):
        cutoff = now - self.window_seconds
        while self._dq and self._dq[0] < cutoff:
            self._dq.popleft()
    def count(self, now=None):
        if now is None: now = time.time()
        self._evict(now)
        return len(self._dq)
    def rate(self, now=None):
        return self.count(now) / self.window_seconds

class LogMonitor:
    def __init__(self, cfg, detector):
        self.log_path = Path(cfg['log']['path'])
        self.poll_ms = cfg['log']['poll_interval_ms'] / 1000.0
        self.window_sec = cfg['sliding_window']['per_ip_seconds']
        self.global_window_sec = cfg['sliding_window']['global_seconds']
        self.detector = detector
        self._ip_windows: Dict[str, SlidingWindowCounter] = defaultdict(
            lambda: SlidingWindowCounter(self.window_sec))
        self._ip_error_windows: Dict[str, SlidingWindowCounter] = defaultdict(
            lambda: SlidingWindowCounter(self.window_sec))
        self._global_window = SlidingWindowCounter(self.global_window_sec)
        log.info('LogMonitor initialised - watching %s', self.log_path)

    def get_ip_rate(self, ip): return self._ip_windows[ip].rate()
    def get_global_rate(self): return self._global_window.rate()
    def get_ip_error_rate(self, ip): return self._ip_error_windows[ip].rate()
    def get_top_ips(self, n=10):
        now = time.time()
        rates = [(ip, w.count(now)) for ip, w in self._ip_windows.items()]
        rates.sort(key=lambda x: x[1], reverse=True)
        return rates[:n]

    def _parse_line(self, line):
        line = line.strip()
        if not line: return None
        try:
            obj = json.loads(line)
            return LogEntry(
                source_ip=obj.get('source_ip', obj.get('remote_addr', '0.0.0.0')),
                timestamp=float(obj.get('timestamp', time.time())),
                method=obj.get('method', 'GET'),
                path=obj.get('path', obj.get('request', '/'))[:128],
                status=int(obj.get('status', 200)),
                response_size=int(obj.get('response_size', obj.get('body_bytes_sent', 0))),
                raw=line)
        except (json.JSONDecodeError, ValueError, KeyError) as exc:
            log.debug('Could not parse line (%s): %s', exc, line[:80])
            return None

    async def run(self):
        log.info('Waiting for log file: %s', self.log_path)
        while not self.log_path.exists():
            await asyncio.sleep(1)
        log.info('Log file found - starting tail.')
        current_inode = self.log_path.stat().st_ino
        with open(self.log_path, 'r') as f:
            f.seek(0, 2)
            while True:
                try:
                    new_inode = self.log_path.stat().st_ino
                    if new_inode != current_inode:
                        log.info('Log rotation detected - reopening.')
                        f.close()
                        f = open(self.log_path, 'r')
                        current_inode = new_inode
                except FileNotFoundError:
                    await asyncio.sleep(1)
                    continue
                while True:
                    line = f.readline()
                    if not line: break
                    entry = self._parse_line(line)
                    if entry is None: continue
                    now = entry.timestamp
                    self._ip_windows[entry.source_ip].add(now)
                    self._global_window.add(now)
                    if entry.status >= 400:
                        self._ip_error_windows[entry.source_ip].add(now)
                    await self.detector.handle_entry(
                        entry,
                        self._ip_windows[entry.source_ip].rate(),
                        self._global_window.rate(),
                        self._ip_error_windows[entry.source_ip].rate())
                await asyncio.sleep(self.poll_ms)
