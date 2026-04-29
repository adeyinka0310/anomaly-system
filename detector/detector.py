import asyncio, logging, time
from typing import Dict
from monitor import LogEntry

log = logging.getLogger('hng.detector')

class AnomalyDetector:
    def __init__(self, cfg, baseline, blocker, unbanner, notifier):
        self._baseline = baseline
        self._blocker = blocker
        self._unbanner = unbanner
        self._notifier = notifier
        det = cfg['detection']
        self._zscore_thresh = det['zscore_threshold']
        self._rate_mult = det['rate_multiplier']
        self._error_mult = det['error_rate_multiplier']
        self._tight_zscore = det['tightened_zscore']
        self._tight_mult = det['tightened_multiplier']
        self._last_alerted: Dict[str,float] = {}
        self._cooldown_seconds = 30
        self._last_global_alert = 0.0
        self._global_cooldown = 60
        log.info('AnomalyDetector ready - zscore_thresh=%.1f rate_mult=%.1fx',
                 self._zscore_thresh, self._rate_mult)

    async def handle_entry(self, entry, ip_rate, global_rate, ip_error_rate):
        is_error = 1 if entry.status >= 400 else 0
        self._baseline.record(count=1, errors=is_error)
        if self._blocker.is_banned(entry.source_ip): return
        await self._check_ip(entry.source_ip, ip_rate, ip_error_rate)
        await self._check_global(global_rate)

    async def _check_ip(self, ip, rate, error_rate):
        mean = self._baseline.effective_mean
        stddev = self._baseline.effective_stddev
        error_mean = self._baseline.effective_error_mean
        error_surge = (error_rate > 0 and error_mean > 0
                       and error_rate > error_mean * self._error_mult)
        zscore_thresh = self._tight_zscore if error_surge else self._zscore_thresh
        rate_mult = self._tight_mult if error_surge else self._rate_mult
        zscore = self._baseline.zscore(rate)
        if zscore > zscore_thresh:
            await self._trigger_ban(ip, rate, mean, stddev,
                f'zscore={zscore:.2f} > threshold={zscore_thresh:.1f}')
            return
        if mean > 0 and rate > mean * rate_mult:
            await self._trigger_ban(ip, rate, mean, stddev,
                f'rate={rate:.2f} > {rate_mult:.1f}x mean={mean:.2f}')

    async def _check_global(self, global_rate):
        mean = self._baseline.effective_mean
        stddev = self._baseline.effective_stddev
        zscore = self._baseline.zscore(global_rate)
        anomalous = (zscore > self._zscore_thresh or
                     (mean > 0 and global_rate > mean * self._rate_mult))
        if not anomalous: return
        now = time.time()
        if now - self._last_global_alert < self._global_cooldown: return
        self._last_global_alert = now
        condition = (f'GLOBAL zscore={zscore:.2f} > {self._zscore_thresh:.1f} '
                     f'or rate={global_rate:.2f} > {self._rate_mult:.1f}x mean={mean:.2f}')
        log.warning('GLOBAL ANOMALY - %s', condition)
        await self._notifier.send_global_alert(global_rate, mean, stddev, condition)

    async def _trigger_ban(self, ip, rate, mean, stddev, condition):
        now = time.time()
        if now - self._last_alerted.get(ip, 0) < self._cooldown_seconds: return
        self._last_alerted[ip] = now
        log.warning('BAN TRIGGERED - IP=%s  %s  rate=%.2f req/s', ip, condition, rate)
        ban_duration = self._unbanner.next_duration(ip)
        asyncio.create_task(self._blocker.ban(ip, ban_duration, rate, mean, condition))
