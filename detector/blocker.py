import asyncio, datetime, logging, subprocess, time
from typing import Dict, Optional

log = logging.getLogger('hng.blocker')

class BanRecord:
    def __init__(self, ip, duration_minutes, rate, mean, condition):
        self.ip = ip
        self.duration_minutes = duration_minutes
        self.rate = rate
        self.mean = mean
        self.condition = condition
        self.banned_at = time.time()
        self.unban_at = (None if duration_minutes < 0
                         else self.banned_at + duration_minutes * 60)
    def is_permanent(self): return self.duration_minutes < 0
    def time_remaining(self):
        if self.unban_at is None: return None
        return max(0.0, self.unban_at - time.time())

class Blocker:
    def __init__(self, cfg, notifier):
        self._notifier = notifier
        self._audit_path = cfg['audit']['path']
        self._alert_timeout = cfg['blocking']['ban_alert_timeout_seconds']
        self._bans: Dict[str,BanRecord] = {}

    def is_banned(self, ip): return ip in self._bans
    def get_bans(self): return dict(self._bans)

    async def ban(self, ip, duration_minutes, rate, mean, condition):
        if ip in self._bans: return
        record = BanRecord(ip, duration_minutes, rate, mean, condition)
        self._bans[ip] = record
        try:
            await asyncio.get_event_loop().run_in_executor(None, self._iptables_ban, ip)
            log.info('iptables DROP added for %s', ip)
        except Exception as exc:
            log.error('iptables ban failed for %s: %s', ip, exc)
        try:
            await asyncio.wait_for(
                self._notifier.send_ban_alert(ip, duration_minutes, rate, mean, condition),
                timeout=self._alert_timeout)
        except asyncio.TimeoutError:
            log.error('Slack ban alert timed out for %s', ip)
        except Exception as exc:
            log.error('Slack alert error: %s', exc)
        self._write_audit('BAN', ip, condition, rate, mean, duration_minutes)

    def unban(self, ip):
        record = self._bans.pop(ip, None)
        if record is None: return None
        try:
            self._iptables_unban(ip)
            log.info('iptables DROP removed for %s', ip)
        except Exception as exc:
            log.error('iptables unban failed for %s: %s', ip, exc)
        self._write_audit('UNBAN', ip, record.condition, record.rate,
                          record.mean, record.duration_minutes)
        return record

    @staticmethod
    def _iptables_ban(ip):
        subprocess.run(['iptables','-I','INPUT','-s',ip,'-j','DROP'],
                       check=True, capture_output=True)
    @staticmethod
    def _iptables_unban(ip):
        subprocess.run(['iptables','-D','INPUT','-s',ip,'-j','DROP'],
                       check=True, capture_output=True)

    def _write_audit(self, action, ip, condition, rate, baseline, duration):
        ts = datetime.datetime.utcnow().isoformat()
        dur_str = 'permanent' if duration < 0 else f'{duration}m'
        line = (f'[{ts}] {action} ip={ip} | condition={condition} | '
                f'rate={rate:.3f} | baseline={baseline:.3f} | duration={dur_str}\n')
        try:
            with open(self._audit_path, 'a') as f: f.write(line)
        except OSError as exc:
            log.warning('Audit log write failed: %s', exc)
