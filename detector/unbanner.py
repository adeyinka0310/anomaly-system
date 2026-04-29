import asyncio, logging, time
from typing import Dict

log = logging.getLogger('hng.unbanner')

class Unbanner:
    def __init__(self, cfg, blocker, notifier):
        self._blocker = blocker
        self._notifier = notifier
        self._schedule = cfg['blocking']['backoff_schedule_minutes']
        self._offence_count: Dict[str,int] = {}

    def next_duration(self, ip):
        count = self._offence_count.get(ip, 0)
        self._offence_count[ip] = count + 1
        return self._schedule[count] if count < len(self._schedule) else -1

    def offence_count(self, ip): return self._offence_count.get(ip, 0)

    async def run(self):
        log.info('Unbanner started - checking every 30 seconds.')
        while True:
            await asyncio.sleep(30)
            await self._process_expired()

    async def _process_expired(self):
        now = time.time()
        for ip, record in list(self._blocker.get_bans().items()):
            if record.is_permanent(): continue
            if record.unban_at and now >= record.unban_at:
                log.info('Ban expired for %s - unbanning.', ip)
                removed = self._blocker.unban(ip)
                if removed:
                    await self._notifier.send_unban_alert(
                        ip, removed.duration_minutes, removed.condition,
                        removed.rate, removed.mean)
