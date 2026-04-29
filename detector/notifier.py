import datetime, json, logging
import aiohttp

log = logging.getLogger('hng.notifier')

def _now(): return datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')

class SlackNotifier:
    def __init__(self, cfg):
        self._webhook = cfg['slack']['webhook_url']
        self._enabled = bool(self._webhook and
                             self._webhook != 'YOUR_SLACK_WEBHOOK_URL_HERE')
        if not self._enabled:
            log.warning('Slack webhook not configured - alerts logged only.')

    async def _post(self, payload):
        if not self._enabled:
            log.info('[SLACK-DRY-RUN] %s', json.dumps(payload)[:200])
            return
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(self._webhook, json=payload,
                                        timeout=aiohttp.ClientTimeout(total=8)) as resp:
                    if resp.status != 200:
                        log.error('Slack error %d: %s', resp.status, await resp.text())
        except Exception as exc:
            log.error('Slack POST failed: %s', exc)

    async def send_ban_alert(self, ip, duration_minutes, rate, mean, condition):
        dur = 'PERMANENT' if duration_minutes < 0 else f'{duration_minutes} minutes'
        await self._post({'text': (
            f':no_entry: *IP BANNED* - `{ip}`\n'
            f'*Condition:* {condition}\n'
            f'*Current rate:* `{rate:.2f}` req/s\n'
            f'*Baseline mean:* `{mean:.2f}` req/s\n'
            f'*Ban duration:* {dur}\n'
            f'*Timestamp:* `{_now()}`')})
        log.info('Slack ban alert sent for %s', ip)

    async def send_unban_alert(self, ip, was_duration, condition, rate, mean):
        await self._post({'text': (
            f':white_check_mark: *IP UNBANNED* - `{ip}`\n'
            f'*Original condition:* {condition}\n'
            f'*Rate at ban time:* `{rate:.2f}` req/s\n'
            f'*Baseline mean:* `{mean:.2f}` req/s\n'
            f'*Ban duration served:* {was_duration} minutes\n'
            f'*Timestamp:* `{_now()}`')})
        log.info('Slack unban alert sent for %s', ip)

    async def send_global_alert(self, global_rate, mean, stddev, condition):
        await self._post({'text': (
            f':warning: *GLOBAL TRAFFIC ANOMALY*\n'
            f'*Condition:* {condition}\n'
            f'*Global rate:* `{global_rate:.2f}` req/s\n'
            f'*Baseline mean:* `{mean:.2f}` req/s\n'
            f'*Baseline stddev:* `{stddev:.2f}`\n'
            f'*Timestamp:* `{_now()}`')})
        log.info('Slack global alert sent - rate=%.2f', global_rate)
