#!/usr/bin/env python3
import asyncio, logging, os, signal, sys, time
from pathlib import Path
import yaml
from monitor import LogMonitor
from baseline import BaselineTracker
from detector import AnomalyDetector
from blocker import Blocker
from unbanner import Unbanner
from notifier import SlackNotifier
from dashboard import Dashboard

logging.basicConfig(level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)])
log = logging.getLogger('hng.main')
START_TIME = time.time()

def load_config(path='config.yaml'):
    config_path = Path(path)
    if not config_path.exists():
        config_path = Path(__file__).parent / path
    with open(config_path) as f:
        cfg = yaml.safe_load(f)
    slack_env = os.environ.get('SLACK_WEBHOOK_URL')
    if slack_env:
        cfg['slack']['webhook_url'] = slack_env
    return cfg

async def main():
    log.info('=' * 60)
    log.info('  HNG Anomaly Detection Engine - Starting Up')
    log.info('=' * 60)
    cfg = load_config()
    Path(cfg['audit']['path']).parent.mkdir(parents=True, exist_ok=True)
    notifier = SlackNotifier(cfg)
    baseline = BaselineTracker(cfg)
    blocker = Blocker(cfg, notifier)
    unbanner = Unbanner(cfg, blocker, notifier)
    detector = AnomalyDetector(cfg, baseline, blocker, unbanner, notifier)
    monitor = LogMonitor(cfg, detector)
    dashboard = Dashboard(cfg, baseline, blocker, unbanner, START_TIME)
    dashboard.set_monitor(monitor)
    loop = asyncio.get_running_loop()
    shutdown_event = asyncio.Event()
    def _handle_signal():
        log.info('Shutdown signal received.')
        shutdown_event.set()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _handle_signal)
    log.info('Launching all subsystems...')
    await asyncio.gather(
        monitor.run(), baseline.run(), unbanner.run(),
        dashboard.run(), shutdown_event.wait(),
        return_exceptions=True)
    log.info('HNG Anomaly Detection Engine - Stopped.')

if __name__ == '__main__':
    asyncio.run(main())
