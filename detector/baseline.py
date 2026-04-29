import asyncio, datetime, logging, math, time
from collections import defaultdict, deque
from typing import Deque, Dict, List, Tuple

log = logging.getLogger('hng.baseline')

def _mean(values): return sum(values)/len(values) if values else 0.0
def _stddev(values, mean):
    if len(values) < 2: return 0.0
    return math.sqrt(sum((v-mean)**2 for v in values)/(len(values)-1))

class BaselineTracker:
    def __init__(self, cfg):
        self._window_secs = cfg['baseline']['window_minutes'] * 60
        self._recalc_interval = cfg['baseline']['recalc_interval_seconds']
        self._min_samples = cfg['baseline']['min_samples']
        self._floor_mean = cfg['baseline']['floor_mean']
        self._floor_stddev = cfg['baseline']['floor_stddev']
        self._audit_path = cfg['audit']['path']
        self._per_second_counts: Deque[Tuple[float,float]] = deque()
        self._error_per_second: Deque[Tuple[float,float]] = deque()
        self._hourly_slots: Dict[int,Deque[float]] = defaultdict(lambda: deque(maxlen=3600))
        self._error_hourly_slots: Dict[int,Deque[float]] = defaultdict(lambda: deque(maxlen=3600))
        self._current_second = math.floor(time.time())
        self._current_count = 0
        self._current_errors = 0
        self.effective_mean = self._floor_mean
        self.effective_stddev = self._floor_stddev
        self.effective_error_mean = 0.0
        self.effective_error_stddev = 0.1
        self.last_recalc = 0.0
        self.history: List[dict] = []
        log.info('BaselineTracker initialised - window=%ds recalc every %ds',
                 self._window_secs, self._recalc_interval)

    def record(self, count=1, errors=0):
        now = math.floor(time.time())
        if now != self._current_second:
            self._commit_bucket()
            self._current_second = now
            self._current_count = 0
            self._current_errors = 0
        self._current_count += count
        self._current_errors += errors

    def zscore(self, rate):
        if self.effective_stddev == 0: return 0.0
        return (rate - self.effective_mean) / self.effective_stddev

    def _commit_bucket(self):
        ts = self._current_second
        count = float(self._current_count)
        errors = float(self._current_errors)
        hour = int(time.strftime('%H', time.localtime(ts)))
        self._per_second_counts.append((ts, count))
        self._error_per_second.append((ts, errors))
        cutoff = ts - self._window_secs
        while self._per_second_counts and self._per_second_counts[0][0] < cutoff:
            self._per_second_counts.popleft()
        while self._error_per_second and self._error_per_second[0][0] < cutoff:
            self._error_per_second.popleft()
        self._hourly_slots[hour].append(count)
        self._error_hourly_slots[hour].append(errors)

    def _recalculate(self):
        hour = int(time.strftime('%H'))
        hourly = list(self._hourly_slots[hour])
        rolling = [c for _,c in self._per_second_counts]
        samples = hourly if len(hourly) >= self._min_samples else rolling
        source = 'hourly' if len(hourly) >= self._min_samples else 'rolling'
        if len(samples) >= 2:
            m = _mean(samples); s = _stddev(samples, m)
        else:
            m = self._floor_mean; s = self._floor_stddev
        self.effective_mean = max(m, self._floor_mean)
        self.effective_stddev = max(s, self._floor_stddev)
        err_h = list(self._error_hourly_slots[hour])
        err_r = [c for _,c in self._error_per_second]
        err_s = err_h if len(err_h) >= self._min_samples else err_r
        self.effective_error_mean = max(_mean(err_s) if len(err_s)>=2 else 0.0, 0.0)
        self.effective_error_stddev = max(_stddev(err_s, self.effective_error_mean) if len(err_s)>=2 else 0.1, 0.1)
        self.last_recalc = time.time()
        self.history.append({'ts': self.last_recalc, 'mean': self.effective_mean,
                             'stddev': self.effective_stddev, 'samples': len(samples), 'source': source})
        if len(self.history) > 100: self.history.pop(0)
        ts_str = datetime.datetime.utcnow().isoformat()
        line = (f'[{ts_str}] BASELINE_RECALC ip=ALL | condition=recalc | '
                f'rate={self.effective_mean:.3f} | baseline={self.effective_mean:.3f} | '
                f'stddev={self.effective_stddev:.3f} | samples={len(samples)} | source={source}\n')
        try:
            with open(self._audit_path, 'a') as f: f.write(line)
        except OSError: pass
        log.info('Baseline recalculated - mean=%.2f stddev=%.2f samples=%d source=%s',
                 self.effective_mean, self.effective_stddev, len(samples), source)

    async def run(self):
        while True:
            await asyncio.sleep(self._recalc_interval)
            self._recalculate()
