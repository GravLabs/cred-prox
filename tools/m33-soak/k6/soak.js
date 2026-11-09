// M33 soak workload (plan §5.5): mixed credential types x mixed callers + SSE, bounded VUs.
// Caller keys come from the per-run keys file written by init-secrets.sh (never committed).
import http from 'k6/http';
import { check } from 'k6';
import { Counter } from 'k6/metrics';
import exec from 'k6/execution'; // k6 1.x removed __iter - iteration counter comes from here

const keys = JSON.parse(open('/soak/keys.txt'));
const BASE = 'http://soakhost:8080';
const scrubMiss = new Counter('scrub_miss');

// Duration comes from SOAK_MINUTES (env), NOT k6 CLI --duration/--vus: those replace the
// scenario executors entirely (k6 warns "cli level configuration overrode scenarios").
// k6 1.x trend stats: p50/p95/p95 are not valid names - use med and p(95)/p(99).
const DURATION = (__ENV.SOAK_MINUTES || '240') + 'm';

export const options = {
  scenarios: {
    cc:    { executor: 'constant-arrival-rate', rate: 40, timeUnit: '1s', duration: DURATION,
             preAllocatedVUs: 10, maxVUs: 12, exec: 'cc' },
    gen1:  { executor: 'constant-arrival-rate', rate: 25, timeUnit: '1s', duration: DURATION,
             preAllocatedVUs: 6, maxVUs: 8, exec: 'gen1' },
    login: { executor: 'constant-arrival-rate', rate: 2, timeUnit: '1s', duration: DURATION,
             preAllocatedVUs: 3, maxVUs: 4, exec: 'login' },
    sse:   { executor: 'constant-arrival-rate', rate: 2, timeUnit: '1s', duration: DURATION,
             preAllocatedVUs: 3, maxVUs: 4, exec: 'sse' },
  },
  summaryTrendStats: ['avg', 'min', 'med', 'p(95)', 'p(99)', 'max'],
};

// Mid-run abort for STEADY windows only (runner sets SOAK_STRICT=1): a dead upstream must
// not run blind for an hour. Fault windows deliberately stay ungated - elevated errors
// ARE the observation there. k6 1.4 takes abortOnFail as a BOOL (the 'movingAverage(N)'
// string form is a newer k6 and fails option parsing); the rate threshold is the
// run-cumulative one, and delayAbortEval demands the breach persist 60 s before aborting.
// Steady error rate is ~0, so a sustained 5%-cumulative breach means the stack is dying.
if (__ENV.SOAK_STRICT === '1') {
  options.thresholds = {
    http_req_failed: [{ threshold: 'rate<0.05', abortOnFail: true, delayAbortEval: '60s' }],
  };
}

function hdr(keyId) {
  return { headers: { 'x-api-key': keyId } };
}

export function cc() {
  // No per-iteration query params: unique URLs = one metric series each (k6 warns past
  // 100k; a 4 h soak would drown the metrics engine). Static per-scenario probe only.
  const r = http.get(`${BASE}/cc/echo?probe=cc`, hdr(keys.b));
  check(r, { 'cc 200': (x) => x.status === 200 });
  noSentinelInBody(r);
}

export function gen1() {
  const r = http.get(`${BASE}/vendor/echo?probe=gen1`, hdr(keys.a));
  check(r, { 'gen1 200': (x) => x.status === 200 });
  noSentinelInBody(r);
}

export function login() {
  const r = http.get(`${BASE}/login-api/echo?probe=login`,
    { headers: { 'x-api-key': keys.c, 'X-API-Env': 'prod' } });
  check(r, { 'login 200': (x) => x.status === 200 });
  noSentinelInBody(r);
}

export function sse() {
  const r = http.get(`${BASE}/sse/stream`, hdr(keys.a));
  check(r, { 'sse 200': (x) => x.status === 200 });
  noSentinelInBody(r);
}

// Caller-side scrub witness (§5.2 M20 doctrine): the reflected secret must never reach us.
function noSentinelInBody(r) {
  if (r.body && r.body.indexOf(keys.probeSecret) !== -1) {
    scrubMiss.add(1, { route: 'echo' });
  }
}

export function handleSummary(data) {
  // Real metric names: trend = http_req_duration, counter = http_reqs, rate = http_req_failed.
  const m = data.metrics.http_req_duration || {};
  const line = [
    new Date().toISOString(), (m.values || {}).med, (m.values || {})['p(95)'], (m.values || {})['p(99)'],
    (data.metrics.http_req_failed || { values: { rate: 'NaN' } }).values.rate,
    (data.metrics.scrub_miss || { values: { sum: 0 } }).values.sum,
  ].join(',');
  return {
    '/soak/k6-summary.json': JSON.stringify(data),
    '/soak/k6-line.csv': line + '\n',
    stdout: textSummary(data) + '\n',
  };
}

function textSummary(data) {
  return Object.keys(data.metrics)
    .filter((k) => ['http_req_duration', 'http_reqs', 'http_req_failed', 'scrub_miss'].includes(k))
    .map((k) => `${k}: ${JSON.stringify(data.metrics[k].values)}`)
    .join('\n');
}
