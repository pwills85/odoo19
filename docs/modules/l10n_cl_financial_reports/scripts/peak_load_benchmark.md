# Peak Load Benchmark Plan

Objetivo: Simular 1000+ usuarios concurrentes contra endpoints clave:
- /api/v1/ratio-analysis/compute (POST)
- /api/v1/ratio-analysis/benchmark (POST)
- /api/v1/ratio-analysis/predict (POST)

Herramientas sugeridas: k6 o Locust.

Ejemplo k6 (pseudo):
```js
import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  vus: 1000,
  duration: '5m',
  thresholds: {
    http_req_duration: ['p(95)<1000'],
    http_req_failed: ['rate<0.01'],
  },
};

export default function () {
  const payload = JSON.stringify({
    company_id: 1,
    date_from: '2025-01-01',
    date_to: '2025-01-31',
    analysis_type: 'comprehensive',
  });
  const headers = {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer <JWT>',
    'X-Signature': 'sha256=<HMAC>',
  };
  const res = http.post('https://<host>/api/v1/ratio-analysis/compute', payload, { headers });
  check(res, { 'status is 200': (r) => r.status === 200 });
  sleep(1);
}
```

KPIs:
- p95 < 1s, error rate < 1%, throughput > 200 rps sostenido.

