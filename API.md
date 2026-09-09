# API

REST: `GET /health`, `GET /health/detailed`, `/api/alerts`, `/api/traffic`,
`/api/assets`, `/api/models`, `/api/metrics`, `/api/diode-status`,
`/api/features/{alert_id}`, `/api/explanation/{alert_id}`, `POST /api/ingest`,
`POST /api/config`, and `POST /api/feedback`.

WebSockets: `/ws/events`, `/ws/alerts`, `/ws/metrics` (all channels share the
receive-side event bus and send heartbeat messages).
