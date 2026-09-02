# Deploying DefectDojo and the exporter with Docker Compose

The repository ships two compose files:

| File | Purpose |
|------|---------|
| `docker-compose.yml` | DefectDojo (official images) + the exporter. Usable on its own. |
| `docker-compose.test.yml` | Optional overlay adding the `testapp` integration tester. |

The base file is adapted from the official
[django-DefectDojo `docker-compose.yml`](https://github.com/DefectDojo/django-DefectDojo/blob/master/docker-compose.yml)
and uses the official published images (`defectdojo/defectdojo-django`,
`defectdojo/defectdojo-nginx`, plus the upstream-pinned `postgres` and
`valkey`). Like the upstream file, it is an evaluation setup: usable as a
starting point for production only after you customize secrets, passwords and
persistence for your environment.

## Quick start

```bash
cp .env.example .env   # optional; every value has a working default
docker compose up -d
```

If something on your host already listens on port 8080, publish DefectDojo
elsewhere with `DD_PORT` (in `.env`, or `DD_PORT=8081 docker compose up -d`);
the exporter talks to nginx over the compose network, so nothing else changes.

On the first boot DefectDojo runs its database migrations and loads fixtures,
which takes several minutes. The exporter waits for it: it retries fetching
its API token every 15 seconds until DefectDojo answers, then starts
collecting.

Once up:

- DefectDojo UI: <http://localhost:8080> — log in as `admin` with
  `DD_ADMIN_PASSWORD` (default `Def3ctDojo@Exporter!`).
- Exporter: <http://localhost:9100/metrics>.

Point Prometheus or VictoriaMetrics at the exporter's `/metrics` endpoint and
Grafana at that datasource.

## How the exporter authenticates

The exporter needs a DefectDojo API token. In this stack it gets one on its
own: `DD_USERNAME`/`DD_PASSWORD` (the admin credentials by default) are
exchanged for a token via `/api/v2/api-token-auth/` at startup. To use a
pre-created token instead — for example a token of a dedicated read-only
user — set `DD_TOKEN` in `.env`; it takes priority over the credentials.

## Configuration

All knobs live in `.env` (see `.env.example`):

- `DD_ADMIN_USER` / `DD_ADMIN_PASSWORD` — admin account created on first
  boot; also used by the exporter and the test app.
- `DD_PORT`, `DD_TLS_PORT` — DefectDojo ports on the host.
- `EXPORTER_PORT` — where the exporter's `/metrics` is published (default 9100).
- `EXPORTER_INTERVAL` — collection interval (default `1m` in this stack).
- `DJANGO_VERSION`, `NGINX_VERSION` — DefectDojo image tags.
- `DD_SECRET_KEY`, `DD_CREDENTIAL_AES_256_KEY`, `DD_DATABASE_PASSWORD` —
  change these for anything that is not a local throwaway.

The exporter runs with `-use-engagement-update-check=false` here: SLA
deadlines pass and findings get mitigated without engagements being updated,
so every cycle re-reads the findings to keep
`dojo_vulnerabilities_sla_breached` and the SLA compliance metrics fresh.

DefectDojo settings overrides (`local_settings.py`) can be dropped into
`docker/extra_settings/`, mirroring the official repository's mechanism.

## The testing overlay

`docker-compose.test.yml` exists to validate the exporter (current and future
metrics) against a real DefectDojo. It is deliberately **not** part of
`docker-compose.yml`, so the base stack never depends on it. It adds:

- `testapp` — a small Go program (`testapp/`) that seeds DefectDojo with a
  deterministic product and verifies the exporter's output.
- `DD_EDITABLE_MITIGATED_DATA=True` on the `uwsgi` service, which the seeder
  needs in order to set mitigation timestamps in the past via the API.

Run it against the stack:

```bash
docker compose -f docker-compose.yml -f docker-compose.test.yml up -d
docker compose -f docker-compose.yml -f docker-compose.test.yml run --rm testapp
```

(The `testapp` service sits behind a compose profile, so plain `up -d` never
starts it; `run` does.)

The test app:

1. Waits for DefectDojo to answer and obtains an API token.
2. Deletes any `exporter-testapp` product left over from a previous run, then
   creates the product (type "Exporter Test"), an engagement and a test.
3. Creates five findings chosen to exercise every metric against DefectDojo's
   default SLA configuration (Critical: 7 days, High: 30, Medium: 90):
   - an active Critical discovered 100 days ago → breaches its SLA,
   - an active High (2 days old) and an active Medium (1 day old),
   - a Critical fixed in 2 days → mitigated within SLA,
   - a Critical fixed in 28 days → mitigated 21 days past its SLA deadline.
4. Polls the exporter's `/metrics` until the expected values appear (active
   counts, SLA breach count, within/outside SLA counts, fix-time sum of 30
   days over 2 findings), then exits 0 on success or 1 with a report of the
   unmet expectations.

Exit code and logs make it usable in CI as an end-to-end gate: bring the
stack up, `run --rm testapp`, tear down.

Reruns are safe — the seed product is recreated from scratch each time. Don't
run the test overlay against a DefectDojo instance whose data you care about:
it deletes and recreates the `exporter-testapp` product (nothing else).

## Tear down

```bash
docker compose down            # keep DefectDojo's data volumes
docker compose down -v         # remove volumes too (full reset)
```
