# Vulnerability Metrics Collector from [DefectDojo](https://github.com/DefectDojo/django-DefectDojo)

## Metrics

The application collects and exposes the following metrics:

- `dojo_vulnerabilities_active`: Number of active vulnerabilities.
- `dojo_vulnerabilities_duplicate`: Number of duplicate vulnerabilities.
- `dojo_vulnerabilities_under_review`: Number of vulnerabilities under review.
- `dojo_vulnerabilities_false_positive`: Number of false positive vulnerabilities.
- `dojo_vulnerabilities_out_of_scope`: Number of vulnerabilities out of scope.
- `dojo_vulnerabilities_risk_accepted`: Number of vulnerabilities with risk accepted.
- `dojo_vulnerabilities_verified`: Number of verified vulnerabilities.
- `dojo_vulnerabilities_mitigated`: Number of mitigated vulnerabilities.
- `dojo_vulnerabilities_sla_breached`: Number of active vulnerabilities currently past their SLA deadline.
- `dojo_vulnerabilities_mitigated_within_sla`: Number of mitigated vulnerabilities that were fixed within their SLA.
- `dojo_vulnerabilities_mitigated_outside_sla`: Number of mitigated vulnerabilities that were fixed after their SLA deadline.
- `dojo_vulnerabilities_fix_time_days_sum`: Total days from discovery to mitigation across mitigated vulnerabilities.
- `dojo_vulnerabilities_fix_time_days_count`: Number of mitigated vulnerabilities included in `dojo_vulnerabilities_fix_time_days_sum`.

The SLA metrics are derived from the `sla_days_remaining` field DefectDojo
computes per finding, so they follow the SLA configuration assigned to each
product. Findings with SLA tracking disabled are excluded from the SLA
metrics, and duplicate findings are excluded from the SLA compliance and
fix-time metrics so they don't skew the stats.

### Example queries

Average fix time in days across everything:

```promql
sum(dojo_vulnerabilities_fix_time_days_sum) / sum(dojo_vulnerabilities_fix_time_days_count)
```

Fix-SLA compliance ratio (fraction of mitigated findings fixed within SLA):

```promql
sum(dojo_vulnerabilities_mitigated_within_sla)
/
(sum(dojo_vulnerabilities_mitigated_within_sla) + sum(dojo_vulnerabilities_mitigated_outside_sla))
```

Open findings currently breaching SLA, by severity:

```promql
sum by (severity) (dojo_vulnerabilities_sla_breached)
```

## Labels

- `product`: The name or identifier of the product associated with the vulnerabilities.
- `product_type`: The type of the product.
- `severity`: The severity level of the vulnerabilities, such as informational, low, medium, high, or critical.
- `cwe`: The Common Weakness Enumeration (CWE) identifier associated with the vulnerabilities.

The per-status metrics (including `dojo_vulnerabilities_sla_breached`) carry
all four labels. The SLA compliance and fix-time metrics
(`dojo_vulnerabilities_mitigated_within_sla`, `dojo_vulnerabilities_mitigated_outside_sla`,
`dojo_vulnerabilities_fix_time_days_sum`, `dojo_vulnerabilities_fix_time_days_count`)
carry `product`, `product_type` and `severity` only, to keep their cardinality low.

## Configuration

The exporter supports configuration parameters via command-line flags. Additionally, if run with the flag `-envflag.enable=true`, any unset command-line flag will automatically fallback to the corresponding environment variable with the same name.

For example, if `-DD_TOKEN` is not provided, the exporter will look for the environment variable `DD_TOKEN`.

Available flags:
```
-DD_TOKEN string
      API token used for authenticating requests to DefectDojo
-DD_URL string
      Base URL of the DefectDojo API (e.g. https://defectdojo.example.com)
-DD_USERNAME string
      DefectDojo username used to obtain an API token when DD_TOKEN is not set
-DD_PASSWORD string
      DefectDojo password used to obtain an API token when DD_TOKEN is not set
-concurrency int
      Maximum number of concurrent API requests to DefectDojo (default 5)
-envflag.enable
      Whether to enable reading flags from environment variables in addition to the command line. Command line flag values have priority over values from environment vars. Flags are read only from the command line if this flag isn't set. See https://docs.victoriametrics.com/victoriametrics/single-server-victoriametrics/#environment-variables for more details
-envflag.prefix string
      Prefix for environment variables if -envflag.enable is set
-interval duration
      Sleep interval duration between metric collection cycles (default 5m0s)
-timeout duration
      API request timeout (default 30s)
-port int
      Port number where the exporter HTTP server will listen (default 8080)
-use-engagement-update-check
      Skip collection if no engagement updates, need disable if vulnerabilities aren't added via engagement (default true)
-version
      Show DefectDojo Exporter version
```

When `DD_TOKEN` is empty and `DD_USERNAME`/`DD_PASSWORD` are set, the exporter
obtains its own API token from `/api/v2/api-token-auth/`, retrying until
DefectDojo is reachable (useful when both start together, e.g. under Docker
Compose). Invalid credentials are a fatal error.

Note that DefectDojo answers HTTP 403 (`{"detail":"Invalid token."}`) — not
401 — when it doesn't recognize the token, e.g. a stale `DD_TOKEN` or a
DefectDojo database that was re-initialized while the exporter kept running.
As long as `DD_USERNAME`/`DD_PASSWORD` are set the exporter recovers on its
own by fetching a fresh token; with only a static `DD_TOKEN` the 403 (with the
response body) is logged so the token can be replaced.

Note: SLA deadlines can pass and findings can be mitigated without any
engagement being updated. If you rely on the SLA metrics, run with
`-use-engagement-update-check=false` so every collection cycle refreshes them.

## Running

Run the exporter with environment variable fallback enabled:

```bash
export DD_URL=https://defectdojo.com
export DD_TOKEN=your_token
./defectdojo-exporter-linux-amd64 --envflag.enable=true --port=9002
```

## Running with Docker Compose (DefectDojo included)

`docker-compose.yml` in this repository deploys DefectDojo (using the official
images) together with the exporter:

```bash
docker compose up -d
# DefectDojo UI:    http://localhost:8080  (admin / Def3ctDojo@Exporter!)
# Exporter metrics: http://localhost:9100/metrics
```

An optional testing overlay, `docker-compose.test.yml`, seeds DefectDojo with
deterministic findings and verifies the exporter's metrics end to end. It is
kept separate from the base compose file, which is fully usable without it:

```bash
docker compose -f docker-compose.yml -f docker-compose.test.yml up -d
docker compose -f docker-compose.yml -f docker-compose.test.yml run --rm testapp
```

See [docs/compose.md](docs/compose.md) for details.
