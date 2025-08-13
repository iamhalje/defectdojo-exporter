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

## Labels

- `product`: The name or identifier of the product associated with the vulnerabilities.
- `product_type`: The type of the product.
- `severity`: The severity level of the vulnerabilities, such as informational, low, medium, high, or critical.
- `cwe`: The Common Weakness Enumeration (CWE) identifier associated with the vulnerabilities.

## Configuration

The exporter supports configuration parameters via command-line flags. Additionally, if run with the flag `-envflag.enable=true`, any unset command-line flag will automatically fallback to the corresponding environment variable with the same name.

For example, if `-DD_TOKEN` is not provided, the exporter will look for the environment variable `DD_TOKEN`.

Available flags:
```
-DD_TOKEN string
      API token used for authenticating requests to DefectDojo
-DD_URL string
      Base URL of the DefectDojo API (e.g. https://defectdojo.example.com)
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
      Skip collection if no engagement updates; disable if vulnerabilities aren't added via engagement (default true)
-version
      Show DefectDojo Exporter version
```

## Running

Run the exporter with environment variable fallback enabled:

```bash
export DD_URL=https://defectdojo.com
export DD_TOKEN=your_token
./defectdojo-exporter-linux-amd64 --envflag.enable=true --port=9002
```

## Quick start

- Download a release binary or build locally:
  - Build locally: `make build` (outputs `bin/defectdojo-exporter-pure`)
  - Cross-compile: `make crossbuild` or `make docker-crossbuild`
- Run with environment variables as shown above.

## Docker

```bash
docker run --rm -p 9002:9002 \
  -e DD_URL=https://defectdojo.example.com \
  -e DD_TOKEN=your_token \
  halje/defectdojo-exporter:latest \
  --envflag.enable=true --port=9002
```

## Kubernetes scrape config (Prometheus)

```yaml
scrape_configs:
  - job_name: defectdojo-exporter
    metrics_path: /metrics
    static_configs:
      - targets: ["defectdojo-exporter.default.svc:8080"]
```

## HTTP endpoints

- `/metrics`: Prometheus metrics
- `/healthz`: liveness probe (200 OK)
- `/ready`: readiness probe (200 OK)
- `/`: small HTML index page

## Performance tuning

- `-concurrency`: Max concurrent DefectDojo API requests. Increase for many products; avoid overloading your Dojo.
- `-interval`: Collection cadence. Lower means higher load; now paced using a ticker to reduce drift.
- `-timeout`: Per-request timeout to the API.
- `-use-engagement-update-check`: When true (default), skip products whose engagements haven't changed since last run.

## Configuration via environment variables

- Enable with `--envflag.enable=true`. Each CLI flag falls back to an env var with the same name (e.g., `DD_URL`, `DD_TOKEN`).
- Optional `--envflag.prefix=YOURPREFIX_` to require a prefix for env vars (e.g., `YOURPREFIX_DD_URL`).

## Helm and dashboards

- Helm chart: see `helm/` for deployment templates.
- Dashboards: see `dashboards/` for example Grafana dashboards.

## Build from source

- Tests: `make tests`
- Formatting: `make fmt`
- Lint: `make golangci-lint`
- Security: `make govulncheck`
- All checks: `make check-all`

## Version

```bash
./defectdojo-exporter-linux-amd64 --version
```

## Security notes

- Use HTTPS for `DD_URL`.
- Store `DD_TOKEN` securely (e.g., Kubernetes Secret).
- The exporter only reads data and exposes aggregated metrics; ensure network policies restrict access to `/metrics` as appropriate.

## License

See `LICENSE`.
