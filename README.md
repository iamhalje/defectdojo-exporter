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

## Lables

- `product`: The name or identifier of the product associated with the vulnerabilities.
- `severity`: The severity level of the vulnerabilities, such as informational, low, medium, high, or critical.
- `cwe`: The Common Weakness Enumeration (CWE) identifier associated with the vulnerabilities.

## Configuration

The application uses a configuration file, config.yaml, which provides necessary details for connecting to DefectDojo and configuring the HTTP server. You can specify the path to the configuration file using the --config flag.

```yaml
# API token used to authenticate with DefectDojo
DD_TOKEN: "kyead0535e212ae08d1d8287085dcccef1af53le"

# URL of the DefectDojo instance to collect metrics from
DD_URL: "https://defectdojo.com"

# Port number for exposing the metrics endpoint
PORT: 8080
```

## Running

By default, the application looks for config.yaml in the current directory if the --config flag is not provided.

```bash
./defectdojo-exporter --config dd-exporter.yaml
```
