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

Create a config.yaml file in the folder with the binary exporter to configure the following variables:

```yaml
DD_TOKEN: "12345678901234567890"
DD_URL: "https://defectdojo.com"
# port for running exporter
PORT: 8080
```

Once configured and running, the collector exposes the metrics at the /metrics endpoint.
