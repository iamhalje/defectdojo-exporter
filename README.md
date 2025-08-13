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
