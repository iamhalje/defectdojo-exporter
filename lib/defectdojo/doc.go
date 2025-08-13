package defectdojo

// Package defectdojo contains the API models and helpers used to interact with
// DefectDojo and to expose Prometheus metrics for collected findings. It keeps
// shared state (e.g., previous metric values) required to zero-out vanished
// series across collection iterations.