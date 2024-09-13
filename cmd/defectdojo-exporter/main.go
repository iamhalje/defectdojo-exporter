package main

import (
	"collector"
	"config"
	"defectdojo"
	"fmt"
	"log"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	// load config
	config := config.LoadConfig()

	// register metric
	prometheus.MustRegister(defectdojo.VulnActiveGauge)
	prometheus.MustRegister(defectdojo.VulnDuplicateGauge)
	prometheus.MustRegister(defectdojo.VulnUnderReviewGauge)
	prometheus.MustRegister(defectdojo.VulnFalsePositiveGauge)
	prometheus.MustRegister(defectdojo.VulnOutOfScopeGauge)
	prometheus.MustRegister(defectdojo.VulnRiskAcceptedGauge)
	prometheus.MustRegister(defectdojo.VulnVerifiedGauge)
	prometheus.MustRegister(defectdojo.VulnMitigatedGauge)

	// start exporter
	go collector.CollectMetrics(config.DD_URL, config.DD_TOKEN)

	http.Handle("/metrics", promhttp.Handler())
	log.Printf("Starting server on :%d", config.PORT)

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", config.PORT), nil))
}
