package main

import (
	"collector"
	"config"
	"defectdojo"
	"flag"
	"fmt"
	"log"
	"net/http"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	cfg  *config.Config
	once sync.Once
)

func init() {
	once.Do(func() {
		configPath := flag.String("config", "config.yaml", "Path to the config file")
		flag.Parse()

		var err error
		cfg, err = config.LoadConfig(*configPath)
		if err != nil {
			log.Fatalf("Error loading config: %v", err)
		}
	})
}

func main() {
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
	go collector.CollectMetrics(cfg.DD_URL, cfg.DD_TOKEN)

	http.Handle("/metrics", promhttp.Handler())
	log.Printf("Starting server on :%d", cfg.PORT)

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", cfg.PORT), nil))
}
