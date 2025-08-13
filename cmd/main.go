package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	_ "go.uber.org/automaxprocs"

	"github.com/VictoriaMetrics/VictoriaMetrics/lib/envflag"
	"github.com/iamhalje/defectdojo-exporter/lib/buildinfo"
	"github.com/iamhalje/defectdojo-exporter/lib/collector"
	"github.com/iamhalje/defectdojo-exporter/lib/defectdojo"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	ddURL               = flag.String("DD_URL", "", "Base URL of the DefectDojo API (e.g. https://defectdojo.example.com)")
	ddToken             = flag.String("DD_TOKEN", "", "API token used for authenticating requests to DefectDojo")
	port                = flag.Int("port", 8080, "Port number where the exporter HTTP server will listen")
	concurrency         = flag.Int("concurrency", 5, "Maximum number of concurrent API requests to DefectDojo")
	interval            = flag.Duration("interval", 5*time.Minute, "Sleep interval duration between metric collection cycles")
	timeout             = flag.Duration("timeout", 30*time.Second, "API request timeout")
	useEngagementUpdate = flag.Bool("use-engagement-update-check", true, "Skip collection if no engagement updates; disable if vulnerabilities aren't added via engagement")
)

func main() {
	envflag.Parse()
	buildinfo.Init()

	if *ddURL == "" || *ddToken == "" {
		log.Fatalf("Both DD_URL and DD_TOKEN must be set")
	}

	prometheus.MustRegister(defectdojo.VulnActiveGauge)
	prometheus.MustRegister(defectdojo.VulnDuplicateGauge)
	prometheus.MustRegister(defectdojo.VulnUnderReviewGauge)
	prometheus.MustRegister(defectdojo.VulnFalsePositiveGauge)
	prometheus.MustRegister(defectdojo.VulnOutOfScopeGauge)
	prometheus.MustRegister(defectdojo.VulnRiskAcceptedGauge)
	prometheus.MustRegister(defectdojo.VulnVerifiedGauge)
	prometheus.MustRegister(defectdojo.VulnMitigatedGauge)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go collector.CollectMetrics(*ddURL, *ddToken, *concurrency, *interval, *timeout, *useEngagementUpdate)

	mux := http.NewServeMux()
	registerHandlers(mux)

	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", *port),
		Handler:           mux,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		log.Printf("Starting Exporter on :%d", *port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Problem starting Exporter: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("Shutdown signal received")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("Exporter shutdown error: %v", err)
	} else {
		log.Println("Exporter stopped gracefully")
	}
}

func registerHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, err := fmt.Fprint(w, "<h2>DefectDojo Exporter</h2>")
		if err != nil {
			log.Fatalf("Error writing response: %v", err)
		}
		_, err = fmt.Fprintf(w, "<p><a href='/metrics'>/metrics</a> -  available service metrics</p>")
		if err != nil {
			log.Fatalf("Error writing reponse: %v", err)
		}
	})

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("ok")); err != nil {
			log.Printf("error writing /healthz response: %v", err)
		}
	})

	mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("ok")); err != nil {
			log.Printf("error writing /ready response: %v", err)
		}
	})

	mux.Handle("/metrics", promhttp.Handler())
}
