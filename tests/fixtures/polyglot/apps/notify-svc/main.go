// Command notify-svc exposes a small internal HTTP API for enqueueing and
// listing tenant notifications. Part of the fixture estate: it must look
// production-plausible but is never compiled into a release.
package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"time"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	verifyKey, err := loadVerifyKey()
	if err != nil {
		logger.Error("auth key load failed", "err", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	store, err := NewStore(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		logger.Error("store init failed", "err", err)
		os.Exit(1)
	}
	defer store.Close()

	mux := http.NewServeMux()
	// Health probe is the only unauthenticated route.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.Handle("POST /v1/notifications", authMiddleware(verifyKey, http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			handleCreate(store, w, r)
		})))
	mux.Handle("GET /v1/notifications", authMiddleware(verifyKey, http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			handleList(store, w, r)
		})))

	server := &http.Server{
		Addr:              ":8080", // TLS terminates at the service mesh sidecar
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	logger.Info("notify-svc listening", "addr", server.Addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("server stopped", "err", err)
		os.Exit(1)
	}
}

func handleCreate(store *Store, w http.ResponseWriter, r *http.Request) {
	tenantID := tenantFrom(r.Context())
	var req CreateNotificationRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	if !req.Valid() {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing fields"})
		return
	}
	// Tenant comes from the verified token, never from the request body.
	id, err := store.InsertNotification(r.Context(), tenantID, req)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store failure"})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"id": id})
}

func handleList(store *Store, w http.ResponseWriter, r *http.Request) {
	tenantID := tenantFrom(r.Context())
	items, err := store.ListNotifications(r.Context(), tenantID, 100)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store failure"})
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
