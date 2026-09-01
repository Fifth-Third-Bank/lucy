package main

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store persists notifications in PostgreSQL. Every statement is
// parameterized via pgx placeholders; no SQL text is ever assembled
// from request data.
type Store struct {
	pool *pgxpool.Pool
}

// CreateNotificationRequest is the accepted write shape. TenantID is
// deliberately absent: it always comes from the verified token.
type CreateNotificationRequest struct {
	Channel  string `json:"channel"`
	Template string `json:"template"`
	Payload  string `json:"payload"`
}

// Valid applies minimal shape checks before any storage work happens.
func (r CreateNotificationRequest) Valid() bool {
	okChannel := r.Channel == "email" || r.Channel == "sms" || r.Channel == "push"
	return okChannel && r.Template != "" && len(r.Payload) <= 4096
}

// Notification is the read model returned by ListNotifications.
type Notification struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenantId"`
	Channel   string    `json:"channel"`
	Template  string    `json:"template"`
	CreatedAt time.Time `json:"createdAt"`
}

// NewStore connects with sslmode taken from DATABASE_URL, which the
// deployment sets to verify-full for the managed database endpoint.
func NewStore(ctx context.Context, databaseURL string) (*Store, error) {
	if databaseURL == "" {
		return nil, errors.New("DATABASE_URL is required")
	}
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, err
	}
	return &Store{pool: pool}, nil
}

// Close releases the underlying pool.
func (s *Store) Close() {
	s.pool.Close()
}

// InsertNotification writes one row and returns its generated id.
func (s *Store) InsertNotification(
	ctx context.Context, tenantID string, req CreateNotificationRequest,
) (string, error) {
	id := uuid.NewString()
	_, err := s.pool.Exec(ctx,
		`INSERT INTO notifications (id, tenant_id, channel, template, payload, created_at)
		 VALUES ($1, $2, $3, $4, $5, now())`,
		id, tenantID, req.Channel, req.Template, req.Payload)
	if err != nil {
		return "", err
	}
	return id, nil
}

// ListNotifications returns recent rows for one tenant only.
func (s *Store) ListNotifications(
	ctx context.Context, tenantID string, limit int,
) ([]Notification, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, tenant_id, channel, template, created_at
		   FROM notifications
		  WHERE tenant_id = $1
		  ORDER BY created_at DESC
		  LIMIT $2`,
		tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]Notification, 0, limit)
	for rows.Next() {
		var n Notification
		if err := rows.Scan(&n.ID, &n.TenantID, &n.Channel, &n.Template, &n.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, n)
	}
	return items, rows.Err()
}
