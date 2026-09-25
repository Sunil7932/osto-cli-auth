package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/Sunil7932/cli-login-2fa/internal/domain"
)

// EventRepository is the Postgres implementation of domain.EventRepository.
type EventRepository struct {
	repository
}

func NewEventRepository(db *sql.DB) *EventRepository {
	return &EventRepository{repository{db: db}}
}

func (r *EventRepository) Append(ctx context.Context, event domain.AuthEvent) error {
	const query = `
		INSERT INTO auth_events (user_id, username, event_type, detail, created_at)
		VALUES ($1, $2, $3, $4, $5)`

	if _, err := r.exec(ctx).ExecContext(ctx, query,
		event.UserID,
		event.Username,
		string(event.Type),
		event.Detail,
		event.CreatedAt,
	); err != nil {
		return fmt.Errorf("insert auth event: %w", err)
	}
	return nil
}

func (r *EventRepository) RecentForUser(ctx context.Context, userID int64, limit int) ([]domain.AuthEvent, error) {
	const query = `
		SELECT id, user_id, username, event_type, detail, created_at
		  FROM auth_events
		 WHERE user_id = $1
		 ORDER BY created_at DESC, id DESC
		 LIMIT $2`

	rows, err := r.exec(ctx).QueryContext(ctx, query, userID, limit)
	if err != nil {
		return nil, fmt.Errorf("select auth events: %w", err)
	}
	defer rows.Close()

	events := make([]domain.AuthEvent, 0, limit)
	for rows.Next() {
		var (
			event     domain.AuthEvent
			ownerID   sql.NullInt64
			eventType string
		)
		if err := rows.Scan(&event.ID, &ownerID, &event.Username, &eventType, &event.Detail, &event.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan auth event: %w", err)
		}
		if ownerID.Valid {
			id := ownerID.Int64
			event.UserID = &id
		}
		event.Type = domain.EventType(eventType)
		event.CreatedAt = event.CreatedAt.UTC()
		events = append(events, event)
	}
	return events, rows.Err()
}
