package zensframework

import (
	"context"
)

type (
	// Producer interface for publishing messages
	Producer[T interface{}] interface {
		Publish(ctx context.Context, msgs ...*T) error
		PublishWithAttributes(ctx context.Context, attributes map[string]string, msgs ...*T) error
		Close() error
	}
)
