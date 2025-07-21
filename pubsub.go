package zensframework

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"cloud.google.com/go/pubsub"
	"github.com/google/uuid"
	"google.golang.org/api/option"
)

type (
	// PubSubMessage represents a message from Google Pub/Sub
	PubSubMessage struct {
		Data        []byte
		Attributes  map[string]string
		ID          string
		PublishTime time.Time
	}

	// PubSubContext is the context for handling Pub/Sub messages
	PubSubContext struct {
		context.Context
		RemainingRetries uint16
		Faulted          bool
		Msg              *PubSubMessage
	}

	// PubSubConsumerFunc is a function that processes a Pub/Sub message
	PubSubConsumerFunc func(ctx *PubSubContext)

	// PubSubConsumer is the interface for consuming Pub/Sub messages
	PubSubConsumer interface {
		HandleFn()
		Close() error
	}

	// PubSubProducer is the interface for producing Pub/Sub messages
	PubSubProducer[T interface{}] interface {
		Publish(ctx context.Context, msgs ...*T) error
		PublishWithAttributes(ctx context.Context, attributes map[string]string, msgs ...*T) error
		Close() error
	}

	// pubSubConsumerImpl implements the PubSubConsumer interface
	pubSubConsumerImpl struct {
		client        *pubsub.Client
		subscription  *pubsub.Subscription
		consumerFunc  PubSubConsumerFunc
		subscriptionID string
		projectID     string
	}

	// pubSubProducerImpl implements the PubSubProducer interface
	pubSubProducerImpl[T interface{}] struct {
		client    *pubsub.Client
		topic     *pubsub.Topic
		topicName string
		projectID string
	}
)

// NewPubSubConsumer creates a new Pub/Sub consumer
func NewPubSubConsumer(
	ctx context.Context,
	projectID string,
	subscriptionID string,
	consumerFunc PubSubConsumerFunc,
	opts ...option.ClientOption,
) (PubSubConsumer, error) {
	client, err := pubsub.NewClient(ctx, projectID, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create pubsub client: %v", err)
	}

	subscription := client.Subscription(subscriptionID)
	exists, err := subscription.Exists(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to check if subscription exists: %v", err)
	}

	if !exists {
		return nil, fmt.Errorf("subscription %s does not exist", subscriptionID)
	}

	// Configure subscription to wait for at least 1 message and wait at most 10 seconds
	subscription.ReceiveSettings.MaxOutstandingMessages = 10
	subscription.ReceiveSettings.MaxOutstandingBytes = 1e9 // 1GB

	return &pubSubConsumerImpl{
		client:        client,
		subscription:  subscription,
		consumerFunc:  consumerFunc,
		subscriptionID: subscriptionID,
		projectID:     projectID,
	}, nil
}

// HandleFn starts consuming messages from the subscription
func (c *pubSubConsumerImpl) HandleFn() {
	ctx := context.Background()
	err := c.subscription.Receive(ctx, func(ctx context.Context, msg *pubsub.Message) {
		pubsubMsg := &PubSubMessage{
			Data:        msg.Data,
			Attributes:  msg.Attributes,
			ID:          msg.ID,
			PublishTime: msg.PublishTime,
		}

		pubsubCtx := &PubSubContext{
			Context:          ctx,
			RemainingRetries: 3, // Default retries
			Faulted:          false,
			Msg:              pubsubMsg,
		}

		// Process the message
		c.consumerFunc(pubsubCtx)

		// Acknowledge the message unless it's faulted
		if !pubsubCtx.Faulted {
			msg.Ack()
		} else {
			msg.Nack()
		}
	})

	if err != nil {
		fmt.Printf("Error receiving messages: %v\n", err)
	}
}

// Close closes the consumer client
func (c *pubSubConsumerImpl) Close() error {
	return c.client.Close()
}

// NewPubSubProducer creates a new Pub/Sub producer
func NewPubSubProducer[T interface{}](
	ctx context.Context,
	projectID string,
	topicName string,
	opts ...option.ClientOption,
) (PubSubProducer[T], error) {
	client, err := pubsub.NewClient(ctx, projectID, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create pubsub client: %v", err)
	}

	topic := client.Topic(topicName)
	exists, err := topic.Exists(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to check if topic exists: %v", err)
	}

	if !exists {
		return nil, fmt.Errorf("topic %s does not exist", topicName)
	}

	// Configure batching
	topic.PublishSettings.ByteThreshold = 5000
	topic.PublishSettings.CountThreshold = 10
	topic.PublishSettings.DelayThreshold = 100 * time.Millisecond

	return &pubSubProducerImpl[T]{
		client:    client,
		topic:     topic,
		topicName: topicName,
		projectID: projectID,
	}, nil
}

// Publish publishes messages to the topic
func (p *pubSubProducerImpl[T]) Publish(ctx context.Context, msgs ...*T) error {
	return p.PublishWithAttributes(ctx, nil, msgs...)
}

// PublishWithAttributes publishes messages with attributes to the topic
func (p *pubSubProducerImpl[T]) PublishWithAttributes(ctx context.Context, attributes map[string]string, msgs ...*T) error {
	if attributes == nil {
		attributes = make(map[string]string)
	}

	// Add standard headers if not present
	if _, ok := attributes[XCORRELATIONID]; !ok {
		attributes[XCORRELATIONID] = uuid.NewString()
	}
	if _, ok := attributes[XCREATEDAT]; !ok {
		attributes[XCREATEDAT] = time.Now().Format(time.RFC3339)
	}

	// Copy headers from context if available
	headers := []string{XTENANTID, XAUTHOR, XAUTHORID, TTENANTID}
	for _, header := range headers {
		if value := GetContextHeader(ctx, header); value != "" && attributes[header] == "" {
			attributes[header] = value
		}
	}

	var results []*pubsub.PublishResult

	for _, msg := range msgs {
		data, err := json.Marshal(msg)
		if err != nil {
			return fmt.Errorf("failed to marshal message: %v", err)
		}

		result := p.topic.Publish(ctx, &pubsub.Message{
			Data:       data,
			Attributes: attributes,
		})
		results = append(results, result)
	}

	// Wait for all messages to be published
	for _, result := range results {
		_, err := result.Get(ctx)
		if err != nil {
			return fmt.Errorf("failed to publish message: %v", err)
		}
	}

	return nil
}

// Close closes the producer client
func (p *pubSubProducerImpl[T]) Close() error {
	p.topic.Stop()
	return p.client.Close()
}

// PubSubContext implementation of context.Context interface
func (pc PubSubContext) Deadline() (deadline time.Time, ok bool) {
	return pc.Context.Deadline()
}

func (pc PubSubContext) Done() <-chan struct{} {
	return pc.Context.Done()
}

func (pc PubSubContext) Err() error {
	return pc.Context.Err()
}

func (pc PubSubContext) Value(key any) any {
	return pc.Context.Value(key)
}