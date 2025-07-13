package zensegur

import (
	"context"

	"cloud.google.com/go/firestore"
)

type Client struct {
	firestore *firestore.Client
	ctx       context.Context
	tenant    string
	headers   map[string]string
}

func NewClient(ctx context.Context, projectID string) (*Client, error) {
	client, err := firestore.NewClient(ctx, projectID)
	if err != nil {
		return nil, err
	}
	return &Client{
		firestore: client,
		ctx:       ctx,
		headers:   make(map[string]string),
	}, nil
}

func (c *Client) WithTenant(tenant string) *Client {
	c.tenant = tenant
	return c
}

func (c *Client) WithHeader(key, value string) *Client {
	c.headers[key] = value
	return c
}

func (c *Client) Repository(collection string) *Repository {
	if c.tenant != "" && c.tenant != "default" {
		collection = c.tenant + "_" + collection
	}
	return NewRepository(c.firestore, collection)
}

func (c *Client) Close() error {
	return c.firestore.Close()
}