package zensframework

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/viper"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	TracingTypeControler  = "controller"
	TracingTypeConsumer   = "consumer"
	TracingTypeProducer   = "producer"
	TracingTypeRepository = "repository"
)

type (
	TracingType string

	Tracing struct {
		CreatedAt     time.Time   `bson:"createdat" json:"createdat"`
		CorrelationId uuid.UUID   `bson:"correlationid" json:"correlationid"`
		Source        string      `bson:"source" json:"source"`
		Stack         []Stack     `bson:"stack" json:"stack"`
		TracingType   TracingType `bson:"tracingtype" json:"tracingtype"`
		Content       interface{} `bson:"content" json:"content"`
	}

	TracingMonitor struct {
		Monitor *Monitoring
		Trace   *Tracing
	}

	Stack struct {
		Code int    `bson:"code" json:"code"`
		Msg  string `bson:"msg" json:"msg"`
	}

	Monitoring struct {
		repo    *mongo.Collection
		tracing bool
	}
)

func NewMonitoring(v *viper.Viper) *Monitoring {

	host := v.GetString("mongodb.connectionString")
	user := v.GetString("mongodb.user")
	pass := v.GetString("mongodb.pass")
	tracing := !v.GetBool("tracing")

	if host == "" {
		return &Monitoring{
			repo:    nil,
			tracing: false,
		}
	}

	opts := options.Client().ApplyURI(host)

	if user != "" {
		opts.SetAuth(options.Credential{Username: user, Password: pass})
	}
	cl, _ := mongo.Connect(context.Background(), opts.SetRegistry(MongoRegistry))
	db := cl.Database("monitoring")
	return &Monitoring{
		repo:    db.Collection("tracing"),
		tracing: tracing,
	}
}

func (m *Monitoring) Start(correlationid uuid.UUID,
	source string, tracingtype TracingType) *TracingMonitor {
	return &TracingMonitor{
		Monitor: m,
		Trace: &Tracing{
			CreatedAt:     time.Now(),
			CorrelationId: correlationid,
			TracingType:   tracingtype,
			Source:        source,
			Stack:         []Stack{},
		},
	}

}

func (m *TracingMonitor) End() {
	if m.Trace == nil {
		fmt.Println("Tracing not started")
	} else {
		if m.Monitor.tracing {
			if _, err := m.Monitor.repo.InsertOne(context.Background(), m.Trace); err != nil {
				fmt.Println("Monitor with error")
			}
		}
	}
}

func (t *TracingMonitor) AddStack(code int, msg string) {
	t.Trace.Stack = append(t.Trace.Stack, Stack{Code: code, Msg: msg})
}

func (t *TracingMonitor) AddContent(msg interface{}) {
	t.Trace.Content = msg
}
