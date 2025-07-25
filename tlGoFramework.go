package zensframework

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"cloud.google.com/go/pubsub"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/spf13/viper"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"go.uber.org/dig"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

type ZSFramework struct {
	ioc            *dig.Container
	configuration  *viper.Viper
	server         *gin.Engine
	agentTelemetry ZSfAgentTelemetry
	healthCheck    []func() (string, bool)
	corsConfig     *cors.Config
}

type ZSFrameworkOptions interface {
	run(zsf *ZSFramework)
}

func AddTenant(monitoring *Monitoring, v *viper.Viper) gin.HandlerFunc {
	return func(ctx *gin.Context) {

		correlation := uuid.New()
		if ctxCorrelation := GetContextHeader(ctx, XCORRELATIONID); ctxCorrelation != "" {
			if id, err := uuid.Parse(ctxCorrelation); err == nil {
				correlation = id
			}
		}
		ctx.Request.Header.Add(XCORRELATIONID, correlation.String())

		createdat := time.Now().Format(time.RFC3339)
		if ctxCreatedat := GetContextHeader(ctx, XCREATEDAT); ctxCreatedat != "" {
			createdat = ctxCreatedat
		}
		ctx.Request.Header.Add(XCREATEDAT, createdat)

		tokenString := ctx.GetHeader("Authorization")
		if tokenString == "" {
			ctx.Request.Header.Add(XTENANTID, "00000000-0000-0000-0000-000000000000")
			return
		}

		tokenString = strings.Replace(tokenString, "Bearer ", "", 1)
		token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
		if err != nil {
			ctx.AbortWithStatus(http.StatusUnauthorized)
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			if ctx.Request.Method == http.MethodPost || ctx.Request.Method == http.MethodPut || ctx.Request.Method == http.MethodDelete || ctx.Request.Method == http.MethodPatch {
				ctx.Request.Header.Add(XAUTHOR, fmt.Sprint(claims["name"]))
				ctx.Request.Header.Add(XAUTHORID, fmt.Sprint(claims["sub"]))
			}

			ctx.Request.Header.Add(XTENANTID, fmt.Sprint(claims[TTENANTID]))
		}

		sourcename := v.GetString("pubsub.projectid")
		if sourcename == "" {
			sourcename, _ = os.Hostname()
		}

		mt := monitoring.Start(correlation, sourcename, TracingTypeControler)
		mt.AddStack(100, ctx.FullPath())

		ctx.Next()

		mt.AddStack(100, fmt.Sprintf("RESULT: %d", ctx.Writer.Status()))

		mt.End()

	}
}

func NewZSFramework(opts ...ZSFrameworkOptions) *ZSFramework {
	location, err := time.LoadLocation("UTC")

	if err != nil {
		panic(err)
	}

	time.Local = location

	// Configuração CORS padrão
	corsConfig := cors.DefaultConfig()
	corsConfig.AllowOrigins = []string{"https://zensegur.com.br", "https://*.zensegur.com.br"}
	corsConfig.AllowHeaders = []string{"Content-Type", "Authorization", "X-Requested-With"}
	corsConfig.AllowCredentials = true

	zsf := &ZSFramework{
		ioc:           dig.New(),
		configuration: initializeViper(),
		server:        gin.Default(),
		healthCheck:   make([]func() (string, bool), 0),
		corsConfig:    &corsConfig,
	}

	corsconfig := cors.New(*zsf.corsConfig)

	for _, opt := range opts {
		opt.run(zsf)
	}

	zsf.ioc.Provide(initializeViper)
	zsf.ioc.Provide(NewMonitoring)
	zsf.ioc.Provide(newLog)
	zsf.ioc.Provide(func() ZSfAgentTelemetry { return zsf.agentTelemetry })

	zsf.ioc.Invoke(func(monitoring *Monitoring, v *viper.Viper) {
		zsf.server.Use(corsconfig, AddTenant(monitoring, v))
	})

	zsf.server.GET("/health", func(ctx *gin.Context) {

		list := make(map[string]bool)
		httpCode := http.StatusOK
		for _, item := range zsf.healthCheck {
			name, status := item()
			list[name] = status
			if !status {
				httpCode = http.StatusServiceUnavailable
			}
		}
		ctx.JSON(httpCode, list)
	})

	if zsf.agentTelemetry != nil {
		zsf.server.Use(zsf.agentTelemetry.gin())
	}
	err = zsf.ioc.Provide(func() *gin.RouterGroup { return zsf.server.Group("/") })
	if err != nil {
		log.Panic(err)
	}

	return zsf
}

// VIPER
func initializeViper() *viper.Viper {
	v := viper.New()
	v.AddConfigPath("./configs")
	v.SetConfigType("json")
	v.SetConfigName(os.Getenv("env"))
	if err := v.ReadInConfig(); err != nil {
		log.Panic(err)
	}
	return v
}

func (zsf *ZSFramework) GetConfig(key string) string {
	return zsf.configuration.GetString(key)
}

// DIG
func (zsf *ZSFramework) RegisterRepository(constructor interface{}) {
	err := zsf.ioc.Provide(constructor)
	if err != nil {
		log.Panic(err)
	}
}

func (zsf *ZSFramework) RegisterApplication(application interface{}) {
	err := zsf.ioc.Provide(application)
	if err != nil {
		log.Panic(err)
	}
}

// GIN
func (zsf *ZSFramework) RegisterController(controller interface{}) {
	err := zsf.ioc.Invoke(controller)
	if err != nil {
		log.Panic(err)
	}
}

func (zsf *ZSFramework) Start() error {
	port := os.Getenv("port")
	if port == "" {
		port = "8081"
	}
	return zsf.server.Run(":" + port)
}

func (zsf *ZSFramework) Invoke(function interface{}) {
	err := zsf.ioc.Invoke(function)
	if err != nil {
		log.Panic(err)
	}
}

// mongo
func (zsf *ZSFramework) RegisterDbMongo(host string, user string, pass string, database string, normalize bool) {

	opts := options.Client().ApplyURI(host)

	if user != "" {
		opts.SetAuth(options.Credential{Username: user, Password: pass})
	}

	if zsf.agentTelemetry != nil {
		opts = opts.SetMonitor(zsf.agentTelemetry.mongoMonitor())
	}

	err := zsf.ioc.Provide(func() *mongo.Database {
		cli, err := newMongoClient(opts, normalize)
		if err != nil {
			return nil
		}
		return cli.Database(database)
	})

	zsf.ioc.Provide(NewMongoTransaction)

	zsf.healthCheck = append(zsf.healthCheck, func() (string, bool) {
		serviceName := "MDB"
		cli, err := newMongoClient(opts, normalize)
		defer func() {
			if err = cli.Disconnect(context.TODO()); err != nil {
				panic(err)
			}
		}()

		if err != nil {
			return serviceName, false
		}

		if err := cli.Ping(context.Background(), readpref.Nearest()); err != nil {
			return serviceName, false
		}
		return serviceName, true
	})

	if err != nil {
		log.Panic(err)
	}
}

// Redis
func (zsf *ZSFramework) RegisterRedis(address string, password string, db string) {

	dbInt, err := strconv.Atoi(db)
	if err != nil {
		log.Panic(err)
	}

	opts := &redis.Options{
		Addr:     address,
		Password: password,
		DB:       dbInt,
	}

	if opts.Addr != "" && opts.Addr != "localhost:6379" {
		opts.TLSConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}

	zsf.healthCheck = append(zsf.healthCheck, func() (string, bool) {
		serviceName := "RDS"
		cli := newRedisClient(opts)
		if cli == nil {
			return serviceName, false
		}

		if _, err := cli.Ping(context.Background()).Result(); err != nil {
			return serviceName, false
		}
		return serviceName, true
	})

	err = zsf.ioc.Provide(func() *redis.Client { return (newRedisClient(opts)) })
	if err != nil {
		log.Panic(err)
	}
}

func (zsf *ZSFramework) RegisterCache(constructor interface{}) {
	err := zsf.ioc.Provide(constructor)
	if err != nil {
		log.Panic(err)
	}
}

// RegisterPubSub registers Google Pub/Sub client
func (zsf *ZSFramework) RegisterPubSub(projectID string, opts ...option.ClientOption) {
	err := zsf.ioc.Provide(func() (string, []option.ClientOption) {
		return projectID, opts
	})
	if err != nil {
		log.Panic(err)
	}

	// Add health check for PubSub
	zsf.healthCheck = append(zsf.healthCheck, func() (string, bool) {
		serviceName := "PUBSUB"
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Simple connectivity check
		client, err := pubsub.NewClient(ctx, projectID, opts...)
		if err != nil {
			return serviceName, false
		}
		defer client.Close()

		// If we can list topics, connection is working
		_, err = client.Topics(ctx).Next()
		if err != nil && err != iterator.Done {
			return serviceName, false
		}

		return serviceName, true
	})
}

// PubSub producer and consumer registration
func (zsf *ZSFramework) RegisterPubSubProducer(producer interface{}) {
	err := zsf.ioc.Provide(producer)
	if err != nil {
		log.Panic(err)
	}
}

func (zsf *ZSFramework) RegisterPubSubConsumer(consumer interface{}) {
	err := zsf.ioc.Invoke(consumer)
	if err != nil {
		log.Panic(err)
	}
}

// ConfigureCORS configures CORS settings
func (zsf *ZSFramework) ConfigureCORS(allowOrigins []string, allowCredentials bool) {
	if len(allowOrigins) > 0 {
		zsf.corsConfig.AllowOrigins = allowOrigins
	}
	zsf.corsConfig.AllowCredentials = allowCredentials
}

// CreateJWTMiddlewareConfig creates a configuration for JWT middleware
func (zsf *ZSFramework) CreateJWTMiddlewareConfig(publicPaths []string) *JWTMiddlewareConfig {
	return &JWTMiddlewareConfig{
		PublicPaths: publicPaths,
	}
}
