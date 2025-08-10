package zensframework

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/bsonrw"
)

const (
	XTENANTID      string = "X-Tenant-Id"
	TTENANTID      string = "tenant_id"
	XAUTHOR        string = "X-Author"
	XAUTHORID      string = "X-Author-Id"
	XCORRELATIONID string = "X-Correlation-Id"
	XCREATEDAT     string = "X-CreatedAt"
)

func helperContext(c context.Context, filter map[string]interface{}, addfilter map[string]string) {
	switch c := c.(type) {
	case *gin.Context:
		for k, v := range addfilter {
			value := string(c.Request.Header.Get(v))
			if value != "" {
				filter[k] = value
			}
		}
	case *PubSubContext: // Google Pub/Sub consumer
		for k, v := range addfilter {
			if value, ok := c.Msg.Attributes[v]; ok {
				filter[k] = value
			}
		}
	default:
		for k, v := range addfilter {
			value := fmt.Sprint(c.Value(v))
			if value != "" {
				filter[k] = value
				break
			}
		}
	}
}

func GetContextHeader(c context.Context, keys ...string) string {

	for _, key := range keys {
		switch c := c.(type) {
		case *gin.Context:
			if sid := c.Request.Header.Get(key); sid != "" {
				return sid
			}

		case *PubSubContext: // Google Pub/Sub consumer
			if value, ok := c.Msg.Attributes[key]; ok && value != "" {
				return value
			}
		default:
			return fmt.Sprint(c.Value(key))
		}
	}

	return ""
}

func getContext(c context.Context) context.Context {

	switch c := c.(type) {
	case *gin.Context:
		return c.Request.Context()
	default:
		return c
	}
}

type kHeader struct {
	keys map[string]string
}

// For Google Pub/Sub support
func (kh *kHeader) ToPubSubAttributes() map[string]string {
	return kh.keys
}

func (kh *kHeader) GetString(key string) string {
	if v, ok := kh.keys[key]; ok {
		return v
	}
	return ""
}

func (kh *kHeader) GetUuid(key string) uuid.UUID {
	if v, ok := kh.keys[key]; ok {
		if id, err := uuid.Parse(v); err == nil {
			return id
		}
	}
	return uuid.New()
}

func helperContextHeaders(c context.Context, addfilter []string) *kHeader {

	filter := &kHeader{keys: map[string]string{}}
	switch c := c.(type) {
	case *gin.Context:
		for _, k := range addfilter {
			value := c.Request.Header.Get(k)
			if value == "" {
				switch k {
				case XCORRELATIONID:
					value := uuid.NewString()
					c.Request.Header.Add(XCORRELATIONID, value)
				case XCREATEDAT:
					value := time.Now().Format(time.RFC3339)
					c.Request.Header.Add(XCREATEDAT, value)
				}
			}
			filter.keys[k] = value
		}
	case *PubSubContext: // Google Pub/Sub consumer
		for _, k := range addfilter {
			if value, ok := c.Msg.Attributes[k]; ok {
				filter.keys[k] = value
			} else {
				switch k {
				case XCORRELATIONID:
					filter.keys[k] = uuid.NewString()
				case XCREATEDAT:
					filter.keys[k] = time.Now().Format(time.RFC3339)
				}
			}
		}
	default:
		for _, k := range addfilter {
			value := fmt.Sprint(c.Value(k))
			if value == "" {
				switch k {
				case XCORRELATIONID:
					value := uuid.NewString()
					c = context.WithValue(c, k, value)
				case XCREATEDAT:
					value := time.Now().Format(time.RFC3339)
					c = context.WithValue(c, k, value)
				}
			}
			filter.keys[k] = value
		}
	}

	return filter
}

func ToContext(c context.Context) context.Context {
	listContext := []string{XTENANTID, XAUTHOR, XAUTHORID, XCORRELATIONID, TTENANTID, XCREATEDAT}

	cc := context.Background()
	switch c := c.(type) {
	case *gin.Context:
		for _, v := range listContext {
			cc = context.WithValue(cc, v, c.Request.Header.Get(v))
		}
	case *PubSubContext: // Google Pub/Sub consumer
		for _, v := range listContext {
			if value, ok := c.Msg.Attributes[v]; ok {
				cc = context.WithValue(cc, v, value)
			}
		}
	default:
		for _, v := range listContext {
			cc = context.WithValue(cc, v, fmt.Sprint(c.Value(v)))
		}
	}
	return cc
}

func GetTenantByToken(ctx *gin.Context) (uuid.UUID, error) {
	tokenString := ctx.GetHeader("Authorization")

	tokenString = strings.Replace(tokenString, "Bearer ", "", 1)
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return uuid.Nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		tenant := fmt.Sprint(claims[TTENANTID])
		if tenant == "" {
			return uuid.Nil, fmt.Errorf("Tenant not found")
		}
		id, err := uuid.Parse(tenant)
		if err != nil {
			return uuid.Nil, fmt.Errorf("Tenant not found")
		}

		return id, nil
	} else {
		return uuid.Nil, fmt.Errorf("Tenant not found")
	}
}

func MarshalWithRegistry(val interface{}) ([]byte, error) {
	buf := bytes.NewBuffer([]byte{})
	vw, err := bsonrw.NewBSONValueWriter(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to create BSON value writer: %w", err)
	}

	enc, err := bson.NewEncoder(vw)
	if err != nil {
		return nil, fmt.Errorf("failed to create BSON encoder: %w", err)
	}

	enc.SetRegistry(MongoRegistry)

	if err := enc.Encode(val); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func UnmarshalWithRegistry(data []byte, val interface{}) error {
	dec, err := bson.NewDecoder(bsonrw.NewBSONDocumentReader(data))
	if err != nil {
		return fmt.Errorf("failed to create BSON decoder: %w", err)
	}
	dec.SetRegistry(MongoRegistry)

	return dec.Decode(val)
}
