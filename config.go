package zensegur

import (
	"log"
	"os"
	"strconv"
	"time"
)

func getEnv(key string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	log.Fatalf("variável de ambiente %s não definida", key)
	return ""
}

func getJWTSecret() []byte {
	return []byte(getEnv("JWT_SECRET"))
}

func getJWTExpiration() time.Duration {
	minutes, _ := strconv.Atoi(getEnv("JWT_EXPIRATION_MINS"))
	return time.Duration(minutes) * time.Minute
}

func getMongoURI() string {
	return getEnv("MONGO_URI")
}

func getMongoDatabase() string {
	return getEnv("MONGO_DATABASE")
}
