package main

import (
    "os"
    "github.com/gin-gonic/gin"
)

func getEnv(key, fallback string) string {
    if value, ok := os.LookupEnv(key); ok {
        return value
    }
    return fallback
}

func main() {
    r := gin.Default()
    r.GET("/ping", func(c *gin.Context) {
        c.JSON(200, gin.H{"message": "pong"})
    })
    listen := getEnv("LISTEN", "0.0.0.0:8080")
    r.Run(listen)
}
