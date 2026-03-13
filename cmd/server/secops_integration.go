package main

import (
	secopshandler "cyberstrike-ai/internal/secops/handler"
	"github.com/gin-gonic/gin"
)

func RegisterSecOpsRoutes(router *gin.Engine, authMiddleware gin.HandlerFunc) {
	secOpsHandler := secopshandler.NewSecOpsHandler()

	api := router.Group("/api")
	protected := api.Group("")
	protected.Use(authMiddleware)

	secOpsHandler.RegisterRoutes(protected)
}
