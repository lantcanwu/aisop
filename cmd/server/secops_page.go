package main

import (
	"github.com/gin-gonic/gin"
)

func RegisterSecOpsPage(router *gin.Engine) {
	router.GET("/secops", func(c *gin.Context) {
		c.HTML(200, "secops.html", nil)
	})
}
