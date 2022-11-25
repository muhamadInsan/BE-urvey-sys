package main

import (
	"survey-go/controllers"
	"survey-go/initializers"
	"survey-go/middlewere"

	"github.com/gin-gonic/gin"
)

func init() {
	initializers.LoadEnv()
	initializers.ConnectDB()
	initializers.SyncDB()
}

func main() {
	r := gin.Default()

	r.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"msg": "pong",
		})
	})

	r.POST("/signup", controllers.Signup)
	r.POST("/login", controllers.Login)
	r.GET("/logout", controllers.Logout)
	r.GET("/validate", middlewere.RequireAuth, controllers.Validate)
	r.DELETE("/user/:id", middlewere.RequireAuth, controllers.DeleteUser)

	r.Run()
}
