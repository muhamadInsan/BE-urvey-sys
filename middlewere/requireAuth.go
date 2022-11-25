package middlewere

import (
	"fmt"
	"net/http"
	"os"
	"survey-go/initializers"
	"survey-go/models"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

func RequireAuth(c *gin.Context) {
	// get the cookie
	tokenString, err := c.Cookie("Authorization")
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"msg": "Unauthorized",
		})
	}
	// Parse takes the token string and a function for looking up the key. The latter is especially
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return []byte(os.Getenv("SECRET")), nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {

		// cek exp cookie
		if float64(time.Now().Unix()) > claims["exp"].(float64) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"msg": "Unauthorized",
			})
		}
		// find user with match token
		var user models.User
		initializers.DB.First(&user, claims["sub"])

		if user.ID == 0 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"msg": "Unauthorized",
			})
		}

		// attach to req
		c.Set("user", user)

		// continue
		c.Next()
	} else {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"msg": "Unauthorized",
		})
	}
}
