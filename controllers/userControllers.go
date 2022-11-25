package controllers

import (
	"net/http"
	"os"
	"survey-go/initializers"
	"survey-go/models"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
)

func Signup(c *gin.Context) {
	// get email/pass off req body
	// var user models.User
	var body struct {
		Username string
		Email    string
		Password string
	}

	if c.BindJSON(&body) != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"msg": "Failed to read req body!",
		})
	}

	// hash password
	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), 10)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "Failed to hash password!",
		})

		return
	}

	// create user
	user := models.User{Username: body.Username, Email: body.Email, Password: string(hash)}
	result := initializers.DB.Create(&user)
	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "Failed to create user!",
		})

		return
	}

	// response
	c.JSON(http.StatusOK, gin.H{"msg": "User created!"})
}

func Login(c *gin.Context) {
	// get email/pass
	var body struct {
		// Username string
		Email    string
		Password string
	}

	if c.BindJSON(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "Failed to read req body!",
		})
	}

	// look up requested user
	var user models.User
	initializers.DB.First(&user, "email = ?", body.Email)

	if user.ID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "Invalid email or password!",
		})
		return
	}

	// compare pswd with save user pswd hash
	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "Invalid email or password!",
		})
		return
	}

	// generate jwt token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID,
		"exp": time.Now().Add(time.Hour * 24 * 30).Unix(),
	})

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString([]byte(os.Getenv("SECRET")))

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "Created token failed!",
		})
		return
	}

	// sent token
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("Authorization", tokenString, 3600*24*1, "", "", false, true)
	c.JSON(http.StatusOK, gin.H{
		"msg": "Login success!",
	})
}

func Validate(c *gin.Context) {
	user, _ := c.Get("user")
	c.JSON(http.StatusOK, gin.H{
		"msg": user,
	})
}

func Logout(c *gin.Context) {
	c.SetCookie("Authorization", "", 0, "", "", true, false)
	c.JSON(http.StatusOK, gin.H{
		"msg": "Logout success!",
	})
}

func DeleteUser(c *gin.Context) {
	id := c.Param("id")
	var user models.User
	c.Bind(user)

	initializers.DB.Delete(&user, id)
	c.JSON(http.StatusOK, gin.H{
		"msg": "Delete user success",
	})
}
