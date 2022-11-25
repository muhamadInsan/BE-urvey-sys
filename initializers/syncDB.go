package initializers

import "survey-go/models"

func SyncDB() {
	DB.AutoMigrate(&models.User{})
}
