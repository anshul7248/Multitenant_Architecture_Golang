package main

import (
	"net/http"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type User struct {
	ID        uint   `gorm:"primaryKey" json:"id"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	Password  string `json:"password"`
	Role      string `json:"role"`
	CreatedAt string `json:"created_at"`
}
type JwtCustomClaims struct {
	UserID uint   `json:"user_id"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

var (
	db        *gorm.DB
	jwtSecret = "nwdfijenijer3459349jeifj"
)

func initDB() {
	dsn := "host=localhost user=postgres password=1234 dbname=tokendb port=5432 sslmode=disable"
	var err error
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		panic("Failed to connect database")
	}
	db.AutoMigrate(&User{})
}

// Handler functions
func register(c echo.Context) error {
	type Input struct {
		Name     string `json:"name"`
		Email    string `json:"email"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	var input Input
	if err := c.Bind(&input); err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{"error": err.Error()})
	}
	user := User{
		Name:     input.Name,
		Email:    input.Email,
		Password: input.Password,
		Role:     input.Role,
	}
	if err := db.Create(&user).Error; err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{"error": err.Error()})

	}
	return c.JSON(http.StatusOK, user)
}
func login(c echo.Context) error {
	type Input struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	var input Input
	if err := c.Bind(&input); err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{"error": err.Error()})
	}
	var u User
	if err := db.Where("email=?", input.Email).First(&u).Error; err != nil {
		return c.JSON(http.StatusUnauthorized, echo.Map{"error": "Email doesn't exists"})
	}
	if u.Password != input.Password {
		return c.JSON(http.StatusUnauthorized, echo.Map{"error": "Password doesn't exists"})
	}
	claims := JwtCustomClaims{
		UserID: u.ID,
		Role:   u.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	t, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, echo.Map{"Token": t})
}
func adminDashboard(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*JwtCustomClaims)

	if claims.Role != "admin" {
		return echo.NewHTTPError(http.StatusForbidden, "Admin can access it only")
	}
	return c.JSON(http.StatusOK, echo.Map{"message": "Welcome to Admin Dashboard", "user_id": claims.UserID})
}
func tenantDashboard(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*JwtCustomClaims)

	if claims.Role != "tenant" {
		return echo.NewHTTPError(http.StatusForbidden, "Tenant can access it only")
	}
	return c.JSON(http.StatusOK, echo.Map{"message": "Welcome to Tenant Dashboard", "user_id": claims.UserID})
}
func userDashboard(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*JwtCustomClaims)

	if claims.Role != "user" {
		return echo.NewHTTPError(http.StatusForbidden, "User can access it only")
	}
	return c.JSON(http.StatusOK, echo.Map{"message": "Welcome to User Dashboard", "user_id": claims.UserID})
}
func main() {
	initDB()
	e := echo.New()
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	e.POST("/register", register)
	e.POST("/login", login)

	config := echojwt.Config{
		SigningKey: []byte(jwtSecret),
		NewClaimsFunc: func(c echo.Context) jwt.Claims {
			return new(JwtCustomClaims)
		},
	}
	r := e.Group("/api")
	r.Use(echojwt.WithConfig(config))
	r.POST("/admin", adminDashboard)
	r.POST("/tenant", tenantDashboard)
	r.POST("/user", userDashboard)

	e.Logger.Fatal(e.Start(":8080"))
}
