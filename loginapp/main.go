package main

import (
	"log"
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"

	"LOGINAPP/auth"
)

const (
	SessionName   = "secure-session"
	SessionSecret = "complex-secret-key-12345!" // In production, use environment variables
	SessionMaxAge = 3600
	Port          = ":8080"
)

var (
	validUsername     = "admin"
	validPasswordHash string
)

func main() {
	// Set a strong password that meets auth.go requirements
	password := "G3v!Xp@9qL$zR1m" // 16 characters with all required character types

	// Validate password strength
	isValid, errMsg := auth.IsStrongPassword(password)
	if !isValid {
		log.Fatal("Weak password:", errMsg)
	}

	// Hash and verify the password
	var err error
	validPasswordHash, err = auth.HashPassword(password)
	if err != nil {
		log.Fatal("Failed to hash password:", err)
	}
	
	// Verify hash works
	if err := bcrypt.CompareHashAndPassword([]byte(validPasswordHash), []byte(password)); err != nil {
		log.Fatal("Password hash verification failed:", err)
	}

	router := gin.Default()

	// Configure session store
	store := cookie.NewStore([]byte(SessionSecret))
	store.Options(sessions.Options{
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		MaxAge:   SessionMaxAge,
		SameSite: http.SameSiteStrictMode,
	})
	router.Use(sessions.Sessions(SessionName, store))

	// Load templates and static files
	router.LoadHTMLGlob("templates/*")
	router.Static("/static", "./static")

	// Security headers middleware
	router.Use(func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Content-Security-Policy", "default-src 'self'")
		c.Next()
	})

	// Routes
	router.GET("/", noCache(), loginHandler)
	router.GET("/login", noCache(), loginHandler)
	router.POST("/login", loginSubmitHandler)
	router.GET("/home", noCache(), authRequired, homeHandler)
	router.POST("/logout", authRequired, logoutHandler)

	// Start server
	if err := router.Run(Port); err != nil {
		log.Fatal("Server failed to start:", err)
	}
}

// Middleware: Authentication check
func authRequired(c *gin.Context) {
	session := sessions.Default(c)
	if user := session.Get("user"); user == nil {
		session.Options(sessions.Options{MaxAge: -1})
		session.Save()
		c.Redirect(http.StatusFound, "/login")
		c.Abort()
	}
}

// Middleware: Disable caching
func noCache() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-store, no-cache, must-revalidate, private")
		c.Header("Pragma", "no-cache")
		c.Header("Expires", "0")
		c.Next()
	}
}

// Login page handler
func loginHandler(c *gin.Context) {
	session := sessions.Default(c)
	if session.Get("user") != nil {
		c.Redirect(http.StatusFound, "/home")
		return
	}

	flashes := session.Flashes()
	session.Save()
	c.HTML(http.StatusOK, "login.html", gin.H{"error": flashes})
}

// Login submission handler
func loginSubmitHandler(c *gin.Context) {
	session := sessions.Default(c)
	username := c.PostForm("username")
	password := c.PostForm("password")

	if username != validUsername || !checkPassword(password) {
		session.AddFlash("Invalid credentials")
		session.Save()
		c.Redirect(http.StatusFound, "/login")
		return
	}

	session.Set("user", username)
	if err := session.Save(); err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}

	c.Redirect(http.StatusFound, "/home")
}

// Password verification
func checkPassword(inputPassword string) bool {
	return bcrypt.CompareHashAndPassword([]byte(validPasswordHash), []byte(inputPassword)) == nil
}

// Home page handler
func homeHandler(c *gin.Context) {
	session := sessions.Default(c)
	user := session.Get("user").(string)
	c.HTML(http.StatusOK, "home.html", gin.H{"user": user})
}

// Logout handler
func logoutHandler(c *gin.Context) {
	session := sessions.Default(c)
	session.Clear()
	session.Options(sessions.Options{MaxAge: -1})
	session.Save()
	c.Redirect(http.StatusFound, "/login")
}






