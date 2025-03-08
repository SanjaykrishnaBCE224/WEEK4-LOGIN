package auth

import (
    "strings"
    "unicode"
    "golang.org/x/crypto/bcrypt"
)

// Function to check password strength
func IsStrongPassword(password string) (bool, string) {
    runes := []rune(password)
    if len(runes) < 12 {
        return false, "Password must be at least 12 characters long"
    }

    var hasUpper, hasLower, hasNumber, hasSpecial bool
    specialChars := "!@#$%^&*()_+-=[]{}|;:',./<>?\"~`\\ "

    for _, char := range password {
        switch {
        case unicode.IsUpper(char):
            hasUpper = true
        case unicode.IsLower(char):
            hasLower = true
        case unicode.IsNumber(char):
            hasNumber = true
        case strings.ContainsRune(specialChars, char):
            hasSpecial = true
        }
    }

    var errorMsg strings.Builder
    if !hasUpper {
        errorMsg.WriteString("Requires at least one uppercase letter. ")
    }
    if !hasLower {
        errorMsg.WriteString("Requires at least one lowercase letter. ")
    }
    if !hasNumber {
        errorMsg.WriteString("Requires at least one number. ")
    }
    if !hasSpecial {
        errorMsg.WriteString("Requires at least one special character. ")
    }

    commonPatterns := []string{
        "123", "abc", "qwerty", "password", "admin", "welcome",
        "letmein", "111111", "sunshine", "iloveyou", "monkey",
    }
    lowerPass := strings.ToLower(password)
    for _, pattern := range commonPatterns {
        if strings.Contains(lowerPass, pattern) {
            errorMsg.WriteString("Password contains a common weak pattern. ")
            break
        }
    }

    // Check for sequential characters using runes
    for i := 0; i < len(runes)-2; i++ {
        current := runes[i]
        next1 := runes[i+1]
        next2 := runes[i+2]
        if (current+1 == next1 && next1+1 == next2) ||
            (current-1 == next1 && next1-1 == next2) {
            errorMsg.WriteString("Password contains sequential characters. ")
            break
        }
    }

    if errorMsg.Len() > 0 {
        return false, errorMsg.String()
    }

    return true, ""
}

// Function to hash password securely using bcrypt
func HashPassword(password string) (string, error) {
    hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    if err != nil {
        return "", err
    }
    return string(hashed), nil
}

