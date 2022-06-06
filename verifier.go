package verifier

import (
	"fmt"
	"github.com/golang-jwt/jwt"
)

type CustomClaims struct {
	UserId uint
	Role   string
	jwt.StandardClaims
}

func VerifyJwt(tokenString string, pubK []byte) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return jwt.ParseRSAPublicKeyFromPEM(pubK), nil
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		if ve, ok := err.(*jwt.ValidationError); ok {
			if ve.Errors&jwt.ValidationErrorMalformed != 0 {
				fmt.Println("That's not even a token")
			} else if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
				// Token is either expired or not active yet
				fmt.Println("Timing is everything")
			} else {
				fmt.Println("Couldn't handle this token:", err)
			}
		} else {
			fmt.Println("Couldn't handle this token:", err)
		}
		return nil, err
	}
	claims := token.Claims.(CustomClaims)
	return &claims, nil
}
