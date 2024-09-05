package middleware

import (
	"a21hc3NpZ25tZW50/model"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

type Claims struct {
	Email string `json:"email"`
	jwt.StandardClaims
}

func Auth() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		cookie, err := ctx.Cookie("session_token")
		if err != nil {
			if ctx.Request.Header.Get("Content-Type") == "application/json" {
				ctx.JSON(http.StatusUnauthorized, model.ErrorResponse{Error: err.Error()})
				ctx.Abort()
				return
			} else {
				ctx.JSON(http.StatusSeeOther, model.ErrorResponse{Error: err.Error()})
				ctx.Abort()
				return
			}

		}

		claims := &model.Claims{}
		tkn, err := jwt.ParseWithClaims(cookie, claims, func(t *jwt.Token) (interface{}, error) {
			return model.JwtKey, nil
		})
		if err != nil {
			ctx.JSON(http.StatusBadRequest, model.ErrorResponse{Error: err.Error()})
			ctx.Abort()
			return
		}

		if !tkn.Valid {
			ctx.JSON(http.StatusBadRequest, model.ErrorResponse{Error: err.Error()})
			ctx.Abort()
			return
		}

		if claims.Email == "" {
			ctx.JSON(http.StatusBadRequest, model.ErrorResponse{Error: err.Error()})
			ctx.Abort()
			return
		}
		ctx.Set("email", claims.Email)
		ctx.Next()

	}
}
