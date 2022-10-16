package msfnd

import (
	"fmt"

	"github.com/gin-gonic/gin"
)

type HealthCheckFn = func(ctx *gin.Context) error

func HealthHandler(checker ...HealthCheckFn) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		for _, checker := range checker {
			err := checker(ctx)
			if err != nil {
				res := map[string]string{
					"status": "unhealty",
					"msg":    fmt.Sprintf("maria ping error: %s", err.Error()),
				}
				ctx.JSON(500, res)
				return
			}
		}

		ctx.JSON(200, map[string]string{"status": "healthy"})
	}

}
