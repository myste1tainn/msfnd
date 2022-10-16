package msfnd

import (
	"fmt"
)

type HealthCheckFn = func(ctx app.AppContext) error

func HealthHandler(checker ...HealthCheckFn) app.AppHandler {
	return func(ctx app.AppContext) {
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
