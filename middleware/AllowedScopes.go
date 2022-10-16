package middleware

import (
	"errors"

	"github.com/gin-gonic/gin"
	"github.com/myste1tainn/msfnd"
	"golang.org/x/exp/slices"
)

func AllowedScopes(allowedScopes ...msfnd.LoginScope) gin.HandlerFunc {
	return func(ctx gin.Context) {
		ParseRouteContext()(ctx)

		if len(ctx.Errors()) > 0 {
			log.Warnf("AllowedScopes is not being checked because there are already error(s) in the context, skipping...")
			return
		}

		WithRouteContext(func(ctx gin.Context, rctx *msfnd.RouteContext) {
			actualScope := msfnd.ParseLoginScope(rctx.LoginScope)
			log.Debugf("validating loginScope = '%v' -> parsedScope = '%v' vs allowedScopes = '%v'", rctx.LoginScope, actualScope, allowedScopes)
			if !slices.Contains(allowedScopes, actualScope) {
				err := errors.New("Wrong scope")
				ctx.Error(err)
				return
			}
		})(ctx)
	}
}
