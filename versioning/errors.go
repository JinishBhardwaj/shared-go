package versioning

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/neocotic/go-problem"
)

// Problem type definitions for versioning errors (RFC 9457).
var problemBadRequest = problem.Type{
	Status: http.StatusBadRequest,
	Title:  "Bad Request",
	URI:    "https://tools.ietf.org/html/rfc7231#section-6.5.1",
}

// writeProblem writes an RFC 9457 Problem Details JSON response for versioning errors.
func writeProblem(c *gin.Context, detail string) {
	p := problem.New(
		problem.FromType(problemBadRequest),
		problem.WithDetail(detail),
		problem.WithInstance(c.Request.URL.Path),
	)
	c.Header("Content-Type", "application/problem+json")
	c.JSON(p.Status, problemToMap(p))
	c.Abort()
}

// problemToMap converts a problem.Problem to a map for JSON serialization,
// omitting empty optional fields per RFC 9457.
func problemToMap(p *problem.Problem) map[string]interface{} {
	result := map[string]interface{}{
		"type":   p.Type,
		"title":  p.Title,
		"status": p.Status,
	}
	if p.Detail != "" {
		result["detail"] = p.Detail
	}
	if p.Instance != "" {
		result["instance"] = p.Instance
	}
	return result
}


