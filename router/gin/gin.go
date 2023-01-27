package gin

import (
	"errors"
	"net/http"
	"sync"

	"github.com/NidzamuddinMSoluix/nidzam-rate-limit/router"
	"golang.org/x/time/rate"

	"github.com/gin-gonic/gin"
	"github.com/luraproject/lura/v2/config"
	"github.com/luraproject/lura/v2/logging"
	"github.com/luraproject/lura/v2/proxy"
	krakendgin "github.com/luraproject/lura/v2/router/gin"
)

var limiter = NewIPRateLimiter(1, 2)

// HandlerFactory is the out-of-the-box basic ratelimit handler factory using the default krakend endpoint
// handler for the gin router
var HandlerFactory = NewRateLimiterMw(logging.NoOp, krakendgin.EndpointHandler)

// NewRateLimiterMw builds a rate limiting wrapper over the received handler factory.
func NewRateLimiterMw(logger logging.Logger, next krakendgin.HandlerFactory) krakendgin.HandlerFactory {
	return func(remote *config.EndpointConfig, p proxy.Proxy) gin.HandlerFunc {
		logPrefix := "[ENDPOINT: " + remote.Endpoint + "][Ratelimit]"
		handlerFunc := next(remote, p)
		handlerFunc = NewTokenLimiterMw()(handlerFunc)
		cfg, err := router.ConfigGetter(remote.ExtraConfig)
		if err != nil {
			if err != router.ErrNoExtraCfg {
				logger.Error(logPrefix, err)
			}

			return handlerFunc
		}

		if cfg.MaxRate <= 0 && cfg.ClientMaxRate <= 0 {

			return handlerFunc
		}

		if cfg.MaxRate > 0 {
			if cfg.Capacity == 0 {
				if cfg.MaxRate < 1 {
					cfg.Capacity = 1
				} else {
					cfg.Capacity = int64(cfg.MaxRate)
				}
			}
			logger.Debug(logPrefix, "Rate limit enabled")
			// handlerFunc = NewEndpointRateLimiterMw(juju.NewLimiter(cfg.MaxRate, cfg.Capacity))(handlerFunc)

			return handlerFunc
		}
		if cfg.ClientMaxRate > 0 {
			if cfg.ClientCapacity == 0 {
				if cfg.MaxRate < 1 {
					cfg.ClientCapacity = 1
				} else {
					cfg.ClientCapacity = int64(cfg.ClientMaxRate)
				}
			}
			logger.Debug(logPrefix, "coba")
			handlerFunc = NewTokenLimiterMw()(handlerFunc)
			// switch strategy := strings.ToLower(cfg.Strategy); strategy {
			// case "ip":
			// 	logger.Debug(logPrefix, "IP-based rate limit enabled")
			// 	handlerFunc = NewIpLimiterWithKeyMw(cfg.Key, cfg.ClientMaxRate, cfg.ClientCapacity)(handlerFunc)
			// case "header":
			// 	logger.Debug(logPrefix, "Header-based rate limit enabled")
			// 	handlerFunc = NewHeaderLimiterMw(cfg.Key, cfg.ClientMaxRate, cfg.ClientCapacity)(handlerFunc)
			// default:
			// 	logger.Warning(logPrefix, "Unknown strategy", strategy)
			// }
		}
		return handlerFunc
	}
}

// EndpointMw is a function that decorates the received handlerFunc with some rateliming logic
type EndpointMw func(gin.HandlerFunc) gin.HandlerFunc

// // NewEndpointRateLimiterMw creates a simple ratelimiter for a given handlerFunc

// // NewHeaderLimiterMw creates a token ratelimiter using the value of a header as a token
// func NewHeaderLimiterMw(header string, maxRate float64, capacity int64) EndpointMw {
// 	return NewTokenLimiterMw(HeaderTokenExtractor(header), juju.NewMemoryStore(maxRate, capacity))
// }

// // NewIpLimiterMw creates a token ratelimiter using the IP of the request as a token
// func NewIpLimiterMw(maxRate float64, capacity int64) EndpointMw {
// 	return NewTokenLimiterMw(IPTokenExtractor, juju.NewMemoryStore(maxRate, capacity))
// }

// // NewIpLimiterWithKeyMw creates a token ratelimiter using the IP of the request as a token
// func NewIpLimiterWithKeyMw(header string, maxRate float64, capacity int64) EndpointMw {
// 	if header == "" {
// 		return NewIpLimiterMw(maxRate, capacity)
// 	}
// 	return NewTokenLimiterMw(NewIPTokenExtractor(header), juju.NewMemoryStore(maxRate, capacity))
// }

// // TokenExtractor defines the interface of the functions to use in order to extract a token for each request
// type TokenExtractor func(*gin.Context) string

// // IPTokenExtractor extracts the IP of the request
// func IPTokenExtractor(c *gin.Context) string { return c.ClientIP() }

// // NewIPTokenExtractor generates an IP TokenExtractor checking first for the contents of the passed header.
// // If nothing is found there, the regular IPTokenExtractor function is called.
// func NewIPTokenExtractor(header string) TokenExtractor {
// 	return func(c *gin.Context) string {
// 		if clientIP := strings.TrimSpace(strings.Split(c.Request.Header.Get(header), ",")[0]); clientIP != "" {
// 			ip := strings.Split(clientIP, ":")[0]
// 			if parsedIP := net.ParseIP(ip); parsedIP != nil {
// 				return ip
// 			}
// 		}
// 		return IPTokenExtractor(c)
// 	}
// }

// // HeaderTokenExtractor returns a TokenExtractor that looks for the value of the designed header
// func HeaderTokenExtractor(header string) TokenExtractor {
// 	return func(c *gin.Context) string { return c.Request.Header.Get(header) }
// }

// // NewTokenLimiterMw returns a token based ratelimiting endpoint middleware with the received TokenExtractor and LimiterStore
//
//	func NewTokenLimiterMw(tokenExtractor TokenExtractor, limiterStore krakendrate.LimiterStore) EndpointMw {
//		return func(next gin.HandlerFunc) gin.HandlerFunc {
//			return func(c *gin.Context) {
//				tokenKey := tokenExtractor(c)
//				if tokenKey == "" {
//					c.AbortWithError(http.StatusTooManyRequests, krakendrate.ErrLimited)
//					return
//				}
//				if !limiterStore(tokenKey).Allow() {
//					c.AbortWithError(http.StatusTooManyRequests, krakendrate.ErrLimited)
//					return
//				}
//				next(c)
//			}
//		}
//	}
type IPRateLimiter struct {
	ips map[string]*rate.Limiter
	mu  *sync.RWMutex
	r   rate.Limit
	b   int
}

// NewIPRateLimiter .
func NewIPRateLimiter(r rate.Limit, b int) *IPRateLimiter {
	i := &IPRateLimiter{
		ips: make(map[string]*rate.Limiter),
		mu:  &sync.RWMutex{},
		r:   r,
		b:   b,
	}

	return i
}

// AddIP creates a new rate limiter and adds it to the ips map,
// using the IP address as the key
func (i *IPRateLimiter) AddIP(ip string) *rate.Limiter {
	i.mu.Lock()
	defer i.mu.Unlock()

	limiter := rate.NewLimiter(i.r, i.b)

	i.ips[ip] = limiter

	return limiter
}

// GetLimiter returns the rate limiter for the provided IP address if it exists.
// Otherwise calls AddIP to add IP address to the map
func (i *IPRateLimiter) GetLimiter(ip string) *rate.Limiter {
	i.mu.Lock()
	limiter, exists := i.ips[ip]

	if !exists {
		i.mu.Unlock()
		return i.AddIP(ip)
	}

	i.mu.Unlock()

	return limiter
}

func NewTokenLimiterMw() EndpointMw {
	return func(next gin.HandlerFunc) gin.HandlerFunc {
		return func(c *gin.Context) {
			ip := c.ClientIP()
			limiter := limiter.GetLimiter(ip)
			if !limiter.Allow() {
				c.AbortWithError(http.StatusTooManyRequests, errors.New("rate limit exceded"))
				return
			}

			next(c)
		}
	}
}
