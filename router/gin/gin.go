package gin

import (
	"github.com/NidzamuddinMSoluix/nidzam-rate-limit/router"

	"github.com/gin-gonic/gin"
	"github.com/luraproject/lura/v2/config"
	"github.com/luraproject/lura/v2/logging"
	"github.com/luraproject/lura/v2/proxy"
	krakendgin "github.com/luraproject/lura/v2/router/gin"
)

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
// func NewTokenLimiterMw(tokenExtractor TokenExtractor, limiterStore krakendrate.LimiterStore) EndpointMw {
// 	return func(next gin.HandlerFunc) gin.HandlerFunc {
// 		return func(c *gin.Context) {
// 			tokenKey := tokenExtractor(c)
// 			if tokenKey == "" {
// 				c.AbortWithError(http.StatusTooManyRequests, krakendrate.ErrLimited)
// 				return
// 			}
// 			if !limiterStore(tokenKey).Allow() {
// 				c.AbortWithError(http.StatusTooManyRequests, krakendrate.ErrLimited)
// 				return
// 			}
// 			next(c)
// 		}
// 	}
// }

func NewTokenLimiterMw() EndpointMw {
	// type client struct {
	// 	limiter  *rate.Limiter
	// 	lastSeen time.Time
	// }
	// var (
	// 	mu      sync.Mutex
	// 	clients = make(map[string]*client)
	// )
	// // Launch a backaground Goroutine that removes old entries
	// // from the clients map once every minute
	// go func() {
	// 	for {
	// 		time.Sleep(time.Minute)
	// 		// Lock before starting to cleanup
	// 		mu.Lock()
	// 		for ip, client := range clients {
	// 			if time.Since(client.lastSeen) > 3*time.Minute {
	// 				delete(clients, ip)
	// 			}
	// 		}
	// 		mu.Unlock()
	// 	}
	// }()
	return func(next gin.HandlerFunc) gin.HandlerFunc {
		return func(c *gin.Context) {
			// ip := c.ClientIP()

			// // Lock()
			// mu.Lock()
			// // Check if the IP address is in the map
			// if _, found := clients[ip]; !found {
			// 	clients[ip] = &client{limiter: rate.NewLimiter(
			// 		rate.Limit(1),
			// 		2,
			// 	)}
			// }
			// // Update the last seen time of the client
			// clients[ip].lastSeen = time.Now()
			// // Check if request allowed
			// if !clients[ip].limiter.Allow() {
			// 	mu.Unlock()
			// 	errr := errors.New("too many request")
			// 	if errr != nil {
			// 		c.AbortWithError(http.StatusTooManyRequests, errr)
			// 		return
			// 	}
			// }

			// mu.Unlock()
			next(c)
		}
	}
}
