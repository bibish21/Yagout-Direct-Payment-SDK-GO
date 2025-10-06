package main

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/example/yagout-payment-sdk/backend/sdk"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// CheckoutRequest is the input from frontend
type CheckoutRequest struct {
	MobileNumber string `json:"mobileNumber"`
	Currency     string `json:"currency"`
	Amount       string `json:"amount"`
	CustomerName string `json:"customerName"`
	Wallet       string `json:"wallet"`
	Email        string `json:"email"`
}

// Order stored in memory
type Order struct {
	OrderNo       string    `json:"orderNo"`
	MobileNumber  string    `json:"mobileNumber"`
	Currency      string    `json:"currency"`
	Amount        string    `json:"amount"`
	CustomerName  string    `json:"customerName"`
	Status        string    `json:"status"`
	TransactionID string    `json:"transactionId,omitempty"`
	CreatedAt     time.Time `json:"createdAt"`
	ResponseRaw   string    `json:"responseRaw,omitempty"`
	Wallet        string    `json:"wallet"`
	StatusMessage string    `json:"statusMessage"`
	Email         string    `json:"email"`
}

var (
	mu    sync.RWMutex
	store = map[string]Order{}
)

func saveOrder(o Order) {
	mu.Lock()
	defer mu.Unlock()
	store[o.OrderNo] = o
}

func getOrder(no string) (Order, bool) {
	mu.RLock()
	defer mu.RUnlock()
	o, ok := store[no]
	return o, ok
}

func listOrders() []Order {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]Order, 0, len(store))
	for _, v := range store {
		out = append(out, v)
	}
	return out
}

// extractInfoFromDecrypted tries to parse a decrypted JSON string (decStr)
// and returns (statusMessage, transactionId) by looking in multiple places:
//   - top-level "statusMessage" or "res_message"
//   - inside "txn_response": "res_message", "status", "ag_ref", "pg_ref"
func extractInfoFromDecrypted(decStr string) (string, string) {
	if decStr == "" {
		return "", ""
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(decStr), &parsed); err != nil {
		// can't parse JSON; return nothing
		return "", ""
	}

	// helper to get string from interface
	getStr := func(m map[string]interface{}, key string) (string, bool) {
		if v, ok := m[key]; ok {
			if s, ok2 := v.(string); ok2 && s != "" {
				return s, true
			}
		}
		return "", false
	}

	// 1) top-level checks
	if v, ok := getStr(parsed, "statusMessage"); ok {
		return v, ""
	}
	if v, ok := getStr(parsed, "res_message"); ok {
		return v, ""
	}
	// 2) txn_response nested
	if txnRaw, ok := parsed["txn_response"]; ok {
		if txnMap, ok2 := txnRaw.(map[string]interface{}); ok2 {
			if v, ok := getStr(txnMap, "res_message"); ok {
				// transaction message exists
				// try to find transaction id too
				if tid, ok2 := getStr(txnMap, "ag_ref"); ok2 {
					return v, tid
				}
				if tid, ok2 := getStr(txnMap, "pg_ref"); ok2 {
					return v, tid
				}
				// no ag_ref/pg_ref found, return message only
				return v, ""
			}
			// if no res_message, maybe status exists
			if st, ok := getStr(txnMap, "status"); ok {
				// get transaction id if possible
				if tid, ok2 := getStr(txnMap, "ag_ref"); ok2 {
					return st, tid
				}
				if tid, ok2 := getStr(txnMap, "pg_ref"); ok2 {
					return st, tid
				}
				return st, ""
			}
		}
	}

	// 3) fallback: maybe top-level transaction id fields exist
	if v, ok := getStr(parsed, "transactionId"); ok {
		return "", v
	}
	if v, ok := getStr(parsed, "transaction_id"); ok {
		return "", v
	}

	// nothing found
	return "", ""
}

func main() {
	cfgPath := filepath.Join(".", "config.properties")
	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		cfgPath = "config.properties"
	}
	conf, err := sdk.LoadConfig(cfgPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	pg, err := sdk.NewGateway(conf)
	if err != nil {
		log.Fatalf("init gateway: %v", err)
	}

	// Use Gin
	r := gin.Default()

	// --- CORS: Allow all origins (wildcard) ---
	// WARNING: This sets Access-Control-Allow-Origin: * and DOES NOT allow credentials (cookies).
	// Don't use in production unless you intend to allow every origin.
	r.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Vary", "Origin")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization, me_id, X-Requested-With")
		// Do NOT set Access-Control-Allow-Credentials when using wildcard origin
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(200)
			return
		}
		c.Next()
	})
	// ------------------------------------------

	// Serve static swagger UI and the openapi file
	// Put swagger dist into ./public/docs/ and put openapi.yaml at project root (./openapi.yaml)
	// These two static mounts let http://localhost:8080/docs/ work.
	r.Static("/docs", "./public/docs")              // serves index.html + assets
	r.StaticFile("/openapi.yaml", "./openapi.yaml") // serve the spec

	api := r.Group("/api")
	api.POST("/checkout", func(c *gin.Context) {
		var req CheckoutRequest
		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json", "details": err.Error()})
			return
		}

		orderNo := "ORD" + uuid.New().String()[:8]
		order := Order{
			OrderNo:       orderNo,
			MobileNumber:  req.MobileNumber,
			Currency:      req.Currency,
			Amount:        req.Amount,
			Wallet:        req.Wallet,
			Email:         req.Email,
			CustomerName:  req.CustomerName,
			Status:        "initiated",
			StatusMessage: "",
			CreatedAt:     time.Now(),
		}
		saveOrder(order)

		pr, err := pg.Pay(sdk.Order{
			OrderNo:      order.OrderNo,
			MobileNumber: order.MobileNumber,
			Currency:     order.Currency,
			Amount:       order.Amount,
			Wallet:       order.Wallet,
			CustomerName: order.CustomerName,
			Email:        order.Email,
		})

		// If there was an error calling Pay, handle it safely (pr may be nil)
		if err != nil {
			order.Status = "failed"

			// Prefer SDK-provided statusMessage if available
			if pr != nil && pr.StatusMessage != "" {
				order.StatusMessage = pr.StatusMessage
			} else {
				// try to extract from decrypted string if present
				if pr != nil && pr.DecryptedResponse != "" {
					if msg, _ := extractInfoFromDecrypted(pr.DecryptedResponse); msg != "" {
						order.StatusMessage = msg
					} else {
						order.StatusMessage = err.Error()
					}
				} else {
					// final fallback: use the error text
					order.StatusMessage = err.Error()
				}
			}

			order.ResponseRaw = err.Error()
			saveOrder(order)
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Success: populate order fields using pr (and fallback to parse decrypted payload)
		order.Status = pr.Status

		// Prefer pr.StatusMessage, otherwise try to parse decrypted payload for a message
		if pr.StatusMessage != "" {
			order.StatusMessage = pr.StatusMessage
		} else if pr.DecryptedResponse != "" {
			if msg, tid := extractInfoFromDecrypted(pr.DecryptedResponse); msg != "" {
				order.StatusMessage = msg
				// if transaction id is found in decrypted payload and we don't have one yet, set it
				if order.TransactionID == "" && tid != "" {
					order.TransactionID = tid
				}
			}
		}

		// If SDK returned a TransactionID, use it (overrides parsed tid)
		if pr.TransactionID != "" {
			order.TransactionID = pr.TransactionID
		}

		order.ResponseRaw = pr.DecryptedResponse
		saveOrder(order)

		c.JSON(http.StatusOK, gin.H{"orderNo": order.OrderNo, "status": pr.Status, "statusMessage": order.StatusMessage})
	})

	api.GET("/order/:orderNo", func(c *gin.Context) {
		no := c.Param("orderNo")
		o, ok := getOrder(no)
		if !ok {
			c.JSON(http.StatusNotFound, gin.H{"error": "order not found"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"order": o})
	})

	api.GET("/orders", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"orders": listOrders()}) })

	// mock gateway (dev only)
	// This matches openapi.yaml path /mock-gateway
	r.POST("/mock-gateway", func(c *gin.Context) {
		var payload map[string]interface{}
		_ = c.BindJSON(&payload)
		mock := map[string]interface{}{"transactionId": "TX-" + uuid.New().String()[:8], "status": "Success", "echo": payload}
		b, _ := json.Marshal(mock)
		resp := map[string]interface{}{"merchantId": conf.MerchantID, "status": "Success", "statusMessage": "Mock OK", "response": base64.StdEncoding.EncodeToString(b)}
		c.JSON(http.StatusOK, resp)
	})

	// health endpoint
	r.GET("/health", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("starting server on :%s (docs: /docs , spec: /openapi.yaml)\n", port)
	r.Run(":" + port)
}
