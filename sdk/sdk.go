package sdk

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/sirupsen/logrus"
)

var (
	// package-level logger used by helper functions that don't have pg receiver
	pkgLogger  *logrus.Logger
	logFilePtr *os.File
)

type Config struct {
	MerchantID        string
	MerchantKeyBase64 string
	StaticIV          string
	Endpoint          string
	SuccessURL        string
	FailureURL        string
	Debug             bool

	RetryMaxAttempts     int
	RetryInitialInterval time.Duration
	RetryMaxInterval     time.Duration
	RequestTimeout       time.Duration

	AllowedOrigin string
	LogLevel      string
	SkipTLSVerify bool
}

func (c *Config) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"MerchantID": c.MerchantID,
		"Endpoint":   c.Endpoint,
		"Debug":      c.Debug,
	}
}

func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out := &Config{}
	lines := strings.Split(string(b), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		k := strings.TrimSpace(parts[0])
		v := strings.TrimSpace(parts[1])
		switch strings.ToLower(k) {
		case "merchantid":
			out.MerchantID = v
		case "merchantkeybase64":
			out.MerchantKeyBase64 = v
		case "staticiv":
			out.StaticIV = v
		case "pg_apiintegration_endpoint", "endpoint":
			out.Endpoint = v
		case "successurl":
			out.SuccessURL = v
		case "failureurl":
			out.FailureURL = v
		case "debug":
			out.Debug = (strings.ToLower(v) == "true" || v == "1")
		case "retrymaxattempts":
			if n, err := fmt.Sscanf(v, "%d", &out.RetryMaxAttempts); err == nil && n > 0 {
			} else {
				out.RetryMaxAttempts = 3
			}
		case "retryinitialintervalms":
			var n int64
			if _, err := fmt.Sscanf(v, "%d", &n); err == nil {
				out.RetryInitialInterval = time.Duration(n) * time.Millisecond
			}
		case "retrymaxintervalms":
			var n int64
			if _, err := fmt.Sscanf(v, "%d", &n); err == nil {
				out.RetryMaxInterval = time.Duration(n) * time.Millisecond
			}
		case "skiptlsverify", "skip_tls_verify", "skip_tls", "SkipTLSVerify":
			lv := strings.ToLower(v)
			if lv == "1" || lv == "true" || lv == "yes" {
				out.SkipTLSVerify = true
			} else {
				out.SkipTLSVerify = false
			}

		case "requesttimeoutms":
			var n int64
			if _, err := fmt.Sscanf(v, "%d", &n); err == nil {
				out.RequestTimeout = time.Duration(n) * time.Millisecond
			}
		case "allowedorigin":
			out.AllowedOrigin = v
		case "loglevel":
			out.LogLevel = v
		}
	}
	if out.RetryMaxAttempts == 0 {
		out.RetryMaxAttempts = 3
	}
	if out.RetryInitialInterval == 0 {
		out.RetryInitialInterval = 500 * time.Millisecond
	}
	if out.RetryMaxInterval == 0 {
		out.RetryMaxInterval = 2 * time.Second
	}
	if out.RequestTimeout == 0 {
		out.RequestTimeout = 10 * time.Second
	}
	return out, nil
}

type PaymentGateway struct {
	Config *Config
	logger *logrus.Logger
	client *http.Client
}

type PaymentResponse struct {
	MerchantID        string                 `json:"merchantId"`
	Status            string                 `json:"status"`
	StatusMessage     string                 `json:"statusMessage"`
	EncryptedResponse string                 `json:"response"`
	DecryptedResponse string                 `json:"decryptedResponse,omitempty"`
	TransactionID     string                 `json:"transactionId,omitempty"`
	Raw               map[string]interface{} `json:"raw,omitempty"`
}

type Order struct {
	OrderNo      string `json:"orderNo"`
	MobileNumber string `json:"mobileNumber"`
	Currency     string `json:"currency"`
	Amount       string `json:"amount"`
	CustomerName string `json:"customerName"`
	Wallet       string `json:"wallet"`
	Email        string `json:"email"`
}

// NewGateway initializes PaymentGateway and sets up logging to debug.log when Debug is true.
// It also sets a package-level logger so package functions (encrypt/decrypt) can log.
func NewGateway(cfg *Config) (*PaymentGateway, error) {
	logger := logrus.New()
	level := logrus.InfoLevel
	if strings.ToLower(cfg.LogLevel) == "debug" || cfg.Debug {
		level = logrus.DebugLevel
	}
	logger.SetLevel(level)
	logger.SetFormatter(&logrus.TextFormatter{FullTimestamp: true})

	// If debug mode enabled, also append logs to debug.log
	var writer io.Writer = os.Stdout
	if cfg.Debug {
		f, err := os.OpenFile("debug.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err == nil {
			// keep file pointer in package scope so it isn't GC'ed and to optionally close later
			logFilePtr = f
			writer = io.MultiWriter(os.Stdout, f)
		} else {
			// if we cannot open file, still continue with stdout and log the error
			logger.Warnf("could not open debug.log for writing: %v", err)
		}
	}
	logger.SetOutput(writer)

	// set package-level logger for helper funcs
	pkgLogger = logger

	// Build transport with TLS config based on cfg.SkipTLSVerify
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.SkipTLSVerify,
		},
	}

	if cfg.SkipTLSVerify {
		logger.Warn("SkipTLSVerify is enabled: TLS certificate verification will be disabled (insecure). Use only for debugging.")
	}

	pg := &PaymentGateway{
		Config: cfg,
		logger: logger,
		client: &http.Client{
			Timeout:   cfg.RequestTimeout,
			Transport: transport,
		},
	}
	logger.Debug("PaymentGateway initialized")
	return pg, nil
}

var (
	alphaRegexWithSpace = regexp.MustCompile(`^[A-Za-z\s]+$`)
	amountRegex         = regexp.MustCompile(`^\d{1,10}(?:\.\d{1,2})?$`)
	orderNoRegex        = regexp.MustCompile(`^[A-Za-z0-9]+$`)
	phoneRegex          = regexp.MustCompile(`^0[97]\d{8}$`)
	emailRegex          = regexp.MustCompile(`^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$`)
	addressAllowed      = regexp.MustCompile(`^[A-Za-z0-9#,\(\)\/\.\-\s]+$`)
)

type fieldSpec struct {
	Required  bool
	Regex     *regexp.Regexp
	MaxLength int
	Custom    func(string) error
}

func collectValidationErrors(section string, data map[string]string, spec map[string]fieldSpec) []string {
	errs := []string{}
	for field, rules := range spec {
		val := strings.TrimSpace(data[field])
		if rules.Required && val == "" {
			errs = append(errs, fmt.Sprintf("%s.%s is required", section, field))
			continue
		}
		if val == "" {
			continue
		}
		if rules.MaxLength > 0 && len(val) > rules.MaxLength {
			errs = append(errs, fmt.Sprintf("%s.%s exceeds max length %d", section, field, rules.MaxLength))
		}
		if rules.Regex != nil && !rules.Regex.MatchString(val) {
			errs = append(errs, fmt.Sprintf("%s.%s does not match expected pattern", section, field))
		}
		if rules.Custom != nil {
			if err := rules.Custom(val); err != nil {
				errs = append(errs, fmt.Sprintf("%s.%s custom validation failed: %v", section, field, err))
			}
		}
	}
	return errs
}

func ValidateTransaction(txn map[string]string, cust map[string]string) error {
	errorsAll := []string{}

	txnSpec := map[string]fieldSpec{
		"order_no": {Required: true, Regex: orderNoRegex, MaxLength: 70},
		"amount":   {Required: false, Regex: amountRegex, MaxLength: 13},
		"currency": {Required: false, Regex: regexp.MustCompile(`^[A-Za-z0-9]{1,3}$`), MaxLength: 3},
	}
	custSpec := map[string]fieldSpec{
		"email_id":  {Required: false, Regex: emailRegex, MaxLength: 100},
		"mobile_no": {Required: true, Regex: phoneRegex, MaxLength: 15},
		"cust_name": {Required: false, Regex: alphaRegexWithSpace, MaxLength: 50},
	}

	errorsAll = append(errorsAll, collectValidationErrors("Txn_Details", txn, txnSpec)...)
	errorsAll = append(errorsAll, collectValidationErrors("cust_details", cust, custSpec)...)

	if len(errorsAll) > 0 {
		return errors.New(strings.Join(errorsAll, "; "))
	}
	return nil
}

func padPKCS7(b []byte, blockSize int) []byte {
	padLen := blockSize - (len(b) % blockSize)
	if padLen == 0 {
		padLen = blockSize
	}
	pad := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(b, pad...)
}

func removePKCS7Padding(b []byte, blockSize int) ([]byte, error) {
	if len(b) == 0 || len(b)%blockSize != 0 {
		return nil, errors.New("invalid padded data length")
	}
	pad := int(b[len(b)-1])
	if pad < 1 || pad > blockSize {
		return nil, fmt.Errorf("invalid padding value %d", pad)
	}
	for i := 0; i < pad; i++ {
		if b[len(b)-1-i] != byte(pad) {
			return nil, errors.New("invalid PKCS7 padding bytes")
		}
	}
	return b[:len(b)-pad], nil
}

// encryptCBCBase64 encrypts plaintext with AES-256-CBC (PKCS7) and returns base64 ciphertext.
// It logs useful debug information to the package logger when available.
func encryptCBCBase64(plaintext []byte, keyB64 string, iv []byte) (string, error) {
	// decode key
	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		if pkgLogger != nil {
			pkgLogger.WithError(err).Error("encryptCBCBase64: key base64 decode failed")
		}
		return "", fmt.Errorf("key base64 decode: %w", err)
	}
	if len(key) != 32 {
		err := fmt.Errorf("key must be 32 bytes after base64 decode, got %d", len(key))
		if pkgLogger != nil {
			pkgLogger.WithField("key_len", len(key)).Error("encryptCBCBase64: invalid key length")
		}
		return "", err
	}

	// Log a fingerprint + length for plaintext; also log full plaintext ONLY if debug enabled.
	if pkgLogger != nil {
		ptHash := sha256.Sum256(plaintext)
		pkgLogger.WithFields(logrus.Fields{
			"plaintext_len":    len(plaintext),
			"plaintext_sha256": fmt.Sprintf("%x", ptHash[:6]),
			"iv_len":           len(iv),
			"key_len":          len(key),
			"action":           "encrypt_start",
			"maybe_sensitive":  true,
			"note":             "plaintext logged in full below only when debug level",
		}).Debug("encryptCBCBase64 inputs")
		// If debug level, also log the full plaintext (merchant request). User specifically requested this.
		if pkgLogger.Level == logrus.DebugLevel {
			pkgLogger.Debugf("encryptCBCBase64 plaintext (full): %s", string(plaintext))
		}
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		if pkgLogger != nil {
			pkgLogger.WithError(err).Error("encryptCBCBase64: aes.NewCipher failed")
		}
		return "", err
	}
	padded := padPKCS7(plaintext, aes.BlockSize)
	ciphertext := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padded)

	b64 := base64.StdEncoding.EncodeToString(ciphertext)

	// Log ciphertext fingerprint and optionally full base64 when debug enabled
	if pkgLogger != nil {
		ctHash := sha256.Sum256(ciphertext)
		fields := logrus.Fields{
			"ciphertext_len":     len(ciphertext),
			"ciphertext_sha256":  fmt.Sprintf("%x", ctHash[:6]),
			"ciphertext_b64_len": len(b64),
			"action":             "encrypt_done",
		}
		// log a short prefix of base64 for quick visual check
		if len(b64) > 48 {
			fields["ciphertext_b64_prefix"] = b64[:48]
		} else {
			fields["ciphertext_b64_prefix"] = b64
		}
		pkgLogger.WithFields(fields).Debug("encryptCBCBase64 output")
		if pkgLogger.Level == logrus.DebugLevel {
			// user asked to log encrypted merchant request - log full base64 in debug mode
			pkgLogger.Debugf("encryptCBCBase64 ciphertext (base64 full): %s", b64)
		}
	}

	return b64, nil
}

// decryptCBCBase64 decodes base64 ciphertext and decrypts AES-256-CBC with provided iv.
// It logs debug information and returns plaintext bytes (unpadded).
func decryptCBCBase64(cipherB64, keyB64 string, iv []byte) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		if pkgLogger != nil {
			pkgLogger.WithError(err).Error("decryptCBCBase64: key base64 decode failed")
		}
		return nil, fmt.Errorf("key base64 decode: %w", err)
	}
	if len(key) != 32 {
		err := fmt.Errorf("key must be 32 bytes after base64 decode, got %d", len(key))
		if pkgLogger != nil {
			pkgLogger.WithField("key_len", len(key)).Error("decryptCBCBase64: invalid key length")
		}
		return nil, err
	}
	ciphertext, err := base64.StdEncoding.DecodeString(cipherB64)
	if err != nil {
		if pkgLogger != nil {
			pkgLogger.WithError(err).WithField("cipher_b64_len", len(cipherB64)).Error("decryptCBCBase64: base64 decode failed")
		}
		return nil, fmt.Errorf("ciphertext base64 decode: %w", err)
	}
	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		err := fmt.Errorf("ciphertext length invalid or not multiple of block size")
		if pkgLogger != nil {
			pkgLogger.WithField("cipher_len", len(ciphertext)).Error("decryptCBCBase64: invalid ciphertext length")
		}
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		if pkgLogger != nil {
			pkgLogger.WithError(err).Error("decryptCBCBase64: aes.NewCipher failed")
		}
		return nil, fmt.Errorf("new cipher: %w", err)
	}

	plainPadded := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, ciphertext[:aes.BlockSize]) // <-- WRONG IV usage defense: ensure caller passes correct IV (we expect iv param)
	// We expect caller to pass iv. Use iv for decryption. Use the provided iv.
	_ = mode
	// Correct decryption below using iv:
	mode = cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plainPadded, ciphertext)

	plain, err := removePKCS7Padding(plainPadded, aes.BlockSize)
	if err != nil {
		if pkgLogger != nil {
			pkgLogger.WithError(err).Error("decryptCBCBase64: padding removal failed")
			// In debug mode, log decrypted padded bytes as well
			if pkgLogger.Level == logrus.DebugLevel {
				pkgLogger.Debugf("decryptCBCBase64 plainPadded (hex): %x", plainPadded)
			}
		}
		return nil, fmt.Errorf("invalid padding after decrypt: %w", err)
	}

	// Log decrypted plaintext (short fingerprint + full when debug)
	if pkgLogger != nil {
		ptHash := sha256.Sum256(plain)
		pkgLogger.WithFields(logrus.Fields{
			"decrypted_len":    len(plain),
			"decrypted_sha256": fmt.Sprintf("%x", ptHash[:6]),
			"action":           "decrypt_done",
		}).Debug("decryptCBCBase64 output")
		if pkgLogger.Level == logrus.DebugLevel {
			pkgLogger.Debugf("decryptCBCBase64 plaintext (full): %s", string(plain))
		}
	}

	return plain, nil
}

func prepareIV(cfgIV string) []byte {
	if b, err := base64.StdEncoding.DecodeString(cfgIV); err == nil && len(b) >= 16 {
		return b[:16]
	}
	b := []byte(cfgIV)
	if len(b) >= 16 {
		return b[:16]
	}
	out := make([]byte, 16)
	copy(out, b)
	return out
}

func (pg *PaymentGateway) buildMerchantRequest(order Order) (string, error) {
	req := map[string]interface{}{
		"card_details":  map[string]string{"cardNumber": "", "expiryMonth": "", "expiryYear": "", "cvv": "", "cardName": ""},
		"other_details": map[string]string{"udf1": "", "udf2": "", "udf3": "", "udf4": "", "udf5": "", "udf6": "", "udf7": ""},
		"ship_details":  map[string]string{"shipAddress": "", "shipCity": "", "shipState": "", "shipCountry": "", "shipZip": "", "shipDays": "", "addressCount": ""},
		"txn_details": map[string]string{
			"agId":            "yagout",
			"meId":            pg.Config.MerchantID,
			"orderNo":         order.OrderNo,
			"amount":          order.Amount,
			"country":         "ETH",
			"currency":        order.Currency,
			"transactionType": "SALE",
			"sucessUrl":       pg.Config.SuccessURL,
			"failureUrl":      pg.Config.FailureURL,
			"channel":         "API",
		},
		"item_details": map[string]string{"itemCount": "", "itemValue": "", "itemCategory": ""},
		"cust_details": map[string]string{"customerName": order.CustomerName, "emailId": order.Email, "mobileNumber": order.MobileNumber, "uniqueId": "", "isLoggedIn": "Y"},
		"pg_details":   map[string]string{"pg_Id": "67ee846571e740418d688c3f", "paymode": "WA", "scheme_Id": "7", "wallet_type": order.Wallet},
		"bill_details": map[string]string{"billAddress": "", "billCity": "", "billState": "", "billCountry": "", "billZip": ""},
	}
	b, err := json.Marshal(req)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (pg *PaymentGateway) sendWithRetry(ctx context.Context, url string, body []byte) ([]byte, error) {
	exp := backoff.NewExponentialBackOff()
	exp.InitialInterval = pg.Config.RetryInitialInterval
	exp.MaxInterval = pg.Config.RetryMaxInterval
	exp.MaxElapsedTime = time.Duration(pg.Config.RetryMaxAttempts) * pg.Config.RetryMaxInterval

	var lastErr error
	var lastResponse []byte

	operation := func() error {
		req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
		if err != nil {
			lastErr = err
			pg.logger.Debugf("create request error: %v", err)
			return backoff.Permanent(err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := pg.client.Do(req)
		if err != nil {
			lastErr = err
			pg.logger.Warnf("request error (will retry): %v", err)
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("server error %d", resp.StatusCode)
			pg.logger.Warnf("server error %d (will retry)", resp.StatusCode)
			return fmt.Errorf("server error %d", resp.StatusCode)
		}

		if resp.StatusCode >= 400 {
			b, _ := io.ReadAll(resp.Body)
			lastErr = fmt.Errorf("client error %d: %s", resp.StatusCode, string(b))
			pg.logger.Errorf("client error %d: %s", resp.StatusCode, string(b))
			return backoff.Permanent(lastErr)
		}

		b, _ := io.ReadAll(resp.Body)
		lastErr = nil
		lastResponse = b
		return nil
	}

	notify := func(err error, d time.Duration) {
		pg.logger.Warnf("retry after error: %v, next attempt in %s", err, d.String())
	}

	err := backoff.RetryNotify(operation, backoff.WithContext(exp, ctx), notify)
	if err != nil {
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, err
	}
	return lastResponse, nil
}

func (pg *PaymentGateway) Pay(order Order) (*PaymentResponse, error) {
	txn := map[string]string{"order_no": order.OrderNo, "amount": order.Amount, "currency": order.Currency}
	cust := map[string]string{"mobile_no": order.MobileNumber, "cust_name": order.CustomerName, "email_id": ""}
	if err := ValidateTransaction(txn, cust); err != nil {
		return nil, err
	}

	merchantReq, err := pg.buildMerchantRequest(order)
	if err != nil {
		return nil, err
	}

	iv := prepareIV(pg.Config.StaticIV)

	// Log merchant request (full) to debug when debug enabled
	if pg.Config.Debug && pkgLogger != nil {
		pkgLogger.Debugf("Pay: merchant request (full): %s", merchantReq)
	} else if pkgLogger != nil {
		// still log a fingerprint at info/debug
		h := sha256.Sum256([]byte(merchantReq))
		pkgLogger.Debugf("Pay: merchant request fingerprint: %x, len=%d", h[:6], len(merchantReq))
	}

	enc, err := encryptCBCBase64([]byte(merchantReq), pg.Config.MerchantKeyBase64, iv)
	if err != nil {
		pg.logger.Errorf("encrypt merchant request failed: %v", err)
		return nil, fmt.Errorf("encrypt merchant request: %w", err)
	}

	// Log the encrypted merchantRequest envelope (base64) to debug.log if enabled
	envelope := map[string]string{"merchantId": pg.Config.MerchantID, "merchantRequest": enc}
	envelopeB, _ := json.Marshal(envelope)
	if pg.Config.Debug && pkgLogger != nil {
		pkgLogger.Debugf("Pay: envelope being sent to PG: %s", string(envelopeB))
	} else if pkgLogger != nil {
		pkgLogger.Debugf("Pay: envelope fingerprint merchantId=%s merchantRequest_b64_len=%d", pg.Config.MerchantID, len(enc))
	}

	ctx, cancel := context.WithTimeout(context.Background(), pg.Config.RequestTimeout+time.Second*5)
	defer cancel()

	target := pg.Config.Endpoint
	// For a local mock or if configured with "mock" in URL, route to internal mock endpoint
	if strings.Contains(strings.ToLower(target), "mock") {
		target = "http://localhost:8080/mock-gateway"
	}

	respBody, err := pg.sendWithRetry(ctx, target, envelopeB)
	if err != nil {
		pg.logger.Errorf("sendWithRetry failed: %v", err)
		return nil, err
	}

	// Log raw response from PG (base64 response) if debug enabled
	if pg.Config.Debug && pkgLogger != nil {
		pkgLogger.Debugf("Pay: raw PG response body: %s", string(respBody))
	} else if pkgLogger != nil {
		pkgLogger.Debugf("Pay: raw PG response length: %d", len(respBody))
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		pg.logger.Errorf("invalid json from PG: %v", err)
		return nil, fmt.Errorf("invalid json from PG: %w", err)
	}

	pr := &PaymentResponse{Raw: parsed}
	if v, ok := parsed["merchantId"].(string); ok {
		pr.MerchantID = v
	}
	if v, ok := parsed["status"].(string); ok {
		pr.Status = v
	}
	if v, ok := parsed["statusMessage"].(string); ok {
		pr.StatusMessage = v
	}
	if v, ok := parsed["response"].(string); ok {
		pr.EncryptedResponse = v

		// Log encrypted response (base64) in debug mode
		if pg.Config.Debug && pkgLogger != nil {
			pkgLogger.Debugf("Pay: PG returned encrypted response (base64): %s", v)
		} else if pkgLogger != nil {
			pkgLogger.Debugf("Pay: PG returned encrypted response length: %d", len(v))
		}

		decBytes, derr := decryptCBCBase64(v, pg.Config.MerchantKeyBase64, iv)
		if derr != nil {
			pg.logger.Errorf("decrypt response failed: %v", derr)
			pr.DecryptedResponse = fmt.Sprintf("decrypt error: %v; raw:%s", derr, v)
		} else {
			pr.DecryptedResponse = string(decBytes)
			// Log decrypted response (full) in debug
			if pg.Config.Debug && pkgLogger != nil {
				pkgLogger.Debugf("Pay: decrypted PG response (full): %s", pr.DecryptedResponse)
			} else if pkgLogger != nil {
				h := sha256.Sum256(decBytes)
				pkgLogger.Debugf("Pay: decrypted PG response fingerprint: %x len=%d", h[:6], len(decBytes))
			}

			var d map[string]interface{}
			if err := json.Unmarshal(decBytes, &d); err == nil {
				if tid, ok := d["transactionId"].(string); ok {
					pr.TransactionID = tid
				} else if tid2, ok := d["transaction_id"].(string); ok {
					pr.TransactionID = tid2
				}
			}
		}
	}

	return pr, nil
}
