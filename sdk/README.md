# Yagout Direct Payment SDK — Backend (Go)

> Go backend + SDK that performs direct API payment integration with a Payment Gateway.
> This README explains how to configure, run, and use the backend & SDK, shows expected inputs/outputs (HTTP + SDK), and lists helpful troubleshooting notes.

---

## Table of contents

* [What it is](#what-it-is)
* [Repo layout](#repo-layout)
* [Requirements](#requirements)
* [Configuration (`config.properties`)](#configuration-configproperties)
* [Run the backend](#run-the-backend)
* [HTTP API (endpoints)](#http-api-endpoints)

  * [`POST /api/checkout` example request/response](#post-apicheckout-examplerequestresponse)
  * [`GET /api/order/:orderNo` example request/response](#get-apiorderno-examplerequestresponse)
  * Mock gateway used for local testing
* [SDK usage (programmatically in Go)](#sdk-usage-programmatically-in-go)

  * `NewGateway`
  * `Pay` and `PaymentResponse` structure
* [Validation rules summary](#validation-rules-summary)
* [Logging & debug mode](#logging--debug-mode)
* [Security notes](#security-notes)
* [Troubleshooting & common errors](#troubleshooting--common-errors)
* [License & contact](#license--contact)

---

## What it is

This project contains:

* A small Go HTTP backend (Gin) that exposes endpoints for an e-commerce checkout flow.
* An internal SDK package (`backend/sdk`) that:

  * Validates the incoming request,
  * Builds the gateway `merchantRequest` JSON,
  * Encrypts the request (AES-256-CBC + PKCS7, base64-encoded),
  * Sends the envelope to the PG `apiIntegration` endpoint with retries,
  * Decrypts the PG response and returns a `PaymentResponse` to the backend.
* A mock gateway endpoint for local testing.

This backend stores orders in an **in-memory** map (concurrency-safe). Suitable for demos and local testing.

---

## Repo layout (relevant)

```
backend/
  ├─ main.go            # HTTP server + handlers (checkout, order, mock-gateway)
  ├─ config.properties  # example property file (merchant credentials & endpoints etc)
  └─ sdk/
      └─ sdk.go         # SDK implementation (NewGateway, Pay, encrypt/decrypt, etc.)
```

---

## Requirements

* Go 1.20+ (or your installed Go toolchain)
* `go mod tidy` (to fetch dependencies)
* Recommended: run backend on a machine where outbound requests to the configured PG endpoint are allowed.

---

## Configuration (`config.properties`)

Create a `config.properties` file in the `backend/` directory (or the working directory when you run the server).

Example:

```
merchantId=202508080001
merchantKeyBase64=BASE64_ENCODED_32BYTE_KEY_HERE
staticIV=BASE64_OR_PLAIN_IV
pg_apiintegration_endpoint=https://uatcheckout.yagoutpay.com/ms-transaction-core-1-0/apiRedirection/apiIntegration
successUrl=https://your.shop/success
failureUrl=https://your.shop/failure
debug=true
requestTimeoutMs=100000
allowedOrigin=http://localhost:5173
logLevel=debug
```

**Notes**

* `merchantKeyBase64` must be a base64 encoded 32-byte key (AES-256). After decoding it must be exactly 32 bytes.
* `staticIV` may be given as base64 or raw text; code will take the first 16 bytes (or decode from base64).
* `debug=true` writes debug logs into `debug.log` and stdout (only enable in development/trusted environments).

---

## Run the backend

In `backend/`:

```bash
go mod tidy
go run .
```

Or build:

```bash
go build -o yagout-backend .
./yagout-backend
```

Default port: `8080`. Set `PORT` env var to change.

---

## HTTP API (endpoints)

### POST `/api/checkout`

Create a checkout and start payment.

**Request JSON**

```json
{
  "mobileNumber": "0915141414",
  "currency": "ETB",
  "amount": "1.00",
  "customerName": "Biniyam Yosef",
  "wallet": "telebirr",
  "email" : "Biniyam@yagoutpay.com"
}
```

**What the server does**

1. Generates an `orderNo` (e.g. `ORD-xxxxxxx`)
2. Stores an Order with status `initiated`
3. Calls `pg.Pay(sdk.Order{...})` to send the merchant request to the PG
4. Updates the order with `status`, `statusMessage`, `transactionId`, and `responseRaw` (decrypted PG payload)
5. Returns order number and status to client

**Success response**

```json
HTTP/1.1 200 OK
{
  "orderNo": "ORDc0a1b2c3",
  "status": "Success",
  "statusMessage": "Successful"
}
```

**Failure response**

```json
HTTP/1.1 500 Internal Server Error
{
  "error": "description of error"
}
```

---

### GET `/api/order/:orderNo`

Fetch stored order info (in-memory).

**Request**

```
GET /api/order/ORDc0a1b2c3
```

**Response**

```json
HTTP/1.1 200 OK
{
  "order": {
    "orderNo": "ORDc0a1b2c3",
    "mobileNumber": "0939619080",
    "currency": "ETB",
    "amount": "1.00",
    "customerName": "Biniyam",
    "status": "Success",
    "statusMessage": "Successful",
    "transactionId": "2058801756793001551",
    "responseRaw": "{\"txn_response\":{...}}",
    "createdAt": "2025-09-02T12:56:00Z",
    "wallet": "telebirr"
  }
}
```

`responseRaw` is stored as the **decrypted** string returned by the SDK (so it may be a JSON string). The frontend typically parses this string to extract nested fields like `txn_response.pg_ref`, `txn_response.res_message` etc.

---
---

### Mock gateway (local testing)

`POST /mock-gateway` — used when `Endpoint` contains `"mock"` or when the code routes to `http://localhost:8080/mock-gateway`. It returns a JSON containing a base64 encoded `response` field (so the SDK can decrypt it).

---

## SDK usage (programmatically in Go)

### `sdk.NewGateway(cfg *sdk.Config) (*sdk.PaymentGateway, error)`

Initializes the SDK with config. Returns an object with `Pay()`.

Example:

```go
conf, _ := sdk.LoadConfig("config.properties")
pg, _ := sdk.NewGateway(conf)
```

### `pg.Pay(order sdk.Order) (*sdk.PaymentResponse, error)`

* Validates the `order` (mobile, amount, orderNo).
* Builds merchant JSON, encrypts, sends to PG endpoint (with retries), decrypts response.
* Returns `PaymentResponse`.

`PaymentResponse` fields:

```go
type PaymentResponse struct {
  MerchantID        string                 `json:"merchantId"`
  Status            string                 `json:"status"`
  StatusMessage     string                 `json:"statusMessage"`      // top-level message returned by PG (if any)
  EncryptedResponse string                 `json:"response"`           // base64 ciphertext returned by PG
  DecryptedResponse string                 `json:"decryptedResponse"`  // decrypted JSON payload (string)
  TransactionID     string                 `json:"transactionId,omitempty"` // filled when SDK extracts transaction id if it exist
  Raw               map[string]interface{} `json:"raw,omitempty"`      // raw PG response parsed into a map
}
```

**Note:** The SDK **tries** to extract `transactionId` and a human `statusMessage` from the decrypted payload (it checks top-level keys and nested `txn_response` keys such as `res_message`, `ag_ref`, `pg_ref`). If your PG nests these in `txn_response`, the SDK will pick them up.

---

## Example: What the SDK returns after successful PG response

Suppose the PG returns (post-decryption) this payload:

```json
{
  "txn_response": {
    "ag_id": "yagout",
    "me_id": "202508080001",
    "order_no": "ORD62159898",
    "amount": "1.00",
    "country": "ETH",
    "currency": "ETB",
    "txn_date": "2025-09-02",
    "txn_time": "12:55:58",
    "ag_ref": "2058801756793001551",
    "pg_ref": "AG_20250902_70600c9bfcd59c5ad5b3",
    "status": "Successful",
    "res_code": "0",
    "res_message": "Successful"
  },
  "pg_details": {
    "pg_id": "67ee846571e740418d688c3f",
    "pg_name": "YAGOUTPAY_MIDDLEWARE",
    "paymode": "WA"
  },
  "fraud_details": {},
  "other_details": {}
}
```

The SDK returns a `PaymentResponse` JSON similar to:

```json
{
  "merchantId": "202508080001",
  "status": "Success",
  "statusMessage": "No Error",               // if PG provided a top-level statusMessage
  "response": "<BASE64_ENCRYPTED_PAYLOAD>",
  "decryptedResponse": "{\"txn_response\":{...}}",
  "transactionId": "2058801756793001551",
  "raw": {
    "merchantId": "202508080001",
    "status": "Success",
    "statusMessage": "No Error",
    "response": "<BASE64_ENCRYPTED_PAYLOAD>"
  }
}
```

> The `transactionId` is populated by the SDK by looking into top-level or `txn_response` keys (`ag_ref` or `pg_ref`).

---

## Validation rules summary

(Implemented in SDK `ValidateTransaction` and helper spec; this is a short summary.)

* `order_no`: alphanumeric, max length 70
* `amount`: numeric up to 10 digits and optional 1-2 decimals (regex: `^\d{1,10}(?:\.\d{1,2})?$`)
* `currency`: 1-3 alnum characters
* `mobile_no`: local format `^0[97]\d{8}$` (e.g. `0912345678` or `0799999999`)
* `email_id`: standard email regex (if supplied)
* name fields: alphabets and spaces only

If validation fails, `pg.Pay` returns an error; the HTTP endpoint returns `400` for malformed input JSON and `500` when SDK fails.

---

## Logging & debug mode

* When `debug=true` in `config.properties`, the SDK writes detailed logs to `debug.log` and stdout (includes merchant request, encrypted payload, decrypted response — **sensitive data**) at debug level.
* Disable debug in production to avoid leaking sensitive info.

---

## Security notes

* Keep `merchantKeyBase64` secret. This key decrypts/encrypts traffic to/from the gateway.
* Do not enable `debug=true` in production, because it logs merchant requests and decrypted responses.
* Rotate keys when needed and ensure TLS for outgoing requests to PG endpoints.
* `config.properties` must be protected (file system permissions).

---

## Troubleshooting & common errors

* **`key must be 32 bytes after base64 decode`**
  Ensure `merchantKeyBase64` decodes to 32 bytes (AES-256 key). If it decodes to shorter/longer bytes you will get this error.

* **Invalid IV length / ciphertext not multiple of block**
  Make sure `staticIV` decodes to >= 16 bytes or is a proper 16 byte textual IV.

* **PG returns non-200 or malformed JSON**
  SDK tries exponential backoff for transient server errors (`5xx`), but it treats `4xx` responses as permanent errors.

* **`decrypt error: invalid padding`**
  Indicates mismatched key/iv or corrupted ciphertext. Check key/iv correctness.

* **No transaction ID appears in the order**
  If the PG puts transaction reference keys under a different nested structure than `txn_response.ag_ref` or `txn_response.pg_ref`, update the SDK or add parsing logic to extract the correct field.

---
---

## License & contact

This repository is provided as-is for integration and demo purposes. Modify and adapt as needed.