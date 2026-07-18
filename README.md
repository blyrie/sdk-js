# Blyrie Web SDK

The **Blyrie Web SDK** is a zero-code active security middleware designed to encrypt sensitive PII (Personally Identifiable Information) directly in the user's browser before it ever reaches your servers. 

By encrypting data at the edge (in the browser), you ensure that your backend database remains secure even in the event of a breach. Blyrie operates on a **Zero-Knowledge** architecture: we hold the keys, you hold the encrypted data.

## Features

- **Zero-Code Integration**: Drop a single `<script>` tag into your HTML. No complex build tools required.
- **Semantic Auto-DLP**: Automatically detects and encrypts sensitive fields like ID numbers, Credit Cards, and Bank Accounts based on pattern recognition.
- **In-Browser Encryption**: Uses standard Web Crypto API (RSA-OAEP + AES-GCM) to encrypt data *before* network transmission.
- **Zero-Knowledge Architecture**: Private keys never leave the Blyrie KMS (Key Management Service). 

## Installation & Usage

Include the SDK in the `<head>` of your HTML document. You will need your Organization ID, which you can get for free at the [Blyrie Dashboard](https://blyrie.com).

### 1. Capture Mode (Public Forms)

Use `mode=capture` on your public-facing pages (e.g., registration forms, checkout pages, contact forms). 

```html
<script src="https://cdn.blyrie.com/sdk.js?org=YOUR_ORG_ID&mode=capture"></script>
```

**What it does:** 
In capture mode, the SDK intercepts outgoing API requests (via `fetch` and `XMLHttpRequest`). If a request contains sensitive data (based on your Encryption Rules), the SDK encrypts the data into a secure `BLYRIE_ENC(...)` payload before sending it to your backend. Your database will safely store the encrypted payload.

### 2. Display Mode (Admin Dashboards)

Use `mode=display` on your internal admin dashboards where you do not want to encrypt outgoing requests (e.g., searching for a user, submitting admin configuration).

```html
<script src="https://cdn.blyrie.com/sdk.js?org=YOUR_ORG_ID&mode=display"></script>
```

**What it does:**
In display mode, the SDK goes into an **"idle" state**. It will **not** encrypt any outgoing requests. This prevents the SDK from accidentally encrypting admin activities.

> **IMPORTANT: The SDK NEVER decrypts data.** 
> To decrypt and display data in your Admin Dashboard, your backend server must request decryption via the Blyrie Server-to-Server API using your secret API Key. Your backend then sends the plaintext data to your dashboard frontend.

### 3. Recommended Security Headers (CSP)

While the Blyrie SDK actively protects against data exfiltration via `fetch`, `XMLHttpRequest`, `WebSocket`, `sendBeacon`, and `Web Worker`, advanced attackers may attempt to leak data via native DOM elements like `<iframe>` or `<img src="...">` (DOM-based Data Exfiltration). 

To achieve bulletproof client-side security, it is highly recommended to configure a strict **Content Security Policy (CSP)** header on your web server alongside the SDK.

Example CSP Header:
```http
Content-Security-Policy: default-src 'self' https://api.blyrie.com; img-src 'self' data:; connect-src 'self' https://api.blyrie.com; frame-src 'none';
```
This forces the browser engine to block unauthorized external image requests, WebRTC channels, or hidden iframes that malware might use to bypass JavaScript-based RASP.

## Decrypting Data (Server-Side)

To view the original data, your backend must send the encrypted payload to the Blyrie Decryption API.

```bash
curl -X POST https://api.blyrie.com/api/v1/decrypt \
  -H "Content-Type: application/json" \
  -H "x-api-key: YOUR_SECRET_API_KEY" \
  -d '{
    "organizationId": "YOUR_ORG_ID",
    "encryptedPayload": "BLYRIE_ENC(.....)"
  }'
```

The Blyrie KMS will decrypt the payload in-memory and return the plaintext data to your server.

## Security & Trust

This SDK is completely open-source. We believe in absolute transparency when it comes to cybersecurity. You can inspect the `sdk.js` file to verify that it uses standard browser cryptography (`window.crypto.subtle`) and does not contain any hidden telemetry, malware, or backdoors.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
