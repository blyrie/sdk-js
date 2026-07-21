(function() {
  console.info("[Blyrie SDK] Active Security Middleware v2.0 Initialized");
  console.info("[Blyrie SDK] Modules: Semantic DLP, Behavioral RASP, Zero-Knowledge Telemetry");
  const scriptTag = document.currentScript || document.querySelector('script[src*="sdk.js"]');
  if (!scriptTag) {
    console.error("[Blyrie SDK] Failed to find script tag.");
    return;
  }
    const urlParams = new URLSearchParams(scriptTag.src.split('?')[1]);
  const orgId = urlParams.get('org');
  const mode = urlParams.get('mode') || 'full'; 
    if (!orgId) {
    console.error("[Blyrie SDK] Missing 'org' parameter in script src.");
    return;
  }
    console.log(`[Blyrie SDK] Booting in mode: ${mode.toUpperCase()}`);
    let rules = [];
  const scriptOrigin = new URL(scriptTag.src).origin;
  const BLYRIE_API_URL = scriptOrigin.includes('cdn.blyrie.com') ? 'https://blyrie.com' : scriptOrigin;
  const originalFetch = window.fetch;
  const originalXHR = window.XMLHttpRequest.prototype.send;
  const originalOpen = window.XMLHttpRequest.prototype.open;
  const clientFingerprint = (function() {
    let fp = sessionStorage.getItem('__blyrie_fp');
    if (!fp) {
      fp = 'client_' + Math.random().toString(36).substring(2, 11) + '_' + Date.now().toString(36);
      sessionStorage.setItem('__blyrie_fp', fp);
    }
    return fp;
  })();
  const BlyrieSemanticEngine = {
    patterns: {
      ID_KTP: {
        keyRegex: /^(nik|ktp|no_ktp|nomor_ktp|id_ktp|identity_number|id_number)$/i,
        valRegex: /^(1[1-9]|2[1-2]|3[1-6]|5[1-3]|6[1-5]|7[1-6]|8[1-2]|9[1-4])\d{14}$/
      },
      BPJS_ID: {
        keyRegex: /^(bpjs|no_bpjs|nomor_bpjs|asuransi|insurance_number|noka)$/i,
        valRegex: /^\d{13}$/
      },
      BANK_ACCOUNT: {
        keyRegex: /^(rekening|no_rekening|nomor_rekening|account_number|norek|bank_account)$/i,
        valRegex: /^\d{8,16}$/
      },
      PHONE_ID: {
        keyRegex: /^(phone|no_hp|nomor_hp|telepon|mobile|whatsapp|wa)$/i,
        valRegex: /^(08|\+628|628)\d{8,11}$/
      },
      PHI_DIAGNOSIS: {
        keyRegex: /^(diagnosa|diagnosis|icd10|rekam_medis|medical_notes|riwayat_penyakit|keluhan|tindakan_medis|resep)$/i,
        valRegex: /(hiv|aids|hepatitis|kanker|cancer|tbc|tuberculosis|psikiatri|jiwa|diabetes|sifilis|gonore|aborsi)/i
      },
      SECRET_KEY: {
        keyRegex: /^(password|secret|token|api_key|private_key|key|pin)$/i,
        valRegex: /.+/
      }
    },
    classify: function(dataObj) {
      const result = {
        detected: false,
        classes: [],
        matchedFields: [],
        byteSize: 0,
        entropyScore: 0
      };
      const classSet = new Set();
      function traverse(obj, visited = new Set()) {
        if (visited.has(obj)) return;
        visited.add(obj);
        for (let key in obj) {
          if (!Object.prototype.hasOwnProperty.call(obj, key)) continue;
          const val = obj[key];
          if (typeof val === 'string') {
            result.byteSize += val.length * 2; 
            for (let className in BlyrieSemanticEngine.patterns) {
              const rule = BlyrieSemanticEngine.patterns[className];
              const keyMatch = rule.keyRegex.test(key);
              const isWildcardVal = rule.valRegex.source === '.+' || rule.valRegex.source === '^.+$';
              const valMatch = !isWildcardVal && rule.valRegex.test(val.trim());
              if (keyMatch || valMatch) {
                result.detected = true;
                classSet.add(className);
                if (!result.matchedFields.includes(key)) {
                  result.matchedFields.push(key);
                }
              }
            }
          } else if (typeof val === 'object' && val !== null) {
            traverse(val, visited);
          }
        }
      }
      traverse(dataObj);
      result.classes = Array.from(classSet);
      result.entropyScore = Math.min(1.0, parseFloat((result.matchedFields.length * 0.25).toFixed(2)));
      return result;
    }
  };
  const BlyrieMemoryEngine = {
    _stateKey: '__blyrie_runtime_state',
    _memory: {
      requestTimestamps: [],
      destinationMap: {}, 
      totalPiiBytesTransferred: 0
    },
    init: function() {
      // Memory state is intentionally kept only in JS closure to prevent sessionStorage tampering by XSS
    },
    save: function() {
      // Intentionally left blank. We do not sync to sessionStorage anymore to prevent manipulation.
    },
    recordAndCheck: function(url, method, semanticResult) {
      const now = Date.now();
      const anomalies = [];
      this._memory.requestTimestamps = this._memory.requestTimestamps.filter(t => now - t < 60000);
      this._memory.requestTimestamps.push(now);
      const velocity = this._memory.requestTimestamps.length;
      if (semanticResult.detected) {
        this._memory.totalPiiBytesTransferred += semanticResult.byteSize;
      }
      if (velocity > 60 || (semanticResult.detected && velocity > 20)) {
        anomalies.push({
          type: "VELOCITY_EXCEEDED",
          severity: "WARNING",
          description: `High request velocity detected (${velocity} req/min). Potential scraper/IDOR bot behavior.`
        });
      }
      if (semanticResult.detected) {
        const urlObj = new URL(url, window.location.origin);
        const cleanPath = urlObj.origin + urlObj.pathname;
        const isHighRiskPath = /\/(export|dump|backup|download|csv|raw|query_all)/i.test(cleanPath);
        for (const cls of semanticResult.classes) {
          if (!this._memory.destinationMap[cls]) {
            this._memory.destinationMap[cls] = [cleanPath];
          } else {
            const knownPaths = this._memory.destinationMap[cls];
            if (!knownPaths.includes(cleanPath)) {
              if (isHighRiskPath || knownPaths.length >= 3) {
                anomalies.push({
                  type: "DESTINATION_ANOMALY",
                  severity: "CRITICAL",
                  semanticClass: cls,
                  description: `Sensitive class '${cls}' sent to unfamiliar or high-risk destination '${cleanPath}'. Historical destinations: [${knownPaths.join(', ')}]`
                });
              }
              knownPaths.push(cleanPath);
            }
          }
        }
      }
      if (semanticResult.byteSize > 50000) {
        anomalies.push({
          type: "BULK_EXFILTRATION_ATTEMPT",
          severity: "CRITICAL",
          description: `Unusually large PII/PHI payload size (${Math.round(semanticResult.byteSize / 1024)} KB) in a single request.`
        });
      }
      this.save();
      return {
        anomalies: anomalies,
        metrics: {
          requestsInLastMinute: velocity,
          totalPiiBytesTransferred: this._memory.totalPiiBytesTransferred
        }
      };
    }
  };
  BlyrieMemoryEngine.init();
  const BlyrieBeacon = {
    _queue: [],
    _flushTimer: null,
    sendSignals: function(url, method, anomalies, metrics, semanticResult) {
      if (!anomalies || anomalies.length === 0) return;
      const urlObj = new URL(url, window.location.origin);
      const cleanPath = urlObj.origin + urlObj.pathname;
      for (const anomaly of anomalies) {
        if (anomaly.severity === 'CRITICAL') {
          console.error(`[Blyrie RASP Alert] ${anomaly.type} - ${anomaly.description}`);
        } else {
          console.warn(`[Blyrie RASP Alert] ${anomaly.type} - ${anomaly.description}`);
        }
        this._queue.push({
          type: anomaly.type,
          severity: anomaly.severity,
          semanticClass: anomaly.semanticClass || (semanticResult.classes.length > 0 ? semanticResult.classes.join(',') : null),
          description: anomaly.description,
          byteSize: semanticResult.byteSize,
          count: semanticResult.matchedFields.length,
          entropyScore: semanticResult.entropyScore
        });
      }
      const hasCritical = anomalies.some(a => a.severity === 'CRITICAL');
      if (hasCritical || this._queue.length >= 3) {
        this.flush(cleanPath, method, metrics);
      } else if (!this._flushTimer) {
        this._flushTimer = setTimeout(() => this.flush(cleanPath, method, metrics), 3000);
      }
    },
    flush: function(endpoint, method, metrics) {
      if (this._queue.length === 0) return;
      if (this._flushTimer) {
        clearTimeout(this._flushTimer);
        this._flushTimer = null;
      }
      const signalsToSend = [...this._queue];
      this._queue = [];
      const payload = JSON.stringify({
        organizationId: orgId,
        clientFingerprint: clientFingerprint,
        endpoint: endpoint,
        method: method,
        signals: signalsToSend,
        metrics: metrics || {}
      });
      const beaconUrl = `${BLYRIE_API_URL}/api/sdk/beacon`;
      if (navigator.sendBeacon) {
        try {
          navigator.sendBeacon(beaconUrl, new Blob([payload], { type: 'application/json' }));
          return;
        } catch (e) {
        }
      }
      originalFetch.call(window, beaconUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: payload,
        keepalive: true
      }).catch(() => {});
    }
  };
  let serverPublicKey = null;
  async function importPublicKey(pemString) {
    try {
      const pemHeader = "-----BEGIN PUBLIC KEY-----";
      const pemFooter = "-----END PUBLIC KEY-----";
      let pemContents = pemString.substring(
        pemString.indexOf(pemHeader) + pemHeader.length,
        pemString.indexOf(pemFooter)
      ).replace(/\s/g, '');
            const binaryDerString = window.atob(pemContents);
      const binaryDer = new Uint8Array(binaryDerString.length);
      for (let i = 0; i < binaryDerString.length; i++) {
        binaryDer[i] = binaryDerString.charCodeAt(i);
      }
      serverPublicKey = await window.crypto.subtle.importKey(
        "spki",
        binaryDer.buffer,
        { name: "RSA-OAEP", hash: "SHA-256" },
        true,
        ["encrypt"]
      );
      console.log("[Blyrie SDK] Asymmetric Cryptography (Public Key) ready.");
    } catch (e) {
      console.error("[Blyrie SDK] Failed to import Public Key:", e);
    }
  }
  async function encryptData(text) {
    if (!serverPublicKey) {
      console.error("[Blyrie SDK] CRITICAL: Public key not available. Failing closed to prevent data leakage.");
      throw new Error("Blyrie SDK: Encryption key is missing. Request aborted to prevent sensitive data exposure.");
    }
    const aesKeyBuffer = window.crypto.getRandomValues(new Uint8Array(32));
    const aesKey = await window.crypto.subtle.importKey(
      "raw",
      aesKeyBuffer,
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt"]
    );
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encodedText = new TextEncoder().encode(text);
        const ciphertextBuffer = await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv },
      aesKey,
      encodedText
    );
        const cipherArray = new Uint8Array(ciphertextBuffer);
    const dataPayload = new Uint8Array(iv.length + cipherArray.length);
    dataPayload.set(iv, 0);
    dataPayload.set(cipherArray, iv.length);
    const encryptedAesKeyBuffer = await window.crypto.subtle.encrypt(
      { name: "RSA-OAEP" },
      serverPublicKey,
      aesKeyBuffer
    );
    const encryptedAesKeyArray = new Uint8Array(encryptedAesKeyBuffer);
    const keyLen = encryptedAesKeyArray.length;
    const finalPayload = new Uint8Array(2 + keyLen + dataPayload.length);
        finalPayload[0] = (keyLen >> 8) & 0xFF;
    finalPayload[1] = keyLen & 0xFF;
    finalPayload.set(encryptedAesKeyArray, 2);
    finalPayload.set(dataPayload, 2 + keyLen);
    let binary = '';
    const chunkSize = 8192;
    for (let i = 0; i < finalPayload.length; i += chunkSize) {
        binary += String.fromCharCode.apply(null, finalPayload.subarray(i, i + chunkSize));
    }
    return "blyrie_shield_0x" + btoa(binary);
  }
    function getMatchingRule(url, method) {
    if (!rules || rules.length === 0) return null;
    return rules.find(rule => {
      if (rule.method !== "*" && rule.method.toUpperCase() !== method.toUpperCase()) {
        return false;
      }
      const regexPattern = rule.endpointPattern.replace(/\*/g, '.*');
      const regex = new RegExp(regexPattern);
      return regex.test(url);
    });
  }
  async function processOutgoingPayload(originalBody, matchedRule, url, method) {
    if (!originalBody) return originalBody;
    let bodyType = 'unknown';
    let dataObj = null;
    let parsedJson = false;
    if (typeof FormData !== 'undefined' && originalBody instanceof FormData) {
      bodyType = 'FormData';
    } else if (typeof URLSearchParams !== 'undefined' && originalBody instanceof URLSearchParams) {
      bodyType = 'URLSearchParams';
    } else if (typeof Blob !== 'undefined' && originalBody instanceof Blob) {
      bodyType = 'Blob';
      try {
        const text = await originalBody.text();
        dataObj = JSON.parse(text);
        parsedJson = true;
        bodyType = 'Blob-JSON';
      } catch (e) {}
    } else if (typeof ArrayBuffer !== 'undefined' && (originalBody instanceof ArrayBuffer || ArrayBuffer.isView(originalBody))) {
      bodyType = 'ArrayBuffer';
      try {
        const text = new TextDecoder('utf-8', { fatal: true }).decode(originalBody);
        dataObj = JSON.parse(text);
        parsedJson = true;
        bodyType = 'ArrayBuffer-JSON';
      } catch (e) {}
    } else if (typeof ReadableStream !== 'undefined' && originalBody instanceof ReadableStream) {
      bodyType = 'ReadableStream';
    } else if (typeof Document !== 'undefined' && originalBody instanceof Document) {
      bodyType = 'Document';
    } else if (typeof originalBody === 'string') {
      bodyType = 'string';
      try {
        dataObj = JSON.parse(originalBody);
        parsedJson = true;
      } catch (e) {
      }
    } else if (typeof originalBody === 'object') {
      bodyType = 'object';
      dataObj = originalBody; 
    }
    if (bodyType === 'FormData' || bodyType === 'URLSearchParams') {
      dataObj = Object.create(null);
      for (const [key, val] of originalBody.entries()) {
        if (typeof val === 'string') {
          if (dataObj[key] !== undefined) {
            if (Array.isArray(dataObj[key])) dataObj[key].push(val);
            else dataObj[key] = [dataObj[key], val];
          } else {
            dataObj[key] = val;
          }
        }
      }
    }
    let semanticResult = null;
    if (dataObj) {
      semanticResult = BlyrieSemanticEngine.classify(dataObj);
      const { anomalies, metrics } = BlyrieMemoryEngine.recordAndCheck(url, method, semanticResult);
      if (anomalies && anomalies.length > 0) {
        setTimeout(() => {
          BlyrieBeacon.sendSignals(url, method, anomalies, metrics, semanticResult);
        }, 0);
      }
    }
    let explicitFields = matchedRule ? (matchedRule.fieldsToEncrypt || []) : [];
    if (semanticResult && semanticResult.detected) {
      explicitFields = [...new Set([...explicitFields, ...semanticResult.matchedFields])];
    }
    let isModified = false;
    if (bodyType === 'FormData' || bodyType === 'URLSearchParams') {
      let newData = bodyType === 'FormData' ? new FormData() : new URLSearchParams();
      for (const [key, val] of originalBody.entries()) {
        if (typeof val === 'string' && explicitFields.includes(key) && !val.startsWith("blyrie_shield_0x")) {
          const encryptedVal = await encryptData(val);
          newData.append(key, encryptedVal);
          isModified = true;
        } else {
          newData.append(key, val);
        }
      }
      if (isModified) console.log(`[Blyrie Active DLP] Encrypted sensitive field(s) in ${bodyType}.`);
      return newData;
    } else if (dataObj) {
      async function encryptFieldsRecursive(obj, visited = new Set(), forceEncrypt = false) {
        if (visited.has(obj)) return;
        visited.add(obj);
        for (let key in obj) {
          if (!Object.prototype.hasOwnProperty.call(obj, key)) continue;
          const val = obj[key];
          const shouldEncrypt = forceEncrypt || explicitFields.includes(key);
          if (shouldEncrypt && typeof val === 'string' && !val.startsWith("blyrie_shield_0x")) {
            obj[key] = await encryptData(val);
            isModified = true;
          } else if (typeof val === 'object' && val !== null) {
            await encryptFieldsRecursive(val, visited, shouldEncrypt);
          }
        }
      }
      let targetObj;
      if (parsedJson) {
        targetObj = JSON.parse(originalBody);
      } else {
        try {
          targetObj = typeof structuredClone === 'function' ? structuredClone(dataObj) : JSON.parse(JSON.stringify(dataObj));
        } catch (e) {
          // Deep copy fallback that strips functions to avoid shallow copy mutation bug
          targetObj = JSON.parse(JSON.stringify(dataObj, (key, value) => {
            if (typeof value === 'function') return undefined;
            return value;
          }));
        }
      }
      await encryptFieldsRecursive(targetObj);
            if (isModified) {
        console.log(`[Blyrie Active DLP] Encrypted ${explicitFields.length} sensitive field(s) before network transmission.`);
      }
      if (bodyType === 'string' && parsedJson) {
        return JSON.stringify(targetObj);
      } else if (bodyType === 'Blob-JSON') {
        return new Blob([JSON.stringify(targetObj)], { type: originalBody.type || 'application/json' });
      } else if (bodyType === 'ArrayBuffer-JSON') {
        return new TextEncoder().encode(JSON.stringify(targetObj));
      } else if (bodyType === 'object') {
        return targetObj;
      }
    }
    return originalBody;
  }
  let rulesLoadedPromise = originalFetch.call(window, `${BLYRIE_API_URL}/api/sdk/rules/${orgId}`)
    .then(res => res.json())
    .then(async data => {
      if (data.success) {
        rules = data.rules || [];
        if (rules.length === 0 && mode !== 'display') {
          console.log(`[Blyrie Active DLP] Loaded 0 explicit rules. Semantic Auto-DLP Engine is ACTIVE for standard PII/PHI patterns.`);
        } else if (mode !== 'display') {
          console.log(`[Blyrie Active DLP] Loaded ${rules.length} explicit encryption rule(s) + Semantic DLP Engine.`);
        }
        if (mode !== 'display' && data.publicKey) await importPublicKey(data.publicKey);
      }
    })
    .catch(err => {
      console.error("[Blyrie SDK] Failed to load rules from server.", err);
    });
  async function ensureRulesReady() {
    if (serverPublicKey || mode === 'display') return;
    try {
      await Promise.race([
        rulesLoadedPromise,
        new Promise(resolve => setTimeout(resolve, 3500))
      ]);
    } catch (e) {}
  }
  window.fetch = async function(...args) {
    let [resource, config] = args;
    let url = '';
    let method = 'GET';
    let originalBody = null;
    let isRequestObj = typeof Request !== 'undefined' && resource instanceof Request;
    if (isRequestObj) {
      url = resource.url;
      method = (config && config.method) ? config.method : (resource.method || 'GET');
      if (['POST', 'PUT', 'PATCH'].includes(method.toUpperCase())) {
        if (config && config.body !== undefined) {
          originalBody = config.body;
        } else {
          try {
            const clone = resource.clone();
            const ct = clone.headers.get('content-type') || '';
            if (ct.includes('multipart/form-data')) {
              originalBody = await clone.formData();
            } else if (ct.includes('application/x-www-form-urlencoded')) {
              const textParams = await clone.text();
              originalBody = new URLSearchParams(textParams);
            } else if (ct.includes('application/json') || ct.includes('text/')) {
              originalBody = await clone.text();
            } else {
              originalBody = await clone.blob();
            }
          } catch(e) {
            try { 
              originalBody = await resource.clone().text(); 
            } catch(err) {
              console.error("[Blyrie SDK] CRITICAL: Failed to parse Request body stream. Blocking request to prevent data leakage.");
              throw new Error("Blyrie SDK: Uncloneable request body blocked.");
            }
          }
        }
      }
    } else {
      if (typeof resource === 'string') {
        url = resource;
      } else if (resource && typeof resource === 'object') {
        url = resource.url || (typeof resource.toString === 'function' ? resource.toString() : '');
      }
      method = (config && config.method) ? config.method : 'GET';
      if (config && config.body !== undefined) {
        originalBody = config.body;
      }
    }
        try {
      url = new URL(url, window.location.origin).href;
    } catch(e) {}
    if (url && url.includes('/api/sdk/')) {
      return originalFetch.apply(window, args);
    }
    await ensureRulesReady();
    const matchedRule = getMatchingRule(url, method);
    if (mode !== 'display' && url.includes('?')) {
      const qs = url.split('?')[1];
      const params = Object.fromEntries(new URLSearchParams(qs));
      const semanticResult = BlyrieSemanticEngine.classify(params);
      if (semanticResult && semanticResult.detected) {
        const { anomalies, metrics } = BlyrieMemoryEngine.recordAndCheck(url, method, semanticResult);
        if (anomalies && anomalies.length > 0) {
          setTimeout(() => BlyrieBeacon.sendSignals(url, method, anomalies, metrics, semanticResult), 0);
        }
        console.error("[Blyrie RASP] CRITICAL: Sensitive data detected in URL Query String. Request blocked.");
        throw new Error("Blyrie SDK: Request blocked due to sensitive PII in URL GET parameters.");
      }
    }
    if (mode !== 'display' && originalBody !== null && originalBody !== undefined) {
      const processedBody = await processOutgoingPayload(originalBody, matchedRule, url, method);
            if (isRequestObj && (!config || config.body === undefined)) {
        const newInit = { body: processedBody };
        if (typeof FormData !== 'undefined' && processedBody instanceof FormData) {
          const newHeaders = new Headers(resource.headers);
          newHeaders.delete('Content-Type');
          newInit.headers = newHeaders;
        }
        resource = new Request(resource, newInit);
        args[0] = resource;
      } else {
        if (!config) config = {};
                let finalBody = processedBody;
        if (typeof finalBody === 'object' && finalBody !== null &&
            !(finalBody instanceof FormData) && 
            !(finalBody instanceof URLSearchParams) && 
            !(finalBody instanceof Blob) && 
            !(finalBody instanceof ArrayBuffer) &&
            !(typeof ArrayBuffer !== 'undefined' && ArrayBuffer.isView(finalBody)) &&
            !(typeof ReadableStream !== 'undefined' && finalBody instanceof ReadableStream) &&
            !(typeof Document !== 'undefined' && finalBody instanceof Document)) {
          finalBody = JSON.stringify(finalBody);
        }
                config.body = finalBody;
        args[1] = config;
      }
    }
        // (Debug log removed to prevent URL parameter leakage in production)
    return originalFetch.apply(window, args);
  };
  Object.defineProperty(window, 'fetch', {
    value: window.fetch,
    writable: false,
    configurable: false
  });
    window.XMLHttpRequest.prototype.open = function(method, url, async) {
    this._blyrieMethod = method;
    this._blyrieAsync = async !== false; 
    try {
      this._blyrieUrl = new URL(url, window.location.origin).href;
    } catch(e) {
      this._blyrieUrl = url;
    }
    if (mode !== 'display' && typeof this._blyrieUrl === 'string' && this._blyrieUrl.includes('?')) {
      const qs = this._blyrieUrl.split('?')[1];
      const params = Object.fromEntries(new URLSearchParams(qs));
      const semanticResult = BlyrieSemanticEngine.classify(params);
      if (semanticResult && semanticResult.detected) {
        console.error("[Blyrie RASP] CRITICAL: Sensitive data detected in XHR URL. Request blocked.");
        throw new Error("Blyrie SDK: XHR blocked due to sensitive PII in URL.");
      }
    }
    return originalOpen.apply(this, arguments);
  };
  window.XMLHttpRequest.prototype.send = function(body) {
    if (this._blyrieUrl && !this._blyrieUrl.includes('/api/sdk/') && body !== undefined && body !== null) {
       if (mode === 'display') {
         return originalXHR.apply(this, [body]);
       }
       if (this._blyrieAsync === false) {
           console.error("[Blyrie SDK] CRITICAL: Synchronous XHR is not supported by Web Crypto API. Request blocked to prevent PII leakage.");
           this.dispatchEvent(new ProgressEvent("error"));
           throw new Error("Blyrie SDK: Synchronous XHR aborted for security reasons.");
       }
              ensureRulesReady().then(() => {
         const matchedRule = getMatchingRule(this._blyrieUrl, this._blyrieMethod || 'POST');
         return processOutgoingPayload(body, matchedRule, this._blyrieUrl, this._blyrieMethod || 'POST');
       }).then(processedBody => {
          let finalBody = processedBody;
          if (typeof finalBody === 'object' && finalBody !== null &&
              !(finalBody instanceof FormData) && 
              !(finalBody instanceof URLSearchParams) && 
              !(finalBody instanceof Blob) && 
              !(finalBody instanceof ArrayBuffer) &&
              !(typeof ArrayBuffer !== 'undefined' && ArrayBuffer.isView(finalBody)) &&
              !(typeof ReadableStream !== 'undefined' && finalBody instanceof ReadableStream) &&
              !(typeof Document !== 'undefined' && finalBody instanceof Document)) {
            finalBody = JSON.stringify(finalBody);
          }
          originalXHR.apply(this, [finalBody]);
       }).catch(err => {
          console.error("[Blyrie SDK] XHR processing aborted for security:", err.message);
          this.dispatchEvent(new ProgressEvent("error"));
       });
       return;
    }
    return originalXHR.apply(this, [body]);
  };
    Object.defineProperty(window.XMLHttpRequest.prototype, 'send', {
    value: window.XMLHttpRequest.prototype.send,
    writable: false,
    configurable: false
  });
  Object.defineProperty(window.XMLHttpRequest.prototype, 'open', {
    value: window.XMLHttpRequest.prototype.open,
    writable: false,
    configurable: false
  });
  if (navigator.sendBeacon) {
    const originalSendBeacon = navigator.sendBeacon;
    navigator.sendBeacon = function(url, data) {
      if (mode === 'display') return originalSendBeacon.apply(this, arguments);
      console.warn("[Blyrie RASP] Intercepted sendBeacon, routing via secure async fetch...");
      window.fetch(url, { method: 'POST', body: data, keepalive: true }).catch(() => {});
      return true;
    };
    Object.defineProperty(navigator, 'sendBeacon', { value: navigator.sendBeacon, writable: false, configurable: false });
  }
  if (window.WebSocket) {
    const OriginalWebSocket = window.WebSocket;
    function SecureWebSocket(url, protocols) {
      const urlStr = url.toString();
      if (mode !== 'display' && urlStr.includes('?')) {
        const queryParams = Object.fromEntries(new URLSearchParams(urlStr.split('?')[1]));
        const semanticResult = BlyrieSemanticEngine.classify(queryParams);
        if (semanticResult && semanticResult.detected) {
          console.error("[Blyrie RASP] CRITICAL: Blocked WebSocket connection containing sensitive PII in URL.");
          throw new Error("Blyrie SDK: Blocked WebSocket connection containing sensitive data in URL.");
        }
      }
      const ws = new OriginalWebSocket(url, protocols);
      const originalSend = ws.send;
      ws.send = function(data) {
        if (mode === 'display') return originalSend.apply(this, arguments);
        if (typeof data === 'string') {
          try {
            const parsed = JSON.parse(data);
            const semanticResult = BlyrieSemanticEngine.classify(parsed);
            if (semanticResult && semanticResult.detected) {
               console.error("[Blyrie RASP] CRITICAL: Blocked WebSocket from sending sensitive PII.");
               return; 
            }
          } catch(e) {}
        }
        return originalSend.apply(this, arguments);
      };
      return ws;
    }
    SecureWebSocket.prototype = OriginalWebSocket.prototype;
    SecureWebSocket.CONNECTING = OriginalWebSocket.CONNECTING;
    SecureWebSocket.OPEN = OriginalWebSocket.OPEN;
    SecureWebSocket.CLOSING = OriginalWebSocket.CLOSING;
    SecureWebSocket.CLOSED = OriginalWebSocket.CLOSED;
    window.WebSocket = SecureWebSocket;
    Object.defineProperty(window, 'WebSocket', { value: window.WebSocket, writable: false, configurable: false });
  }
  if (window.Worker) {
    const OriginalWorker = window.Worker;
    window.Worker = function(scriptURL, options) {
      if (mode !== 'display') {
        const urlStr = scriptURL.toString();
        if (urlStr.startsWith('blob:') || urlStr.startsWith('data:')) {
           console.error("[Blyrie RASP] CRITICAL: Blocked untrusted inline Web Worker (Blob/Data URI).");
           throw new Error("Blyrie SDK: Inline Web Workers are blocked to prevent RASP bypass.");
        }
      }
      return new OriginalWorker(scriptURL, options);
    };
    Object.defineProperty(window, 'Worker', { value: window.Worker, writable: false, configurable: false });
  }
})();
