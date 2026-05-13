/**
 * HTTP Client dengan Interceptors, Error Handling, & Retry Logic
 * File: api/http-client.js
 */

(function (global) {
  // ============== LOGGER ==============
  class Logger {
    constructor(config = {}) {
      this.enabled = config.enabled !== false;
      this.level = config.level || "debug";
      this.logRequests = config.logRequests !== false;
      this.logResponses = config.logResponses !== false;
      this.logErrors = config.logErrors !== false;
    }

    log(level, message, data = null) {
      if (!this.enabled) return;

      const levelMap = { debug: 0, info: 1, warn: 2, error: 3 };
      if (levelMap[level] < levelMap[this.level]) return;

      const timestamp = new Date().toISOString();
      const prefix = `[${timestamp}] [API] [${level.toUpperCase()}]`;

      if (data) {
        console[level === "error" ? "error" : level](prefix, message, data);
      } else {
        console[level === "error" ? "error" : level](prefix, message);
      }
    }

    request(method, url, body) {
      if (this.logRequests) {
        this.log("debug", `→ ${method} ${url}`, body ? { body } : null);
      }
    }

    response(method, url, status, data) {
      if (this.logResponses) {
        this.log("debug", `← ${method} ${url} [${status}]`, data);
      }
    }

    error(message, error) {
      if (this.logErrors) {
        this.log("error", message, error);
      }
    }
  }

  // ============== CACHE MANAGER ==============
  class CacheManager {
    constructor(config = {}) {
      this.enabled = config.enabled !== false;
      this.ttlMs = config.ttlMs || 5 * 60 * 1000;
      this.storageKey = config.storageKey || "api_cache";
      this.cache = new Map();
      this.loadFromStorage();
    }

    loadFromStorage() {
      if (!this.enabled) return;
      try {
        const stored = sessionStorage.getItem(this.storageKey);
        if (stored) {
          const data = JSON.parse(stored);
          this.cache = new Map(Object.entries(data));
        }
      } catch (e) {
        console.warn("Failed to load cache from storage");
      }
    }

    saveToStorage() {
      if (!this.enabled) return;
      try {
        const data = Object.fromEntries(this.cache);
        sessionStorage.setItem(this.storageKey, JSON.stringify(data));
      } catch (e) {
        console.warn("Failed to save cache to storage");
      }
    }

    set(key, value) {
      if (!this.enabled) return;
      this.cache.set(key, {
        value,
        expiresAt: Date.now() + this.ttlMs,
      });
      this.saveToStorage();
    }

    get(key) {
      if (!this.enabled) return null;
      const entry = this.cache.get(key);
      if (!entry) return null;

      if (Date.now() > entry.expiresAt) {
        this.cache.delete(key);
        this.saveToStorage();
        return null;
      }

      return entry.value;
    }

    clear() {
      this.cache.clear();
      try {
        sessionStorage.removeItem(this.storageKey);
      } catch {}
    }
  }

  // ============== REQUEST/RESPONSE INTERCEPTORS ==============
  class Interceptors {
    constructor() {
      this.requestInterceptors = [];
      this.responseInterceptors = [];
      this.errorInterceptors = [];
    }

    addRequest(handler) {
      this.requestInterceptors.push(handler);
    }

    addResponse(handler) {
      this.responseInterceptors.push(handler);
    }

    addError(handler) {
      this.errorInterceptors.push(handler);
    }

    async executeRequest(config) {
      let request = config;
      for (const handler of this.requestInterceptors) {
        request = await handler(request);
      }
      return request;
    }

    async executeResponse(response) {
      let resp = response;
      for (const handler of this.responseInterceptors) {
        resp = await handler(resp);
      }
      return resp;
    }

    async executeError(error) {
      let err = error;
      for (const handler of this.errorInterceptors) {
        err = await handler(err);
      }
      return err;
    }
  }

  // ============== HTTP CLIENT ==============
  class HttpClient {
    constructor(config = {}) {
      this.config = { ...config };
      this.logger = new Logger(config.LOG || {});
      this.cache = new CacheManager(config.CACHE || {});
      this.interceptors = new Interceptors();
      this.abortControllers = new Map();
      this.setupDefaultInterceptors();
    }

    setupDefaultInterceptors() {
      // Default request interceptor: add auth token
      this.interceptors.addRequest(async (config) => {
        const token = window.getToken?.() || null;
        if (token) {
          config.headers = {
            ...config.headers,
            Authorization: `Bearer ${token}`,
          };
        }
        return config;
      });

      // Default error interceptor: handle 401
      this.interceptors.addError(async (error) => {
        if (error.status === 401) {
          // Clear all tokens
          Object.keys(this.config.TOKEN_KEYS || {}).forEach((role) => {
            const key = this.config.TOKEN_KEYS[role];
            localStorage.removeItem(key);
          });
          // Redirect to login
          setTimeout(() => {
            window.location.href = "daftar.html";
          }, 500);
        }
        throw error;
      });
    }

    generateCacheKey(method, url, body) {
      const bodyStr = body ? JSON.stringify(body) : "";
      return `${method}:${url}:${bodyStr}`;
    }

    async timeout(promise, ms) {
      return Promise.race([
        promise,
        new Promise((_, reject) =>
          setTimeout(
            () => reject(new Error("Request timeout")),
            ms,
          ),
        ),
      ]);
    }

    async retry(
      fn,
      maxAttempts = 3,
      delayMs = 1000,
      backoffMultiplier = 2,
    ) {
      let lastError;
      for (let attempt = 1; attempt <= maxAttempts; attempt++) {
        try {
          return await fn();
        } catch (error) {
          lastError = error;
          if (attempt < maxAttempts) {
            const delay = delayMs * Math.pow(backoffMultiplier, attempt - 1);
            await new Promise((resolve) => setTimeout(resolve, delay));
          }
        }
      }
      throw lastError;
    }

    async request(config) {
      const {
        method = "GET",
        url,
        body = null,
        headers = {},
        cache = true,
        useCache = true,
        timeout = this.config.REQUEST_TIMEOUT,
        retry = this.config.RETRY?.enabled,
      } = config;

      const fullUrl = this.config.getApiUrl
        ? this.config.getApiUrl(url)
        : url;

      // Check cache for GET requests
      if (
        useCache &&
        cache &&
        method === "GET" &&
        this.cache.enabled
      ) {
        const cacheKey = this.generateCacheKey(method, fullUrl, body);
        const cached = this.cache.get(cacheKey);
        if (cached) {
          this.logger.log("debug", `✓ Cache hit: ${method} ${fullUrl}`);
          return cached;
        }
      }

      // Build request config
      let fetchConfig = {
        method,
        headers: {
          ...this.config.DEFAULT_HEADERS,
          ...headers,
        },
        getApiUrl: this.config.getApiUrl,
      };

      if (body && method !== "GET") {
        fetchConfig.body =
          typeof body === "string" ? body : JSON.stringify(body);
      }

      // Apply request interceptors
      if (this.config.INTERCEPTORS?.enabled) {
        fetchConfig = await this.interceptors.executeRequest(fetchConfig);
      }

      // Log request
      this.logger.request(method, fullUrl, body);

      // Create abort controller
      const abortController = new AbortController();
      const requestId = `${Date.now()}-${Math.random()}`;
      this.abortControllers.set(requestId, abortController);
      fetchConfig.signal = abortController.signal;

      try {
        // Execute with retry if enabled
        const execute = () =>
          this.timeout(
            fetch(fullUrl, fetchConfig),
            timeout,
          );

        const response = retry
          ? await this.retry(
              execute,
              this.config.RETRY.maxAttempts,
              this.config.RETRY.delayMs,
              this.config.RETRY.backoffMultiplier,
            )
          : await execute();

        this.abortControllers.delete(requestId);

        // Parse response
        const contentType = response.headers.get("content-type") || "";
        let data;

        if (contentType.includes("application/json")) {
          data = await response.json();
        } else if (contentType.includes("text")) {
          data = await response.text();
        } else if (contentType.includes("blob")) {
          data = await response.blob();
        } else {
          data = await response.text();
        }

        // Handle non-ok responses
        if (!response.ok) {
          const error = new Error(
            data?.message || data?.error || `HTTP ${response.status}`,
          );
          error.status = response.status;
          error.data = data;
          error.response = response;

          // Apply error interceptors
          if (this.config.INTERCEPTORS?.enabled) {
            throw await this.interceptors.executeError(error);
          }
          throw error;
        }

        // Log response
        this.logger.response(method, fullUrl, response.status, data);

        // Cache GET responses
        if (
          useCache &&
          cache &&
          method === "GET" &&
          this.cache.enabled &&
          response.ok
        ) {
          const cacheKey = this.generateCacheKey(
            method,
            fullUrl,
            body,
          );
          this.cache.set(cacheKey, data);
        }

        // Apply response interceptors
        if (this.config.INTERCEPTORS?.enabled) {
          return await this.interceptors.executeResponse(data);
        }

        return data;
      } catch (error) {
        this.logger.error(`${method} ${fullUrl} failed`, error);

        // Apply error interceptors
        if (this.config.INTERCEPTORS?.enabled) {
          throw await this.interceptors.executeError(error);
        }
        throw error;
      }
    }

    get(url, config = {}) {
      return this.request({ ...config, method: "GET", url });
    }

    post(url, body, config = {}) {
      return this.request({ ...config, method: "POST", url, body });
    }

    put(url, body, config = {}) {
      return this.request({ ...config, method: "PUT", url, body });
    }

    patch(url, body, config = {}) {
      return this.request({ ...config, method: "PATCH", url, body });
    }

    delete(url, config = {}) {
      return this.request({ ...config, method: "DELETE", url });
    }

    abort(requestId) {
      const controller = this.abortControllers.get(requestId);
      if (controller) {
        controller.abort();
        this.abortControllers.delete(requestId);
      }
    }

    clearCache() {
      this.cache.clear();
    }
  }

  // ============== EXPOSE GLOBALLY ==============
  global.HttpClient = HttpClient;
  global.Logger = Logger;
  global.CacheManager = CacheManager;
  global.Interceptors = Interceptors;
})(window);
