/**
 * API Configuration
 * Centralized configuration management untuk aplikasi
 */

(function (global) {
  // ============== ENVIRONMENT & BASE URL ==============
  const ENV = {
    development: "http://localhost:8080",
    staging: "https://staging.api.example.com",
    production: "https://pvvtr4cd-8080.asse.devtunnels.ms/",
  };

  // Tentukan environment (bisa dari URL params atau hardcoded)
  const CURRENT_ENV = (() => {
    const params = new URLSearchParams(window.location.search);
    const env = params.get("env") || "production";
    return env in ENV ? env : "production";
  })();

  const API_BASE_URL = (
    window.API_URL ||
    window.API_BASE ||
    ENV[CURRENT_ENV] ||
    ENV.production
  ).replace(/\/+$/, "");

  // ============== API CONFIGURATION ==============
  const ApiConfig = {
    // Base URL dan environment
    API_BASE_URL,
    ENV: CURRENT_ENV,

    // Timeout untuk requests (ms)
    REQUEST_TIMEOUT: 30000,

    // Retry configuration
    RETRY: {
      enabled: true,
      maxAttempts: 3,
      delayMs: 1000,
      backoffMultiplier: 2,
      retryableStatuses: [408, 429, 500, 502, 503, 504],
    },

    // Cache configuration
    CACHE: {
      enabled: true,
      ttlMs: 5 * 60 * 1000, // 5 menit
      storageKey: "api_cache",
    },

    // Logging
    LOG: {
      enabled: true,
      logRequests: true,
      logResponses: true,
      logErrors: true,
      logLevel: CURRENT_ENV === "production" ? "warn" : "debug",
    },

    // Request/Response interceptors
    INTERCEPTORS: {
      enabled: true,
    },

    // Role-based token keys
    TOKEN_KEYS: {
      satker: "jwt_satker",
      admin: "jwt_admin",
      superadmin: "jwt_superadmin",
    },

    // Default headers
    DEFAULT_HEADERS: {
      "Content-Type": "application/json",
    },
  };

  // ============== HELPER FUNCTIONS ==============
  function getApiUrl(path = "") {
    const basePath = ApiConfig.API_BASE_URL;
    const cleanPath = String(path || "").replace(/^\/+/, "");
    if (/^https?:\/\//i.test(path)) return path;
    return cleanPath ? `${basePath}/${cleanPath}` : basePath;
  }

  function getToken(role = null) {
    if (!role) {
      // Try to get any available token
      for (const [, key] of Object.entries(ApiConfig.TOKEN_KEYS)) {
        const token = localStorage.getItem(key);
        if (token) return token;
      }
      return null;
    }
    const key = ApiConfig.TOKEN_KEYS[role];
    return key ? localStorage.getItem(key) : null;
  }

  // ============== EXPOSE GLOBALLY ==============
  global.ApiConfig = ApiConfig;
  global.API_BASE_URL = API_BASE_URL;
  global.API_URL = API_BASE_URL; // Backward compatibility
  global.getApiUrl = getApiUrl;
  global.getToken = getToken;
})(window);
