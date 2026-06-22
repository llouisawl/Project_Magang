/**
 * API Endpoints Configuration
 * Centralized definition of all API endpoints
 * File: api/endpoints.js
 */

(function (global) {
  // ============== ENDPOINT DEFINITIONS ==============
  const Endpoints = {
    // --------- Authentication ---------
    auth: {
      login: "/auth/login",
      logout: "/auth/logout",
      refresh: "/auth/refresh",
      verify: "/auth/verify",
    },

    // --------- Kertas Kerja (Admin) ---------
    kertasKerja: {
      list: "/kertas-kerja/",
      getAll: `/kertas-kerja/all`,
      validate: (id) => `/kertas-kerja/${id}/validate`,
      upload: "/kertas-kerja/upload",
      delete: (id) => `/kertas-kerja/${id}`,
      download: (id) => `/kertas-kerja/${id}/download`,
    },

    // --------- Data Lelang (Satker) ---------
    dataLelang: {
      list: "/data-lelang",
      get: (id) => `/data-lelang/${id}`,
      create: "/data-lelang/tambah-data",
      update: (id) => `/data-lelang/${id}`,
      delete: (id) => `/data-lelang/${id}`,
      download: "/data-lelang/download",
      upload: "/data-lelang/upload",
      uploadExcel: "/data-lelang/upload-excel",
      merek: "/data-lelang/merek",
        tipe: (merek) => `/data-lelang/tipe?merek=${encodeURIComponent(merek)}`,
    },

    // --------- Hasil Taksir ---------
    hasilTaksir: {
      list: "/hasil-taksir",
      get: (id) => `/hasil-taksir/${id}`,
      create: "/hasil-taksir",
      update: (id) => `/hasil-taksir/${id}`,
      delete: (id) => `/hasil-taksir/${id}`,
      download: "/hasil-taksir/download",
    },

    // --------- Riwayat Perubahan ---------
    riwayat: {
      list: "/riwayat",
      get: (id) => `/riwayat/${id}`,
      filter: "/riwayat/filter",
    },

    // --------- Riwayat Upload ---------
    riwayatUpload: {
      list: "/riwayat-upload",
      get: (id) => `/riwayat-upload/${id}`,
      filter: "/riwayat-upload/filter",
    },

    // --------- User Management ---------
    user: {
      list: "/user/all",
      get: (id) => `/user/${id}`,
      create: "/user",
      update: (id) => `/user/${id}`,
      delete: (id) => `/user/${id}`,
      changePassword: "/user/change-password",
      profile: "/user/profile",
    },

    // --------- Reports ---------
    reports: {
      summary: "/reports/summary",
      detail: "/reports/detail",
      export: "/reports/export",
    },

    // --------- Health Check ---------
    health: {
      check: "/health",
      status: "/status",
    },
  };

  // ============== HELPER FUNCTIONS ==============

  /**
   * Build a full URL from endpoint
   * @param {string} endpoint - Endpoint path or function
   * @param {any[]} params - Parameters for dynamic endpoints
   * @returns {string} Full URL
   */
  function buildUrl(endpoint, ...params) {
    if (typeof endpoint === "function") {
      return endpoint(...params);
    }
    return endpoint;
  }

  /**
   * Get endpoint by path (e.g., 'kertasKerja.list')
   * @param {string} path - Dot notation path
   * @returns {string|function} Endpoint definition
   */
  function getEndpoint(path) {
    const parts = path.split(".");
    let current = Endpoints;

    for (const part of parts) {
      if (current && typeof current === "object") {
        current = current[part];
      } else {
        console.warn(`Endpoint tidak ditemukan: ${path}`);
        return null;
      }
    }

    return current;
  }

  // ============== EXPOSE GLOBALLY ==============
  global.Endpoints = Endpoints;
  global.buildUrl = buildUrl;
  global.getEndpoint = getEndpoint;
})(window);
