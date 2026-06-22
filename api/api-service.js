/**
 * API Service Layer
 * High-level API methods organized by feature/module
 * File: api/api-service.js
 */

(function (global) {
  // ============== API SERVICE FACTORY ==============
  class ApiService {
    constructor(httpClient) {
      this.http = httpClient;
      this.setupServices();
    }

    setupServices() {
      /**
       * Authentication Service
       */
      this.auth = {
        login: async (username, password) => {
          return this.http.post(Endpoints.auth.login, {
            username,
            password,
          });
        },

        logout: async () => {
          return this.http.post(Endpoints.auth.logout, {});
        },

        refresh: async () => {
          return this.http.post(Endpoints.auth.refresh, {});
        },

        verify: async () => {
          return this.http.get(Endpoints.auth.verify);
        },
      };

      /**
       * Kertas Kerja Service (Admin)
       */
      this.kertasKerja = {
        list: async (filters = {}) => {
          return this.http.get(Endpoints.kertasKerja.list, {
            useCache: true,
            ...filters,
          });
        },

        get: async (id) => {
          return this.http.get(Endpoints.kertasKerja.get(id), {
            useCache: true,
          });
        },

        validate: async (id, data) => {
          return this.http.patch(
            Endpoints.kertasKerja.validate(id),
            data,
          );
        },

        upload: async (formData) => {
          const config = {
            method: "POST",
            url: Endpoints.kertasKerja.upload,
            body: formData,
          };
          // Jangan set Content-Type header untuk FormData
          return this.http.request({
            ...config,
            headers: {},
          });
        },

        delete: async (id) => {
          return this.http.delete(Endpoints.kertasKerja.delete(id));
        },

        download: async (id) => {
          return this.http.get(Endpoints.kertasKerja.download(id), {
            useCache: false,
          });
        },
      };

      /**
       * Data Lelang Service (Satker)
       */
      this.dataLelang = {
        list: async (filters = {}) => {
          return this.http.get(Endpoints.dataLelang.list, {
            useCache: true,
            ...filters,
          });
        },

        get: async (id) => {
          return this.http.get(Endpoints.dataLelang.get(id), {
            useCache: true,
          });
        },

        create: async (data) => {
          return this.http.post(Endpoints.dataLelang.create, data);
        },

        update: async (id, data) => {
          return this.http.put(
            Endpoints.dataLelang.update(id),
            data,
          );
        },

        delete: async (id) => {
          return this.http.delete(Endpoints.dataLelang.delete(id));
        },

        download: async (filters = {}) => {
          return this.http.get(Endpoints.dataLelang.download, {
            useCache: false,
            ...filters,
          });
        },

        upload: async (formData) => {
          return this.http.request({
            method: "POST",
            url: Endpoints.dataLelang.upload,
            body: formData,
            headers: {},
          });
        },
      };

      /**
       * Hasil Taksir Service
       */
      this.hasilTaksir = {
        list: async (filters = {}) => {
          return this.http.get(Endpoints.hasilTaksir.list, {
            useCache: true,
            ...filters,
          });
        },

        get: async (id) => {
          return this.http.get(Endpoints.hasilTaksir.get(id), {
            useCache: true,
          });
        },

        create: async (data) => {
          return this.http.post(Endpoints.hasilTaksir.create, data);
        },

        update: async (id, data) => {
          return this.http.put(
            Endpoints.hasilTaksir.update(id),
            data,
          );
        },

        delete: async (id) => {
          return this.http.delete(Endpoints.hasilTaksir.delete(id));
        },

        download: async (filters = {}) => {
          return this.http.get(Endpoints.hasilTaksir.download, {
            useCache: false,
            ...filters,
          });
        },
      };

      /**
       * Riwayat Service
       */
      this.riwayat = {
        list: async (filters = {}) => {
          return this.http.get(Endpoints.riwayat.list, {
            useCache: true,
            ...filters,
          });
        },

        get: async (id) => {
          return this.http.get(Endpoints.riwayat.get(id), {
            useCache: true,
          });
        },

        filter: async (criteria) => {
          return this.http.post(Endpoints.riwayat.filter, criteria);
        },
      };

      /**
       * Riwayat Upload Service
       */
      this.riwayatUpload = {
        list: async (filters = {}) => {
          return this.http.get(Endpoints.riwayatUpload.list, {
            useCache: true,
            ...filters,
          });
        },

        get: async (id) => {
          return this.http.get(Endpoints.riwayatUpload.get(id), {
            useCache: true,
          });
        },

        filter: async (criteria) => {
          return this.http.post(
            Endpoints.riwayatUpload.filter,
            criteria,
          );
        },
      };

      /**
       * Master Data Service
       */
      this.master = {
        getKota: async () => {
          return this.http.get(Endpoints.master.kota, {
            useCache: true,
            cache: true,
          });
        },

        getKpknl: async () => {
          return this.http.get(Endpoints.master.kpknl, {
            useCache: true,
            cache: true,
          });
        },

        getJenisKendaraan: async () => {
          return this.http.get(Endpoints.master.jenisKendaraan, {
            useCache: true,
            cache: true,
          });
        },

        getLokasi: async () => {
          return this.http.get(Endpoints.master.lokasi, {
            useCache: true,
            cache: true,
          });
        },

        getSatker: async () => {
          return this.http.get(Endpoints.master.satker, {
            useCache: true,
            cache: true,
          });
        },

        getTipe: async () => {
          return this.http.get(Endpoints.master.tipe, {
            useCache: true,
            cache: true,
          });
        },
      };

      /**
       * User Management Service
       */
      this.user = {
        list: async (filters = {}) => {
          return this.http.get(Endpoints.user.list, { ...filters });
        },

        get: async (id) => {
          return this.http.get(Endpoints.user.get(id));
        },

        create: async (data) => {
          return this.http.post(Endpoints.user.create, data);
        },

        update: async (id, data) => {
          return this.http.put(Endpoints.user.update(id), data);
        },

        delete: async (id) => {
          return this.http.delete(Endpoints.user.delete(id));
        },

        changePassword: async (data) => {
          return this.http.post(
            Endpoints.user.changePassword,
            data,
          );
        },

        getProfile: async () => {
          return this.http.get(Endpoints.user.profile);
        },
      };

      /**
       * Reports Service
       */
      this.reports = {
        getSummary: async (filters = {}) => {
          return this.http.get(Endpoints.reports.summary, {
            ...filters,
          });
        },

        getDetail: async (filters = {}) => {
          return this.http.get(Endpoints.reports.detail, {
            ...filters,
          });
        },

        export: async (format, filters = {}) => {
          return this.http.get(Endpoints.reports.export, {
            useCache: false,
            ...filters,
            format,
          });
        },
      };

      /**
       * Health Check Service
       */
      this.health = {
        check: async () => {
          return this.http.get(Endpoints.health.check, {
            useCache: false,
          });
        },

        status: async () => {
          return this.http.get(Endpoints.health.status);
        },
      };
    }
  }

  // ============== INITIALIZE GLOBAL API SERVICE ==============
  // Akan di-initialize di file utama (index.html, Admin.html, etc)
  // Sebelum itu, load: config.js → http-client.js → endpoints.js → api-service.js

  function initializeApiService(config = {}) {
    const finalConfig = {
      ...window.ApiConfig,
      ...{
        getApiUrl: (url) => {
          const basePath = window.API_BASE_URL || "";
          const cleanPath = String(url || "").replace(/^\/+/, "");
          if (/^https?:\/\//i.test(url)) return url;
          return cleanPath
            ? `${basePath}/${cleanPath}`
            : basePath;
        },
      },
    };

    const httpClient = new HttpClient(finalConfig);
    return new ApiService(httpClient);
  }

  // ============== EXPOSE GLOBALLY ==============
  global.ApiService = ApiService;
  global.initializeApiService = initializeApiService;
})(window);
