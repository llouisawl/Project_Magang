# API Refactoring Documentation

Dokumentasi lengkap untuk sistem API yang sudah di-refactor. Struktur ini dirancang untuk menjadi maintainable, scalable, dan developer-friendly.

## 📁 Struktur File

```
api/
├── config.js              # Konfigurasi global aplikasi
├── http-client.js         # HTTP Client dengan interceptors & retry logic
├── endpoints.js           # Definisi endpoint API
├── api-service.js         # High-level API service methods
└── README.md             # Dokumentasi ini
```

## 🚀 Quick Start

### 1. Load Scripts dalam Order yang Benar

Tambahkan di `<head>` atau sebelum `</body>`:

```html
<!-- ✅ PASTIKAN URUTAN INI BENAR -->
<script src="api/config.js"></script>
<script src="api/http-client.js"></script>
<script src="api/endpoints.js"></script>
<script src="api/api-service.js"></script>
<script src="auth.js"></script>

<script>
  // Initialize API service setelah semua module loaded
  const api = window.initializeApiService();
  
  // Sekarang bisa pakai secara global:
  // api.auth.login()
  // api.kertasKerja.list()
  // api.dataLelang.create()
  // dst...
</script>
```

### 2. Menggunakan API Service

```javascript
// ✅ SIMPLE LOGIN
async function handleLogin(username, password) {
  try {
    const result = await api.auth.login(username, password);
    console.log("Login berhasil:", result);
  } catch (error) {
    console.error("Login gagal:", error.message);
  }
}

// ✅ FETCH DATA DENGAN CACHING OTOMATIS
async function loadKertasKerja() {
  try {
    const list = await api.kertasKerja.list();
    console.log("Data kertas kerja:", list);
  } catch (error) {
    showError(error.message);
  }
}

// ✅ CREATE DATA
async function submitDataLelang(formData) {
  try {
    const result = await api.dataLelang.create(formData);
    showSuccess("Data berhasil ditambahkan");
    return result;
  } catch (error) {
    showError(error.message);
  }
}

// ✅ UPDATE DATA
async function updateHasilTaksir(id, data) {
  try {
    const result = await api.hasilTaksir.update(id, data);
    showSuccess("Data berhasil diperbarui");
  } catch (error) {
    showError(error.message);
  }
}

// ✅ DELETE DATA
async function deleteKertasKerja(id) {
  try {
    await api.kertasKerja.delete(id);
    showSuccess("Data berhasil dihapus");
  } catch (error) {
    showError(error.message);
  }
}

// ✅ DOWNLOAD FILE
async function downloadReport(filters = {}) {
  try {
    const blob = await api.hasilTaksir.download(filters);
    // Trigger download
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "report.xlsx";
    a.click();
    URL.revokeObjectURL(url);
  } catch (error) {
    showError(error.message);
  }
}
```

## 📊 Available Services

### Authentication
```javascript
api.auth.login(username, password)      // → { token, role, name }
api.auth.logout()
api.auth.refresh()
api.auth.verify()
```

### Kertas Kerja (Admin Only)
```javascript
api.kertasKerja.list(filters)          // GET /kertas-kerja/all
api.kertasKerja.get(id)                // GET /kertas-kerja/:id
api.kertasKerja.validate(id, data)     // PATCH /kertas-kerja/:id/validate
api.kertasKerja.upload(formData)       // POST /kertas-kerja/upload
api.kertasKerja.delete(id)             // DELETE /kertas-kerja/:id
api.kertasKerja.download(id)           // GET /kertas-kerja/:id/download
```

### Data Lelang (Satker)
```javascript
api.dataLelang.list(filters)           // GET /data-lelang
api.dataLelang.get(id)                 // GET /data-lelang/:id
api.dataLelang.create(data)            // POST /data-lelang/tambah-data
api.dataLelang.update(id, data)        // PUT /data-lelang/:id
api.dataLelang.delete(id)              // DELETE /data-lelang/:id
api.dataLelang.download(filters)       // GET /data-lelang/download
api.dataLelang.upload(formData)        // POST /data-lelang/upload
```

### Hasil Taksir
```javascript
api.hasilTaksir.list(filters)          // GET /hasil-taksir
api.hasilTaksir.get(id)                // GET /hasil-taksir/:id
api.hasilTaksir.create(data)           // POST /hasil-taksir
api.hasilTaksir.update(id, data)       // PUT /hasil-taksir/:id
api.hasilTaksir.delete(id)             // DELETE /hasil-taksir/:id
api.hasilTaksir.download(filters)      // GET /hasil-taksir/download
```

### Riwayat
```javascript
api.riwayat.list(filters)              // GET /riwayat
api.riwayat.get(id)                    // GET /riwayat/:id
api.riwayat.filter(criteria)           // POST /riwayat/filter
```

### Master Data (Cached)
```javascript
api.master.getKota()                   // GET /master/kota
api.master.getKpknl()                  // GET /master/kpknl
api.master.getJenisKendaraan()         // GET /master/jenis-kendaraan
api.master.getLokasi()                 // GET /master/lokasi
api.master.getSatker()                 // GET /master/satker
api.master.getTipe()                   // GET /master/tipe
```

### User Management
```javascript
api.user.list(filters)                 // GET /user
api.user.get(id)                       // GET /user/:id
api.user.create(data)                  // POST /user
api.user.update(id, data)              // PUT /user/:id
api.user.delete(id)                    // DELETE /user/:id
api.user.changePassword(data)          // POST /user/change-password
api.user.getProfile()                  // GET /user/profile
```

### Reports
```javascript
api.reports.getSummary(filters)        // GET /reports/summary
api.reports.getDetail(filters)         // GET /reports/detail
api.reports.export(format, filters)    // GET /reports/export
```

## ⚙️ Konfigurasi

Edit `api/config.js` untuk menyesuaikan:

```javascript
// Base URL
const API_BASE_URL = "https://pvvtr4cd-8080.asse.devtunnels.ms/";

// Request timeout
REQUEST_TIMEOUT: 30000,

// Retry configuration
RETRY: {
  enabled: true,
  maxAttempts: 3,
  delayMs: 1000,
  backoffMultiplier: 2,
  retryableStatuses: [408, 429, 500, 502, 503, 504],
},

// Caching
CACHE: {
  enabled: true,
  ttlMs: 5 * 60 * 1000,  // 5 menit
},

// Logging
LOG: {
  enabled: true,
  logRequests: true,
  logResponses: true,
  logErrors: true,
  logLevel: "debug",  // atau "warn" di production
},
```

## 🔒 Error Handling

Semua error dari API akan throw sebagai Error dengan properti tambahan:

```javascript
try {
  await api.kertasKerja.get(invalidId);
} catch (error) {
  console.log(error.message);    // Error message dari server
  console.log(error.status);     // HTTP status code
  console.log(error.data);       // Response body
  console.log(error.response);   // Full Response object
}
```

### Common Errors:
- **401 Unauthorized**: Token invalid/expired → Redirect ke login (otomatis)
- **403 Forbidden**: User tidak punya akses
- **404 Not Found**: Resource tidak ditemukan
- **500 Server Error**: Server error
- **Network Error**: Tidak bisa koneksi ke server

## 💾 Caching

GET requests otomatis di-cache selama TTL (Time To Live):

```javascript
// ✅ CACHED - Response disimpan 5 menit di sessionStorage
const data = await api.master.getKota();

// ✅ FORCE SKIP CACHE
const data = await api.master.getKota({ useCache: false });

// ✅ CLEAR SEMUA CACHE
api.http.clearCache();
```

## 🔄 Retry Logic

Request otomatis retry 3x jika terjadi error 5xx atau timeout:

```javascript
// Configuration di api/config.js
RETRY: {
  maxAttempts: 3,           // coba 3x
  delayMs: 1000,            // delay awal 1 detik
  backoffMultiplier: 2,     // exponential backoff
  retryableStatuses: [500, 502, 503, 504],
}

// Coba: 1x, tunggu 1s, coba 2x, tunggu 2s, coba 3x
```

## 🎣 Custom Interceptors

Tambahkan interceptor untuk modify request/response:

```javascript
const http = api.http;

// Request interceptor
http.interceptors.addRequest(async (config) => {
  config.headers["X-Custom-Header"] = "value";
  return config;
});

// Response interceptor
http.interceptors.addResponse(async (response) => {
  // Transform response sebelum diberikan ke code
  return response;
});

// Error interceptor
http.interceptors.addError(async (error) => {
  // Handle error khusus
  if (error.status === 403) {
    showPermissionError();
  }
  throw error;
});
```

## 📝 Contoh Implementasi

### Admin.html - Load Kertas Kerja

**BEFORE:**
```javascript
// Spread across HTML dengan fetch manual
async function loadKertasKerja() {
  const tbody = ensureTbody();
  try {
    const res = await fetch(trimSlashR(API) + LIST_ENDPOINT, {
      headers: { ...HEADERS_AUTH },
    });

    if (res.status === 204) {
      // handle kosong
      return;
    }

    if (!res.ok) throw new Error("HTTP " + res.status);

    const json = await res.json().catch(() => ({}));
    const list = Array.isArray(json?.data) ? json.data : [];
    // ... process data
  } catch (err) {
    showError(err.message);
  }
}
```

**AFTER:**
```javascript
// Bersih, universal, reusable
async function loadKertasKerja() {
  try {
    const tbody = ensureTbody();
    const list = await api.kertasKerja.list();
    
    ALL_ROWS = list;
    VIEW_ROWS = [...ALL_ROWS];
    renderRows(VIEW_ROWS);
  } catch (error) {
    showError(error.message);
    tbody.innerHTML = `<tr><td>Error: ${error.message}</td></tr>`;
  }
}
```

### TambahData.html - Submit Form

**BEFORE:**
```javascript
// Manual headers, endpoint, error handling
const res = await fetch(ENDPOINT_ADD, {
  method: "POST",
  headers: HEADERS_AUTH,
  body: JSON.stringify(formData),
});

if (!res.ok) throw new Error("HTTP " + res.status);
const result = await res.json();
```

**AFTER:**
```javascript
// Cleaner, dengan retry otomatis & caching
try {
  const result = await api.dataLelang.create(formData);
  showSuccess("Data berhasil ditambahkan");
  return result;
} catch (error) {
  showError(error.message);
}
```

## 🎯 Best Practices

1. **Selalu use try-catch**
   ```javascript
   try {
     const data = await api.kertasKerja.list();
   } catch (error) {
     showError(error.message);
   }
   ```

2. **Provide User Feedback**
   ```javascript
   showLoading(true);
   try {
     // API call
   } finally {
     showLoading(false);
   }
   ```

3. **Clear Cache saat Update/Delete**
   ```javascript
   await api.kertasKerja.delete(id);
   api.http.clearCache();  // ← Clear to reload
   ```

4. **Use Filters untuk Pagination**
   ```javascript
   const data = await api.kertasKerja.list({
     page: 1,
     limit: 20,
     search: "nilai taksir",
   });
   ```

5. **Handle File Uploads**
   ```javascript
   const formData = new FormData();
   formData.append("file", fileInput.files[0]);
   formData.append("metadata", JSON.stringify(meta));
   
   await api.kertasKerja.upload(formData);
   ```

## 🐛 Debugging

Enable logging untuk debug:

```javascript
// Di browser console
window.ApiConfig.LOG.logRequests = true;
window.ApiConfig.LOG.logResponses = true;
window.ApiConfig.LOG.logErrors = true;
```

Atau set di config.js:
```javascript
LOG: {
  enabled: true,
  logLevel: "debug",
  logRequests: true,
  logResponses: true,
  logErrors: true,
}
```

## 🔄 Migration Guide

Untuk migrate dari old code:

1. Change dari `fetch()` ke `api.*.*()`
2. Remove manual header construction
3. Remove manual error handling boilerplate
4. Add try-catch around API calls
5. Test thoroughly

## 📞 Support

Untuk error atau improvement:
- Check console logs
- Verify endpoint di `api/endpoints.js`
- Check configuration di `api/config.js`
- Verify auth token ada di localStorage

---

**Version**: 1.0.0  
**Last Updated**: May 2026
