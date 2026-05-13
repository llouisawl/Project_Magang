# API Refactoring Migration Guide

Panduan langkah demi langkah untuk migrate dari old API pattern ke new refactored API service.

## 📋 Overview

Struktur baru memisahkan concerns menjadi 4 layer:

```
┌─────────────────────────────────────────┐
│   HTML Files (Admin.html, etc)          │  ← Your Pages
├─────────────────────────────────────────┤
│   API Service Layer (api-service.js)    │  ← High-level methods
├─────────────────────────────────────────┤
│   HTTP Client (http-client.js)          │  ← Fetch + interceptors
├─────────────────────────────────────────┤
│   Config (config.js, endpoints.js)      │  ← Configuration
└─────────────────────────────────────────┘
```

## 🎯 Migration Steps

### Step 1: Update HTML Header

**BEFORE:**
```html
<!DOCTYPE html>
<html>
<head>
  <script src="config.js"></script>
  <script src="auth.js"></script>
  <!-- Tidak ada API organization -->
</head>
<body>
</body>
</html>
```

**AFTER:**
```html
<!DOCTYPE html>
<html>
<head>
  <!-- ✅ ADD THESE IN ORDER -->
  <script src="api/config.js"></script>
  <script src="api/http-client.js"></script>
  <script src="api/endpoints.js"></script>
  <script src="api/api-service.js"></script>
  <script src="auth.js"></script>
</head>
<body>
</body>
</html>
```

### Step 2: Initialize API Service

**BEFORE:**
```html
<script>
  // Manual configuration
  const API = (typeof API_URL !== "undefined" && API_URL) || "";
  const TOKEN = localStorage.getItem("jwt_admin") || "";
  const HEADERS_AUTH = TOKEN ? { Authorization: `Bearer ${TOKEN}` } : {};
  
  const LIST_ENDPOINT = "/kertas-kerja/all";
  const VALIDATE_ENDPOINT = (id) => `/kertas-kerja/${id}/validate`;
  // ... more endpoints
</script>
```

**AFTER:**
```html
<script>
  // ✅ ONE LINE: Initialize global API service
  const api = window.initializeApiService();
  
  // Now use:
  // api.kertasKerja.list()
  // api.kertasKerja.validate(id, data)
  // etc...
</script>
```

### Step 3: Migrate API Calls

#### Example 1: Simple GET (List Data)

**BEFORE:**
```javascript
async function loadKertasKerja() {
  const tbody = ensureTbody();
  const table = $("#kertasKerjaTable");
  
  tbody.innerHTML = `<tr><td colspan="7" style="padding:16px">Memuat data…</td></tr>`;
  
  try {
    const res = await fetch(trimSlashR(API) + LIST_ENDPOINT, {
      headers: { ...HEADERS_AUTH },
    });
    
    if (res.status === 204) {
      ALL_ROWS = [];
      tbody.innerHTML = "";
      return;
    }
    
    if (!res.ok) throw new Error("HTTP " + res.status);
    
    const json = await res.json().catch(() => ({}));
    const list = Array.isArray(json?.data)
      ? json.data
      : Array.isArray(json?.result)
        ? json.result
        : Array.isArray(json)
          ? json
          : [];
    
    ALL_ROWS = list.map(normalizeKK);
    VIEW_ROWS = [...ALL_ROWS];
    renderTable();
  } catch (err) {
    tbody.innerHTML = `<tr><td>Error: ${err.message}</td></tr>`;
  }
}
```

**AFTER:**
```javascript
async function loadKertasKerja() {
  try {
    const tbody = ensureTbody();
    tbody.innerHTML = `<tr><td colspan="7" style="padding:16px">Memuat data…</td></tr>`;
    
    // ✅ ONE LINE for API call
    const list = await api.kertasKerja.list();
    
    ALL_ROWS = list.map(normalizeKK);
    VIEW_ROWS = [...ALL_ROWS];
    renderTable();
  } catch (err) {
    const tbody = ensureTbody();
    tbody.innerHTML = `<tr><td>Error: ${err.message}</td></tr>`;
  }
}
```

#### Example 2: POST (Create Data)

**BEFORE:**
```javascript
async function submitForm(formData) {
  try {
    const res = await fetch(trimSlashR(API) + ENDPOINT_ADD, {
      method: "POST",
      headers: { ...HEADERS_AUTH },
      body: JSON.stringify(formData),
    });
    
    if (!res.ok) throw new Error("HTTP " + res.status);
    
    const result = await res.json();
    showSuccess("Data berhasil ditambahkan");
    
    // Refresh list
    await loadKertasKerja();
  } catch (err) {
    showError(err.message);
  }
}
```

**AFTER:**
```javascript
async function submitForm(formData) {
  try {
    // ✅ ONE LINE for API call
    const result = await api.dataLelang.create(formData);
    
    showSuccess("Data berhasil ditambahkan");
    
    // Refresh list (clear cache)
    api.http.clearCache();
    await loadDataLelang();
  } catch (err) {
    showError(err.message);
  }
}
```

#### Example 3: PATCH (Update/Validate)

**BEFORE:**
```javascript
async function validateFile(id, file, tr) {
  try {
    const formData = new FormData();
    formData.append("file", file);
    
    const res = await fetch(trimSlashR(API) + VALIDATE_ENDPOINT(id), {
      method: "PATCH",
      headers: { ...HEADERS_AUTH },
      body: formData,
    });
    
    if (!res.ok) throw new Error("HTTP " + res.status);
    
    const result = await res.json();
    tr.classList.add("validated");
    showSuccess("File validated");
  } catch (err) {
    showError(err.message);
  }
}
```

**AFTER:**
```javascript
async function validateFile(id, file, tr) {
  try {
    const formData = new FormData();
    formData.append("file", file);
    
    // ✅ ONE LINE for API call
    const result = await api.kertasKerja.validate(id, formData);
    
    tr.classList.add("validated");
    showSuccess("File validated");
    api.http.clearCache();
  } catch (err) {
    showError(err.message);
  }
}
```

#### Example 4: DELETE

**BEFORE:**
```javascript
async function deleteRow(id) {
  if (!confirm("Yakin ingin hapus?")) return;
  
  try {
    const res = await fetch(
      `${trimSlashR(API)}/kertas-kerja/${id}`,
      {
        method: "DELETE",
        headers: { ...HEADERS_AUTH },
      },
    );
    
    if (!res.ok) throw new Error("HTTP " + res.status);
    
    showSuccess("Data berhasil dihapus");
    await loadKertasKerja();
  } catch (err) {
    showError(err.message);
  }
}
```

**AFTER:**
```javascript
async function deleteRow(id) {
  if (!confirm("Yakin ingin hapus?")) return;
  
  try {
    // ✅ ONE LINE for API call
    await api.kertasKerja.delete(id);
    
    showSuccess("Data berhasil dihapus");
    api.http.clearCache();
    await loadKertasKerja();
  } catch (err) {
    showError(err.message);
  }
}
```

#### Example 5: Upload File

**BEFORE:**
```javascript
async function uploadFile(file) {
  try {
    const formData = new FormData();
    formData.append("file", file);
    formData.append("metadata", JSON.stringify({ type: "kertas_kerja" }));
    
    // ⚠️ Manual FormData handling
    const res = await fetch(trimSlashR(API) + UPLOAD_ENDPOINT, {
      method: "POST",
      headers: HEADERS_AUTH,  // ⚠️ NO Content-Type for FormData
      body: formData,
    });
    
    if (!res.ok) throw new Error("HTTP " + res.status);
    
    const result = await res.json();
    showSuccess("File uploaded");
  } catch (err) {
    showError(err.message);
  }
}
```

**AFTER:**
```javascript
async function uploadFile(file) {
  try {
    const formData = new FormData();
    formData.append("file", file);
    formData.append("metadata", JSON.stringify({ type: "kertas_kerja" }));
    
    // ✅ Api service handles FormData correctly
    const result = await api.kertasKerja.upload(formData);
    
    showSuccess("File uploaded");
    api.http.clearCache();
  } catch (err) {
    showError(err.message);
  }
}
```

### Step 4: Update Error Handling

**BEFORE:**
```javascript
try {
  // ... API call
} catch (err) {
  if (err instanceof TypeError) {
    console.error("Network error:", err);
    showError("Jaringan tidak tersedia");
  } else {
    console.error("Error:", err);
    showError(err.message || "Terjadi kesalahan");
  }
}
```

**AFTER:**
```javascript
try {
  // ... API call
} catch (error) {
  // ✅ Error sudah terstruktur dengan baik
  console.log(error.status);    // HTTP status
  console.log(error.message);   // Error message
  console.log(error.data);      // Response payload
  
  // Handle specific errors
  if (error.status === 401) {
    // Unauthorized - redirect ke login (otomatis di interceptor)
  } else if (error.status === 403) {
    showError("Anda tidak memiliki akses");
  } else if (error.status === 404) {
    showError("Data tidak ditemukan");
  } else {
    showError(error.message);
  }
}
```

### Step 5: Cache Management

**AFTER:**
```javascript
// ✅ Cache otomatis untuk GET requests
const data = await api.master.getKota();

// ✅ Skip cache jika diperlukan
const fresh = await api.master.getKota({ useCache: false });

// ✅ Clear cache setelah mutation
await api.dataLelang.create(data);
api.http.clearCache();
```

## 🔄 Full File Migration Example

### Admin.html (BEFORE - Partial)

```html
<!DOCTYPE html>
<html>
<head>
  <script src="config.js"></script>
  <script src="auth.js"></script>
  <style>/* ... */</style>
</head>
<body>
  <!-- HTML content -->
  <script>
    Auth.protectPage("admin", "daftar.html");
    
    const API = (typeof API_URL !== "undefined" && API_URL) || "";
    const TOKEN = localStorage.getItem("jwt_admin") || "";
    const HEADERS_AUTH = TOKEN ? { Authorization: `Bearer ${TOKEN}` } : {};
    
    const LIST_ENDPOINT = "/kertas-kerja/all";
    const VALIDATE_ENDPOINT = (id) => `/kertas-kerja/${id}/validate`;
    
    let ALL_ROWS = [];
    let VIEW_ROWS = [];
    
    async function loadKertasKerja() {
      // ... fetch logic
    }
    
    async function patchValidate(file, tr) {
      // ... fetch logic
    }
  </script>
</body>
</html>
```

### Admin.html (AFTER - Partial)

```html
<!DOCTYPE html>
<html>
<head>
  <!-- ✅ Load API modules -->
  <script src="api/config.js"></script>
  <script src="api/http-client.js"></script>
  <script src="api/endpoints.js"></script>
  <script src="api/api-service.js"></script>
  <script src="auth.js"></script>
  <style>/* ... */</style>
</head>
<body>
  <!-- HTML content - unchanged -->
  <script>
    // ✅ ONE LINE setup
    Auth.protectPage("admin", "daftar.html");
    const api = window.initializeApiService();
    
    let ALL_ROWS = [];
    let VIEW_ROWS = [];
    
    // ✅ SIMPLIFIED function
    async function loadKertasKerja() {
      try {
        const list = await api.kertasKerja.list();
        ALL_ROWS = list.map(normalizeKK);
        VIEW_ROWS = [...ALL_ROWS];
        renderTable();
      } catch (err) {
        showError(err.message);
      }
    }
    
    // ✅ SIMPLIFIED function
    async function patchValidate(file, tr) {
      try {
        await api.kertasKerja.validate(kkId, file);
        tr.classList.add("validated");
        api.http.clearCache();
      } catch (err) {
        showError(err.message);
      }
    }
  </script>
</body>
</html>
```

## 📊 Before & After Comparison

| Aspek | Before | After |
|-------|--------|-------|
| **Boilerplate Code** | Banyak fetch logic di setiap function | Minimal, delegated to service |
| **Error Handling** | Manual, inconsistent | Automatic, standardized |
| **Caching** | Tidak ada | Otomatis untuk GET |
| **Retry Logic** | Tidak ada | Otomatis untuk 5xx errors |
| **Token Management** | Manual per file | Centralized |
| **Logging** | Ad-hoc console.log | Structured, toggleable |
| **Interceptors** | Tidak ada | Automatic (auth, error handling) |
| **Endpoints** | Scattered across files | Centralized definition |
| **Timeout** | Manual fetch timeout | Automatic (30s default) |
| **Content-Type** | Manual header management | Automatic |

## ✅ Checklist Untuk Setiap File

Untuk migrate setiap HTML file:

- [ ] Tambah script tags di `<head>` (4 API files + auth.js)
- [ ] Initialize `const api = window.initializeApiService()`
- [ ] Replace semua `fetch()` calls dengan `api.*.*()` calls
- [ ] Remove manual `HEADERS_AUTH` setup
- [ ] Remove manual endpoint constants
- [ ] Remove manual error handling boilerplate
- [ ] Add `try-catch` around API calls
- [ ] Add `api.http.clearCache()` setelah mutations
- [ ] Test di browser dan check console logs
- [ ] Verify authentication masih berfungsi

## 🧪 Testing Setelah Migration

```javascript
// 1. Check API initialized
console.log(window.api)  // Should exist and have methods

// 2. Test simple GET
api.master.getKota()
  .then(data => console.log("✓ GET works", data))
  .catch(err => console.error("✗ GET failed", err))

// 3. Check error handling
api.kertasKerja.get(invalid_id)
  .catch(err => console.log("✓ Error handling works", err.message))

// 4. Check logging
window.ApiConfig.LOG.logRequests = true
api.master.getKota()  // Should log in console

// 5. Check caching
const start = performance.now()
await api.master.getKota()
const t1 = performance.now() - start

const start2 = performance.now()
await api.master.getKota()
const t2 = performance.now() - start2

console.log(`First: ${t1}ms, Cache hit: ${t2}ms`)  // t2 should be much faster
```

## 🚨 Common Issues & Solutions

### Issue 1: "api is not defined"
```javascript
// ❌ Wrong
<script src="api/api-service.js"></script>
// Where is initialization?

// ✅ Correct
<script>
  const api = window.initializeApiService();
</script>
```

### Issue 2: FormData not uploading
```javascript
// ❌ Wrong - Manual header management breaks FormData
const res = await fetch(url, {
  method: "POST",
  headers: { "Content-Type": "application/json", ...HEADERS_AUTH },
  body: formData,  // Mixing headers and formData!
});

// ✅ Correct - Use API service
await api.kertasKerja.upload(formData);
```

### Issue 3: Old endpoints still partially used
```javascript
// ❌ Wrong - Mix of old and new
const endpoint = LIST_ENDPOINT;  // Old constant
await api.get(endpoint);

// ✅ Correct - Use service methods only
await api.kertasKerja.list();
```

### Issue 4: Cache not clearing after update
```javascript
// ❌ Wrong
await api.kertasKerja.delete(id);
// Lupa clear cache!

// ✅ Correct
await api.kertasKerja.delete(id);
api.http.clearCache();
await loadKertasKerja();
```

## 🎓 Summary

Migration dari fetch manual ke API service memberikan:

✅ **Less Code** - Reduce boilerplate by ~60%  
✅ **Better Errors** - Consistent error handling  
✅ **Auto Caching** - Built-in request caching  
✅ **Auto Retry** - Automatic retry for network errors  
✅ **Logging** - Structured logging for debugging  
✅ **Maintainable** - Centralized endpoints  
✅ **Type-safe** - Organized, documented methods  
✅ **Interceptors** - Automatic auth token management  
✅ **Modern** - Follows current best practices  

---

**Happy Migrating! 🚀**
