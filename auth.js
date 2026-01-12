// =================== auth.js (fixed multi-session, robust roles) ===================
(function (global) {
  const API = (global.API_URL || "").replace(/\/+$/, "");

  // ------- Storage keys per role (pisah total) -------
  const STORAGE_KEYS = {
    satker: "jwt_satker",
    admin: "jwt_admin",
    superadmin: "jwt_superadmin",
  };

  function saveToken(role, token) {
    const key = STORAGE_KEYS[role];
    if (!key) return;
    localStorage.setItem(key, token);
  }
  function getToken(role) {
    const key = STORAGE_KEYS[role];
    return key ? localStorage.getItem(key) : null;
  }
  function deleteToken(role) {
    const key = STORAGE_KEYS[role];
    if (key) localStorage.removeItem(key);
  }

  // ------- JWT helpers -------
  function base64UrlDecode(str) {
    try {
      str = String(str || "")
        .replace(/-/g, "+")
        .replace(/_/g, "/");
      const json = decodeURIComponent(
        Array.prototype.map
          .call(
            atob(str),
            (c) => "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2)
          )
          .join("")
      );
      return json;
    } catch {
      return "{}";
    }
  }
  function parseJwt(token) {
    if (!token || token.split(".").length < 2) return {};
    const payload = token.split(".")[1];
    try {
      return JSON.parse(base64UrlDecode(payload));
    } catch {
      return {};
    }
  }

  // ------- Role helpers (robust untuk array/variasi field) -------
  function rawRoleFields(claims) {
    return [
      claims?.role,
      claims?.Role,
      claims?.ROLES,
      claims?.roles,
      claims?.authorities,
      claims?.data?.role,
      claims?.user?.role,
    ].filter((v) => v != null && v !== "");
  }

  function normalizeRoleString(s) {
    const v = String(s || "").toLowerCase();
    if (/\bsuper/.test(v)) return "superadmin";
    if (/\badmin\b/.test(v) || /role_admin/.test(v)) return "admin";
    if (/\bsat/.test(v) || /\bsatker\b/.test(v)) return "satker";
    return ""; // tak dikenali
  }

  // Kembalikan daftar unik role yang terdeteksi dari claims
  function rolesFromClaims(claims) {
    const out = new Set();
    for (const f of rawRoleFields(claims)) {
      if (Array.isArray(f)) {
        for (const it of f) {
          const r = normalizeRoleString(it);
          if (r) out.add(r);
        }
      } else {
        const r = normalizeRoleString(f);
        if (r) out.add(r);
      }
    }
    return Array.from(out);
  }

  // Pilih role "utama" berdasar prioritas (untuk memutuskan ke key mana token disimpan)
  function pickPrimaryRole(claims) {
    const list = rolesFromClaims(claims);
    if (list.includes("superadmin")) return "superadmin";
    if (list.includes("admin")) return "admin";
    if (list.includes("satker")) return "satker";
    // fallback dari satu field string tunggal
    const single =
      normalizeRoleString(claims?.role) ||
      normalizeRoleString(claims?.Role) ||
      normalizeRoleString(claims?.ROLES) ||
      "";
    return single || "";
  }

  function hasRole(claims, expected) {
    const list = rolesFromClaims(claims);
    return list.includes(String(expected || "").toLowerCase());
  }

  // Nama tampilan dari claims (banyak versi field)
  function extractName(claims) {
    const c = claims || {};
    return (
      c.nama_satker ||
      c.nama ||
      c.name ||
      c.fullname ||
      c.full_name ||
      c.username ||
      c.preferred_username ||
      c.email ||
      c?.data?.name ||
      ""
    );
  }

  // -------- API Client per-role (opsional dipakai di halaman) --------
  class ApiClient {
    constructor(role /* 'satker' | 'admin' | 'superadmin' */) {
      this.role = role;
    }
    headers(extra = {}) {
      const t = getToken(this.role);
      const h = { "Content-Type": "application/json", ...extra };
      if (t) h.Authorization = `Bearer ${t}`;
      return h;
    }
    abs(path) {
      const p = String(path || "");
      if (/^https?:\/\//i.test(p)) return p;
      return `${API}${p.startsWith("/") ? "" : "/"}${p}`;
    }
    async get(path) {
      const r = await fetch(this.abs(path), {
        method: "GET",
        headers: this.headers(),
      });
      return this.#parse(r);
    }
    async post(path, body) {
      const r = await fetch(this.abs(path), {
        method: "POST",
        headers: this.headers(),
        body: JSON.stringify(body ?? {}),
      });
      return this.#parse(r);
    }
    async patch(path, body) {
      const r = await fetch(this.abs(path), {
        method: "PATCH",
        headers: this.headers(),
        body: JSON.stringify(body ?? {}),
      });
      return this.#parse(r);
    }
    async delete(path) {
      const r = await fetch(this.abs(path), {
        method: "DELETE",
        headers: this.headers(),
      });
      return this.#parse(r);
    }
    async #parse(res) {
      const json = await res.json().catch(() => ({}));
      if (!res.ok) {
        const msg = json?.message || json?.error || `HTTP ${res.status}`;
        throw new Error(msg);
      }
      return json;
    }
  }

  // --------- Public Auth API ----------
  const Auth = {
    ApiClient,

    // Login: simpan token DI KUNCI PER-ROLE (tanpa menyentuh role lain)
    async login({ username, password }) {
      const res = await fetch(`${API}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ nama_satker: username, password }),
      }).then((r) => r.json());

      const token =
        res?.data?.access_token || res?.access_token || res?.token || null;
      if (!token) throw new Error("Login gagal: token tidak ditemukan.");

      const claims = parseJwt(token);
      const primaryRole = pickPrimaryRole(claims);
      if (!primaryRole)
        throw new Error("Login gagal: role tidak terdeteksi dari token.");

      // Simpan *hanya* ke slot sesuai role utama token
      saveToken(primaryRole, token);

      // Simpan fallback nama terakhir diketik (opsional)
      try {
        if (username) localStorage.setItem("last_username", String(username));
      } catch {}

      return { role: primaryRole, token, name: extractName(claims) };
    },

    // Logout role tertentu
    logout(role) {
      deleteToken(role);
    },

    // Ambil nama tampilan dari token per-role
    getName(role) {
      const t = getToken(role);
      let name = "";
      if (t) {
        const c = parseJwt(t);
        name =
          c.nama_satker ||
          c.nama ||
          c.name ||
          c.fullname ||
          c.full_name ||
          c.username ||
          c.preferred_username ||
          c.email ||
          c?.data?.nama_satker ||
          c?.data?.nama ||
          c?.data?.name ||
          c?.user?.name ||
          c?.user?.fullname ||
          c?.user?.username ||
          "";
      }
      if (name) return name;

      // ⬇️ fallback khusus role (tidak tercampur antar role)
      const perRole = localStorage.getItem(`display_${role}`) || "";
      if (perRole) return perRole;

      // ⬇️ fallback terakhir (opsional) — boleh kamu hapus kalau mau
      return localStorage.getItem("last_username") || "";
    },
    // Guard halaman: wajib ada token role tsb & (opsional) token masih memuat role tsb
    protectPage(expectedRole, redirectTo = "daftar.html") {
      const t = getToken(expectedRole);
      if (!t) {
        location.replace(redirectTo);
        return;
      }
      const claims = parseJwt(t);

      // exp check
      if (claims?.exp && Date.now() / 1000 > claims.exp) {
        deleteToken(expectedRole);
        location.replace(redirectTo);
        return;
      }

      // Pastikan token ini memang memiliki role yang diharapkan (antisalah-simpan)
      if (!hasRole(claims, expectedRole)) {
        // Jangan hapus slot lain—cukup arahkan ke login
        location.replace(redirectTo);
      }
    },

    // (Opsional) Debug cepat di console
    listTokens() {
      return {
        jwt_satker: !!localStorage.getItem("jwt_satker"),
        jwt_admin: !!localStorage.getItem("jwt_admin"),
        jwt_superadmin: !!localStorage.getItem("jwt_superadmin"),
      };
    },
  };

  global.Auth = Auth;
})(window);
// =================== end of auth.js ===================
