export function validateConfig(config) {
  try {
    const url = new URL(config.supabaseUrl);
    if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash || url.pathname !== "/") return false;
    const key = config.publishableKey;
    if (!key || key.startsWith("sb_secret_") || /\s/.test(key)) return false;
    if (key.startsWith("sb_publishable_")) return true;
    const payload = JSON.parse(atob(key.split(".")[1].replace(/-/g,"+").replace(/_/g,"/")));
    return payload.role === "anon";
  } catch { return false; }
}

export function supportAddress(value) {
  return /^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/.test(value ?? "") ? value : null;
}

export class AccountApiError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}

export function createAccountApi(config, fetcher = fetch) {
  if (!validateConfig(config)) throw new Error("Account website is not configured.");
  const base = config.supabaseUrl.replace(/\/$/, "");
  async function call(path, body, token, method = "POST") {
    let response;
    try {
      response = await fetcher(base + path, { method, headers: {
        apikey: config.publishableKey, "Content-Type": "application/json",
        ...(token ? { Authorization: "Bearer " + token } : {}),
      }, ...(body === undefined ? {} : { body: JSON.stringify(body) }), cache: "no-store", credentials: "omit", referrerPolicy: "no-referrer", signal: AbortSignal.timeout(45000) });
    } catch {
      throw new AccountApiError("NETWORK", "Connection interrupted. If deletion was submitted, its result is unconfirmed. Do not assume it failed; contact support if necessary.");
    }
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      // Never render raw provider error bodies or accidentally expose tokens.
      const code = data.code ?? (response.status === 401 ? "SESSION_INACTIVE" : "REQUEST_FAILED");
      const messages = {
        SESSION_INACTIVE: "This session is no longer active. Your account may have been signed out or deleted.",
        REAUTH_REQUIRED: "Sign in again and confirm deletion within 10 minutes.",
        RATE_LIMITED: "Too many attempts. Wait a minute before trying again.",
        DELETION_UNCONFIRMED: "The deletion result is unconfirmed. Contact support if you cannot verify the outcome.",
        DELETION_FAILED: "Deletion was not confirmed. Try again or contact support. Your local files have not been erased.",
      };
      throw new AccountApiError(code, messages[code] ?? "The request could not be completed. Check your sign-in details or try again later.");
    }
    return data;
  }
  return {
    password: (email, password) => call("/auth/v1/token?grant_type=password", { email: email.trim(), password }),
    exchange: (code, verifier) => call("/auth/v1/token?grant_type=pkce", { auth_code: code, code_verifier: verifier }),
    user: token => call("/auth/v1/user", undefined, token, "GET"),
    status: token => call("/functions/v1/account-controls", { action: "status" }, token),
    remove: token => call("/functions/v1/account-controls", { action: "delete", confirmation: "DELETE" }, token),
    logout: token => call("/auth/v1/logout?scope=local", {}, token),
    async google(redirectUrl, storage, cryptoProvider = crypto) {
      const random = cryptoProvider.getRandomValues(new Uint8Array(32));
      const encode = bytes => btoa(String.fromCharCode(...bytes)).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"");
      const verifier = encode(random);
      const challenge = encode(new Uint8Array(await cryptoProvider.subtle.digest("SHA-256", new TextEncoder().encode(verifier))));
      storage.setItem("enotes-deletion-pkce", JSON.stringify({ verifier, at: Date.now() }));
      const url = new URL(base + "/auth/v1/authorize");
      url.search = new URLSearchParams({ provider: "google", redirect_to: redirectUrl, code_challenge: challenge, code_challenge_method: "s256", prompt: "select_account" });
      return url.href;
    },
  };
}

export function consumeVerifier(storage, now = Date.now()) {
  const raw = storage.getItem("enotes-deletion-pkce"); storage.removeItem("enotes-deletion-pkce");
  try {
    const data = JSON.parse(raw);
    if (typeof data.verifier !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(data.verifier) ||
        !Number.isFinite(data.at) || now < data.at || now-data.at > 600000) throw new Error();
    return data.verifier;
  } catch { throw new Error("Google sign-in expired or belongs to another tab. Start again."); }
}
