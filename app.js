import { config } from "./config.js";
import { createAccountApi, validateConfig, supportAddress, consumeVerifier } from "./auth.js";

const el = id => document.getElementById(id);
let token = null, busy = false, uncertain = false, completed = false;
// GitHub Pages cannot set frame-ancestors response headers: fail closed in frames too.
const embedded = window.self !== window.top;
const configured = validateConfig(config) && !embedded;
const api = configured ? createAccountApi(config) : null;
el("configuration").hidden = configured;
if (embedded) el("configuration").textContent = "Open this account page directly in your browser to sign in securely.";
const address = supportAddress(config.supportEmail);
if (address) {
  el("support").href = "mailto:" + encodeURIComponent(address) + "?subject=eNotes%20account%20access%20and%20deletion";
  el("support").hidden = false; el("support-pending").hidden = true;
}
function update() {
  el("google").disabled = el("email-signin").disabled = !configured || busy;
  el("switch").disabled = busy;
  el("delete").disabled = !token || busy || uncertain || !el("acknowledge").checked || el("confirmation").value !== "DELETE";
  el("delete").textContent = busy && token ? "Please wait…" : "Delete my account permanently";
  el("signed-out").hidden = !!token || completed;
  el("signed-in").hidden = !token;
  el("login").setAttribute("aria-busy", String(busy));
}
function message(text, error = false) {
  el("status").textContent = text; el("status").dataset.error = String(error);
}
function clearIdentity() {
  token = null; el("identity").textContent = "";
  el("acknowledge").checked = false; el("confirmation").value = "";
  sessionStorage.removeItem("enotes-deletion-pkce");
}
async function verifiedSession(data) {
  if (typeof data.access_token !== "string") throw new Error("Sign-in did not complete. Try again.");
  const user = await api.user(data.access_token);
  await api.status(data.access_token);
  token = data.access_token; // No refresh token or account details are persisted.
  uncertain = false;
  el("identity").textContent = user.email ?? "Your verified eNotes account";
  message("Account verified. Review the information and confirm only if you want to delete this account.");
}
async function action(task) {
  if (busy) return;
  busy = true; message("Please wait…"); update();
  try { await task(); }
  catch (e) {
    if (e.code === "SESSION_INACTIVE" || e.code === "REAUTH_REQUIRED") clearIdentity();
    message(e.message ?? "The request could not be completed. Try again.", true);
  } finally { busy = false; update(); }
}
el("login").addEventListener("submit", event => {
  event.preventDefault();
  if (!api || !el("login").reportValidity()) return;
  action(async () => {
    try { await verifiedSession(await api.password(el("email").value, el("password").value)); }
    finally { el("password").value = ""; }
  });
});
el("google").addEventListener("click", () => {
  if (!api) return;
  action(async () => {
    const callback = new URL(location.pathname, location.origin).href;
    location.assign(await api.google(callback, sessionStorage));
  });
});
el("switch").addEventListener("click", () => action(async () => {
  let revoked = true;
  try { if (token) await api.logout(token); } catch { revoked = false; }
  clearIdentity(); uncertain = false;
  message(revoked ? "You can sign in with another account." : "This page was signed out. Server sign-out could not be confirmed.");
}));
el("acknowledge").addEventListener("change", update);
el("confirmation").addEventListener("input", update);
el("delete").addEventListener("click", () => {
  if (el("delete").disabled) return;
  action(async () => {
    try {
      const result = await api.remove(token);
      if (result.deleted !== true) throw new Error("Deletion was not confirmed. Contact support.");
      clearIdentity(); completed = true; el("completed").hidden = false;
      el("action-title").hidden = true;
      message("Deletion confirmed for your eNotes account. Your Google account has not been deleted.");
    } catch (e) {
      if (e.code === "NETWORK" || e.code === "DELETION_UNCONFIRMED") uncertain = true;
      throw e;
    }
  });
});
// Strip callback parameters before networking; never let tokens/codes leak to other links.
const params = new URLSearchParams(location.search);
const code = params.get("code"), callbackError = params.has("error");
if (location.search || location.hash) history.replaceState(null, "", location.pathname);
if (callbackError) {
  sessionStorage.removeItem("enotes-deletion-pkce"); message("Google sign-in was cancelled or could not complete. Try again.", true);
} else if (code && api) {
  action(async () => { await verifiedSession(await api.exchange(code, consumeVerifier(sessionStorage))); });
}
update();
