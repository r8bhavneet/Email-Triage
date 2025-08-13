const REDIRECT_URI = `https://${chrome.runtime.id}.chromiumapp.org/`;
const SCOPES = [
  "https://www.googleapis.com/auth/gmail.readonly",
  "https://www.googleapis.com/auth/gmail.modify"
].join(" ");
const AUTH_EP  = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_EP = "https://oauth2.googleapis.com/token";

/***** STEP 2: UI ELEMENTS *****/
const elSignIn  = document.getElementById("signin");
const elRefresh = document.getElementById("refresh");  // will enable later
const elStatus  = document.getElementById("status");
const elList    = document.getElementById("list");
const elSignOut = document.getElementById("signout");


let CLIENT_ID = "";
let CLIENT_SECRET = "";

async function loadConfig() {
  const res = await fetch(chrome.runtime.getURL("config.json")).catch(()=>null);
  if (!res || !res.ok) throw new Error("Missing config.json—copy config.example.json and fill in credentials.");
  const cfg = await res.json();
  CLIENT_ID = cfg.CLIENT_ID;
  CLIENT_SECRET = cfg.CLIENT_SECRET;
}


function showFriendlyError(msg) {
  elStatus.textContent = "Error";
  if (elList) {
    elList.innerHTML = `
      <div style="color:#b00;white-space:pre-wrap;border:1px solid #f2c; padding:8px; border-radius:6px;">
        ${msg}
      </div>
    `;
  }
}

// --- call at startup, before sign-in ---
loadConfig()
  .then(async () => {
    try {
      const token = await loadToken();
      if (token && token.access_token && !isExpired(token)) {
        setSignedInUI(true); // your existing one
      } else {
        setSignedInUI(false);
      }
    } catch (e) {
      console.error("[init] failed to read token:", e);
      setSignedInUI(false);
    }
  })
  .catch(err => {
    console.error("[init] config load failed:", err);
    showFriendlyError("Missing or invalid config.json. Copy config.example.json and fill in CLIENT_ID/SECRET.");
    setSignedInUI(false);
  });


(async function init() {
  const token = await loadToken();
  if (token && token.access_token && !isExpired(token)) {
    elStatus.textContent = "Signed in";
    elRefresh.disabled = false; // we’ll use this later to fetch Gmail
  } else {
    elStatus.textContent = "Signed out";
    elRefresh.disabled = true;
  }
})();


elSignIn.addEventListener("click", async () => {
  try {
    disableButtons(true);
    const codeVerifier  = b64urlRandom(32);
    const codeChallenge = await sha256b64url(codeVerifier);
    const state         = hexRandom(16);

    const authUrl = new URL(AUTH_EP);
    authUrl.searchParams.set("client_id", CLIENT_ID);
    authUrl.searchParams.set("response_type", "code");
    authUrl.searchParams.set("redirect_uri", REDIRECT_URI);
    authUrl.searchParams.set("scope", SCOPES);
    authUrl.searchParams.set("state", state);
    authUrl.searchParams.set("prompt", "consent");
    authUrl.searchParams.set("access_type", "offline");
    authUrl.searchParams.set("code_challenge", codeChallenge);
    authUrl.searchParams.set("code_challenge_method", "S256");

    // Launch Google sign-in
    const redirect = await chrome.identity.launchWebAuthFlow({
      url: authUrl.toString(),
      interactive: true
    });

    // Parse returned ?code=...
    const url = new URL(redirect);
    if (url.searchParams.get("state") !== state) throw new Error("State mismatch");
    const code = url.searchParams.get("code");
    if (!code) throw new Error("No authorization code returned");

    // Exchange code -> tokens
    const token = await exchangeCodeForToken({ code, codeVerifier });
    await saveToken(token);
    setSignedInUI(true);

    // Broadcast the state change so other parts of the extension update
    chrome.runtime.sendMessage({ type: "auth-state", signedIn: true });

    console.log("[oauth] token saved", token);
    elStatus.textContent = "Signed in";
    elRefresh.disabled = false;
  } catch (err) {
    console.error("[oauth] sign-in failed:", err);
    alert(`Sign-in failed:\n${err.message || err}`);
    elStatus.textContent = "Signed out";
    elRefresh.disabled = true;
  } finally {
    disableButtons(false);
  }
});

async function getAccessToken() {
  const token = await loadToken();
  if (!token) throw new Error("Not signed in");
  if (!isExpired(token)) return token.access_token;
  if (!token.refresh_token) throw new Error("Missing refresh token");
  const refreshed = await refreshToken(token.refresh_token);
  const merged = { ...token, ...refreshed, expiry_date: nowMs() + (refreshed.expires_in || 3600) * 1000 };
  await saveToken(merged);
  return merged.access_token;
}


async function revokeTokenAndSignOut() {
  setSignedInUI(false);
  try {
    const { token } = await chrome.storage.local.get(["token"]);
    if (token?.access_token) {
      // Revoke access token (refresh token gets invalidated on server side soon after)
      await fetch("https://oauth2.googleapis.com/revoke", {
        method: "POST",
        headers: { "Content-Type":"application/x-www-form-urlencoded" },
        body: new URLSearchParams({ token: token.access_token })
      }).catch(()=>{});
    }
  } finally {
    await chrome.storage.local.remove(["token"]);
    cachedAccessToken = null;
    elStatus.textContent = "Signed out";
    elRefresh.disabled = true;
    elSignOut.disabled = true;
  }
}

elSignOut.addEventListener("click", revokeTokenAndSignOut);

// Enable/disable with sign-in state:
function setSignedInUI(isSignedIn) {
  elStatus.textContent = isSignedIn ? "Signed in" : "Signed out";
  elRefresh.disabled   = !isSignedIn;
  if (elSignIn)  elSignIn.disabled  = false;        // allow re-auth
  if (elSignOut) elSignOut.disabled = !isSignedIn;  // only enabled when signed in
}



/***** --- SMALL, TESTABLE HELPERS BELOW --- *****/

// 5a) Exchange authorization code for tokens
async function exchangeCodeForToken({ code, codeVerifier }) {
  const body = new URLSearchParams({
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    code,
    code_verifier: codeVerifier,
    grant_type: "authorization_code",
    redirect_uri: REDIRECT_URI
  });
  const res = await fetch(TOKEN_EP, {
    method: "POST",
    headers: { "Content-Type":"application/x-www-form-urlencoded" },
    body
  });
  const json = await res.json();
  if (!res.ok || !json.access_token) {
    throw new Error(`Token exchange failed: ${res.status} ${res.statusText} ${JSON.stringify(json)}`);
  }
  json.expiry_date = nowMs() + (json.expires_in || 3600) * 1000;
  return json;
}

// 5b) Refresh token
async function refreshToken(refresh_token) {
  const body = new URLSearchParams({
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    grant_type: "refresh_token",
    refresh_token
  });
  const res = await fetch(TOKEN_EP, {
    method: "POST",
    headers: { "Content-Type":"application/x-www-form-urlencoded" },
    body
  });
  const json = await res.json();
  if (!res.ok || !json.access_token) {
    throw new Error(`Refresh failed: ${res.status} ${res.statusText} ${JSON.stringify(json)}`);
  }
  return json;
}

// 5c) Token storage
async function saveToken(token) {
  await chrome.storage.local.set({ token });
}
async function loadToken() {
  const { token } = await chrome.storage.local.get(["token"]);
  return token || null;
}

// 5d) Expiry helpers
function isExpired(t) {
  return !t.expiry_date || nowMs() > (t.expiry_date - 60_000); // refresh 60s early
}
function nowMs() { return Date.now(); }

// 5e) Crypto helpers for PKCE
function b64urlRandom(lengthBytes) {
  const buf = new Uint8Array(lengthBytes);
  crypto.getRandomValues(buf);
  return base64url(buf);
}
function hexRandom(lengthBytes) {
  const buf = new Uint8Array(lengthBytes);
  crypto.getRandomValues(buf);
  return Array.from(buf).map(b => b.toString(16).padStart(2,"0")).join("");
}
async function sha256b64url(str) {
  const enc = new TextEncoder().encode(str);
  const hash = await crypto.subtle.digest("SHA-256", enc);
  return base64url(new Uint8Array(hash));
}
function base64url(bytes) {
  let s = btoa(String.fromCharCode(...bytes));
  return s.replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
}

// 5f) Small UI utility
function disableButtons(disabled) {
  elSignIn.disabled = disabled;
  elRefresh.disabled = disabled || elStatus.textContent !== "Signed in";
}


/***** Gmail API helpers *****/
async function gmailApi(path, init = {}) {
  const at = await getAccessToken();
  const res = await fetch(`https://www.googleapis.com/gmail/v1/users/me/${path}`, {
    ...init,
    headers: {
      "Authorization": `Bearer ${at}`,
      "Accept": "application/json",
      ...(init.headers || {})
    }
  });
  const text = await res.text();
  if (!res.ok) {
    // surface detailed errors in the popup console
    throw new Error(`Gmail ${res.status} ${res.statusText} – ${text}`);
  }
  return text ? JSON.parse(text) : {};
}

async function listSpamIds(limit = 10) {
  // q=in:spam → only Spam folder
  const data = await gmailApi(`messages?q=in:spam&maxResults=${limit}`);
  return (data.messages || []).map(m => m.id);
}


async function rescueToInbox(messageId) {
  return gmailApi(`messages/${messageId}/modify`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      removeLabelIds: ["SPAM"],
      addLabelIds: ["INBOX"]
    })
  });
}


elRefresh.addEventListener("click", async () => {
  elRefresh.disabled = true;
  elStatus.textContent = "Fetching…";
  elList.innerHTML = "";
  try {
    const msgs = await listSpamDetails(10);
    elStatus.textContent = `Found ${msgs.length} in Spam`;

    if (!msgs.length) {
      elList.innerHTML = "<div class='muted'>No messages in Spam.</div>";
      return;
    }

    const html = msgs.map(m => {
      const h = headerMap(m.payload?.headers);
      const from = h["from"] || "(unknown sender)";
      const subject = h["subject"] || "(no subject)";
      const date = h["date"] || "";
      const snippet = m.snippet || "";
      return `
        <div class="msg" data-id="${m.id}">
          <div class="from">${escapeHtml(from)}</div>
          <div class="subject">${escapeHtml(subject)}</div>
          <div class="muted">${escapeHtml(date)}</div>
          <div class="muted" style="margin-top:6px">${escapeHtml(snippet)}</div>
          <div style="margin-top:8px">
            <button class="rescue-btn">Rescue to Inbox</button>
          </div>
        </div>
      `;
    }).join("");

    elList.innerHTML = html;
    elList.querySelectorAll(".rescue-btn").forEach(btn => {
        btn.addEventListener("click", async (e) => {
            const card = e.target.closest(".msg");
            const id = card.dataset.id;

            // optimistic UI
            const oldHTML = card.innerHTML;
            card.innerHTML = `<div class="muted">Rescuing…</div>`;

            try {
                await rescueToInbox(id);
                // remove the card on success
                card.remove();
            } catch (err) {
                console.error("[gmail] rescue error:", err);
                // put the card back and show an inline error
                card.innerHTML = oldHTML + `<div class="muted" style="color:#b00;margin-top:6px">Failed to rescue. See console.</div>`;
            }
        });
    });

  } catch (err) {
    console.error("[gmail] details error:", err);
    elStatus.textContent = "Error";
    elList.innerHTML = `<pre style="white-space:pre-wrap">${String(err.message || err)}</pre>`;
  } finally {
    elRefresh.disabled = false;
  }
});



/***** Message detail helpers *****/
function headerMap(headers) {
  const map = {};
  for (const h of (headers || [])) map[(h.name || "").toLowerCase()] = h.value || "";
  return map;
}
function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, c => ({ "&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;" }[c]));
}

async function getMessageMetadata(id) {
  // Ask for only key headers; we’ll grab snippet with a second call if missing
  const meta = await gmailApi(`messages/${id}?format=metadata&metadataHeaders=From&metadataHeaders=Subject&metadataHeaders=Date`);
  if (!meta.snippet) {
    const full = await gmailApi(`messages/${id}?format=full`);
    meta.snippet = full.snippet || "";
    if (!meta.payload) meta.payload = full.payload;
  }
  return meta;
}

async function listSpamDetails(limit = 10) {
  const ids = await listSpamIds(limit);
  const details = [];
  for (const id of ids) {
    try { details.push(await getMessageMetadata(id)); }
    catch (e) { console.warn("Failed to fetch details for", id, e); }
  }
  return details;
}


// Update UI whenever the token changes in storage
chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local") return;
  if (!changes.token) return;

  const newToken = changes.token.newValue;
  const signedIn = !!(newToken?.access_token) && !isExpired(newToken);
  setSignedInUI(signedIn);
});

// (optional) handle explicit broadcasts
chrome.runtime.onMessage.addListener((msg) => {
  if (msg?.type === "auth-state") {
    setSignedInUI(!!msg.signedIn);
  }
});

















// document.getElementById("signin").addEventListener("click", () => {
//   alert("Sign-in will be implemented in the next step.");
// });

// document.getElementById("refresh").addEventListener("click", () => {
//   const list = document.getElementById("list");
//   list.innerHTML = `
//     <div>
//       <strong>Flight Alerts</strong> - Your itinerary update
//       <button>Rescue</button>
//     </div>
//   `;
// });
