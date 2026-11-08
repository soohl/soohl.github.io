// Decrypts the current page in the browser.
// The AES key comes from the gate server after the visitor solves an ALTCHA challenge.
// The key is cached in localStorage per key id, so a visitor solves it once per publish.
(() => {
  const base = document.currentScript.src;
  const sealed = document.getElementById("sealed");
  const kid = sealed.dataset.kid;
  const gate = document.querySelector('meta[name="gate"]').content.replace(/\/$/, "");
  const storeName = "gate.key." + kid;
  const aad = new TextEncoder().encode(kid);
  const MIME = {
    css: "text/css", js: "text/javascript", mjs: "text/javascript", json: "application/json",
    png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg", gif: "image/gif", webp: "image/webp",
    avif: "image/avif", svg: "image/svg+xml", ico: "image/x-icon", woff2: "font/woff2",
    woff: "font/woff", mp4: "video/mp4", webm: "video/webm", mp3: "audio/mpeg", pdf: "application/pdf",
  };

  const fromB64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

  async function openSealed(key, bytes) {
    const plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: bytes.subarray(0, 12), additionalData: aad }, key, bytes.subarray(12));
    return new Uint8Array(plain);
  }

  // Decrypt local files that the page uses (images, styles, scripts) and point to blob URLs.
  async function decryptAssets(key, doc) {
    const els = doc.querySelectorAll("[src], link[href]");
    await Promise.all([...els].map(async (el) => {
      const attr = el.hasAttribute("src") ? "src" : "href";
      const url = new URL(el.getAttribute(attr), location.href);
      if (url.origin !== location.origin || url.pathname.endsWith("/") || /\.html?$/.test(url.pathname)) return;
      const resp = await fetch(url.pathname + ".enc");
      if (!resp.ok) return;
      const data = await openSealed(key, new Uint8Array(await resp.arrayBuffer()));
      const ext = url.pathname.split(".").pop().toLowerCase();
      el.setAttribute(attr, URL.createObjectURL(new Blob([data], { type: MIME[ext] || "application/octet-stream" })));
    }));
  }

  async function render(rawKey) {
    const key = await crypto.subtle.importKey("raw", fromB64(rawKey), "AES-GCM", false, ["decrypt"]);
    const html = new TextDecoder().decode(await openSealed(key, fromB64(sealed.textContent.trim())));
    const doc = new DOMParser().parseFromString(html, "text/html");
    await decryptAssets(key, doc);
    document.open();
    document.write("<!doctype html>\n" + doc.documentElement.outerHTML);
    document.close();
  }

  function forgetOldKeys() {
    for (const name of Object.keys(localStorage)) {
      if (name.startsWith("gate.key.") && name !== storeName) localStorage.removeItem(name);
    }
  }

  async function askForKey() {
    document.body.innerHTML = `
      <main class="gate">
        <h1>Check before reading</h1>
        <p>Tick the box. Your browser solves a short puzzle, then the page opens.</p>
        <altcha-widget challenge="${gate}/challenge"></altcha-widget>
        <p class="gate-error" role="alert"></p>
      </main>`;
    const error = document.querySelector(".gate-error");
    await import(new URL("altcha.min.js", base).href);
    const widget = document.querySelector("altcha-widget");
    return new Promise((resolve) => {
      widget.addEventListener("statechange", async (ev) => {
        if (ev.detail.state !== "verified") return;
        try {
          // text/plain keeps this a simple CORS request, with no preflight.
          const resp = await fetch(gate + "/key", {
            method: "POST",
            headers: { "Content-Type": "text/plain" },
            body: JSON.stringify({ payload: ev.detail.payload, kid }),
          });
          if (!resp.ok) throw new Error("The server did not accept the check.");
          const got = await resp.json();
          if (got.kid !== kid) {
            // This page is older than the current key. Load the new version once.
            if (!sessionStorage.getItem("gate.reloaded")) {
              sessionStorage.setItem("gate.reloaded", "1");
              location.reload();
            }
            throw new Error("This page changed. Reload the page.");
          }
          resolve(got.key);
        } catch (e) {
          error.textContent = e.message + " Try again.";
          widget.reset?.();
        }
      });
    });
  }

  async function main() {
    sessionStorage.removeItem("gate.reloaded");
    let rawKey = localStorage.getItem(storeName);
    if (rawKey) {
      try {
        return await render(rawKey);
      } catch {
        localStorage.removeItem(storeName);
      }
    }
    rawKey = await askForKey();
    localStorage.setItem(storeName, rawKey);
    forgetOldKeys();
    await render(rawKey);
  }

  main().catch((e) => {
    document.body.textContent = "This page could not be opened: " + e.message;
  });
})();
