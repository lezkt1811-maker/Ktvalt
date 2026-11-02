// Neon Photo Vault Worker: stores original photo bytes in an R2 bucket.
// Secret: VAULT_KEY (set in Cloudflare dashboard, never committed).
// Binding: PHOTOS (R2 bucket).

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Authorization, Content-Type, X-Original-Name, X-Original-Size, X-Original-Modified, X-SHA256",
  "Access-Control-Expose-Headers": "Content-Disposition, Content-Type",
};

const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { ...CORS, "Content-Type": "application/json" },
  });

const fail = (msg, status) => new Response(msg, { status, headers: CORS });

function authorized(request, env, url) {
  const expected = env.VAULT_KEY;
  if (!expected) return false;
  const header = request.headers.get("Authorization") || "";
  const bearer = header.startsWith("Bearer ") ? header.slice(7) : "";
  // Image previews and downloads pass the key as ?token= because <img> tags can't send headers.
  const token = url.searchParams.get("token") || "";
  const given = bearer || token;
  return given.length > 0 && timingSafeEqual(given, expected);
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// Hard cap so storage never goes past R2's 10 GB free tier.
// 9.5 GB leaves a safety margin. Uploads that would exceed it are refused.
const STORAGE_CAP_BYTES = 9.5e9;

async function totalStoredBytes(bucket) {
  let total = 0, cursor;
  do {
    const page = await bucket.list({ cursor });
    for (const obj of page.objects) total += obj.size;
    cursor = page.truncated ? page.cursor : undefined;
  } while (cursor);
  return total;
}

// Keys look like: <64 hex sha256>.<optional extension>
const KEY_RE = /^[a-f0-9]{64}(\.[a-z0-9]{1,10})?$/;

function toHex(buffer) {
  return [...new Uint8Array(buffer)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function contentDisposition(name) {
  const safe = (name || "photo").replace(/[\r\n"]/g, "_");
  return `attachment; filename="${safe}"; filename*=UTF-8''${encodeURIComponent(name || "photo")}`;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
    if (!authorized(request, env, url)) return fail("Unauthorized", 401);

    const path = url.pathname;

    // Connection check: the page calls this first and shows the file count.
    if (request.method === "GET" && path === "/api/ping") {
      let count = 0, cursor;
      do {
        const page = await env.PHOTOS.list({ cursor });
        count += page.objects.length;
        cursor = page.truncated ? page.cursor : undefined;
      } while (cursor);
      return json({ ok: true, count });
    }

    // List every archived file with its metadata.
    if (request.method === "GET" && path === "/api/list") {
      const files = [];
      let cursor;
      do {
        const page = await env.PHOTOS.list({ cursor, include: ["customMetadata", "httpMetadata"] });
        for (const obj of page.objects) {
          const meta = obj.customMetadata || {};
          files.push({
            key: obj.key,
            originalName: meta.originalName || obj.key,
            contentType: obj.httpMetadata?.contentType || "",
            size: obj.size,
            uploaded: obj.uploaded ? new Date(obj.uploaded).toISOString().slice(0, 10) : "",
          });
        }
        cursor = page.truncated ? page.cursor : undefined;
      } while (cursor);
      files.sort((a, b) => (a.uploaded < b.uploaded ? 1 : -1));
      return json({ files });
    }

    // Upload one original file. Duplicates (same SHA-256) are not stored twice.
    const uploadMatch = path.match(/^\/api\/upload\/(.+)$/);
    if (request.method === "PUT" && uploadMatch) {
      const key = decodeURIComponent(uploadMatch[1]);
      if (!KEY_RE.test(key)) return fail("Bad key", 400);

      const existing = await env.PHOTOS.head(key);
      if (existing) return json({ ok: true, deduplicated: true, key });

      const declared = Number(request.headers.get("Content-Length") || 0);
      if (declared > 0) {
        const used = await totalStoredBytes(env.PHOTOS);
        if (used + declared > STORAGE_CAP_BYTES) {
          return fail("Storage cap reached: 9.5 GB limit. Delete something first.", 507);
        }
      }

      const body = await request.arrayBuffer();
      if ((await totalStoredBytes(env.PHOTOS)) + body.byteLength > STORAGE_CAP_BYTES) {
        return fail("Storage cap reached: 9.5 GB limit. Delete something first.", 507);
      }
      const digest = toHex(await crypto.subtle.digest("SHA-256", body));
      const claimed = request.headers.get("X-SHA256") || "";
      if (digest !== claimed || !key.startsWith(digest)) return fail("Hash mismatch", 400);

      await env.PHOTOS.put(key, body, {
        httpMetadata: { contentType: request.headers.get("Content-Type") || "application/octet-stream" },
        customMetadata: {
          originalName: decodeURIComponent(request.headers.get("X-Original-Name") || "photo"),
          originalSize: request.headers.get("X-Original-Size") || String(body.byteLength),
          originalModified: request.headers.get("X-Original-Modified") || "0",
          sha256: digest,
        },
      });
      return json({ ok: true, deduplicated: false, key });
    }

    // Download or preview one file.
    const fileMatch = path.match(/^\/api\/file\/(.+)$/);
    if (fileMatch && request.method === "GET") {
      const key = decodeURIComponent(fileMatch[1]);
      if (!KEY_RE.test(key)) return fail("Bad key", 400);
      const obj = await env.PHOTOS.get(key);
      if (!obj) return fail("Not found", 404);
      const headers = new Headers(CORS);
      obj.writeHttpMetadata(headers);
      headers.set("Content-Disposition", contentDisposition(obj.customMetadata?.originalName || key));
      return new Response(obj.body, { headers });
    }

    // Delete one archive copy. This does not touch the photo on the phone.
    if (fileMatch && request.method === "DELETE") {
      const key = decodeURIComponent(fileMatch[1]);
      if (!KEY_RE.test(key)) return fail("Bad key", 400);
      await env.PHOTOS.delete(key);
      return json({ ok: true });
    }

    // Re-hash a stored file and confirm it still matches its fingerprint.
    const verifyMatch = path.match(/^\/api\/verify\/(.+)$/);
    if (verifyMatch && request.method === "GET") {
      const key = decodeURIComponent(verifyMatch[1]);
      if (!KEY_RE.test(key)) return fail("Bad key", 400);
      const obj = await env.PHOTOS.get(key);
      if (!obj) return fail("Not found", 404);
      const digest = toHex(await crypto.subtle.digest("SHA-256", await obj.arrayBuffer()));
      return json({ ok: digest === key.slice(0, 64) });
    }

    return fail("Not found", 404);
  },
};
