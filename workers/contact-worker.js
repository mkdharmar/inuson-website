/**
 * Inuson International Inc. — Cloudflare Worker
 * Handles contact form, talent request, and career application submissions.
 *
 * DEPLOYMENT GUIDE
 * ─────────────────────────────────────────────────────────────────────────────
 * 1. Install Wrangler: npm install -g wrangler
 * 2. Authenticate:     wrangler login
 * 3. Configure wrangler.toml (see bottom of this file for template)
 * 4. Set secrets:
 *      wrangler secret put AWS_SES_ACCESS_KEY_ID
 *      wrangler secret put AWS_SES_SECRET_ACCESS_KEY
 * 5. Deploy:           wrangler deploy
 *
 * REQUIRED ENVIRONMENT VARIABLES (set as Cloudflare Worker secrets)
 * ─────────────────────────────────────────────────────────────────────────────
 *   AWS_SES_ACCESS_KEY_ID      — AWS IAM access key with ses:SendEmail permission
 *   AWS_SES_SECRET_ACCESS_KEY  — Corresponding secret key
 *   AWS_SES_REGION             — AWS region (e.g. "us-east-1") — set in wrangler.toml
 *   FROM_EMAIL                 — Verified SES sender (e.g. "noreply@inuson.com")
 *   NOTIFY_EMAILS              — Comma-separated recipients (e.g. "info@inuson.com,manoj@inuson.com")
 *   CORS_ORIGIN                — Allowed origin (e.g. "https://www.inusoninternational.com")
 *
 * ENDPOINTS
 * ─────────────────────────────────────────────────────────────────────────────
 *   POST /contact         — General contact form
 *   POST /request-talent  — Talent request form
 *   POST /apply           — Career application (with optional résumé upload)
 *   GET  /health          — Health check
 *
 * RATE LIMITING
 * ─────────────────────────────────────────────────────────────────────────────
 * Simple in-memory rate limiting: 5 submissions per IP per 10 minutes.
 * For production, use Cloudflare Rate Limiting rules or Durable Objects.
 */

// ─── In-memory rate limit store (resets on Worker restart) ───────────────────
const rateLimitStore = new Map();
const RATE_LIMIT_MAX = 5;
const RATE_LIMIT_WINDOW_MS = 10 * 60 * 1000; // 10 minutes

function isRateLimited(ip) {
  const now = Date.now();
  const entry = rateLimitStore.get(ip) || { count: 0, resetAt: now + RATE_LIMIT_WINDOW_MS };
  if (now > entry.resetAt) {
    rateLimitStore.set(ip, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
    return false;
  }
  if (entry.count >= RATE_LIMIT_MAX) return true;
  entry.count++;
  rateLimitStore.set(ip, entry);
  return false;
}

// ─── CORS helpers ─────────────────────────────────────────────────────────────
function corsHeaders(env) {
  return {
    "Access-Control-Allow-Origin": env.CORS_ORIGIN || "*",
    "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };
}

function jsonResponse(data, status = 200, env) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...corsHeaders(env) },
  });
}

// ─── Input sanitisation ───────────────────────────────────────────────────────
function sanitise(str = "", maxLen = 2000) {
  return String(str).replace(/[<>]/g, "").trim().slice(0, maxLen);
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// ─── AWS SES v4 signing ───────────────────────────────────────────────────────
async function sha256hex(message) {
  const data = typeof message === "string" ? new TextEncoder().encode(message) : message;
  const hash = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2, "0")).join("");
}

async function hmacSha256(key, message) {
  const k = typeof key === "string" ? new TextEncoder().encode(key) : key;
  const m = typeof message === "string" ? new TextEncoder().encode(message) : message;
  const cryptoKey = await crypto.subtle.importKey("raw", k, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, m));
}

async function getSignatureKey(key, dateStamp, regionName, serviceName) {
  const kDate    = await hmacSha256("AWS4" + key, dateStamp);
  const kRegion  = await hmacSha256(kDate, regionName);
  const kService = await hmacSha256(kRegion, serviceName);
  const kSigning = await hmacSha256(kService, "aws4_request");
  return kSigning;
}

async function sendViaSES(env, { to, subject, body, isHtml = false }) {
  const region    = env.AWS_SES_REGION || "us-east-1";
  const accessKey = env.AWS_SES_ACCESS_KEY_ID;
  const secretKey = env.AWS_SES_SECRET_ACCESS_KEY;
  const from      = env.FROM_EMAIL || "noreply@inuson.com";

  const endpoint = `https://email.${region}.amazonaws.com/v2/email/outbound-emails`;
  const payload  = JSON.stringify({
    FromEmailAddress: from,
    Destination: { ToAddresses: Array.isArray(to) ? to : [to] },
    Content: {
      Simple: {
        Subject: { Data: subject, Charset: "UTF-8" },
        Body: isHtml
          ? { Html: { Data: body, Charset: "UTF-8" } }
          : { Text: { Data: body, Charset: "UTF-8" } },
      },
    },
  });

  const now         = new Date();
  const amzDate     = now.toISOString().replace(/[:-]|\.\d{3}/g, "").slice(0, 15) + "Z";
  const dateStamp   = amzDate.slice(0, 8);
  const payloadHash = await sha256hex(payload);

  const canonicalHeaders = `content-type:application/json\nhost:email.${region}.amazonaws.com\nx-amz-date:${amzDate}\n`;
  const signedHeaders    = "content-type;host;x-amz-date";
  const canonicalRequest = [
    "POST", "/v2/email/outbound-emails", "",
    canonicalHeaders, signedHeaders, payloadHash,
  ].join("\n");

  const credentialScope  = `${dateStamp}/${region}/ses/aws4_request`;
  const stringToSign     = ["AWS4-HMAC-SHA256", amzDate, credentialScope, await sha256hex(canonicalRequest)].join("\n");
  const signingKey       = await getSignatureKey(secretKey, dateStamp, region, "ses");
  const signature        = [...(await hmacSha256(signingKey, stringToSign))].map(b => b.toString(16).padStart(2, "0")).join("");

  const authHeader = `AWS4-HMAC-SHA256 Credential=${accessKey}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

  const res = await fetch(endpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-amz-date": amzDate,
      "Authorization": authHeader,
    },
    body: payload,
  });

  if (!res.ok) {
    const err = await res.text();
    throw new Error(`SES error ${res.status}: ${err}`);
  }
  return true;
}

// ─── Timestamp helper ─────────────────────────────────────────────────────────
function timestamp() {
  return new Date().toLocaleString("en-US", { timeZone: "America/New_York", dateStyle: "full", timeStyle: "short" }) + " ET";
}

// ─── Route handlers ───────────────────────────────────────────────────────────

/** POST /contact */
async function handleContact(request, env) {
  let data;
  try { data = await request.json(); } catch { return jsonResponse({ error: "Invalid JSON" }, 400, env); }

  const name    = sanitise(data.name);
  const email   = sanitise(data.email, 320);
  const company = sanitise(data.company);
  const phone   = sanitise(data.phone, 30);
  const subject = sanitise(data.subject, 200);
  const message = sanitise(data.message);
  const pageUrl = sanitise(data.pageUrl, 500);

  if (!name)              return jsonResponse({ error: "Name is required" }, 400, env);
  if (!isValidEmail(email)) return jsonResponse({ error: "Valid email is required" }, 400, env);
  if (!message)           return jsonResponse({ error: "Message is required" }, 400, env);

  const notifyEmails = (env.NOTIFY_EMAILS || "info@inuson.com,manoj@inuson.com").split(",").map(e => e.trim());
  const ts = timestamp();

  // Notification to Inuson team
  await sendViaSES(env, {
    to: notifyEmails,
    subject: `New Website Enquiry — Inuson.com`,
    body: `New contact form submission received.\n\n` +
      `Name:      ${name}\n` +
      `Company:   ${company || "—"}\n` +
      `Email:     ${email}\n` +
      `Phone:     ${phone || "—"}\n` +
      `Subject:   ${subject || "—"}\n\n` +
      `Message:\n${message}\n\n` +
      `Page URL:  ${pageUrl || "—"}\n` +
      `Timestamp: ${ts}\n`,
  });

  // Auto-reply to visitor
  await sendViaSES(env, {
    to: email,
    subject: `We've received your message — Inuson International Inc.`,
    body: `Hi ${name},\n\nThank you for reaching out to Inuson International Inc.\n\n` +
      `We've received your message and a member of our team will be in touch with you shortly.\n\n` +
      `In the meantime, feel free to explore our services and industry pages at https://www.inusoninternational.com.\n\n` +
      `Best regards,\nThe Inuson Team\n\n` +
      `Inuson International Inc.\n315 Lowell Avenue, Hamilton, NJ 08619\n+1 (315) 596-2665\ninfo@inuson.com`,
  });

  return jsonResponse({ success: true, message: "Thank you. We'll be in touch shortly." }, 200, env);
}

/** POST /request-talent */
async function handleTalentRequest(request, env) {
  let data;
  try { data = await request.json(); } catch { return jsonResponse({ error: "Invalid JSON" }, 400, env); }

  const name     = sanitise(data.name);
  const company  = sanitise(data.company);
  const email    = sanitise(data.email, 320);
  const phone    = sanitise(data.phone, 30);
  const industry = sanitise(data.industry, 100);
  const jobTitle = sanitise(data.jobTitle, 200);
  const hiring   = sanitise(data.hiringRequirements);
  const message  = sanitise(data.message);
  const pageUrl  = sanitise(data.pageUrl, 500);

  if (!name)               return jsonResponse({ error: "Name is required" }, 400, env);
  if (!isValidEmail(email)) return jsonResponse({ error: "Valid email is required" }, 400, env);
  if (!company)            return jsonResponse({ error: "Company is required" }, 400, env);

  const notifyEmails = (env.NOTIFY_EMAILS || "info@inuson.com,manoj@inuson.com").split(",").map(e => e.trim());
  const ts = timestamp();

  await sendViaSES(env, {
    to: notifyEmails,
    subject: `New Talent Request — Inuson.com`,
    body: `New talent request received.\n\n` +
      `Name:                ${name}\n` +
      `Company:             ${company}\n` +
      `Email:               ${email}\n` +
      `Phone:               ${phone || "—"}\n` +
      `Industry:            ${industry || "—"}\n` +
      `Job Title:           ${jobTitle || "—"}\n\n` +
      `Hiring Requirements:\n${hiring || "—"}\n\n` +
      `Additional Message:\n${message || "—"}\n\n` +
      `Page URL:  ${pageUrl || "—"}\n` +
      `Timestamp: ${ts}\n`,
  });

  await sendViaSES(env, {
    to: email,
    subject: `Your talent request has been received — Inuson International Inc.`,
    body: `Hi ${name},\n\nThank you for submitting your talent request to Inuson International Inc.\n\n` +
      `We take a relationship-driven approach to every search. A member of our team will review your requirements and reach out to discuss how we can best support your organization.\n\n` +
      `We're committed to your success and look forward to connecting.\n\n` +
      `Best regards,\nThe Inuson Team\n\n` +
      `Inuson International Inc.\n315 Lowell Avenue, Hamilton, NJ 08619\n+1 (315) 596-2665\ninfo@inuson.com`,
  });

  return jsonResponse({ success: true, message: "Your talent request has been received. We'll be in touch soon." }, 200, env);
}

/** POST /apply — multipart/form-data with optional résumé */
async function handleApplication(request, env) {
  let formData;
  try { formData = await request.formData(); } catch { return jsonResponse({ error: "Invalid form data" }, 400, env); }

  const name       = sanitise(formData.get("name") || "");
  const email      = sanitise(formData.get("email") || "", 320);
  const phone      = sanitise(formData.get("phone") || "", 30);
  const location   = sanitise(formData.get("location") || "", 200);
  const linkedin   = sanitise(formData.get("linkedin") || "", 500);
  const message    = sanitise(formData.get("message") || "");
  const coverLetter= sanitise(formData.get("coverLetter") || "");
  const resumeFile = formData.get("resume");

  if (!name)               return jsonResponse({ error: "Name is required" }, 400, env);
  if (!isValidEmail(email)) return jsonResponse({ error: "Valid email is required" }, 400, env);

  // Validate résumé if provided
  let resumeInfo = null;
  if (resumeFile && resumeFile.size > 0) {
    const allowedTypes = ["application/pdf", "application/msword", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"];
    const MAX_SIZE = 5 * 1024 * 1024; // 5 MB
    if (!allowedTypes.includes(resumeFile.type)) {
      return jsonResponse({ error: "Résumé must be PDF, DOC, or DOCX" }, 400, env);
    }
    if (resumeFile.size > MAX_SIZE) {
      return jsonResponse({ error: "Résumé must be under 5 MB" }, 400, env);
    }
    resumeInfo = { name: resumeFile.name, type: resumeFile.type, size: Math.round(resumeFile.size / 1024) + " KB" };
  }

  const notifyEmails = (env.NOTIFY_EMAILS || "info@inuson.com,manoj@inuson.com").split(",").map(e => e.trim());
  const ts = timestamp();

  await sendViaSES(env, {
    to: notifyEmails,
    subject: `New Candidate Application — Inuson.com`,
    body: `New career application received.\n\n` +
      `Name:         ${name}\n` +
      `Email:        ${email}\n` +
      `Phone:        ${phone || "—"}\n` +
      `Location:     ${location || "—"}\n` +
      `LinkedIn:     ${linkedin || "—"}\n` +
      (resumeInfo ? `Résumé:       ${resumeInfo.name} (${resumeInfo.type}, ${resumeInfo.size})\n` : `Résumé:       Not provided\n`) +
      `\nMessage:\n${message || "—"}\n\n` +
      (coverLetter ? `Cover Letter:\n${coverLetter}\n\n` : "") +
      `Timestamp: ${ts}\n\n` +
      `Note: If a résumé was attached, retrieve it from the form submission or integrate Cloudflare R2 storage for file persistence.`,
  });

  await sendViaSES(env, {
    to: email,
    subject: `Application received — Inuson International Inc.`,
    body: `Hi ${name},\n\nThank you for your interest in opportunities through Inuson International Inc.\n\n` +
      `We've received your application and our team will review your submission. If your background aligns with current or upcoming opportunities, we'll be in touch.\n\n` +
      `We appreciate you taking the time to connect with us.\n\n` +
      `Best regards,\nThe Inuson Team\n\n` +
      `Inuson International Inc.\n315 Lowell Avenue, Hamilton, NJ 08619\n+1 (315) 596-2665\ninfo@inuson.com`,
  });

  return jsonResponse({ success: true, message: "Application received. Thank you for your interest." }, 200, env);
}

// ─── Main entry point ─────────────────────────────────────────────────────────
export default {
  async fetch(request, env) {
    const url    = new URL(request.url);
    const path   = url.pathname.replace(/\/$/, "");
    const method = request.method.toUpperCase();

    // CORS preflight
    if (method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(env) });
    }

    // Health check
    if (method === "GET" && path === "/health") {
      return jsonResponse({ status: "ok", service: "inuson-contact-worker", ts: new Date().toISOString() }, 200, env);
    }

    // Only allow POST for form endpoints
    if (method !== "POST") {
      return jsonResponse({ error: "Method not allowed" }, 405, env);
    }

    // Rate limiting
    const clientIp = request.headers.get("CF-Connecting-IP") || "unknown";
    if (isRateLimited(clientIp)) {
      return jsonResponse({ error: "Too many requests. Please try again later." }, 429, env);
    }

    try {
      if (path === "/contact")        return await handleContact(request, env);
      if (path === "/request-talent") return await handleTalentRequest(request, env);
      if (path === "/apply")          return await handleApplication(request, env);
      return jsonResponse({ error: "Not found" }, 404, env);
    } catch (err) {
      console.error("Worker error:", err);
      return jsonResponse({ error: "An internal error occurred. Please try again." }, 500, env);
    }
  },
};

/*
────────────────────────────────────────────────────────────────────────────────
wrangler.toml TEMPLATE
Save as wrangler.toml in the same directory as this worker file.
────────────────────────────────────────────────────────────────────────────────

name = "inuson-contact-worker"
main = "contact-worker.js"
compatibility_date = "2024-01-01"

[vars]
AWS_SES_REGION = "us-east-1"
FROM_EMAIL     = "noreply@inuson.com"
NOTIFY_EMAILS  = "info@inuson.com,manoj@inuson.com"
CORS_ORIGIN    = "https://www.inusoninternational.com"

# Set these as secrets (never commit to git):
# wrangler secret put AWS_SES_ACCESS_KEY_ID
# wrangler secret put AWS_SES_SECRET_ACCESS_KEY

[[routes]]
pattern = "api.inusoninternational.com/*"
zone_name = "inusoninternational.com"

────────────────────────────────────────────────────────────────────────────────
CONNECT FORMS TO THIS WORKER
────────────────────────────────────────────────────────────────────────────────

Contact form:
  fetch("https://api.inusoninternational.com/contact", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, email, company, phone, subject, message, pageUrl: location.href })
  })

Talent request:
  fetch("https://api.inusoninternational.com/request-talent", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, company, email, phone, industry, jobTitle, hiringRequirements, message, pageUrl: location.href })
  })

Career application (with résumé):
  const fd = new FormData();
  fd.append("name", name); fd.append("email", email);
  fd.append("phone", phone); fd.append("location", location);
  fd.append("linkedin", linkedin); fd.append("message", message);
  fd.append("resume", fileInput.files[0]);
  fetch("https://api.inusoninternational.com/apply", { method: "POST", body: fd })

────────────────────────────────────────────────────────────────────────────────
AWS SES SETUP CHECKLIST
────────────────────────────────────────────────────────────────────────────────
1. Verify sender domain or email in AWS SES console
2. Request production access (move out of SES sandbox)
3. Create IAM user with ses:SendEmail permission
4. Generate access key & secret — set as Wrangler secrets
5. Set FROM_EMAIL to your verified SES address

OPTIONAL FUTURE EXTENSIONS
────────────────────────────────────────────────────────────────────────────────
- Cloudflare R2 for résumé file storage (persist uploads, attach links to emails)
- Zoho Recruit webhook integration on /apply
- Zoho CRM webhook integration on /contact and /request-talent
- Slack notification via Incoming Webhook on every form submission
- Cloudflare Durable Objects for persistent rate limiting across Worker instances
- Turnstile (Cloudflare CAPTCHA) for additional spam protection
*/
