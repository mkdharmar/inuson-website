/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * Inuson International Inc. — Cloudflare Worker
 * Email backend for contact forms, talent requests, and career applications.
 *
 * Transport: AWS SES HTTP API (v4-signed requests)
 * NOTE: Cloudflare Workers run in a V8 isolate — raw TCP/SMTP connections are
 * not available. This worker calls the AWS SES REST endpoint directly using
 * AWS Signature Version 4, which is the correct approach for Workers.
 * The SES_SMTP_USERNAME / SES_SMTP_PASSWORD env vars map to your AWS IAM
 * access key ID and secret access key respectively (see setup guide below).
 *
 * ═══════════════════════════════════════════════════════════════════════════════
 * ENDPOINTS
 * ─────────────────────────────────────────────────────────────────────────────
 *   POST /contact         — General contact form
 *   POST /request-talent  — Talent request form
 *   POST /apply           — Career application (multipart/form-data, optional résumé)
 *   GET  /health          — Health check
 *
 * ═══════════════════════════════════════════════════════════════════════════════
 * CLOUDFLARE SECRETS — set with: wrangler secret put <NAME>
 * ─────────────────────────────────────────────────────────────────────────────
 *   SES_SMTP_HOST       e.g. "email-smtp.us-east-1.amazonaws.com"
 *                       Used to derive the AWS region automatically.
 *
 *   SES_SMTP_PORT       e.g. "587"  (informational — not used for HTTP API)
 *
 *   SES_SMTP_USERNAME   Your AWS IAM Access Key ID
 *                       (NOT the SES SMTP derived password — use the IAM key ID)
 *                       e.g. "AKIAIOSFODNN7EXAMPLE"
 *
 *   SES_SMTP_PASSWORD   Your AWS IAM Secret Access Key
 *                       e.g. "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
 *
 *   EMAIL_FROM          Verified SES sender address
 *                       e.g. "contact@inuson.com"
 *
 *   EMAIL_TO            Notification recipient(s), comma-separated
 *                       e.g. "contact@inuson.com"
 *
 *   CORS_ORIGIN         Allowed origin for browser requests
 *                       e.g. "https://inuson.com"
 *
 *   COMPANY_NAME        e.g. "Inuson International Inc."
 *
 *   WEBSITE_URL         e.g. "https://inuson.com"
 *
 * ═══════════════════════════════════════════════════════════════════════════════
 * AWS SES SETUP CHECKLIST
 * ─────────────────────────────────────────────────────────────────────────────
 *  1. Log in to AWS Console → SES → Verified Identities
 *  2. Verify the domain inuson.com (or the email address contact@inuson.com)
 *  3. Request production access (move out of SES sandbox) via AWS Support
 *  4. Go to IAM → Users → Create user → attach policy "AmazonSESFullAccess"
 *     (or a custom policy with ses:SendEmail permission only)
 *  5. Create Access Key for that user → copy Access Key ID and Secret
 *  6. Set wrangler secrets:
 *       wrangler secret put SES_SMTP_USERNAME   ← paste Access Key ID
 *       wrangler secret put SES_SMTP_PASSWORD   ← paste Secret Access Key
 *       wrangler secret put SES_SMTP_HOST       ← e.g. email-smtp.us-east-1.amazonaws.com
 *       wrangler secret put EMAIL_FROM          ← contact@inuson.com
 *       wrangler secret put EMAIL_TO            ← contact@inuson.com
 *       wrangler secret put CORS_ORIGIN         ← https://inuson.com
 *       wrangler secret put COMPANY_NAME        ← Inuson International Inc.
 *       wrangler secret put WEBSITE_URL         ← https://inuson.com
 *
 * ═══════════════════════════════════════════════════════════════════════════════
 * DEPLOYMENT
 * ─────────────────────────────────────────────────────────────────────────────
 *  npm install -g wrangler
 *  wrangler login
 *  wrangler deploy
 *
 * See wrangler.toml template at the bottom of this file.
 * ═══════════════════════════════════════════════════════════════════════════════
 */

// ─── Rate limiting (in-memory; resets on Worker restart) ─────────────────────
// For persistent rate limiting across all Worker instances, use Durable Objects.
const rateLimitStore = new Map();
const RATE_LIMIT_MAX = 5;           // max submissions
const RATE_LIMIT_WINDOW_MS = 600000; // per 10 minutes

function checkRateLimit(ip) {
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

// ─── CORS ─────────────────────────────────────────────────────────────────────
function corsHeaders(env) {
  return {
    "Access-Control-Allow-Origin": env.CORS_ORIGIN || "https://inuson.com",
    "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Max-Age": "86400",
  };
}

function jsonResp(data, status = 200, env) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...corsHeaders(env) },
  });
}

// ─── Input helpers ────────────────────────────────────────────────────────────
function sanitise(val = "", maxLen = 4000) {
  return String(val).replace(/[<>]/g, "").trim().slice(0, maxLen);
}

function isValidEmail(e) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e);
}

function isSpam(text) {
  // Basic keyword filter — extend as needed
  const spamKeywords = /\b(viagra|casino|crypto|bitcoin|forex|click here|free money|earn \$|make money fast|seo service|buy followers)\b/i;
  return spamKeywords.test(text);
}

// ─── AWS region from SMTP host ────────────────────────────────────────────────
function regionFromHost(host = "") {
  // "email-smtp.us-east-1.amazonaws.com" → "us-east-1"
  const m = host.match(/email-smtp\.([a-z0-9-]+)\.amazonaws\.com/);
  return m ? m[1] : "us-east-1";
}

// ─── AWS SES v4 signing ───────────────────────────────────────────────────────
async function sha256hex(message) {
  const data = typeof message === "string" ? new TextEncoder().encode(message) : message;
  const buf = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
}

async function hmacSha256(key, msg) {
  const k = typeof key === "string" ? new TextEncoder().encode(key) : key;
  const m = typeof msg === "string" ? new TextEncoder().encode(msg) : msg;
  const ck = await crypto.subtle.importKey("raw", k, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", ck, m));
}

async function buildSigningKey(secret, date, region) {
  const kDate    = await hmacSha256("AWS4" + secret, date);
  const kRegion  = await hmacSha256(kDate, region);
  const kService = await hmacSha256(kRegion, "ses");
  return hmacSha256(kService, "aws4_request");
}

/**
 * Send an email via AWS SES HTTP API (v4 signed).
 * @param {object} env  - Worker environment bindings
 * @param {object} opts - { to: string|string[], replyTo?: string, subject, body, isHtml? }
 */
async function sendEmail(env, { to, replyTo, subject, body, isHtml = false }) {
  const region    = regionFromHost(env.SES_SMTP_HOST);
  const accessKey = env.SES_SMTP_USERNAME;   // IAM Access Key ID
  const secretKey = env.SES_SMTP_PASSWORD;   // IAM Secret Access Key
  const from      = env.EMAIL_FROM || "contact@inuson.com";
  const endpoint  = `https://email.${region}.amazonaws.com/v2/email/outbound-emails`;

  const payload = JSON.stringify({
    FromEmailAddress: from,
    Destination: { ToAddresses: Array.isArray(to) ? to : [to] },
    ...(replyTo ? { ReplyToAddresses: [replyTo] } : {}),
    Content: {
      Simple: {
        Subject: { Data: subject, Charset: "UTF-8" },
        Body: isHtml
          ? { Html: { Data: body, Charset: "UTF-8" } }
          : { Text: { Data: body, Charset: "UTF-8" } },
      },
    },
  });

  const now       = new Date();
  const amzDate   = now.toISOString().replace(/[:-]|\.\d{3}/g, "").slice(0, 15) + "Z";
  const dateStamp = amzDate.slice(0, 8);
  const payHash   = await sha256hex(payload);
  const host      = `email.${region}.amazonaws.com`;

  const canonHeaders  = `content-type:application/json\nhost:${host}\nx-amz-date:${amzDate}\n`;
  const signedHeaders = "content-type;host;x-amz-date";
  const canonReq      = ["POST", "/v2/email/outbound-emails", "", canonHeaders, signedHeaders, payHash].join("\n");
  const credScope     = `${dateStamp}/${region}/ses/aws4_request`;
  const strToSign     = ["AWS4-HMAC-SHA256", amzDate, credScope, await sha256hex(canonReq)].join("\n");
  const sigKey        = await buildSigningKey(secretKey, dateStamp, region);
  const signature     = [...(await hmacSha256(sigKey, strToSign))].map(b => b.toString(16).padStart(2, "0")).join("");
  const authHeader    = `AWS4-HMAC-SHA256 Credential=${accessKey}/${credScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

  const res = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json", "x-amz-date": amzDate, "Authorization": authHeader },
    body: payload,
  });

  if (!res.ok) {
    const err = await res.text();
    throw new Error(`SES ${res.status}: ${err}`);
  }
}

// ─── Timestamp ────────────────────────────────────────────────────────────────
function ts() {
  return new Date().toLocaleString("en-US", {
    timeZone: "America/New_York",
    dateStyle: "full",
    timeStyle: "short",
  }) + " ET";
}

// ─── Route: POST /contact ─────────────────────────────────────────────────────
async function handleContact(req, env, ip, country) {
  let raw;
  try { raw = await req.json(); } catch { return jsonResp({ error: "Invalid request body." }, 400, env); }

  const name    = sanitise(raw.name);
  const company = sanitise(raw.company);
  const email   = sanitise(raw.email, 320);
  const phone   = sanitise(raw.phone, 30);
  const subject = sanitise(raw.subject, 200);
  const message = sanitise(raw.message);
  const pageUrl = sanitise(raw.pageUrl, 500);

  if (!name)              return jsonResp({ error: "Name is required." }, 400, env);
  if (!isValidEmail(email)) return jsonResp({ error: "A valid email address is required." }, 400, env);
  if (!message)           return jsonResp({ error: "Message is required." }, 400, env);
  if (isSpam(message) || isSpam(name)) return jsonResp({ error: "Submission rejected." }, 400, env);

  const to         = (env.EMAIL_TO || "contact@inuson.com").split(",").map(e => e.trim());
  const companyStr = company ? `Company:   ${company}` : "";
  const timestamp  = ts();

  // Notification to Inuson team
  await sendEmail(env, {
    to,
    replyTo: email,
    subject: `New Website Enquiry — Inuson.com`,
    body: [
      "New contact form submission received via inuson.com",
      "",
      `Name:      ${name}`,
      companyStr,
      `Email:     ${email}`,
      `Phone:     ${phone || "—"}`,
      `Subject:   ${subject || "—"}`,
      "",
      "Message:",
      message,
      "",
      `Page URL:  ${pageUrl || "—"}`,
      `Timestamp: ${timestamp}`,
      `IP:        ${ip || "—"}`,
      `Country:   ${country || "—"}`,
    ].filter(l => l !== undefined).join("\n"),
  });

  // Auto-reply to visitor
  const companyName = env.COMPANY_NAME || "Inuson International Inc.";
  const websiteUrl  = env.WEBSITE_URL  || "https://inuson.com";
  await sendEmail(env, {
    to: email,
    subject: `Thank you for contacting Inuson`,
    body: [
      `Hi ${name},`,
      "",
      `Thank you for reaching out to ${companyName}.`,
      "",
      "We have received your message and a member of our team will respond to you shortly.",
      "",
      `In the meantime, you're welcome to explore our services and resources at ${websiteUrl}.`,
      "",
      "Best regards,",
      `The Inuson Team`,
      "",
      `${companyName}`,
      "315 Lowell Avenue, Hamilton, NJ 08619",
      "+1 (315) 596-2665",
      "contact@inuson.com",
    ].join("\n"),
  });

  return jsonResp({ success: true, message: "Thank you. We'll be in touch shortly." }, 200, env);
}

// ─── Route: POST /request-talent ─────────────────────────────────────────────
async function handleTalentRequest(req, env, ip, country) {
  let raw;
  try { raw = await req.json(); } catch { return jsonResp({ error: "Invalid request body." }, 400, env); }

  const name     = sanitise(raw.name);
  const company  = sanitise(raw.company);
  const email    = sanitise(raw.email, 320);
  const phone    = sanitise(raw.phone, 30);
  const industry = sanitise(raw.industry, 100);
  const jobTitle = sanitise(raw.jobTitle, 200);
  const hiring   = sanitise(raw.hiringRequirements);
  const message  = sanitise(raw.message);
  const pageUrl  = sanitise(raw.pageUrl, 500);

  if (!name)               return jsonResp({ error: "Name is required." }, 400, env);
  if (!isValidEmail(email)) return jsonResp({ error: "A valid email address is required." }, 400, env);
  if (!company)            return jsonResp({ error: "Company name is required." }, 400, env);
  if (isSpam(message + hiring)) return jsonResp({ error: "Submission rejected." }, 400, env);

  const to        = (env.EMAIL_TO || "contact@inuson.com").split(",").map(e => e.trim());
  const timestamp = ts();

  await sendEmail(env, {
    to,
    replyTo: email,
    subject: `New Talent Request — Inuson.com`,
    body: [
      "New talent request received via inuson.com",
      "",
      `Name:                ${name}`,
      `Company:             ${company}`,
      `Email:               ${email}`,
      `Phone:               ${phone || "—"}`,
      `Industry:            ${industry || "—"}`,
      `Job Title:           ${jobTitle || "—"}`,
      "",
      "Hiring Requirements:",
      hiring || "—",
      "",
      "Additional Notes:",
      message || "—",
      "",
      `Page URL:  ${pageUrl || "—"}`,
      `Timestamp: ${timestamp}`,
      `IP:        ${ip || "—"}`,
      `Country:   ${country || "—"}`,
    ].join("\n"),
  });

  const companyName = env.COMPANY_NAME || "Inuson International Inc.";
  const websiteUrl  = env.WEBSITE_URL  || "https://inuson.com";
  await sendEmail(env, {
    to: email,
    subject: `Your talent request has been received — Inuson`,
    body: [
      `Hi ${name},`,
      "",
      `Thank you for submitting your talent request to ${companyName}.`,
      "",
      "We take a relationship-driven approach to every search. A member of our team will review your requirements and reach out to discuss how we can best support your organization.",
      "",
      "We look forward to connecting.",
      "",
      "Best regards,",
      "The Inuson Team",
      "",
      `${companyName}`,
      "315 Lowell Avenue, Hamilton, NJ 08619",
      "+1 (315) 596-2665",
      "contact@inuson.com",
      websiteUrl,
    ].join("\n"),
  });

  return jsonResp({ success: true, message: "Your talent request has been received. We'll be in touch soon." }, 200, env);
}

// ─── Route: POST /apply ───────────────────────────────────────────────────────
async function handleApply(req, env, ip, country) {
  let form;
  try { form = await req.formData(); } catch { return jsonResp({ error: "Invalid form data." }, 400, env); }

  const name        = sanitise(form.get("name") || "");
  const email       = sanitise(form.get("email") || "", 320);
  const phone       = sanitise(form.get("phone") || "", 30);
  const location    = sanitise(form.get("location") || "", 200);
  const linkedin    = sanitise(form.get("linkedin") || "", 500);
  const message     = sanitise(form.get("message") || "");
  const coverLetter = sanitise(form.get("coverLetter") || "");
  const resumeFile  = form.get("resume");

  if (!name)               return jsonResp({ error: "Name is required." }, 400, env);
  if (!isValidEmail(email)) return jsonResp({ error: "A valid email address is required." }, 400, env);

  // Validate résumé
  let resumeInfo = null;
  const ALLOWED_TYPES = [
    "application/pdf",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  ];
  const MAX_SIZE = 5 * 1024 * 1024; // 5 MB

  if (resumeFile && resumeFile.size > 0) {
    if (!ALLOWED_TYPES.includes(resumeFile.type)) {
      return jsonResp({ error: "Résumé must be PDF, DOC, or DOCX format." }, 400, env);
    }
    if (resumeFile.size > MAX_SIZE) {
      return jsonResp({ error: "Résumé file must be under 5 MB." }, 400, env);
    }
    resumeInfo = {
      name: resumeFile.name,
      type: resumeFile.type,
      size: Math.round(resumeFile.size / 1024) + " KB",
    };
  }

  const to        = (env.EMAIL_TO || "contact@inuson.com").split(",").map(e => e.trim());
  const timestamp = ts();

  await sendEmail(env, {
    to,
    replyTo: email,
    subject: `New Candidate Application — Inuson.com`,
    body: [
      "New career application received via inuson.com",
      "",
      `Name:      ${name}`,
      `Email:     ${email}`,
      `Phone:     ${phone || "—"}`,
      `Location:  ${location || "—"}`,
      `LinkedIn:  ${linkedin || "—"}`,
      `Résumé:    ${resumeInfo ? `${resumeInfo.name} (${resumeInfo.type}, ${resumeInfo.size})` : "Not provided"}`,
      "",
      "Message:",
      message || "—",
      "",
      coverLetter ? `Cover Letter:\n${coverLetter}` : "",
      "",
      `Timestamp: ${timestamp}`,
      `IP:        ${ip || "—"}`,
      `Country:   ${country || "—"}`,
      "",
      resumeInfo
        ? "NOTE: Résumé was uploaded. To persist files, integrate Cloudflare R2 (see OPTIONAL EXTENSIONS below)."
        : "",
    ].filter(l => l !== null && l !== undefined).join("\n").trim(),
  });

  const companyName = env.COMPANY_NAME || "Inuson International Inc.";
  await sendEmail(env, {
    to: email,
    subject: `Application received — Inuson International Inc.`,
    body: [
      `Hi ${name},`,
      "",
      `Thank you for your interest in opportunities through ${companyName}.`,
      "",
      "We have received your application and our team will review your submission. If your background aligns with current or upcoming opportunities, we will be in touch.",
      "",
      "We appreciate you taking the time to connect with us.",
      "",
      "Best regards,",
      "The Inuson Team",
      "",
      `${companyName}`,
      "315 Lowell Avenue, Hamilton, NJ 08619",
      "+1 (315) 596-2665",
      "contact@inuson.com",
    ].join("\n"),
  });

  return jsonResp({ success: true, message: "Application received. Thank you for your interest." }, 200, env);
}

// ─── Main fetch handler ───────────────────────────────────────────────────────
export default {
  async fetch(request, env) {
    const url     = new URL(request.url);
    const path    = url.pathname.replace(/\/$/, "");
    const method  = request.method.toUpperCase();
    const ip      = request.headers.get("CF-Connecting-IP") || "";
    const country = request.headers.get("CF-IPCountry") || "";

    // CORS preflight
    if (method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(env) });
    }

    // Health check
    if (method === "GET" && path === "/health") {
      return jsonResp({
        status: "ok",
        service: "inuson-contact-worker",
        region: regionFromHost(env.SES_SMTP_HOST || ""),
        ts: new Date().toISOString(),
      }, 200, env);
    }

    // All form routes require POST
    if (method !== "POST") {
      return jsonResp({ error: "Method not allowed." }, 405, env);
    }

    // Rate limiting
    if (checkRateLimit(ip || "unknown")) {
      return jsonResp({ error: "Too many requests. Please wait a few minutes and try again." }, 429, env);
    }

    // Validate required secrets are present
    if (!env.SES_SMTP_USERNAME || !env.SES_SMTP_PASSWORD) {
      console.error("Missing SES credentials — set SES_SMTP_USERNAME and SES_SMTP_PASSWORD secrets.");
      return jsonResp({ error: "Server configuration error. Please contact us directly." }, 500, env);
    }

    try {
      if (path === "/contact")        return await handleContact(request, env, ip, country);
      if (path === "/request-talent") return await handleTalentRequest(request, env, ip, country);
      if (path === "/apply")          return await handleApply(request, env, ip, country);
      return jsonResp({ error: "Not found." }, 404, env);
    } catch (err) {
      console.error("Worker error:", err?.message || err);
      return jsonResp({ error: "An error occurred. Please try again or contact us directly." }, 500, env);
    }
  },
};

/*
════════════════════════════════════════════════════════════════════════════════
wrangler.toml — save in the workers/ directory alongside this file
════════════════════════════════════════════════════════════════════════════════

name = "inuson-contact-worker"
main = "contact-worker.js"
compatibility_date = "2024-09-01"

# Non-sensitive vars (safe to commit)
[vars]
SES_SMTP_PORT  = "587"
COMPANY_NAME   = "Inuson International Inc."
WEBSITE_URL    = "https://inuson.com"
CORS_ORIGIN    = "https://inuson.com"

# ⚠️  Set all sensitive values as secrets — NEVER put them in wrangler.toml
#
#   wrangler secret put SES_SMTP_HOST      → e.g. email-smtp.us-east-1.amazonaws.com
#   wrangler secret put SES_SMTP_USERNAME  → your IAM Access Key ID
#   wrangler secret put SES_SMTP_PASSWORD  → your IAM Secret Access Key
#   wrangler secret put EMAIL_FROM         → contact@inuson.com
#   wrangler secret put EMAIL_TO           → contact@inuson.com

# Custom domain route (after adding api.inuson.com CNAME → your pages project)
[[routes]]
pattern = "api.inuson.com/*"
zone_name = "inuson.com"

════════════════════════════════════════════════════════════════════════════════
CONNECTING FORMS TO THIS WORKER
════════════════════════════════════════════════════════════════════════════════

Contact form — JSON POST:

  fetch("https://api.inuson.com/contact", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      name, company, email, phone, subject, message,
      pageUrl: window.location.href
    })
  })
  .then(r => r.json())
  .then(data => {
    if (data.success) window.location.href = "/thank-you";
    else alert(data.error || "Something went wrong.");
  });

Talent request — JSON POST:

  fetch("https://api.inuson.com/request-talent", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      name, company, email, phone, industry,
      jobTitle, hiringRequirements, message,
      pageUrl: window.location.href
    })
  });

Career application — multipart FormData:

  const fd = new FormData();
  fd.append("name", name);
  fd.append("email", email);
  fd.append("phone", phone);
  fd.append("location", location);
  fd.append("linkedin", linkedin);
  fd.append("message", message);
  if (resumeInput.files[0]) fd.append("resume", resumeInput.files[0]);

  fetch("https://api.inuson.com/apply", { method: "POST", body: fd });

════════════════════════════════════════════════════════════════════════════════
OPTIONAL FUTURE EXTENSIONS
════════════════════════════════════════════════════════════════════════════════
  - Cloudflare R2 bucket:  store uploaded résumés, include signed download
    URL in the notification email instead of noting "file not persisted"
  - Turnstile CAPTCHA:     add Cloudflare Turnstile widget to forms; validate
    cf-turnstile-response server-side before sending email
  - Durable Objects:       persistent cross-instance rate limiting
  - Zoho CRM webhook:      POST lead data to Zoho on /contact and /request-talent
  - Zoho Recruit webhook:  POST application data to Zoho on /apply
  - Slack webhook:         real-time Slack notification on every submission
*/
