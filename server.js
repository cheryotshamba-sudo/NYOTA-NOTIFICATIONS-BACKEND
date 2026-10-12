
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());

/*
 * Preserve the original request bytes.
 * Paylor's signature must be checked against these exact bytes.
 */
app.use(
  express.json({
    limit: "100kb",
    verify: (req, res, buffer) => {
      req.rawBody = Buffer.from(buffer);
    }
  })
);

// Database connection
const pool = process.env.DATABASE_URL
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: process.env.DATABASE_URL.includes("localhost")
        ? false
        : { rejectUnauthorized: false }
    })
  : null;

// Health check
app.get("/", (req, res) => {
  res.json({
    app: "NYOTA Payment Notifications",
    status: "running",
    paymentVerification: process.env.PAYLOR_WEBHOOK_SECRET
      ? "configured"
      : "missing secret",
    smsNotifications: "not configured"
  });
});

// Database health check
app.get("/api/health", async (req, res) => {
  if (!pool) {
    return res.status(503).json({
      status: "not ready",
      message: "DATABASE_URL is not configured."
    });
  }

  try {
    await pool.query("SELECT 1");

    return res.json({
      status: "healthy",
      database: "connected"
    });
  } catch (error) {
    console.error("Database health check failed:", error.message);

    return res.status(503).json({
      status: "unavailable",
      message: "Database connection failed."
    });
  }
});

/*
 * Verify Paylor's HMAC-SHA256 signature.
 * Supports both local payment callbacks and
 * Global payment webhooks.
 */
function verifyPaylorSignature(req) {
  const secret = process.env.PAYLOR_WEBHOOK_SECRET;

  if (!secret || !Buffer.isBuffer(req.rawBody)) {
    return false;
  }

  const signature =
    req.get("x-webhook-signature") ||
    req.get("x-paylor-signature");

  if (!signature || !/^[a-f0-9]{64}$/i.test(signature)) {
    return false;
  }

  const expected = crypto
    .createHmac("sha256", secret)
    .update(req.rawBody)
    .digest();

  const received = Buffer.from(signature, "hex");

  return (
    received.length === expected.length &&
    crypto.timingSafeEqual(received, expected)
  );
}

/*
 * Paylor callback endpoint.
 * Both paths are available for easier configuration.
 */
function handlePaylorWebhook(req, res) {
  if (!process.env.PAYLOR_WEBHOOK_SECRET) {
    console.error("PAYLOR_WEBHOOK_SECRET is missing.");

    return res.status(503).json({
      error: "Webhook verification is not configured."
    });
  }

  if (!verifyPaylorSignature(req)) {
    console.warn("Rejected webhook: invalid signature.");

    return res.status(401).json({
      error: "Invalid webhook signature."
    });
  }

  const payload = req.body;

  if (!payload || typeof payload !== "object" ||
      Array.isArray(payload)) {
    return res.status(400).json({
      error: "Invalid webhook payload."
    });
  }

  const event = payload.event;
  const transaction = payload.transaction || {};

  const reference =
    transaction.reference || payload.merchantReference ||
    payload.reference || null;

  /*
   * Log only essential event details.
   * Do not treat an event as a database credit or SMS
   * trigger until reconciliation and idempotency are added.
   */
  console.log("Verified Paylor webhook:", {
    event: typeof event === "string" ? event : "unknown",
    reference:
      typeof reference === "string" ? reference : null,
    receivedAt: new Date().toISOString()
  });

  // A verified notification is not, by itself, a completed
  // application-level reconciliation or customer notification.
  return res.status(200).json({
    received: true,
    verified: true
  });
}

app.post("/api/paylor-callback", handlePaylorWebhook);
app.post("/paylor-callback", handlePaylorWebhook);

// Existing payment-status route remains informational only.
app.get("/api/payment-status", (req, res) => {
  res.json({
    status: "not_configured",
    message:
      "Customer payment status lookup has not been connected."
  });
});

// Not found
app.use((req, res) => {
  res.status(404).json({
    error: "Endpoint not found."
  });
});

// Error handler
app.use((err, req, res, next) => {
  if (err.type === "entity.parse.failed") {
    return res.status(400).json({
      error: "Invalid JSON payload."
    });
  }

  if (err.type === "entity.too.large") {
    return res.status(413).json({
      error: "Request payload is too large."
    });
  }

  console.error("Server error:", err.message);

  res.status(500).json({
    error: "An internal server error occurred."
  });
});

const server = app.listen(PORT, () => {
  console.log(
    `NYOTA Payment Notifications listening on port ${PORT}`
  );
});

async function shutdown() {
  server.close(async () => {
    if (pool) {
      await pool.end().catch(() => {});
    }

    process.exit(0);
  });
}

process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
