
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());

// Preserve the original request body for Paylor signature verification.
app.use(
  express.json({
    limit: "100kb",
    verify: (req, res, buffer) => {
      req.rawBody = Buffer.from(buffer);
    }
  })
);

// PostgreSQL connection
const pool = process.env.DATABASE_URL
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: process.env.DATABASE_URL.includes("localhost")
        ? false
        : { rejectUnauthorized: false }
    })
  : null;

// Main health check
app.get("/", (req, res) => {
  res.json({
    app: "NYOTA Payment Notifications",
    status: "running",
    paymentVerification: process.env.PAYLOR_WEBHOOK_SECRET
      ? "configured"
      : "missing secret",
    database: pool ? "configured" : "not configured",
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

// Verify the Paylor webhook signature using the original request bytes.
function verifyPaylorSignature(req) {
  const secret = process.env.PAYLOR_WEBHOOK_SECRET;

  if (!secret || !Buffer.isBuffer(req.rawBody)) {
    return false;
  }

  // Paylor documentation lists different headers for local and Global
  // webhooks. Also accept the header shown in your dashboard.
  const signature =
    req.get("x-webhook-signature") ||
    req.get("x-paylor-signature") ||
    req.get("x-payment-signature");

  if (!signature) {
    return false;
  }

  const normalizedSignature = signature.trim();

  // Paylor documentation specifies a hexadecimal SHA-256 HMAC.
  if (!/^[a-f0-9]{64}$/i.test(normalizedSignature)) {
    return false;
  }

  const expected = crypto
    .createHmac("sha256", secret)
    .update(req.rawBody)
    .digest();

  const received = Buffer.from(normalizedSignature, "hex");

  return (
    received.length === expected.length &&
    crypto.timingSafeEqual(received, expected)
  );
}

// Receive verified Paylor webhook notifications.
function handlePaylorWebhook(req, res) {
  if (!process.env.PAYLOR_WEBHOOK_SECRET) {
    console.error("PAYLOR_WEBHOOK_SECRET is missing.");

    return res.status(503).json({
      error: "Webhook verification is not configured."
    });
  }

  if (!verifyPaylorSignature(req)) {
    console.warn("Paylor webhook rejected: invalid signature.");

    return res.status(401).json({
      error: "Invalid webhook signature."
    });
  }

  const payload = req.body;

  if (
    !payload ||
    typeof payload !== "object" ||
    Array.isArray(payload) ||
    typeof payload.event !== "string"
  ) {
    return res.status(400).json({
      error: "Invalid webhook payload."
    });
  }

  // Paylor sends local events with a transaction object and
  // Global collection events with fields at the top level.
  const transaction =
    payload.transaction &&
    typeof payload.transaction === "object" &&
    !Array.isArray(payload.transaction)
      ? payload.transaction
      : {};

  const reference =
    transaction.reference ||
    payload.merchantReference ||
    payload.reference ||
    null;

  const status =
    transaction.status ||
    payload.status ||
    null;

  // Log minimal details. Never log secrets or full payment payloads.
  console.log("Verified Paylor webhook received:", {
    event: payload.event,
    reference:
      typeof reference === "string" ? reference : null,
    status: typeof status === "string" ? status : null,
    receivedAt: new Date().toISOString()
  });

  // A verified notification is not yet a database update,
  // payment reconciliation, or SMS notification.
  return res.status(200).json({
    received: true,
    verified: true
  });
}

// Register both callback paths.
app.post("/api/paylor-callback", handlePaylorWebhook);
app.post("/paylor-callback", handlePaylorWebhook);

// Informational payment-status endpoint.
app.get("/api/payment-status", (req, res) => {
  res.json({
    status: "not_configured",
    message: "Payment status lookup has not been connected."
  });
});

// Handle unknown routes.
app.use((req, res) => {
  res.status(404).json({
    error: "Endpoint not found."
  });
});

// Handle malformed JSON and other errors.
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

  return res.status(500).json({
    error: "An internal server error occurred."
  });
});

// Start server.
const server = app.listen(PORT, () => {
  console.log(
    `NYOTA Payment Notifications listening on port ${PORT}`
  );
});

// Graceful shutdown.
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
