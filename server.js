
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: "100kb" }));

// Database connection
const pool = process.env.DATABASE_URL
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: process.env.DATABASE_URL.includes("localhost")
        ? false
        : { rejectUnauthorized: false }
    })
  : null;

// Basic health check
app.get("/", (req, res) => {
  res.json({
    app: "NYOTA Payment Notifications",
    status: "running",
    mode: process.env.NODE_ENV === "production" ? "production" : "development",
    paymentVerification: "not configured",
    smsNotifications: "not configured"
  });
});

// Check database connectivity
app.get("/api/health", async (req, res) => {
  if (!pool) {
    return res.status(503).json({
      status: "not ready",
      message: "DATABASE_URL has not been configured in Render."
    });
  }

  try {
    await pool.query("SELECT 1");
    res.json({ status: "healthy", database: "connected" });
  } catch (error) {
    console.error("Database health check failed:", error.message);
    res.status(503).json({
      status: "unavailable",
      message: "Database connection failed."
    });
  }
});

// This endpoint does not claim to verify or receive payments.
// Real payment callbacks must be configured and authenticated
// before any customer can receive a payment-success SMS.
app.get("/api/payment-status", (req, res) => {
  res.json({
    status: "not_configured",
    message: "Live payment verification has not been connected."
  });
});

// Safe fallback for unknown routes
app.use((req, res) => {
  res.status(404).json({ error: "Endpoint not found." });
});

// Handle unexpected server errors
app.use((err, req, res, next) => {
  console.error("Server error:", err.message);
  res.status(500).json({ error: "An internal server error occurred." });
});

const server = app.listen(PORT, () => {
  console.log(`NYOTA backend listening on port ${PORT}`);
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
