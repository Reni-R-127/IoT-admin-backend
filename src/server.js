import "dotenv/config";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import mongoose from "mongoose";
import rateLimit from "express-rate-limit";
import adminRoutes from "./routes/admin.js";
import path from "path";

const app = express();
const port = Number(process.env.PORT || 5001);

// Trust the reverse proxy used by Render.
// This is required for express-rate-limit to handle forwarded IP headers.
app.set("trust proxy", 1);

app.disable("x-powered-by");

const allowedOrigins = (
  process.env.CLIENT_ORIGINS || "http://localhost:5174"
)
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);

app.use(
  helmet({
    crossOriginResourcePolicy: {
      policy: "cross-origin",
    },
  })
);

app.use(
  cors({
    origin(origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      return callback(new Error("Origin not allowed by CORS"));
    },
  })
);

app.use(express.json({ limit: "1mb" }));

// API rate limiting
app.use(
  "/api",
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 200,
    standardHeaders: true,
    legacyHeaders: false,
  })
);

// Health check
app.get("/api/health", (_req, res) => {
  res.json({
    ok: true,
    service: "iot-admin-backend",
    database:
      mongoose.connection.readyState === 1
        ? "connected"
        : "disconnected",
  });
});
app.use("/uploads", express.static(path.resolve("uploads")));
// Admin routes
app.use("/api/admin", adminRoutes);

// Central error handler
app.use((err, _req, res, _next) => {
  console.error("Admin API error:", err.message);

  if (err.message === "Origin not allowed by CORS") {
    return res.status(403).json({ message: "Origin not allowed." });
  }

  if (err instanceof Error && err.name === "MulterError") {
    const status = err.code === "LIMIT_FILE_SIZE" ? 413 : 400;

    return res.status(status).json({
      message:
        err.code === "LIMIT_FILE_SIZE"
          ? "Image must be 3 MB or smaller."
          : err.message,
    });
  }

  if (err.message === "Upload a JPG, PNG, or WebP image.") {
    return res.status(400).json({ message: err.message });
  }

  return res.status(500).json({
    message: "Server error. Check admin backend logs.",
  });
});

// Environment validation
if (!process.env.MONGODB_URI) {
  console.error("MONGODB_URI is missing in admin-backend environment variables.");
  process.exit(1);
}

if (
  !process.env.ADMIN_API_KEY ||
  process.env.ADMIN_API_KEY.length < 32
) {
  console.error(
    "ADMIN_API_KEY must be at least 32 characters in admin-backend environment variables."
  );
  process.exit(1);
}

// Connect to MongoDB and start server
try {
  await mongoose.connect(process.env.MONGODB_URI, {
    serverSelectionTimeoutMS: 10000,
  });

  console.log("MongoDB connected successfully.");

  app.listen(port, "0.0.0.0", () => {
    console.log(`Admin API listening on port ${port}`);
  });
} catch (error) {
  console.error("Failed to start admin backend:", error.message);
  process.exit(1);
}
