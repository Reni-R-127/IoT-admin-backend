/**
 * File: admin-backend/src/server.js
 *
 * Purpose:
 * Main Admin Backend server.
 *
 * Features:
 * - Express API server
 * - MongoDB connection
 * - Super Admin bootstrap and email migration
 * - Staff authentication configuration
 * - API rate limiting
 * - CORS and security headers
 * - Media upload serving
 *
 * Authentication:
 * Super Admin: Email + Password + JWT
 * Staff: Email + Password + JWT
 *
 * Default port: 5001
 */

import "dotenv/config";

import express from "express";
import cors from "cors";
import helmet from "helmet";
import mongoose from "mongoose";
import rateLimit from "express-rate-limit";
import bcrypt from "bcryptjs";
import path from "path";

import adminRoutes from "./routes/admin.js";

import { SuperAdmin } from "./models/Content.js";


// ======================================================
// APP CONFIGURATION
// ======================================================

const app = express();

const PORT = Number(process.env.PORT || 5001);

app.set("trust proxy", 1);
app.disable("x-powered-by");


// ======================================================
// EMAIL VALIDATION
// ======================================================

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}


// ======================================================
// CORS
// ======================================================

const allowedOrigins = (
  process.env.CLIENT_ORIGINS ||
  "http://localhost:5174"
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

      return callback(
        new Error("Origin not allowed by CORS")
      );
    },
  })
);


// ======================================================
// BODY PARSER
// ======================================================

app.use(
  express.json({
    limit: "1mb",
  })
);


// ======================================================
// API RATE LIMITING
// ======================================================

app.use(
  "/api",
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 200,
    standardHeaders: true,
    legacyHeaders: false,
  })
);


// ======================================================
// LOGIN RATE LIMITING
// ======================================================

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    message: "Too many login attempts. Please try again later.",
  },
});

app.use("/api/admin/auth/login", loginLimiter);
app.use("/api/admin/staff/login", loginLimiter);


// ======================================================
// HEALTH CHECK
// ======================================================

app.get("/api/health", (_req, res) => {
  return res.json({
    ok: true,
    service: "iot-admin-backend",
    port: PORT,
    database:
      mongoose.connection.readyState === 1
        ? "connected"
        : "disconnected",
  });
});


// ======================================================
// STATIC MEDIA FILES
// ======================================================

app.use(
  "/uploads",
  express.static(path.resolve("uploads"))
);


// ======================================================
// ADMIN ROUTES
// ======================================================

app.use("/api/admin", adminRoutes);


// ======================================================
// 404 HANDLER
// ======================================================

app.use((req, res) => {
  return res.status(404).json({
    message: "API endpoint not found.",
    path: req.originalUrl,
  });
});


// ======================================================
// CENTRAL ERROR HANDLER
// ======================================================

app.use((error, _req, res, _next) => {
  console.error("Admin API error:", error);

  if (error.message === "Origin not allowed by CORS") {
    return res.status(403).json({
      message: "Origin not allowed.",
    });
  }

  if (
    error.name === "MulterError" &&
    error.code === "LIMIT_FILE_SIZE"
  ) {
    return res.status(413).json({
      message: "Image must be 3 MB or smaller.",
    });
  }

  if (error.name === "ValidationError") {
    return res.status(400).json({
      message: error.message,
    });
  }

  return res.status(500).json({
    message: "Internal server error. Check backend logs.",
  });
});


// ======================================================
// INITIAL SUPER ADMIN CREATION / MIGRATION
//
// Existing account:
// username: admin
//
// New account:
// email: SUPER_ADMIN_EMAIL
//
// Migration:
// - Existing password hash is preserved.
// - Existing account ID is preserved.
// - Existing temporary password is preserved.
// - Only email field is added.
// ======================================================

async function initializeSuperAdmin() {
  const email = String(
    process.env.SUPER_ADMIN_EMAIL || ""
  )
    .trim()
    .toLowerCase();

  const temporaryPassword =
    process.env.SUPER_ADMIN_INITIAL_PASSWORD;

  // Email is mandatory.
  if (!email || !isValidEmail(email)) {
    throw new Error(
      "Set a valid SUPER_ADMIN_EMAIL in admin-backend/.env."
    );
  }

  // Use the raw MongoDB collection for safe legacy migration.
  // This allows us to inspect old documents that used username
  // before the schema was changed to email.
  const collection = SuperAdmin.collection;

  const existingAdmin = await collection.findOne({});

  // ----------------------------------------------------
  // EXISTING ACCOUNT MIGRATION
  // ----------------------------------------------------

  if (existingAdmin) {
    const existingEmail = String(
      existingAdmin.email || ""
    )
      .trim()
      .toLowerCase();

    // Already migrated.
    if (existingEmail) {
      if (existingEmail !== email) {
        throw new Error(
          "The existing Super Admin email differs from SUPER_ADMIN_EMAIL. No account changes were made."
        );
      }

      console.log(
        "Existing Super Admin email account verified."
      );

      return;
    }

    // Legacy account found without email.
    // Preserve its password hash and account ID.
    if (!existingAdmin.passwordHash) {
      throw new Error(
        "Legacy Super Admin account has no password hash. Manual account recovery is required."
      );
    }

    await collection.updateOne(
      {
        _id: existingAdmin._id,
      },
      {
        $set: {
          email,
          updatedAt: new Date(),
        },
        $unset: {
          username: "",
        },
      }
    );

    console.log(
      "Existing Super Admin account migrated to email login successfully."
    );

    console.log(
      "Existing password hash and account ID have been preserved."
    );

    return;
  }


  // ----------------------------------------------------
  // CREATE FIRST SUPER ADMIN
  // Only when no existing account is found.
  // ----------------------------------------------------

  if (
    !temporaryPassword ||
    temporaryPassword.length < 16
  ) {
    throw new Error(
      "SUPER_ADMIN_INITIAL_PASSWORD must contain at least 16 characters for first account creation."
    );
  }

  const passwordHash = await bcrypt.hash(
    temporaryPassword,
    12
  );

  await SuperAdmin.create({
    email,
    passwordHash,
    active: true,
    mustChangePassword: true,
    tokenVersion: 0,
    lastPasswordChangedAt: null,
    lastLoginAt: null,
  });

  console.log(
    "Initial Super Admin email account created successfully."
  );
}


// ======================================================
// ENVIRONMENT VALIDATION
// ======================================================

function validateEnvironment() {
  if (!process.env.MONGODB_URI) {
    throw new Error(
      "MONGODB_URI is missing from admin-backend/.env."
    );
  }

  if (
    !process.env.SUPER_ADMIN_EMAIL ||
    !isValidEmail(process.env.SUPER_ADMIN_EMAIL.trim())
  ) {
    throw new Error(
      "A valid SUPER_ADMIN_EMAIL is required."
    );
  }

  if (
    !process.env.STAFF_JWT_SECRET ||
    Buffer.byteLength(process.env.STAFF_JWT_SECRET) < 32
  ) {
    throw new Error(
      "STAFF_JWT_SECRET must be at least 32 characters."
    );
  }

  if (
    !process.env.ADMIN_JWT_SECRET ||
    Buffer.byteLength(process.env.ADMIN_JWT_SECRET) < 32
  ) {
    throw new Error(
      "ADMIN_JWT_SECRET must be at least 32 characters."
    );
  }

  if (process.env.ADMIN_JWT_SECRET === process.env.STAFF_JWT_SECRET) {
    throw new Error(
      "ADMIN_JWT_SECRET and STAFF_JWT_SECRET must be different values."
    );
  }
}


// ======================================================
// START SERVER
// ======================================================

async function startServer() {
  try {
    validateEnvironment();

    await mongoose.connect(
      process.env.MONGODB_URI,
      {
        serverSelectionTimeoutMS: 10000,
      }
    );

    console.log("MongoDB connected successfully.");

    console.log("Connected database:", mongoose.connection.name);
console.log("Connected host:", mongoose.connection.host);
console.log("Super Admin collection:", SuperAdmin.collection.name);

    // Create or migrate existing Super Admin account.
    await initializeSuperAdmin();

    app.listen(PORT, "0.0.0.0", () => {
      console.log(
        `Admin API listening on port ${PORT}`
      );

      console.log(
        "Super Admin authentication: Email + Password."
      );
    });

  } catch (error) {
    console.error(
      "Admin backend startup failed:",
      error.message
    );

    process.exit(1);
  }
}


startServer();

