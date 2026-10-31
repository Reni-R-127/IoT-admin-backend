/**
 * File: admin-backend/scripts/reset-super-admin-temp-password.js
 *
 * Purpose:
 * Local Super Admin password recovery.
 *
 * Usage:
 * node scripts/reset-super-admin-temp-password.js --confirm
 *
 * This is a local script, not a public API.
 */

import "dotenv/config";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";

import { SuperAdmin } from "../src/models/Content.js";

async function resetTemporaryPassword() {
  try {
    // Require explicit confirmation.
    if (!process.argv.includes("--confirm")) {
      throw new Error(
        "Confirmation required. Run with --confirm."
      );
    }

    const mongoUri = process.env.MONGODB_URI;

    const email = String(
      process.env.SUPER_ADMIN_EMAIL || ""
    )
      .trim()
      .toLowerCase();

    const temporaryPassword =
      process.env.SUPER_ADMIN_INITIAL_PASSWORD;

    if (!mongoUri || !email) {
      throw new Error(
        "MONGODB_URI and SUPER_ADMIN_EMAIL are required."
      );
    }

    if (
      !temporaryPassword ||
      temporaryPassword.length < 16
    ) {
      throw new Error(
        "Temporary password must contain at least 16 characters."
      );
    }

    await mongoose.connect(mongoUri);

    console.log("MongoDB connected.");

    const admin = await SuperAdmin.findOne({
      email,
    }).select("+passwordHash");

    if (!admin) {
      throw new Error(
        "Super Admin account not found."
      );
    }

    if (!admin.active) {
      throw new Error(
        "Super Admin account is inactive."
      );
    }

    // Replace password with a new bcrypt hash.
    admin.passwordHash = await bcrypt.hash(
      temporaryPassword,
      12
    );

    // Force password change on the next login.
    admin.mustChangePassword = true;

    // Revoke previous sessions.
    admin.tokenVersion =
      Number(admin.tokenVersion || 0) + 1;

    admin.lastPasswordChangedAt = null;

    await admin.save();

    console.log(
      "Super Admin temporary password reset successfully."
    );

    console.log("Email:", admin.email);

    console.log(
      "First-login password change is required."
    );

  } catch (error) {
    console.error(
      "Password reset failed:",
      error.message
    );

    process.exitCode = 1;

  } finally {
    if (mongoose.connection.readyState !== 0) {
      await mongoose.disconnect();
    }
  }
}

resetTemporaryPassword();