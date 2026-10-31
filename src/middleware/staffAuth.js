/**
 * File: admin-backend/src/middleware/staffAuth.js
 *
 * Purpose:
 * Authenticate Super Admin and Staff users.
 *
 * Super Admin:
 * Authenticated using ADMIN_API_KEY.
 *
 * Staff:
 * Authenticated using JWT Bearer token.
 *
 * Security:
 * - Timing-safe API key comparison.
 * - JWT signature and expiry validation.
 * - Staff active status validation.
 * - JWT tokenVersion validation.
 * - Temporary password change enforcement.
 * - Module-based permission validation.
 * - Staff management restricted to Super Admin.
 */

import crypto from "crypto";
import jwt from "jsonwebtoken";
import { Staff } from "../models/Content.js";


// ======================================================
// SUPER ADMIN API KEY VALIDATION
// ======================================================

function isSuperAdminKey(req) {
  const expected = process.env.ADMIN_API_KEY;
  const supplied = req.get("x-admin-key");

  if (
    !expected ||
    !supplied ||
    Buffer.byteLength(expected) < 32
  ) {
    return false;
  }

  const expectedBuffer = Buffer.from(expected, "utf8");
  const suppliedBuffer = Buffer.from(supplied, "utf8");

  if (expectedBuffer.length !== suppliedBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(
    expectedBuffer,
    suppliedBuffer
  );
}


// ======================================================
// STAFF MODULE PERMISSION MAPPING
// ======================================================

function getModulePermission(path) {
  const moduleName = path
    .split("/")
    .filter(Boolean)[0];

  const permissions = {
    overview: "overview",
    courses: "courses",
    products: "products",
    blogs: "blogs",
    pricing: "pricing",
    projects: "projects",
    media: "media",
    enquiries: "enquiries",
    notifications: "notifications",
    reviews: "reviews",
    testimonials: "reviews",
    staff: "staff",
    settings: "settings",
  };

  return permissions[moduleName] || null;
}


// ======================================================
// MAIN AUTHENTICATION MIDDLEWARE
// ======================================================

export async function requireAdminOrStaff(req, res, next) {
  try {

    // --------------------------------------------------
    // 1. SUPER ADMIN AUTHENTICATION
    // --------------------------------------------------

    if (isSuperAdminKey(req)) {
      req.auth = {
        type: "superadmin",
      };

      return next();
    }


    // --------------------------------------------------
    // 2. STAFF JWT AUTHENTICATION
    // --------------------------------------------------

    const authHeader = req.get("authorization") || "";

    const bearerMatch = authHeader.match(/^Bearer\s+(.+)$/i);

    const token = bearerMatch
      ? bearerMatch[1].trim()
      : "";

    if (!token) {
      return res.status(401).json({
        message: "Authentication required.",
      });
    }


    // --------------------------------------------------
    // 3. JWT SECRET VALIDATION
    // --------------------------------------------------

    const secret = process.env.STAFF_JWT_SECRET;

    if (
      !secret ||
      Buffer.byteLength(secret) < 32
    ) {
      return res.status(503).json({
        message: "Staff authentication is not configured.",
      });
    }


    // --------------------------------------------------
    // 4. VERIFY JWT TOKEN
    // --------------------------------------------------

    const decoded = jwt.verify(
      token,
      secret,
      {
        algorithms: ["HS256"],
      }
    );

    if (
      !decoded ||
      typeof decoded.sub !== "string" ||
      !Number.isInteger(decoded.tokenVersion)
    ) {
      return res.status(401).json({
        message: "Invalid authentication token.",
      });
    }


    // --------------------------------------------------
    // 5. FETCH STAFF ACCOUNT
    // --------------------------------------------------

    const staff = await Staff.findById(decoded.sub);

    if (!staff || !staff.active) {
      return res.status(401).json({
        message: "Staff account is inactive or unavailable.",
      });
    }


    // --------------------------------------------------
    // 6. TOKEN VERSION VALIDATION
    // --------------------------------------------------

    const currentTokenVersion = Number(
      staff.tokenVersion ?? 0
    );

    if (decoded.tokenVersion !== currentTokenVersion) {
      return res.status(401).json({
        message: "Session expired. Please log in again.",
      });
    }


    // --------------------------------------------------
    // 7. SET AUTHENTICATED STAFF DETAILS
    // --------------------------------------------------

    req.auth = {
      type: "staff",
      id: staff._id.toString(),
      role: staff.role,
      permissions: Array.isArray(staff.permissions)
        ? staff.permissions
        : [],
      mustChangePassword: Boolean(
        staff.mustChangePassword
      ),
    };

    req.staff = staff;


    // --------------------------------------------------
    // 8. TEMPORARY PASSWORD CHANGE ENFORCEMENT
    // --------------------------------------------------

    const isPasswordChangeRoute =
      req.path === "/staff/change-password" &&
      req.method === "POST";

    if (
      staff.mustChangePassword &&
      !isPasswordChangeRoute
    ) {
      return res.status(403).json({
        code: "PASSWORD_CHANGE_REQUIRED",
        message: "Change your temporary password first.",
      });
    }


    // --------------------------------------------------
    // 9. STAFF MANAGEMENT RESTRICTION
    // --------------------------------------------------

    const isStaffManagementRoute =
      req.path === "/staff" ||
      req.path.startsWith("/staff/");

    if (
      isStaffManagementRoute &&
      !isPasswordChangeRoute
    ) {
      return res.status(403).json({
        message: "Only Super Admin can manage staff accounts.",
      });
    }


    // --------------------------------------------------
    // 10. MODULE PERMISSION VALIDATION
    // --------------------------------------------------

    const permission = getModulePermission(req.path);

    const staffPermissions = Array.isArray(staff.permissions)
      ? staff.permissions
      : [];

    if (
      !permission ||
      !staffPermissions.includes(permission)
    ) {
      return res.status(403).json({
        message: "You do not have permission to access this module.",
      });
    }


    // --------------------------------------------------
    // 11. AUTHENTICATION SUCCESSFUL
    // --------------------------------------------------

    return next();

  } catch (error) {

    if (
      error.name === "JsonWebTokenError" ||
      error.name === "TokenExpiredError" ||
      error.name === "NotBeforeError" ||
      error.name === "CastError"
    ) {
      return res.status(401).json({
        message: "Invalid or expired authentication token.",
      });
    }

    return next(error);
  }
}


// ======================================================
// SUPER ADMIN ONLY MIDDLEWARE
// ======================================================

export function requireSuperAdmin(req, res, next) {
  if (req.auth?.type !== "superadmin") {
    return res.status(403).json({
      message: "Super Admin access required.",
    });
  }

  return next();
}