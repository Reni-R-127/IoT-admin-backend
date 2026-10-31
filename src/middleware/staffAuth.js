/**
 * File: admin-backend/src/middleware/staffAuth.js
 *
 * Purpose:
 * Authenticate Super Admin and Staff JWT sessions and enforce
 * permissions against the current MongoDB account on every request.
 *
 * Important:
 * - Role is descriptive only; it never grants access.
 * - Staff access comes only from the permissions array.
 * - Staff can never access Staff Management or Super Admin Settings.
 * - Temporary-password users can access only their password-change route.
 */

import jwt from "jsonwebtoken";
import { Staff, SuperAdmin } from "../models/Content.js";

const MODULE_PERMISSION = Object.freeze({
  overview: "overview",
  courses: "courses",
  blogs: "blogs",
  pricing: "pricing",
  projects: "projects",
  media: "media",
  enquiries: "enquiries",
  notifications: "notifications",
  reviews: "reviews",
  testimonials: "testimonials",
});

function getBearerToken(req) {
  const authorization = req.get("authorization") || "";
  const match = authorization.match(/^Bearer\s+(\S+)$/i);
  return match ? match[1] : null;
}

function sendUnauthorized(res, message = "Please sign in again.") {
  return res.status(401).json({
    code: "AUTHENTICATION_REQUIRED",
    message,
  });
}

/**
 * Validate a JWT against the secret for its claimed account type.
 * The decoded claim is only used to select a secret; jwt.verify
 * must still validate the signature before any claim is trusted.
 */
export async function requireAdminOrStaff(req, res, next) {
  try {
    const token = getBearerToken(req);

    if (!token) {
      return sendUnauthorized(
        res,
        "Authentication required. Please sign in."
      );
    }

    const unverified = jwt.decode(token);

    const accountType = unverified?.accountType;

    if (
      accountType !== "superadmin" &&
      accountType !== "staff"
    ) {
      return sendUnauthorized(res, "Invalid authentication token.");
    }

    const secret =
      accountType === "superadmin"
        ? process.env.ADMIN_JWT_SECRET
        : process.env.STAFF_JWT_SECRET;

    if (!secret || Buffer.byteLength(secret) < 32) {
      return res.status(503).json({
        message: "Authentication is not configured correctly.",
      });
    }

    const decoded = jwt.verify(token, secret, {
      algorithms: ["HS256"],
    });

    if (
      decoded.accountType !== accountType ||
      typeof decoded.sub !== "string" ||
      !Number.isInteger(decoded.tokenVersion)
    ) {
      return sendUnauthorized(res, "Invalid authentication token.");
    }

    // --------------------------------------------------
    // SUPER ADMIN
    // --------------------------------------------------

    if (accountType === "superadmin") {
      const admin = await SuperAdmin.findById(decoded.sub);

      if (!admin || !admin.active) {
        return sendUnauthorized(
          res,
          "Super Admin account is inactive or unavailable."
        );
      }

      if (
        decoded.tokenVersion !== Number(admin.tokenVersion || 0)
      ) {
        return res.status(401).json({
          code: "SESSION_REVOKED",
          message: "Your session has expired. Please log in again.",
        });
      }

      req.auth = {
        type: "superadmin",
        id: admin._id.toString(),
        email: admin.email,
        mustChangePassword: Boolean(admin.mustChangePassword),
      };

      req.superAdmin = admin;

      const isPasswordChangeRequest =
        req.method === "POST" &&
        req.path === "/settings/super-admin-password";

      if (admin.mustChangePassword && !isPasswordChangeRequest) {
        return res.status(403).json({
          code: "PASSWORD_CHANGE_REQUIRED",
          message:
            "Set your permanent password before accessing the dashboard.",
        });
      }

      return next();
    }

    // --------------------------------------------------
    // STAFF
    // --------------------------------------------------

    const staff = await Staff.findById(decoded.sub);

    if (!staff || !staff.active) {
      return sendUnauthorized(
        res,
        "Staff account is inactive or unavailable."
      );
    }

    if (
      decoded.tokenVersion !== Number(staff.tokenVersion || 0)
    ) {
      return res.status(401).json({
        code: "SESSION_REVOKED",
        message: "Your session has expired. Please log in again.",
      });
    }

    const isStaffPasswordChangeRequest =
      req.method === "POST" &&
      req.path === "/staff/change-password";

    req.auth = {
      type: "staff",
      id: staff._id.toString(),
      name: staff.name,
      email: staff.email,
      role: staff.role,
      permissions: Array.isArray(staff.permissions)
        ? staff.permissions
        : [],
      mustChangePassword: Boolean(staff.mustChangePassword),
    };

    req.staff = staff;

    if (
      staff.mustChangePassword &&
      !isStaffPasswordChangeRequest
    ) {
      return res.status(403).json({
        code: "PASSWORD_CHANGE_REQUIRED",
        message: "Change your temporary password first.",
      });
    }

    // A staff member can change their own password, but cannot
    // access staff management or Super Admin security endpoints.
    if (isStaffPasswordChangeRequest) {
      return next();
    }

    if (
      req.path === "/staff" ||
      req.path.startsWith("/staff/") ||
      req.path === "/settings" ||
      req.path.startsWith("/settings/")
    ) {
      return res.status(403).json({
        code: "SUPER_ADMIN_ONLY",
        message: "This section is available to Super Admin only.",
      });
    }

    const moduleName = req.path.split("/").filter(Boolean)[0];

    const currentPermissions = Array.isArray(staff.permissions)
      ? staff.permissions
      : [];

    // Media upload is a supporting action inside content pages rather
    // than a standalone menu page. Allow it only when the user has at
    // least one content-editing permission.
    if (moduleName === "media") {
      const mediaAllowedByContentPage = [
        "courses",
        "blogs",
        "pricing",
        "projects",
        "reviews",
        "testimonials",
      ].some((permission) => currentPermissions.includes(permission));

      if (!mediaAllowedByContentPage) {
        return res.status(403).json({
          code: "PERMISSION_DENIED",
          message: "Media uploads require access to an assigned content page.",
        });
      }

      return next();
    }

    const requiredPermission = MODULE_PERMISSION[moduleName];

    if (
      !requiredPermission ||
      !currentPermissions.includes(requiredPermission)
    ) {
      return res.status(403).json({
        code: "PERMISSION_DENIED",
        message: "You do not have permission to access this page or action.",
      });
    }

    return next();
  } catch (error) {
    if (
      error?.name === "JsonWebTokenError" ||
      error?.name === "TokenExpiredError" ||
      error?.name === "NotBeforeError"
    ) {
      return sendUnauthorized(res, "Invalid or expired authentication token.");
    }

    return next(error);
  }
}

export function requireSuperAdmin(req, res, next) {
  if (req.auth?.type !== "superadmin") {
    return res.status(403).json({
      code: "SUPER_ADMIN_ONLY",
      message: "Super Admin access required.",
    });
  }

  return next();
}
