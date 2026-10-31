/**
 * File: admin-backend/src/routes/admin.js
 *
 * Purpose:
 * Admin APIs for website content and staff management.
 *
 * Features:
 * - Super Admin login
 * - Staff login
 * - Super Admin password management
 * - Staff password management
 * - Product CRUD
 * - Course CRUD
 * - Blog CRUD
 * - Pricing CRUD
 * - Project CRUD
 * - Testimonial management
 * - Review management
 * - Enquiry management
 * - Notification management
 * - Media uploads
 *
 * Authentication:
 * Super Admin: JWT Bearer token
 * Staff: JWT Bearer token + module permissions
 *
 * Database: MongoDB / Mongoose
 */

import { Router } from "express";
import crypto from "crypto";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

import {
  Course,
  Product,
  Blog,
  PricingPlan,
  ProjectLab,
  Review,
  Enquiry,
  Notification,
  Staff,
  SuperAdmin,
  STAFF_PERMISSIONS,
} from "../models/Content.js";

import {
  requireAdminOrStaff,
  requireSuperAdmin,
} from "../middleware/staffAuth.js";

import { uploadImage } from "../middleware/upload.js";

const r = Router();


// ======================================================
// CONSTANTS
// ======================================================

const PRODUCT_TONES = [
  "blue",
  "green",
  "purple",
  "orange",
];

const PRODUCT_FIELDS = [
  "name",
  "slug",
  "category",
  "badge",
  "tone",
  "description",
  "features",
  "audience",
  "projects",
  "price",
  "image",
  "popular",
  "active",
  "sortOrder",
];


// ======================================================
// COMMON HELPERS
// ======================================================

function asyncRoute(handler) {
  return (req, res, next) => {
    Promise.resolve(handler(req, res, next)).catch(next);
  };
}

function isValidEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function normalizeStaffRole(value) {
  if (typeof value !== "string") return null;

  const role = value.trim().replace(/\s+/g, " ");

  if (
    role.length < 2 ||
    role.length > 60 ||
    /[\u0000-\u001f\u007f]/.test(role)
  ) {
    return null;
  }

  return role;
}

function normalizeStaffPermissions(value) {
  if (!Array.isArray(value)) return null;

  const permissions = [...new Set(value)];

  if (
    !permissions.every(
      (permission) =>
        typeof permission === "string" &&
        STAFF_PERMISSIONS.includes(permission)
    )
  ) {
    return null;
  }

  return permissions;
}

function handleValidationError(error, res) {
  if (error?.code === 11000) {
    res.status(409).json({
      message: "A record with this value already exists.",
    });
    return true;
  }

  if (
    error?.name === "ValidationError" ||
    error?.name === "CastError"
  ) {
    res.status(400).json({
      message: error.message,
    });
    return true;
  }

  return false;
}


// ======================================================
// PRODUCT HELPERS
// ======================================================

function normalizeProductBody(body = {}) {
  const payload = {};

  for (const field of PRODUCT_FIELDS) {
    if (body[field] !== undefined) {
      payload[field] = body[field];
    }
  }

  if (
    payload.image === undefined &&
    typeof body.imageUrl === "string"
  ) {
    payload.image = body.imageUrl;
  }

  if (typeof payload.name === "string") {
    payload.name = payload.name.trim();
  }

  if (typeof payload.slug === "string") {
    payload.slug = payload.slug
      .trim()
      .toLowerCase()
      .replace(/\s+/g, "-");
  }

  if (typeof payload.category === "string") {
    payload.category = payload.category.trim();
  }

  if (typeof payload.badge === "string") {
    payload.badge = payload.badge.trim();
  }

  if (typeof payload.description === "string") {
    payload.description = payload.description.trim();
  }

  if (typeof payload.image === "string") {
    payload.image = payload.image.trim();
  }

  if (Array.isArray(payload.features)) {
    payload.features = payload.features
      .filter((item) => typeof item === "string")
      .map((item) => item.trim())
      .filter(Boolean);
  }

  if (payload.sortOrder !== undefined) {
    payload.sortOrder = Number(payload.sortOrder);
  }

  return payload;
}

function validateProductBody(payload) {
  if (!payload.name || !payload.slug || !payload.category) {
    return "Product name, slug and category are required.";
  }

  if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(payload.slug)) {
    return "Use a valid lowercase product slug with letters, numbers and hyphens.";
  }

  if (
    payload.tone !== undefined &&
    !PRODUCT_TONES.includes(payload.tone)
  ) {
    return "Invalid product tone.";
  }

  if (
    payload.features !== undefined &&
    !Array.isArray(payload.features)
  ) {
    return "Product features must be an array.";
  }

  if (
    payload.popular !== undefined &&
    typeof payload.popular !== "boolean"
  ) {
    return "Popular must be true or false.";
  }

  if (
    payload.active !== undefined &&
    typeof payload.active !== "boolean"
  ) {
    return "Active must be true or false.";
  }

  if (
    payload.sortOrder !== undefined &&
    (
      !Number.isFinite(payload.sortOrder) ||
      payload.sortOrder < 0
    )
  ) {
    return "Sort order must be a non-negative number.";
  }

  return null;
}

// ======================================================
// SUPER ADMIN LOGIN
// POST /api/admin/auth/login
// Login using EMAIL + PASSWORD
// ======================================================

r.post(
  "/auth/login",
  asyncRoute(async (req, res) => {
    const email = String(req.body?.email || "")
      .trim()
      .toLowerCase();

    const password = String(req.body?.password || "");

    if (!email || !password) {
      return res.status(400).json({
        message: "Email and password are required.",
      });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({
        message: "Enter a valid email address.",
      });
    }

    const admin = await SuperAdmin.findOne({
      email,
    }).select("+passwordHash");

    if (!admin || !admin.active || !admin.passwordHash) {
      return res.status(401).json({
        message: "Invalid email or password.",
      });
    }

    const passwordMatches = await bcrypt.compare(
      password,
      admin.passwordHash
    );

    if (!passwordMatches) {
      return res.status(401).json({
        message: "Invalid email or password.",
      });
    }

    const secret = process.env.ADMIN_JWT_SECRET;

    if (!secret || Buffer.byteLength(secret) < 32) {
      return res.status(503).json({
        message: "Admin authentication is not configured.",
      });
    }

    const token = jwt.sign(
      {
        sub: admin._id.toString(),
        accountType: "superadmin",
        tokenVersion: Number(admin.tokenVersion || 0),
      },
      secret,
      {
        expiresIn: "8h",
        algorithm: "HS256",
      }
    );

    admin.lastLoginAt = new Date();
    await admin.save();

    return res.json({
      message: "Login successful.",
      token,
      tokenType: "Bearer",
      expiresIn: 28800,
      mustChangePassword: Boolean(admin.mustChangePassword),

      admin: {
        id: admin._id.toString(),
        email: admin.email,
      },
    });
  })
);


// ======================================================
// 2. STAFF LOGIN
// Public route - MUST be before authentication middleware.
//
// POST /api/admin/staff/login
// ======================================================

r.post(
  "/staff/login",
  asyncRoute(async (req, res) => {
    const email = String(req.body?.email || "")
      .trim()
      .toLowerCase();

    const password = String(req.body?.password || "");

    if (!email || !password) {
      return res.status(400).json({
        message: "Email and password are required.",
      });
    }

    const secret = process.env.STAFF_JWT_SECRET;

    if (!secret || Buffer.byteLength(secret) < 32) {
      return res.status(503).json({
        message: "Staff authentication is not configured.",
      });
    }

    const staff = await Staff.findOne({ email })
      .select("+passwordHash");

    if (!staff || !staff.active || !staff.passwordHash) {
      return res.status(401).json({
        message: "Invalid email or password.",
      });
    }

    const passwordMatches = await bcrypt.compare(
      password,
      staff.passwordHash
    );

    if (!passwordMatches) {
      return res.status(401).json({
        message: "Invalid email or password.",
      });
    }

    const token = jwt.sign(
      {
        sub: staff._id.toString(),
        accountType: "staff",
        tokenVersion: Number(staff.tokenVersion || 0),
      },
      secret,
      {
        expiresIn: "8h",
        algorithm: "HS256",
      }
    );

    return res.json({
      message: "Staff login successful.",
      token,
      tokenType: "Bearer",
      expiresIn: 28800,
      mustChangePassword: Boolean(staff.mustChangePassword),

      staff: {
        id: staff._id.toString(),
        name: staff.name,
        email: staff.email,
        role: staff.role,
        permissions: staff.permissions || [],
      },
    });
  })
);


// ======================================================
// 3. AUTHENTICATION MIDDLEWARE
//
// All routes below this point require authentication.
//
// IMPORTANT:
// Password change route MUST be below this middleware.
// ======================================================

r.use(requireAdminOrStaff);


// ======================================================
// 4. SUPER ADMIN PASSWORD CHANGE
//
// POST /api/admin/settings/super-admin-password
//
// Used for:
// - Initial temporary password replacement
// - Future Super Admin password changes
// ======================================================

r.post(
  "/settings/super-admin-password",
  requireSuperAdmin,
  asyncRoute(async (req, res) => {
    const currentPassword = String(
      req.body?.currentPassword || ""
    );

    const newPassword = String(
      req.body?.newPassword || ""
    );

    if (!currentPassword || !newPassword) {
      return res.status(400).json({
        message: "Current and new passwords are required.",
      });
    }

    if (newPassword.length < 14) {
      return res.status(400).json({
        message: "Password must contain at least 14 characters.",
      });
    }

    if (
      !/[A-Z]/.test(newPassword) ||
      !/[a-z]/.test(newPassword) ||
      !/[0-9]/.test(newPassword) ||
      !/[!@#$%^&*(),.?":{}|<>_\-]/.test(newPassword)
    ) {
      return res.status(400).json({
        message:
          "Password must include uppercase, lowercase, number and special character.",
      });
    }

    if (
      !req.auth?.id ||
      req.auth.type !== "superadmin"
    ) {
      return res.status(401).json({
        message: "Super Admin login required.",
      });
    }

    const admin = await SuperAdmin.findById(req.auth.id)
      .select("+passwordHash");

    if (!admin || !admin.active) {
      return res.status(401).json({
        message: "Super Admin account is unavailable.",
      });
    }

    const matches = await bcrypt.compare(
      currentPassword,
      admin.passwordHash
    );

    if (!matches) {
      return res.status(401).json({
        message: "Current password is incorrect.",
      });
    }

    if (currentPassword === newPassword) {
      return res.status(400).json({
        message:
          "New password must be different from current password.",
      });
    }

    admin.passwordHash = await bcrypt.hash(
      newPassword,
      12
    );

    admin.mustChangePassword = false;
    admin.lastPasswordChangedAt = new Date();

    // Revoke previous Super Admin JWT sessions.
    admin.tokenVersion =
      Number(admin.tokenVersion || 0) + 1;

    await admin.save();

    return res.json({
      message:
        "Password updated successfully. Please log in again.",
      mustLoginAgain: true,
      sessionRevoked: true,
    });
  })
);


// ======================================================
// 5. STAFF PASSWORD CHANGE
// POST /api/admin/staff/change-password
//
// Supports first-time temporary-password replacement and
// later password changes. Current password is always verified.
// ======================================================

r.post(
  "/staff/change-password",
  asyncRoute(async (req, res) => {
    const currentPassword = String(
      req.body?.currentPassword || ""
    );

    const newPassword = String(
      req.body?.newPassword || ""
    );

    if (!currentPassword || !newPassword) {
      return res.status(400).json({
        message: "Current and new passwords are required.",
      });
    }

    if (newPassword.length < 14) {
      return res.status(400).json({
        message: "Password must contain at least 14 characters.",
      });
    }

    if (
      !/[A-Z]/.test(newPassword) ||
      !/[a-z]/.test(newPassword) ||
      !/[0-9]/.test(newPassword) ||
      !/[!@#$%^&*(),.?":{}|<>_\-]/.test(newPassword)
    ) {
      return res.status(400).json({
        message:
          "Password must include uppercase, lowercase, number and special character.",
      });
    }

    if (!req.auth?.id || req.auth.type !== "staff") {
      return res.status(401).json({
        message: "A valid staff session is required.",
      });
    }

    const staff = await Staff.findById(req.auth.id)
      .select("+passwordHash");

    if (!staff || !staff.active) {
      return res.status(401).json({
        message: "Staff account is inactive or unavailable.",
      });
    }

    const currentMatches = await bcrypt.compare(
      currentPassword,
      staff.passwordHash
    );

    if (!currentMatches) {
      return res.status(401).json({
        message: "Current password is incorrect.",
      });
    }

    if (currentPassword === newPassword) {
      return res.status(400).json({
        message: "New password must be different from current password.",
      });
    }

    staff.passwordHash = await bcrypt.hash(newPassword, 12);
    staff.mustChangePassword = false;
    staff.tokenVersion = Number(staff.tokenVersion || 0) + 1;

    await staff.save();

    return res.json({
      message: "Password changed successfully. Please sign in again.",
      mustLoginAgain: true,
      sessionRevoked: true,
    });
  })
);


// ======================================================
// 6. MEDIA UPLOAD
//
// POST /api/admin/media/upload
// ======================================================

r.post(
  "/media/upload",
  uploadImage.single("file"),
  (req, res) => {
    if (!req.file) {
      return res.status(400).json({
        message: "Please select an image.",
      });
    }

    const imageUrl =
      `${req.protocol}://${req.get("host")}/uploads/${req.file.filename}`;

    return res.status(201).json({
      url: imageUrl,
      imageUrl,
      filename: req.file.filename,
    });
  }
);


// ======================================================
// 7. STUDENT TESTIMONIALS
// ======================================================

r.get(
  "/testimonials",
  asyncRoute(async (_req, res) => {
    const items = await Review.find()
      .sort({ sortOrder: 1, createdAt: -1 })
      .lean();

    return res.json(
      items.map((item) => ({
        ...item,
        studentName: item.studentName || item.name || "",
        quote: item.quote || item.message || "",
        published:
          typeof item.published === "boolean"
            ? item.published
            : Boolean(item.approved),
      }))
    );
  })
);


r.post(
  "/testimonials",
  asyncRoute(async (req, res) => {
    const body = req.body || {};

    const studentName = String(
      body.studentName ?? body.name ?? ""
    ).trim();

    const quote = String(
      body.quote ?? body.message ?? ""
    ).trim();

    const rating = Number(body.rating ?? 5);

    if (!studentName || !quote) {
      return res.status(400).json({
        message: "Student name and testimonial message are required.",
      });
    }

    if (
      !Number.isInteger(rating) ||
      rating < 1 ||
      rating > 5
    ) {
      return res.status(400).json({
        message: "Rating must be between 1 and 5.",
      });
    }

    const published =
      typeof body.published === "boolean"
        ? body.published
        : body.approved === true;

    const item = await Review.create({
      name: studentName,
      studentName,
      role: String(body.role ?? "Student").trim() || "Student",
      rating,
      message: quote,
      quote,
      videoUrl: String(body.videoUrl ?? "").trim(),
      thumbnailUrl: String(body.thumbnailUrl ?? "").trim(),
      course: String(body.course ?? "").trim(),
      duration: String(body.duration ?? "").trim(),
      approved: published,
      published,
      sortOrder: Number.isFinite(Number(body.sortOrder))
        ? Number(body.sortOrder)
        : 0,
    });

    return res.status(201).json(item);
  })
);


r.put(
  "/testimonials/:id",
  asyncRoute(async (req, res) => {
    const body = req.body || {};

    const studentName = String(
      body.studentName ?? body.name ?? ""
    ).trim();

    const quote = String(
      body.quote ?? body.message ?? ""
    ).trim();

    const rating = Number(body.rating ?? 5);

    if (!studentName || !quote) {
      return res.status(400).json({
        message: "Student name and testimonial message are required.",
      });
    }

    if (
      !Number.isInteger(rating) ||
      rating < 1 ||
      rating > 5
    ) {
      return res.status(400).json({
        message: "Rating must be between 1 and 5.",
      });
    }

    const published =
      typeof body.published === "boolean"
        ? body.published
        : body.approved === true;

    const item = await Review.findByIdAndUpdate(
      req.params.id,
      {
        name: studentName,
        studentName,
        role: String(body.role ?? "Student").trim() || "Student",
        rating,
        message: quote,
        quote,
        videoUrl: String(body.videoUrl ?? "").trim(),
        thumbnailUrl: String(body.thumbnailUrl ?? "").trim(),
        course: String(body.course ?? "").trim(),
        duration: String(body.duration ?? "").trim(),
        approved: published,
        published,
        sortOrder: Number.isFinite(Number(body.sortOrder))
          ? Number(body.sortOrder)
          : 0,
      },
      {
        new: true,
        runValidators: true,
      }
    );

    if (!item) {
      return res.status(404).json({
        message: "Testimonial not found.",
      });
    }

    return res.json(item);
  })
);


r.patch(
  "/testimonials/:id",
  asyncRoute(async (req, res) => {
    const published =
      typeof req.body?.published === "boolean"
        ? req.body.published
        : req.body?.approved;

    if (typeof published !== "boolean") {
      return res.status(400).json({
        message: "A valid publication status is required.",
      });
    }

    const item = await Review.findByIdAndUpdate(
      req.params.id,
      {
        published,
        approved: published,
      },
      {
        new: true,
        runValidators: true,
      }
    );

    if (!item) {
      return res.status(404).json({
        message: "Testimonial not found.",
      });
    }

    return res.json(item);
  })
);


r.delete(
  "/testimonials/:id",
  asyncRoute(async (req, res) => {
    const item = await Review.findByIdAndDelete(req.params.id);

    if (!item) {
      return res.status(404).json({
        message: "Testimonial not found.",
      });
    }

    return res.status(204).end();
  })
);


// ======================================================
// 8. OVERVIEW
// GET /api/admin/overview
// ======================================================

r.get(
  "/overview",
  asyncRoute(async (_req, res) => {
    const [
      courses,
      products,
      blogs,
      reviews,
      enquiries,
      newEnquiries,
      enrolled,
      pricingPlans,
      projects,
      unreadNotifications,
      ratings,
    ] = await Promise.all([
      Course.countDocuments(),
      Product.countDocuments(),
      Blog.countDocuments(),
      Review.countDocuments(),
      Enquiry.countDocuments(),
      Enquiry.countDocuments({ status: "new" }),
      Enquiry.countDocuments({ status: "enrolled" }),
      PricingPlan.countDocuments({ active: true }),
      ProjectLab.countDocuments({ active: true }),
      Notification.countDocuments({ read: false }),

      Review.aggregate([
        {
          $match: { approved: true },
        },
        {
          $group: {
            _id: null,
            average: { $avg: "$rating" },
            count: { $sum: 1 },
          },
        },
      ]),
    ]);

    return res.json({
      courses,
      products,
      blogs,
      reviews,
      enquiries,
      newEnquiries,
      enrolled,
      pricingPlans,
      projects,
      unreadNotifications,
      averageRating: ratings[0]?.average || 0,
      approvedReviews: ratings[0]?.count || 0,
    });
  })
);


// ======================================================
// 9. COURSES
// ======================================================

r.get(
  "/courses",
  asyncRoute(async (_req, res) => {
    const items = await Course.find()
      .sort({ createdAt: -1 })
      .lean();

    return res.json(items);
  })
);


r.post(
  "/courses",
  asyncRoute(async (req, res) => {
    const item = await Course.create(req.body || {});

    return res.status(201).json(item);
  })
);


r.put(
  "/courses/:id",
  asyncRoute(async (req, res) => {
    const item = await Course.findByIdAndUpdate(
      req.params.id,
      req.body || {},
      {
        new: true,
        runValidators: true,
      }
    );

    if (!item) {
      return res.status(404).json({
        message: "Course not found.",
      });
    }

    return res.json(item);
  })
);


r.delete(
  "/courses/:id",
  asyncRoute(async (req, res) => {
    const item = await Course.findByIdAndDelete(req.params.id);

    if (!item) {
      return res.status(404).json({
        message: "Course not found.",
      });
    }

    return res.status(204).end();
  })
);


// ======================================================
// 10. PRODUCTS / IOT KITS
// ======================================================

r.get(
  "/products",
  asyncRoute(async (_req, res) => {
    const items = await Product.find()
      .sort({
        sortOrder: 1,
        createdAt: -1,
      })
      .lean();

    return res.json(items);
  })
);


r.post(
  "/products",
  asyncRoute(async (req, res) => {
    const payload = normalizeProductBody(req.body);

    const validationError = validateProductBody(payload);

    if (validationError) {
      return res.status(400).json({
        message: validationError,
      });
    }

    const duplicate = await Product.findOne({
      slug: payload.slug,
    }).select("_id");

    if (duplicate) {
      return res.status(409).json({
        message: "Product slug already exists.",
      });
    }

    const product = await Product.create(payload);

    return res.status(201).json({
      message: "Product created successfully.",
      product,
    });
  })
);


r.put(
  "/products/:id",
  asyncRoute(async (req, res) => {
    const existing = await Product.findById(req.params.id);

    if (!existing) {
      return res.status(404).json({
        message: "Product not found.",
      });
    }

    const incoming = normalizeProductBody(req.body);

    if (Object.keys(incoming).length === 0) {
      return res.status(400).json({
        message: "No valid product fields were supplied.",
      });
    }

    const merged = {
      name: incoming.name ?? existing.name,
      slug: incoming.slug ?? existing.slug,
      category: incoming.category ?? existing.category,
      badge: incoming.badge ?? existing.badge,
      tone: incoming.tone ?? existing.tone,
      description: incoming.description ?? existing.description,
      features: incoming.features ?? existing.features,
      audience: incoming.audience ?? existing.audience,
      projects: incoming.projects ?? existing.projects,
      price: incoming.price ?? existing.price,
      image: incoming.image ?? existing.image,
      popular: incoming.popular ?? existing.popular,
      active: incoming.active ?? existing.active,
      sortOrder: incoming.sortOrder ?? existing.sortOrder,
    };

    const validationError = validateProductBody(merged);

    if (validationError) {
      return res.status(400).json({
        message: validationError,
      });
    }

    const duplicate = await Product.findOne({
      slug: merged.slug,
      _id: { $ne: existing._id },
    }).select("_id");

    if (duplicate) {
      return res.status(409).json({
        message: "Another product already uses this slug.",
      });
    }

    const product = await Product.findByIdAndUpdate(
      req.params.id,
      {
        $set: merged,
      },
      {
        new: true,
        runValidators: true,
      }
    );

    return res.json({
      message: "Product updated successfully.",
      product,
    });
  })
);


r.patch(
  "/products/:id/status",
  asyncRoute(async (req, res) => {
    if (typeof req.body?.active !== "boolean") {
      return res.status(400).json({
        message: "Active status must be true or false.",
      });
    }

    const product = await Product.findByIdAndUpdate(
      req.params.id,
      {
        $set: {
          active: req.body.active,
        },
      },
      {
        new: true,
        runValidators: true,
      }
    );

    if (!product) {
      return res.status(404).json({
        message: "Product not found.",
      });
    }

    return res.json({
      message: "Product status updated successfully.",
      product,
    });
  })
);


r.delete(
  "/products/:id",
  asyncRoute(async (req, res) => {
    const product = await Product.findByIdAndDelete(
      req.params.id
    );

    if (!product) {
      return res.status(404).json({
        message: "Product not found.",
      });
    }

    return res.json({
      message: "Product deleted successfully.",
      id: product._id,
    });
  })
);


// ======================================================
// 11. BLOGS
// ======================================================

r.get(
  "/blogs",
  asyncRoute(async (_req, res) => {
    const items = await Blog.find()
      .sort({ createdAt: -1 })
      .lean();

    return res.json(items);
  })
);


r.post(
  "/blogs",
  asyncRoute(async (req, res) => {
    const body = req.body || {};

    const item = await Blog.create({
      ...body,
      publishedAt: body.published
        ? new Date()
        : undefined,
    });

    return res.status(201).json(item);
  })
);


r.put(
  "/blogs/:id",
  asyncRoute(async (req, res) => {
    const body = req.body || {};

    const item = await Blog.findByIdAndUpdate(
      req.params.id,
      {
        ...body,
        publishedAt: body.published
          ? body.publishedAt || new Date()
          : null,
      },
      {
        new: true,
        runValidators: true,
      }
    );

    if (!item) {
      return res.status(404).json({
        message: "Blog not found.",
      });
    }

    return res.json(item);
  })
);


r.delete(
  "/blogs/:id",
  asyncRoute(async (req, res) => {
    const item = await Blog.findByIdAndDelete(req.params.id);

    if (!item) {
      return res.status(404).json({
        message: "Blog not found.",
      });
    }

    return res.status(204).end();
  })
);


// ======================================================
// 12. PRICING PLANS
// ======================================================

r.get(
  "/pricing",
  asyncRoute(async (_req, res) => {
    const items = await PricingPlan.find()
      .sort({
        order: 1,
        createdAt: -1,
      })
      .lean();

    return res.json(items);
  })
);


r.post(
  "/pricing",
  asyncRoute(async (req, res) => {
    const item = await PricingPlan.create(req.body || {});

    return res.status(201).json(item);
  })
);


r.put(
  "/pricing/:id",
  asyncRoute(async (req, res) => {
    const item = await PricingPlan.findByIdAndUpdate(
      req.params.id,
      req.body || {},
      {
        new: true,
        runValidators: true,
      }
    );

    if (!item) {
      return res.status(404).json({
        message: "Pricing plan not found.",
      });
    }

    return res.json(item);
  })
);


r.delete(
  "/pricing/:id",
  asyncRoute(async (req, res) => {
    const item = await PricingPlan.findByIdAndDelete(
      req.params.id
    );

    if (!item) {
      return res.status(404).json({
        message: "Pricing plan not found.",
      });
    }

    return res.status(204).end();
  })
);


// ======================================================
// 13. PROJECT LAB
// ======================================================

r.get(
  "/projects",
  asyncRoute(async (_req, res) => {
    const items = await ProjectLab.find()
      .sort({ createdAt: -1 })
      .lean();

    return res.json(items);
  })
);


r.post(
  "/projects",
  asyncRoute(async (req, res) => {
    const item = await ProjectLab.create(req.body || {});

    return res.status(201).json(item);
  })
);


r.put(
  "/projects/:id",
  asyncRoute(async (req, res) => {
    const item = await ProjectLab.findByIdAndUpdate(
      req.params.id,
      req.body || {},
      {
        new: true,
        runValidators: true,
      }
    );

    if (!item) {
      return res.status(404).json({
        message: "Project not found.",
      });
    }

    return res.json(item);
  })
);


r.delete(
  "/projects/:id",
  asyncRoute(async (req, res) => {
    const item = await ProjectLab.findByIdAndDelete(
      req.params.id
    );

    if (!item) {
      return res.status(404).json({
        message: "Project not found.",
      });
    }

    return res.status(204).end();
  })
);


// ======================================================
// 14. ENQUIRIES
// ======================================================

r.get(
  "/enquiries",
  asyncRoute(async (req, res) => {
    const page = Math.max(
      1,
      Number(req.query.page) || 1
    );

    const limit = Math.min(
      100,
      Math.max(1, Number(req.query.limit) || 50)
    );

    const [items, total] = await Promise.all([
      Enquiry.find()
        .sort({ createdAt: -1 })
        .skip((page - 1) * limit)
        .limit(limit)
        .lean(),

      Enquiry.countDocuments(),
    ]);

    return res.json({
      items,
      total,
      page,
      limit,
    });
  })
);


r.patch(
  "/enquiries/:id",
  asyncRoute(async (req, res) => {
    const allowedStatuses = [
      "new",
      "contacted",
      "enrolled",
      "closed",
    ];

    if (!allowedStatuses.includes(req.body?.status)) {
      return res.status(400).json({
        message: "Invalid enquiry status.",
      });
    }

    const item = await Enquiry.findByIdAndUpdate(
      req.params.id,
      {
        status: req.body.status,
      },
      {
        new: true,
        runValidators: true,
      }
    );

    if (!item) {
      return res.status(404).json({
        message: "Enquiry not found.",
      });
    }

    return res.json(item);
  })
);


// ======================================================
// 15. NOTIFICATIONS
// ======================================================

// Keep /read-all before /:id.

r.get(
  "/notifications",
  asyncRoute(async (req, res) => {
    const page = Math.max(
      1,
      Number(req.query.page) || 1
    );

    const limit = Math.min(
      100,
      Math.max(1, Number(req.query.limit) || 50)
    );

    const [items, total, unread] = await Promise.all([
      Notification.find()
        .sort({ createdAt: -1 })
        .skip((page - 1) * limit)
        .limit(limit)
        .lean(),

      Notification.countDocuments(),

      Notification.countDocuments({
        read: false,
      }),
    ]);

    return res.json({
      items,
      total,
      unread,
      page,
      limit,
    });
  })
);


r.patch(
  "/notifications/read-all",
  asyncRoute(async (_req, res) => {
    const result = await Notification.updateMany(
      { read: false },
      {
        $set: {
          read: true,
        },
      }
    );

    return res.json({
      message: "All notifications marked as read.",
      modifiedCount: result.modifiedCount,
    });
  })
);


r.patch(
  "/notifications/:id",
  asyncRoute(async (req, res) => {
    if (typeof req.body?.read !== "boolean") {
      return res.status(400).json({
        message: "A valid read status is required.",
      });
    }

    const item = await Notification.findByIdAndUpdate(
      req.params.id,
      {
        read: req.body.read,
      },
      {
        new: true,
        runValidators: true,
      }
    );

    if (!item) {
      return res.status(404).json({
        message: "Notification not found.",
      });
    }

    return res.json(item);
  })
);


r.delete(
  "/notifications/:id",
  asyncRoute(async (req, res) => {
    const item = await Notification.findByIdAndDelete(
      req.params.id
    );

    if (!item) {
      return res.status(404).json({
        message: "Notification not found.",
      });
    }

    return res.status(204).end();
  })
);


// ======================================================
// 16. REVIEWS
// ======================================================

r.get(
  "/reviews",
  asyncRoute(async (_req, res) => {
    const items = await Review.find()
      .sort({ createdAt: -1 })
      .lean();

    return res.json(items);
  })
);


r.post(
  "/reviews",
  asyncRoute(async (req, res) => {
    const {
      name,
      role,
      rating,
      message,
      approved,
    } = req.body || {};

    const numericRating = Number(rating);

    if (
      typeof name !== "string" ||
      !name.trim() ||
      typeof role !== "string" ||
      typeof message !== "string" ||
      !message.trim() ||
      !Number.isInteger(numericRating) ||
      numericRating < 1 ||
      numericRating > 5
    ) {
      return res.status(400).json({
        message:
          "Name, role, valid rating and review message are required.",
      });
    }

    const review = await Review.create({
      name: name.trim(),
      studentName: name.trim(),
      role: role.trim() || "Parent",
      rating: numericRating,
      message: message.trim(),
      quote: message.trim(),
      approved: approved === true,
      published: approved === true,
    });

    return res.status(201).json({
      message: "Review created successfully.",
      review,
    });
  })
);


r.patch(
  "/reviews/:id",
  asyncRoute(async (req, res) => {
    if (typeof req.body?.approved !== "boolean") {
      return res.status(400).json({
        message: "A valid approval status is required.",
      });
    }

    const item = await Review.findByIdAndUpdate(
      req.params.id,
      {
        approved: req.body.approved,
        published: req.body.approved,
      },
      {
        new: true,
        runValidators: true,
      }
    );

    if (!item) {
      return res.status(404).json({
        message: "Review not found.",
      });
    }

    return res.json(item);
  })
);


r.delete(
  "/reviews/:id",
  asyncRoute(async (req, res) => {
    const item = await Review.findByIdAndDelete(
      req.params.id
    );

    if (!item) {
      return res.status(404).json({
        message: "Review not found.",
      });
    }

    return res.status(204).end();
  })
);


// ======================================================
// 17. STAFF MANAGEMENT
// SUPER ADMIN ONLY
//
// Role is free text. Authorization is controlled exclusively
// by the allowed permissions array, not by the role label.
// ======================================================

// GET /api/admin/staff
r.get(
  "/staff",
  requireSuperAdmin,
  asyncRoute(async (_req, res) => {
    const staff = await Staff.find()
      .select("-passwordHash -tokenVersion")
      .sort({ createdAt: -1 })
      .lean();

    return res.json({
      items: staff,
      total: staff.length,
    });
  })
);


// POST /api/admin/staff
// Creates a staff account and returns its temporary password once.
r.post(
  "/staff",
  requireSuperAdmin,
  asyncRoute(async (req, res) => {
    const name = String(req.body?.name || "").trim();
    const email = String(req.body?.email || "")
      .trim()
      .toLowerCase();

    const role = normalizeStaffRole(req.body?.role || "Staff");
    const permissions = normalizeStaffPermissions(
      req.body?.permissions ?? []
    );

    const active =
      typeof req.body?.active === "boolean"
        ? req.body.active
        : true;

    if (!name || name.length > 100) {
      return res.status(400).json({
        message: "Staff name is required and must be 100 characters or fewer.",
      });
    }

    if (!isValidEmail(email)) {
      return res.status(400).json({
        message: "Enter a valid staff email address.",
      });
    }

    if (!role) {
      return res.status(400).json({
        message: "Enter a role between 2 and 60 characters.",
      });
    }

    if (!permissions) {
      return res.status(400).json({
        message: "One or more selected permissions are invalid.",
      });
    }

    const existing = await Staff.findOne({ email }).select("_id");

    if (existing) {
      return res.status(409).json({
        message: "A staff account with this email already exists.",
      });
    }

    const temporaryPassword = crypto
      .randomBytes(18)
      .toString("base64url");

    const passwordHash = await bcrypt.hash(temporaryPassword, 12);

    const staff = await Staff.create({
      name,
      email,
      passwordHash,
      role,
      permissions,
      active,
      mustChangePassword: true,
      tokenVersion: 0,
    });

    return res.status(201).json({
      message: "Staff account created. Copy the temporary password now; it will not be shown again.",
      staff: {
        id: staff._id.toString(),
        name: staff.name,
        email: staff.email,
        role: staff.role,
        permissions: staff.permissions,
        active: staff.active,
        mustChangePassword: staff.mustChangePassword,
      },
      temporaryPassword,
    });
  })
);


// PATCH /api/admin/staff/:id/permissions
// "View Permissions" editor saves only page permissions.
// Every save increments tokenVersion and forces the staff member
// to sign in again so removed access cannot remain in an old session.
r.patch(
  "/staff/:id/permissions",
  requireSuperAdmin,
  asyncRoute(async (req, res) => {
    const permissions = normalizeStaffPermissions(
      req.body?.permissions
    );

    if (!permissions) {
      return res.status(400).json({
        message: "One or more selected permissions are invalid.",
      });
    }

    const staff = await Staff.findByIdAndUpdate(
      req.params.id,
      {
        $set: {
          permissions,
        },
        $inc: {
          tokenVersion: 1,
        },
      },
      {
        new: true,
        runValidators: true,
      }
    ).select("-passwordHash -tokenVersion");

    if (!staff) {
      return res.status(404).json({
        message: "Staff member not found.",
      });
    }

    return res.json({
      message: "Staff permissions updated. The staff member must sign in again.",
      staff,
    });
  })
);


// PUT /api/admin/staff/:id
// Updates profile, custom role and active state.
r.put(
  "/staff/:id",
  requireSuperAdmin,
  asyncRoute(async (req, res) => {
    const name = String(req.body?.name || "").trim();
    const email = String(req.body?.email || "")
      .trim()
      .toLowerCase();

    const role = normalizeStaffRole(req.body?.role);
    const active = req.body?.active;

    if (!name || name.length > 100) {
      return res.status(400).json({
        message: "Staff name is required and must be 100 characters or fewer.",
      });
    }

    if (!isValidEmail(email)) {
      return res.status(400).json({
        message: "Enter a valid staff email address.",
      });
    }

    if (!role) {
      return res.status(400).json({
        message: "Enter a role between 2 and 60 characters.",
      });
    }

    if (typeof active !== "boolean") {
      return res.status(400).json({
        message: "Account active status must be true or false.",
      });
    }

    const duplicate = await Staff.findOne({
      email,
      _id: { $ne: req.params.id },
    }).select("_id");

    if (duplicate) {
      return res.status(409).json({
        message: "Email address already belongs to another staff member.",
      });
    }

    const staff = await Staff.findByIdAndUpdate(
      req.params.id,
      {
        $set: {
          name,
          email,
          role,
          active,
        },
        $inc: {
          tokenVersion: 1,
        },
      },
      {
        new: true,
        runValidators: true,
      }
    ).select("-passwordHash -tokenVersion");

    if (!staff) {
      return res.status(404).json({
        message: "Staff member not found.",
      });
    }

    return res.json({
      message: "Staff member updated. The staff member must sign in again.",
      staff,
    });
  })
);


// DELETE /api/admin/staff/:id
// Soft-deletes by deactivating and revoking all sessions.
r.delete(
  "/staff/:id",
  requireSuperAdmin,
  asyncRoute(async (req, res) => {
    const staff = await Staff.findByIdAndUpdate(
      req.params.id,
      {
        $set: {
          active: false,
        },
        $inc: {
          tokenVersion: 1,
        },
      },
      {
        new: true,
      }
    ).select("_id");

    if (!staff) {
      return res.status(404).json({
        message: "Staff member not found.",
      });
    }

    return res.json({
      message: "Staff access revoked successfully.",
    });
  })
);


// ======================================================
// CENTRAL ERROR HANDLER
// ======================================================

r.use((error, _req, res, _next) => {
  console.error("Admin API route error:", error);

  if (handleValidationError(error, res)) {
    return;
  }

  return res.status(500).json({
    message: "Admin API operation failed.",
  });
});


// ======================================================
// EXPORT
// ======================================================

export default r;