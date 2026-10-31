/**
 * File: admin-backend/src/models/Content.js
 *
 * Purpose:
 * MongoDB models used by the Admin Dashboard API.
 *
 * Models:
 * Course, Product, Blog, PricingPlan, ProjectLab,
 * Review, Enquiry, Notification, Staff.
 *
 * Database:
 * MongoDB with Mongoose.
 */

import mongoose from "mongoose";

// ======================================================
// SUPER ADMIN MODEL
// ======================================================

const superAdminSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      maxlength: 254,
    },

    passwordHash: {
      type: String,
      required: true,
      select: false,
    },

    active: {
      type: Boolean,
      default: true,
    },

    mustChangePassword: {
      type: Boolean,
      default: true,
    },

    tokenVersion: {
      type: Number,
      default: 0,
    },

    lastPasswordChangedAt: {
      type: Date,
      default: null,
    },

    lastLoginAt: {
      type: Date,
      default: null,
    },
  },
  {
    timestamps: true,
  }
);


// ======================================================
// SUPER ADMIN MODEL EXPORT
// ======================================================

export const SuperAdmin =
  mongoose.models.SuperAdmin ||
  mongoose.model("SuperAdmin", superAdminSchema);

// ======================================================
// COURSE MODEL
// ======================================================

const courseSchema = new mongoose.Schema(
  {
    title: {
      type: String,
      required: true,
      trim: true,
    },

    slug: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      lowercase: true,
    },

    description: {
      type: String,
      default: "",
    },

    ageRange: {
      type: String,
      default: "",
    },

    duration: {
      type: String,
      default: "",
    },

    level: {
      type: String,
      default: "Beginner",
    },

    price: {
      type: String,
      default: "Contact us",
    },

    image: {
      type: String,
      default: "",
    },

    active: {
      type: Boolean,
      default: true,
    },
  },
  { timestamps: true }
);


// ======================================================
// PRODUCT / IOT KIT MODEL
// Shared collection with website backend.
// ======================================================

const productSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
    },

    slug: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      lowercase: true,
    },

    category: {
      type: String,
      required: true,
      trim: true,
      default: "Other",
    },

    badge: {
      type: String,
      default: "",
      trim: true,
    },

    tone: {
      type: String,
      enum: ["blue", "green", "purple", "orange"],
      default: "blue",
    },

    description: {
      type: String,
      default: "",
      trim: true,
    },

    features: {
      type: [String],
      default: [],
    },

    audience: {
      type: String,
      default: "",
      trim: true,
    },

    projects: {
      type: String,
      default: "",
      trim: true,
    },

    price: {
      type: String,
      default: "Contact us",
      trim: true,
    },

    image: {
      type: String,
      default: "",
      trim: true,
    },

    popular: {
      type: Boolean,
      default: false,
    },

    active: {
      type: Boolean,
      default: true,
    },

    sortOrder: {
      type: Number,
      default: 0,
    },
  },
  { timestamps: true }
);


// ======================================================
// BLOG MODEL
// ======================================================

const blogSchema = new mongoose.Schema(
  {
    title: {
      type: String,
      required: true,
      trim: true,
    },

    slug: {
      type: String,
      required: true,
      unique: true,
      trim: true,
    },

    category: {
      type: String,
      default: "IoT",
    },

    excerpt: {
      type: String,
      default: "",
    },

    content: {
      type: String,
      default: "",
    },

    image: {
      type: String,
      default: "",
    },

    published: {
      type: Boolean,
      default: false,
    },

    publishedAt: {
      type: Date,
      default: null,
    },
  },
  { timestamps: true }
);


// ======================================================
// PRICING PLAN MODEL
// ======================================================

const pricingPlanSchema = new mongoose.Schema(
  {
    title: {
      type: String,
      required: true,
      trim: true,
    },

    description: {
      type: String,
      default: "",
    },

    price: {
      type: String,
      required: true,
    },

    features: {
      type: [String],
      default: [],
    },

    active: {
      type: Boolean,
      default: true,
    },

    order: {
      type: Number,
      default: 0,
    },
  },
  { timestamps: true }
);


// ======================================================
// PROJECT LAB MODEL
// ======================================================

const projectLabSchema = new mongoose.Schema(
  {
    title: {
      type: String,
      required: true,
      trim: true,
    },

    description: {
      type: String,
      default: "",
    },

    category: {
      type: String,
      default: "",
    },

    image: {
      type: String,
      default: "",
    },

    technologies: {
      type: [String],
      default: [],
    },

    active: {
      type: Boolean,
      default: true,
    },
  },
  { timestamps: true }
);


// ======================================================
// REVIEW / TESTIMONIAL MODEL
// ======================================================

const reviewSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
    },

    role: {
      type: String,
      default: "Parent",
      trim: true,
    },

    rating: {
      type: Number,
      default: 5,
      min: 1,
      max: 5,
    },

    message: {
      type: String,
      required: true,
      trim: true,
    },

    approved: {
      type: Boolean,
      default: false,
    },

    studentName: {
      type: String,
      trim: true,
      default: "",
    },

    quote: {
      type: String,
      trim: true,
      default: "",
    },

    videoUrl: {
      type: String,
      trim: true,
      default: "",
    },

    thumbnailUrl: {
      type: String,
      trim: true,
      default: "",
    },

    course: {
      type: String,
      trim: true,
      default: "",
    },

    duration: {
      type: String,
      trim: true,
      default: "",
    },

    published: {
      type: Boolean,
      default: false,
    },

    sortOrder: {
      type: Number,
      default: 0,
    },
  },
  { timestamps: true }
);


// ======================================================
// ENQUIRY MODEL
// ======================================================

const enquirySchema = new mongoose.Schema(
  {
    parentName: {
      type: String,
      required: true,
      trim: true,
    },

    childName: {
      type: String,
      default: "",
    },

    childAge: {
      type: Number,
      min: 1,
      max: 18,
    },

    phone: {
      type: String,
      required: true,
      trim: true,
    },

    email: {
      type: String,
      required: true,
      lowercase: true,
      trim: true,
    },

    course: {
      type: String,
      required: true,
      trim: true,
    },

    message: {
      type: String,
      default: "",
    },

    status: {
      type: String,
      enum: ["new", "contacted", "enrolled", "closed"],
      default: "new",
    },

    source: {
      type: String,
      default: "website",
    },
  },
  { timestamps: true }
);


// ======================================================
// NOTIFICATION MODEL
// ======================================================

const notificationSchema = new mongoose.Schema(
  {
    type: {
      type: String,
      enum: ["enquiry", "whatsapp", "system"],
      default: "enquiry",
    },

    title: {
      type: String,
      required: true,
      trim: true,
    },

    message: {
      type: String,
      default: "",
    },

    source: {
      type: String,
      default: "website",
    },

    section: {
      type: String,
      default: "",
    },

    read: {
      type: Boolean,
      default: false,
    },

    metadata: {
      type: mongoose.Schema.Types.Mixed,
      default: {},
    },
  },
  { timestamps: true }
);


// ======================================================
// STAFF MODULE PERMISSIONS
// Staff cannot receive Super Admin-only modules.
// Role names are free text and are not used for authorization.
// ======================================================

export const STAFF_PERMISSIONS = [
  "overview",
  "courses",
  "blogs",
  "pricing",
  "projects",
  "enquiries",
  "notifications",
  "reviews",
  "testimonials",
];


// ======================================================
// STAFF MODEL
// ======================================================

const staffSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
      maxlength: 100,
    },

    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      maxlength: 254,
    },

    passwordHash: {
      type: String,
      required: true,
      select: false,
    },

    // Custom display role entered by Super Admin.
    // Authorization is based only on permissions, never role text.
    role: {
      type: String,
      required: true,
      trim: true,
      minlength: 2,
      maxlength: 60,
      default: "Staff",
    },

    permissions: {
      type: [
        {
          type: String,
          enum: STAFF_PERMISSIONS,
        },
      ],
      default: [],
    },

    active: {
      type: Boolean,
      default: true,
    },

    mustChangePassword: {
      type: Boolean,
      default: true,
    },

    tokenVersion: {
      type: Number,
      default: 0,
    },
  },
  { timestamps: true }
);


// ======================================================
// MODEL EXPORTS
// ======================================================

export const Course =
  mongoose.models.Course ||
  mongoose.model("Course", courseSchema);

export const Product =
  mongoose.models.Product ||
  mongoose.model("Product", productSchema);

export const Blog =
  mongoose.models.Blog ||
  mongoose.model("Blog", blogSchema);

export const PricingPlan =
  mongoose.models.PricingPlan ||
  mongoose.model("PricingPlan", pricingPlanSchema);

export const ProjectLab =
  mongoose.models.ProjectLab ||
  mongoose.model("ProjectLab", projectLabSchema);

export const Review =
  mongoose.models.Review ||
  mongoose.model("Review", reviewSchema);

export const Enquiry =
  mongoose.models.Enquiry ||
  mongoose.model("Enquiry", enquirySchema);

export const Notification =
  mongoose.models.Notification ||
  mongoose.model("Notification", notificationSchema);

export const Staff =
  mongoose.models.Staff ||
  mongoose.model("Staff", staffSchema);