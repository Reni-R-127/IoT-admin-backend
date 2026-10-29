import mongoose from "mongoose";

// ==================== COURSE MODEL ====================
const courseSchema = new mongoose.Schema(
  {
    title: { type: String, required: true, trim: true },
    slug: { type: String, required: true, unique: true, trim: true },
    description: { type: String, default: "" },
    ageRange: { type: String, default: "" },
    duration: { type: String, default: "" },
    level: { type: String, default: "Beginner" },
    price: { type: String, default: "Contact us" },
    image: { type: String, default: "" },
    active: { type: Boolean, default: true },
  },
  { timestamps: true }
);

// ==================== BLOG MODEL ====================
const blogSchema = new mongoose.Schema(
  {
    title: { type: String, required: true, trim: true },
    slug: { type: String, required: true, unique: true, trim: true },
    category: { type: String, default: "IoT" },
    excerpt: { type: String, default: "" },
    content: { type: String, default: "" },
    image: { type: String, default: "" },
    published: { type: Boolean, default: false },
    publishedAt: { type: Date, default: null },
  },
  { timestamps: true }
);

// ==================== PRICING PLAN MODEL ====================
const pricingPlanSchema = new mongoose.Schema(
  {
    title: { type: String, required: true, trim: true },
    description: { type: String, default: "" },
    price: { type: String, required: true },
    features: { type: [String], default: [] },
    active: { type: Boolean, default: true },
    order: { type: Number, default: 0 },
  },
  { timestamps: true }
);

// ==================== PROJECT LAB MODEL ====================
const projectLabSchema = new mongoose.Schema(
  {
    title: { type: String, required: true, trim: true },
    description: { type: String, default: "" },
    category: { type: String, default: "" },
    image: { type: String, default: "" },
    technologies: { type: [String], default: [] },
    active: { type: Boolean, default: true },
  },
  { timestamps: true }
);

// ==================== REVIEW MODEL ====================
const reviewSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    role: { type: String, default: "Parent" },
    rating: { type: Number, required: true, min: 1, max: 5 },
    message: { type: String, required: true, trim: true },
    approved: { type: Boolean, default: false },
  },
  { timestamps: true }
);

// ==================== ENQUIRY MODEL ====================
const enquirySchema = new mongoose.Schema(
  {
    parentName: { type: String, required: true, trim: true },
    childName: { type: String, default: "" },
    childAge: { type: Number, min: 1, max: 18 },
    phone: { type: String, required: true, trim: true },
    email: { type: String, required: true, lowercase: true, trim: true },
    course: { type: String, required: true, trim: true },
    message: { type: String, default: "" },
    status: {
      type: String,
      enum: ["new", "contacted", "enrolled", "closed"],
      default: "new",
    },
    source: { type: String, default: "website" },
  },
  { timestamps: true }
);

// ==================== NOTIFICATION MODEL ====================
const notificationSchema = new mongoose.Schema(
  {
    type: {
      type: String,
      enum: ["enquiry", "whatsapp", "system"],
      default: "enquiry",
    },
    title: { type: String, required: true, trim: true },
    message: { type: String, default: "" },
    source: { type: String, default: "website" },
    section: { type: String, default: "" },
    read: { type: Boolean, default: false },
    metadata: {
      type: mongoose.Schema.Types.Mixed,
      default: {},
    },
  },
  { timestamps: true }
);

// ==================== MODEL EXPORTS ====================
// Reuse registered models to prevent OverwriteModelError.

export const Course =
  mongoose.models.Course ||
  mongoose.model("Course", courseSchema);

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