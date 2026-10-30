import { Router } from "express";

import {
  Course,
  Blog,
  PricingPlan,
  ProjectLab,
  Review,
  Enquiry,
  Notification,
} from "../models/Content.js";

import { requireAdmin } from "../middleware/adminKey.js";

const r = Router();

// Protect all admin routes.
r.use(requireAdmin);

/**
 * File: admin-backend/src/routes/admin.js
 * Purpose: Provides API routes for student testimonials.
 * Dependencies: Review model from ../models/Content.js
 * Data Source: MongoDB Review collection.
 * Security: Protected by the existing requireAdmin middleware.
 * Related Files: Admin Student Testimonials page and public website.
 */

// ==================== STUDENT TESTIMONIALS ====================

r.get("/testimonials", async (_q, s, next) => {
  try {
    const items = await Review.find()
      .sort({ createdAt: -1 })
      .lean();

    return s.json(items);
  } catch (error) {
    next(error);
  }
});

r.post("/testimonials", async (q, s, next) => {
  try {
    const {
      name,
      role,
      rating,
      message,
      approved,
    } = q.body ?? {};

    if (
      typeof name !== "string" ||
      !name.trim() ||
      typeof role !== "string" ||
      !role.trim() ||
      typeof message !== "string" ||
      !message.trim()
    ) {
      return s.status(400).json({
        message: "Name, role, and testimonial message are required.",
      });
    }

    const numericRating = Number(rating);

    if (
      !Number.isInteger(numericRating) ||
      numericRating < 1 ||
      numericRating > 5
    ) {
      return s.status(400).json({
        message: "Rating must be between 1 and 5.",
      });
    }

    const item = await Review.create({
      name: name.trim(),
      role: role.trim(),
      rating: numericRating,
      message: message.trim(),
      approved: approved === true,
    });

    return s.status(201).json(item);
  } catch (error) {
    if (error.name === "ValidationError") {
      return s.status(400).json({
        message: error.message,
      });
    }

    next(error);
  }
});

r.put("/testimonials/:id", async (q, s, next) => {
  try {
    const {
      name,
      role,
      rating,
      message,
      approved,
    } = q.body ?? {};

    if (
      typeof name !== "string" ||
      !name.trim() ||
      typeof role !== "string" ||
      !role.trim() ||
      typeof message !== "string" ||
      !message.trim()
    ) {
      return s.status(400).json({
        message: "Name, role, and testimonial message are required.",
      });
    }

    const numericRating = Number(rating);

    if (
      !Number.isInteger(numericRating) ||
      numericRating < 1 ||
      numericRating > 5
    ) {
      return s.status(400).json({
        message: "Rating must be between 1 and 5.",
      });
    }

    const item = await Review.findByIdAndUpdate(
      q.params.id,
      {
        name: name.trim(),
        role: role.trim(),
        rating: numericRating,
        message: message.trim(),
        approved: approved === true,
      },
      {
        new: true,
        runValidators: true,
      }
    );

    if (!item) {
      return s.status(404).json({
        message: "Testimonial not found.",
      });
    }

    return s.json(item);
  } catch (error) {
    if (
      error.name === "ValidationError" ||
      error.name === "CastError"
    ) {
      return s.status(400).json({
        message: error.message,
      });
    }

    next(error);
  }
});

r.patch("/testimonials/:id", async (q, s, next) => {
  try {
    if (typeof q.body?.approved !== "boolean") {
      return s.status(400).json({
        message: "A valid publication status is required.",
      });
    }

    const item = await Review.findByIdAndUpdate(
      q.params.id,
      { approved: q.body.approved },
      {
        new: true,
        runValidators: true,
      }
    );

    if (!item) {
      return s.status(404).json({
        message: "Testimonial not found.",
      });
    }

    return s.json(item);
  } catch (error) {
    if (error.name === "CastError") {
      return s.status(400).json({
        message: "Invalid testimonial ID.",
      });
    }

    next(error);
  }
});

r.delete("/testimonials/:id", async (q, s, next) => {
  try {
    const item = await Review.findByIdAndDelete(q.params.id);

    if (!item) {
      return s.status(404).json({
        message: "Testimonial not found.",
      });
    }

    return s.status(204).end();
  } catch (error) {
    if (error.name === "CastError") {
      return s.status(400).json({
        message: "Invalid testimonial ID.",
      });
    }

    next(error);
  }
});

/**
 * File: admin-backend/src/routes/admin.js
 * Purpose: Creates student reviews using the existing Review model.
 * Dependencies: Review from ../models/Content.js
 * Data Source: Validated request body.
 * Security: Requires the existing admin router authentication middleware.
 * Related Files: admin-frontend/src/pages/ReviewsPage.jsx
 */

r.post("/reviews", async (q, s, next) => {
  try {
    const { name, role, rating, message, approved } = q.body ?? {};

    if (
      typeof name !== "string" ||
      !name.trim() ||
      typeof role !== "string" ||
      typeof message !== "string" ||
      !message.trim()
    ) {
      return s.status(400).json({
        message: "Name, role, and review message are required.",
      });
    }

    const numericRating = Number(rating);

    if (
      !Number.isInteger(numericRating) ||
      numericRating < 1 ||
      numericRating > 5
    ) {
      return s.status(400).json({
        message: "Rating must be between 1 and 5.",
      });
    }

    const review = await Review.create({
      name: name.trim(),
      role: role.trim() || "Parent",
      rating: numericRating,
      message: message.trim(),
      approved: approved === true,
    });

    return s.status(201).json({
      message: "Review created successfully.",
      review,
    });
  } catch (error) {
    next(error);
  }
});

// ==================== OVERVIEW ====================

r.get("/overview", async (_q, s, next) => {
  try {
    const [
      courses,
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
      Blog.countDocuments(),
      Review.countDocuments(),
      Enquiry.countDocuments(),
      Enquiry.countDocuments({ status: "new" }),
      Enquiry.countDocuments({ status: "enrolled" }),
      PricingPlan.countDocuments({ active: true }),
      ProjectLab.countDocuments({ active: true }),
      Notification.countDocuments({ read: false }),
      Review.aggregate([
        { $match: { approved: true } },
        {
          $group: {
            _id: null,
            average: { $avg: "$rating" },
            count: { $sum: 1 },
          },
        },
      ]),
    ]);

    s.json({
      courses,
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
  } catch (e) {
    next(e);
  }
});

// ==================== COURSES ====================

r.get("/courses", async (_q, s, next) => {
  try {
    s.json(
      await Course.find().sort({ createdAt: -1 }).lean()
    );
  } catch (e) {
    next(e);
  }
});

r.post("/courses", async (q, s, next) => {
  try {
    const item = await Course.create(q.body);
    s.status(201).json(item);
  } catch (e) {
    if (e.code === 11000) {
      return s.status(400).json({
        message: "Course slug already exists",
      });
    }
    if (e.name === "ValidationError") {
      return s.status(400).json({ message: e.message });
    }
    next(e);
  }
});

r.put("/courses/:id", async (q, s, next) => {
  try {
    const item = await Course.findByIdAndUpdate(
      q.params.id,
      q.body,
      { new: true, runValidators: true }
    );

    if (!item) {
      return s.status(404).json({
        message: "Course not found",
      });
    }

    s.json(item);
  } catch (e) {
    if (e.name === "ValidationError" || e.name === "CastError") {
      return s.status(400).json({ message: e.message });
    }
    if (e.code === 11000) {
      return s.status(400).json({
        message: "Course slug already exists",
      });
    }
    next(e);
  }
});

r.delete("/courses/:id", async (q, s, next) => {
  try {
    const item = await Course.findByIdAndDelete(q.params.id);

    if (!item) {
      return s.status(404).json({
        message: "Course not found",
      });
    }

    s.status(204).end();
  } catch (e) {
    next(e);
  }
});

// ==================== BLOGS ====================

r.get("/blogs", async (_q, s, next) => {
  try {
    s.json(
      await Blog.find().sort({ createdAt: -1 }).lean()
    );
  } catch (e) {
    next(e);
  }
});

r.post("/blogs", async (q, s, next) => {
  try {
    const item = await Blog.create({
      ...q.body,
      publishedAt: q.body.published
        ? new Date()
        : undefined,
    });

    s.status(201).json(item);
  } catch (e) {
    if (e.code === 11000) {
      return s.status(400).json({
        message: "Blog slug already exists",
      });
    }
    if (e.name === "ValidationError") {
      return s.status(400).json({ message: e.message });
    }
    next(e);
  }
});

r.put("/blogs/:id", async (q, s, next) => {
  try {
    const item = await Blog.findByIdAndUpdate(
      q.params.id,
      {
        ...q.body,
        publishedAt: q.body.published
          ? q.body.publishedAt || new Date()
          : null,
      },
      { new: true, runValidators: true }
    );

    if (!item) {
      return s.status(404).json({
        message: "Blog not found",
      });
    }

    s.json(item);
  } catch (e) {
    if (e.name === "ValidationError" || e.name === "CastError") {
      return s.status(400).json({ message: e.message });
    }
    if (e.code === 11000) {
      return s.status(400).json({
        message: "Blog slug already exists",
      });
    }
    next(e);
  }
});

r.delete("/blogs/:id", async (q, s, next) => {
  try {
    const item = await Blog.findByIdAndDelete(q.params.id);

    if (!item) {
      return s.status(404).json({
        message: "Blog not found",
      });
    }

    s.status(204).end();
  } catch (e) {
    next(e);
  }
});

// ==================== PRICING PLANS ====================

r.get("/pricing", async (_q, s, next) => {
  try {
    s.json(
      await PricingPlan.find()
        .sort({ order: 1, createdAt: -1 })
        .lean()
    );
  } catch (e) {
    next(e);
  }
});

r.post("/pricing", async (q, s, next) => {
  try {
    const item = await PricingPlan.create(q.body);
    s.status(201).json(item);
  } catch (e) {
    if (e.name === "ValidationError") {
      return s.status(400).json({ message: e.message });
    }
    next(e);
  }
});

r.put("/pricing/:id", async (q, s, next) => {
  try {
    const item = await PricingPlan.findByIdAndUpdate(
      q.params.id,
      q.body,
      { new: true, runValidators: true }
    );

    if (!item) {
      return s.status(404).json({
        message: "Pricing plan not found",
      });
    }

    s.json(item);
  } catch (e) {
    if (e.name === "ValidationError" || e.name === "CastError") {
      return s.status(400).json({ message: e.message });
    }
    next(e);
  }
});

r.delete("/pricing/:id", async (q, s, next) => {
  try {
    const item = await PricingPlan.findByIdAndDelete(q.params.id);

    if (!item) {
      return s.status(404).json({
        message: "Pricing plan not found",
      });
    }

    s.status(204).end();
  } catch (e) {
    next(e);
  }
});

// ==================== PROJECT LAB ====================

r.get("/projects", async (_q, s, next) => {
  try {
    s.json(
      await ProjectLab.find()
        .sort({ createdAt: -1 })
        .lean()
    );
  } catch (e) {
    next(e);
  }
});

r.post("/projects", async (q, s, next) => {
  try {
    const item = await ProjectLab.create(q.body);
    s.status(201).json(item);
  } catch (e) {
    if (e.name === "ValidationError") {
      return s.status(400).json({ message: e.message });
    }
    next(e);
  }
});

r.put("/projects/:id", async (q, s, next) => {
  try {
    const item = await ProjectLab.findByIdAndUpdate(
      q.params.id,
      q.body,
      { new: true, runValidators: true }
    );

    if (!item) {
      return s.status(404).json({
        message: "Project not found",
      });
    }

    s.json(item);
  } catch (e) {
    if (e.name === "ValidationError" || e.name === "CastError") {
      return s.status(400).json({ message: e.message });
    }
    next(e);
  }
});

r.delete("/projects/:id", async (q, s, next) => {
  try {
    const item = await ProjectLab.findByIdAndDelete(q.params.id);

    if (!item) {
      return s.status(404).json({
        message: "Project not found",
      });
    }

    s.status(204).end();
  } catch (e) {
    next(e);
  }
});

// ==================== ENQUIRIES ====================

r.get("/enquiries", async (q, s, next) => {
  try {
    const page = Math.max(1, Number(q.query.page) || 1);
    const limit = Math.min(100, Number(q.query.limit) || 50);

    const [items, total] = await Promise.all([
      Enquiry.find()
        .sort({ createdAt: -1 })
        .skip((page - 1) * limit)
        .limit(limit)
        .lean(),
      Enquiry.countDocuments(),
    ]);

    s.json({ items, total, page, limit });
  } catch (e) {
    next(e);
  }
});

r.patch("/enquiries/:id", async (q, s, next) => {
  try {
    const allowedStatuses = [
      "new",
      "contacted",
      "enrolled",
      "closed",
    ];

    if (!allowedStatuses.includes(q.body.status)) {
      return s.status(400).json({
        message: "Invalid enquiry status",
      });
    }

    const item = await Enquiry.findByIdAndUpdate(
      q.params.id,
      { status: q.body.status },
      { new: true, runValidators: true }
    );

    if (!item) {
      return s.status(404).json({
        message: "Enquiry not found",
      });
    }

    s.json(item);
  } catch (e) {
    next(e);
  }
});

// ==================== NOTIFICATIONS ====================

r.get("/notifications", async (q, s, next) => {
  try {
    const page = Math.max(1, Number(q.query.page) || 1);
    const limit = Math.min(100, Number(q.query.limit) || 50);

    const [items, total, unread] = await Promise.all([
      Notification.find()
        .sort({ createdAt: -1 })
        .skip((page - 1) * limit)
        .limit(limit)
        .lean(),
      Notification.countDocuments(),
      Notification.countDocuments({ read: false }),
    ]);

    s.json({ items, total, unread, page, limit });
  } catch (e) {
    next(e);
  }
});

r.patch("/notifications/:id", async (q, s, next) => {
  try {
    const item = await Notification.findByIdAndUpdate(
      q.params.id,
      { read: Boolean(q.body.read) },
      { new: true, runValidators: true }
    );

    if (!item) {
      return s.status(404).json({
        message: "Notification not found",
      });
    }

    s.json(item);
  } catch (e) {
    next(e);
  }
});

r.patch("/notifications/read-all", async (_q, s, next) => {
  try {
    const result = await Notification.updateMany(
      { read: false },
      { $set: { read: true } }
    );

    s.json({
      message: "All notifications marked as read",
      modifiedCount: result.modifiedCount,
    });
  } catch (e) {
    next(e);
  }
});

r.delete("/notifications/:id", async (q, s, next) => {
  try {
    const item = await Notification.findByIdAndDelete(q.params.id);

    if (!item) {
      return s.status(404).json({
        message: "Notification not found",
      });
    }

    s.status(204).end();
  } catch (e) {
    next(e);
  }
});

// ==================== REVIEWS ====================

r.get("/reviews", async (_q, s, next) => {
  try {
    s.json(
      await Review.find().sort({ createdAt: -1 }).lean()
    );
  } catch (e) {
    next(e);
  }
});

r.patch("/reviews/:id", async (q, s, next) => {
  try {
    const item = await Review.findByIdAndUpdate(
      q.params.id,
      { approved: Boolean(q.body.approved) },
      { new: true, runValidators: true }
    );

    if (!item) {
      return s.status(404).json({
        message: "Review not found",
      });
    }

    s.json(item);
  } catch (e) {
    next(e);
  }
});

r.delete("/reviews/:id", async (q, s, next) => {
  try {
    const item = await Review.findByIdAndDelete(q.params.id);

    if (!item) {
      return s.status(404).json({
        message: "Review not found",
      });
    }

    s.status(204).end();
  } catch (e) {
    next(e);
  }
});

export default r;
