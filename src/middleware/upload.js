import multer from "multer";
import path from "path";
import fs from "fs";

const uploadDir = path.resolve("uploads");

if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => {
    cb(null, uploadDir);
  },

  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const safeName = `${Date.now()}-${Math.round(Math.random() * 1e9)}${ext}`;
    cb(null, safeName);
  },
});

const allowedTypes = ["image/jpeg", "image/png", "image/webp"];

function fileFilter(_req, file, cb) {
  if (!allowedTypes.includes(file.mimetype)) {
    return cb(new Error("Upload a JPG, PNG, or WebP image."));
  }

  cb(null, true);
}

export const uploadImage = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: 3 * 1024 * 1024,
    files: 1,
  },
});
