export function requireAdmin(req, res, next) {
  const expected = process.env.ADMIN_API_KEY;
  const supplied = req.get("x-admin-key");
  if (!expected || expected.length < 32) {
    return res.status(503).json({ message: "Admin API is not configured. Set ADMIN_API_KEY on the admin backend." });
  }
  if (!supplied || supplied.length !== expected.length || supplied !== expected) {
    return res.status(401).json({ message: "Unauthorized admin API request. Check the admin proxy key configuration." });
  }
  next();
}
