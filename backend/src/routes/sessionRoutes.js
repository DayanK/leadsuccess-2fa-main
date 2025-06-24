// Backend/src/routes/sessionRoutes.js - Session management routes
const express = require("express");
const sessionController = require("../controllers/sessionController");
const { requireAuth } = require("../middleware/authMiddleware");

const router = express.Router();

// Session routes (all require authentication)
router.get("/", requireAuth, sessionController.getSessions);
router.post("/logout-all", requireAuth, sessionController.logoutAllSessions);

module.exports = router;