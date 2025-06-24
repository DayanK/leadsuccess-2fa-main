// Backend/src/routes/deviceRoutes.js - Device management routes
const express = require("express");
const deviceController = require("../controllers/deviceController");
const { requireAuth } = require("../middleware/authMiddleware");

const router = express.Router();

// Device routes (all require authentication)
router.get("/", requireAuth, deviceController.getDevices);
router.delete("/:deviceId", requireAuth, deviceController.removeDevice);

module.exports = router;