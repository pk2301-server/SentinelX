const express = require("express");
const router = express.Router();

const {
  createScan,
  getScans,
  getScan,
  deleteScan,
} = require("../controllers/scanController");

router.post("/", createScan);
router.get("/", getScans);
router.get("/:id", getScan);
router.delete("/:id", deleteScan);

module.exports = router;