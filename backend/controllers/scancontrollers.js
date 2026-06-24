const Scan = require("../models/scan");

// Create Scan
exports.createScan = async (req, res) => {
  try {
    const scan = await Scan.create(req.body);
    res.status(201).json(scan);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

// Get All Scans
exports.getScans = async (req, res) => {
  try {
    const scans = await Scan.find().sort({ createdAt: -1 });
    res.json(scans);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

// Get Single Scan
exports.getScan = async (req, res) => {
  try {
    const scan = await Scan.findById(req.params.id);

    if (!scan)
      return res.status(404).json({ message: "Scan not found" });

    res.json(scan);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

// Delete Scan
exports.deleteScan = async (req, res) => {
  try {
    await Scan.findByIdAndDelete(req.params.id);
    res.json({ message: "Scan deleted" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};