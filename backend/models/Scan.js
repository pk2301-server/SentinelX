const mongoose = require("mongoose");

const scanSchema = new mongoose.Schema({
    target: {
        type: String,
        required: true
    },

    scanType: {
        type: String,
        enum: ["quick", "full", "custom"],
        default: "quick"
    },

    status: {
        type: String,
        enum: ["queued", "running", "completed", "failed"],
        default: "queued"
    },

    progress: {
        type: Number,
        default: 0
    },

    riskScore: {
        type: Number,
        default: 0
    },

    vulnerabilities: [{
        severity: String,
        title: String,
        description: String,
        solution: String
    }],

    startedAt: Date,

    completedAt: Date

}, {
    timestamps: true
});

module.exports = mongoose.model("Scan", scanSchema);