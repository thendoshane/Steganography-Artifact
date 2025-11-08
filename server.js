require('dotenv').config();
const express = require('express');
const multer = require('multer');
const axios = require('axios');
const FormData = require('form-data');
const fs = require('fs');
const cors = require('cors');
const path = require('path');
const { execFile } = require('child_process');
const sharp = require('sharp'); // <-- The only change in imports

const app = express();
const port = process.env.PORT || 3001;

// --- Your working setup code (Unchanged) ---
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const UPLOADS_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

const upload = multer({
  dest: UPLOADS_DIR,
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    cb(null, true);
  },
});

function safeUnlink(filePath) {
  try {
    if (filePath && fs.existsSync(filePath)) fs.unlinkSync(filePath);
  } catch (e) {
    console.warn('safeUnlink failed for', filePath, e.message);
  }
}

app.get('/', (req, res) => res.json({ ok: true, message: 'Server running' }));

// --- VirusTotal Endpoint (Unchanged) ---
app.post('/scan', upload.single('file'), async (req, res) => {
  // ... (Your working code is unchanged)
  console.log('--- /scan called ---');
  if (!req.file) {
    return res.status(400).json({ error: true, details: 'No file uploaded.' });
  }
  const filePath = req.file.path;
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) {
    safeUnlink(filePath);
    return res.status(500).json({ error: true, details: 'VIRUSTOTAL_API_KEY not set on server.' });
  }
  try {
    const vtUrl = 'https://www.virustotal.com/api/v3/files';
    const formData = new FormData();
    formData.append('file', fs.createReadStream(filePath));
    const uploadResponse = await axios.post(vtUrl, formData, {
      headers: { ...formData.getHeaders(), 'x-apikey': apiKey },
      maxBodyLength: Infinity,
      maxContentLength: Infinity,
    });
    const analysisId = uploadResponse.data?.data?.id;
    if (!analysisId) {
      throw new Error('No analysis id returned from VirusTotal upload.');
    }
    const analysisUrl = `https://www.virustotal.com/api/v3/analyses/${analysisId}`;
    let analysisResponse;
    let attempts = 0;
    do {
      await new Promise((r) => setTimeout(r, 15000));
      analysisResponse = await axios.get(analysisUrl, {
        headers: { 'x-apikey': apiKey },
      });
      attempts++;
    } while (
      analysisResponse?.data?.data?.attributes?.status !== 'completed' &&
      attempts < 20
    );
    const results = analysisResponse?.data?.data?.attributes?.results;
    safeUnlink(filePath);
    if (!results) {
      return res.status(500).json({ error: true, details: 'No results returned from VirusTotal.' });
    }
    return res.json(results);
  } catch (err) {
    console.error('VirusTotal error:', err.response ? err.response.data : err.message);
    safeUnlink(filePath);
    return res.status(500).json({ error: true, details: 'Error scanning with VirusTotal.' });
  }
});


// --- YARA Scan Endpoint (Unchanged) ---
app.post('/yara-scan', (req, res) => {
  // ... (Your working code is unchanged)
  console.log('--- /yara-scan called ---');
  upload.single('file')(req, res, (multerErr) => {
    try {
      if (multerErr) {
        return res.status(400).json({ error: true, details: multerErr.code || multerErr.message });
      }
      if (!req.file) {
        return res.status(400).json({ error: true, details: 'No file uploaded.' });
      }
      const yaraRule = req.body?.yaraRule;
      if (!yaraRule || !yaraRule.toString().trim()) {
        safeUnlink(req.file.path);
        return res.status(400).json({ error: true, details: 'No YARA rule provided.' });
      }
      const ruleFilePath = path.join(UPLOADS_DIR, `${req.file.filename}.yar`);
      fs.writeFileSync(ruleFilePath, yaraRule);
      const yaraExecutable = process.env.YARA_PATH || (process.platform === 'win32' ? 'C:\\ProgramData\\chocolatey\\bin\\yara64.exe' : 'yara');
      execFile(yaraExecutable, [ruleFilePath, req.file.path], { windowsHide: true }, (error, stdout, stderr) => {
        safeUnlink(req.file.path);
        safeUnlink(ruleFilePath);
        if (error) {
          console.error('YARA execution error:', error.message || error, stderr ? stderr.toString() : null);
          return res.status(400).json({ error: true, details: stderr ? stderr.toString() : (error.message || 'YARA execution failed') });
        }
        const out = stdout ? stdout.toString().trim() : '';
        if (!out) {
          return res.json({ rules: [] });
        }
        const ruleNames = out.split(/\r?\n/).map((line) => line.split(/\s+/)[0]).filter(Boolean);
        return res.json({ rules: ruleNames.map((r) => ({ id: r })) });
      });
    } catch (ex) {
      console.error('Unexpected error in /yara-scan:', ex);
      safeUnlink(req.file?.path);
      safeUnlink(path.join(UPLOADS_DIR, `${req.file?.filename}.yar`));
      return res.status(500).json({ error: true, details: ex.message });
    }
  });
});

// --- FINAL ML Anomaly Detection Endpoint using 'sharp' ---
app.post('/ml-scan', upload.single('file'), async (req, res) => {
    console.log('--- /ml-scan called ---');
    if (!req.file) {
        return res.status(400).json({ error: true, details: 'No file uploaded for ML scan.' });
    }

    const filePath = req.file.path;

    try {
        const image = sharp(filePath);
        const metadata = await image.metadata(); // Get width, height, etc.
        const pixelData = await image.raw().toBuffer(); // Get the raw pixel data

        // 1. Feature Extraction: Calculate Entropy
        const byteCounts = new Array(256).fill(0);
        for (let i = 0; i < pixelData.length; i++) {
            byteCounts[pixelData[i]]++;
        }

        let entropy = 0;
        const totalBytes = pixelData.length;
        if (totalBytes === 0) {
            safeUnlink(filePath);
            return res.status(400).json({ error: true, details: 'Image contains no pixel data.' });
        }

        for (let i = 0; i < 256; i++) {
            if (byteCounts[i] === 0) continue;
            const probability = byteCounts[i] / totalBytes;
            entropy -= probability * Math.log2(probability);
        }

        // 2. Anomaly Detection (Simulation)
        let isAnomaly = false;
        let anomalyReason = "Normal statistical profile based on entropy analysis.";
        const ENTROPY_THRESHOLD = 7.9;

        if (entropy > ENTROPY_THRESHOLD) {
            isAnomaly = true;
            anomalyReason = `High entropy (${entropy.toFixed(4)}) detected. This can be an indicator of embedded encrypted or compressed data.`;
        }

        // 3. Send results
        return res.json({
            isAnomaly,
            anomalyReason,
            features: {
                entropy: entropy.toFixed(4),
                width: metadata.width,
                height: metadata.height,
            }
        });

    } catch (err) {
        console.error('ML Scan Error (sharp):', err.message);
        return res.status(500).json({ error: true, details: 'Failed to process the image with sharp. It may be corrupted or in an unsupported format.' });
    } finally {
        safeUnlink(filePath);
    }
});
// --- End of ML Endpoint ---



// Global error handler (fallback)
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: true, details: err.message || 'Server error' });
});

app.listen(port, () => {
  console.log(`Server listening on http://localhost:${port}`);
});

