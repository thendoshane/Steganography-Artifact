// api/scan.js (CommonJS Version)
const formidable = require('formidable');
const FormData = require('form-data');
const fs = require('fs');
const axios = require('axios');

// Disable Vercel's default body parser
module.exports.config = {
  api: {
    bodyParser: false,
  },
};

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: `Method ${req.method} Not Allowed` });
  }

  console.log("1. Request received at /api/scan (CommonJS)");

  try {
    // 1. Parse the file using Formidable
    const data = await new Promise((resolve, reject) => {
      const form = new formidable.IncomingForm({
        keepExtensions: true, // Keep file extension (.jpg, .png, etc)
        allowEmptyFiles: false,
        maxFileSize: 5 * 1024 * 1024, // 5MB Limit
      });
      
      form.parse(req, (err, fields, files) => {
        if (err) return reject(err);
        resolve({ fields, files });
      });
    });

    // Handle Formidable v2/v3 array differences safely
    const fileEntry = data.files.file;
    const file = Array.isArray(fileEntry) ? fileEntry[0] : fileEntry;

    if (!file) {
      console.error("No file found in upload");
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const apiKey = process.env.VIRUSTOTAL_API_KEY;
    if (!apiKey) {
      console.error("API Key Missing");
      return res.status(500).json({ error: 'Server Config Error: API Key missing' });
    }

    // 2. Upload to VirusTotal
    console.log(`2. Uploading ${file.originalFilename || 'file'} to VirusTotal...`);
    
    const uploadFormData = new FormData();
    uploadFormData.append('file', fs.createReadStream(file.filepath));

    const uploadResponse = await axios.post(
      'https://www.virustotal.com/api/v3/files',
      uploadFormData,
      {
        headers: {
          ...uploadFormData.getHeaders(),
          'x-apikey': apiKey,
        },
        maxContentLength: Infinity,
        maxBodyLength: Infinity,
      }
    );

    const analysisId = uploadResponse.data.data.id;
    console.log(`3. Scan ID: ${analysisId}. Starting polling...`);

    // 3. Poll for Results
    const POLLING_INTERVAL = 3000; 
    const MAX_POLLING_ATTEMPTS = 18; // ~54 seconds (Safe buffer for 60s limit)
    let attempts = 0;
    let analysisCompleted = false;
    let finalResults = null;

    while (!analysisCompleted && attempts < MAX_POLLING_ATTEMPTS) {
      attempts++;
      await new Promise(resolve => setTimeout(resolve, POLLING_INTERVAL));

      const reportResponse = await axios.get(
        `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
        { headers: { 'x-apikey': apiKey } }
      );

      const status = reportResponse.data.data.attributes.status;
      
      if (status === 'completed') {
        analysisCompleted = true;
        finalResults = reportResponse.data.data.attributes.results;
      }
    }

    if (!analysisCompleted) {
      return res.status(504).json({ error: 'Scan timed out. Please try again.' });
    }

    return res.status(200).json(finalResults);

  } catch (error) {
    console.error('API Error:', error.message);
    
    // Extract specific error if available
    const errorMsg = error.response?.data?.error?.message || error.message;
    
    return res.status(500).json({ 
      error: 'Internal Server Error', 
      details: errorMsg 
    });
  }
};