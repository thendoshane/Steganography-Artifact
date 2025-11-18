// api/scan.js
import { IncomingForm } from 'formidable';
import FormData from 'form-data';
import fs from 'fs';
import axios from 'axios';

export const config = {
  api: {
    bodyParser: false, // Disables Vercel's default parser so Formidable works
  },
};

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: `Method ${req.method} Not Allowed` });
  }

  console.log("1. Request received at /api/scan (Backend Polling Mode)");

  try {
    // 1. Parse the incoming file
    const data = await new Promise((resolve, reject) => {
      const form = new IncomingForm();
      form.parse(req, (err, fields, files) => {
        if (err) {
            console.error("Form parse error:", err);
            reject(err);
        }
        resolve({ fields, files });
      });
    });

    const fileArray = data.files.file;
    const file = Array.isArray(fileArray) ? fileArray[0] : fileArray;

    if (!file) {
      console.error("No file found in request:", data.files);
      return res.status(400).json({ error: 'No file provided in the upload' });
    }

    const apiKey = process.env.VIRUSTOTAL_API_KEY;
    if (!apiKey) {
      console.error("CRITICAL: VIRUSTOTAL_API_KEY is missing in Environment Variables");
      return res.status(500).json({ error: 'Server configuration error: Missing API Key' });
    }

    // 2. Upload to VirusTotal
    console.log(`2. Uploading file: ${file.originalFilename}`);
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
    if (!analysisId) {
        console.error("No analysis ID received from VirusTotal upload:", uploadResponse.data);
        return res.status(500).json({ error: 'Failed to initiate VirusTotal scan.' });
    }
    console.log(`3. File uploaded, analysis ID: ${analysisId}. Starting backend polling...`);

    // 3. Backend Polling for Results
    const POLLING_INTERVAL = 3000; // 3 seconds
    const MAX_POLLING_ATTEMPTS = 20; // Max 60 seconds (20 * 3s)
    let attempts = 0;
    let analysisCompleted = false;
    let finalResults = null;

    while (!analysisCompleted && attempts < MAX_POLLING_ATTEMPTS) {
        attempts++;
        console.log(`Polling attempt ${attempts} for analysis ID: ${analysisId}`);
        await new Promise(resolve => setTimeout(resolve, POLLING_INTERVAL)); // Wait

        const reportResponse = await axios.get(
            `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
            {
                headers: { 'x-apikey': apiKey },
            }
        );

        const status = reportResponse.data.data.attributes.status;
        console.log(`Analysis status: ${status}`);

        if (status === 'completed') {
            analysisCompleted = true;
            finalResults = reportResponse.data.data.attributes.results;
        }
    }

    if (!analysisCompleted) {
        console.error("VirusTotal analysis timed out on backend for ID:", analysisId);
        return res.status(504).json({ error: 'VirusTotal analysis timed out.' }); // 504 Gateway Timeout
    }

    // 4. Send final results to frontend
    console.log("4. Analysis completed. Sending results to frontend.");
    return res.status(200).json(finalResults);

  } catch (error) {
    console.error('--- API ERROR DETAILS ---');
    if (error.response) {
      console.error('Status:', error.response.status);
      console.error('Data:', JSON.stringify(error.response.data));
      // Attempt to pass through VT's error message
      return res.status(error.response.status).json({
          error: 'VirusTotal API Error',
          details: error.response.data.error?.message || JSON.stringify(error.response.data)
      });
    } else {
      console.error('Error Message:', error.message);
      return res.status(500).json({ error: 'Internal Server Error', details: error.message });
    }
  }
}