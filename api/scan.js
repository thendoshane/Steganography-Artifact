// api/scan.js
import { IncomingForm } from 'formidable';
import FormData from 'form-data';
import fs from 'fs';
import axios from 'axios';

// We must disable the default body parser to handle file uploads manually
export const config = {
  api: {
    bodyParser: false,
  },
};

export default async function handler(req, res) {
  // 1. Only allow POST requests
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  try {
    // 2. Parse the incoming file using Formidable
    const data = await new Promise((resolve, reject) => {
      const form = new IncomingForm();
      form.parse(req, (err, fields, files) => {
        if (err) return reject(err);
        resolve({ fields, files });
      });
    });

    const file = data.files.file?.[0] || data.files.file; // Handle array or single object

    if (!file) {
      return res.status(400).json({ error: 'No file provided' });
    }

    // 3. Prepare the file to send to VirusTotal
    const formData = new FormData();
    formData.append('file', fs.createReadStream(file.filepath));

    // 4. Send to VirusTotal using your SECRET API Key from Vercel Environment Variables
    const vtResponse = await axios.post(
      'https://www.virustotal.com/api/v3/files',
      formData,
      {
        headers: {
          ...formData.getHeaders(),
          'x-apikey': process.env.VIRUSTOTAL_API_KEY, // Use the backend env var
        },
      }
    );

    // 5. Return the result to your frontend
    return res.status(200).json(vtResponse.data);

  } catch (error) {
    console.error('API Error:', error.response?.data || error.message);
    return res.status(500).json({ 
      error: 'Scan failed', 
      details: error.response?.data?.error?.message || error.message 
    });
  }
}