import React, { useState } from 'react';
import axios from 'axios';
import './FileScanner.css';

function FileScanner() {
  const [selectedFile, setSelectedFile] = useState(null);
  const [scanResult, setScanResult] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [currentPage, setCurrentPage] = useState(1);
  const resultsPerPage = 10;

  const handleFileChange = (event) => {
    const file = event.target.files && event.target.files[0];
    if (file) {
      setSelectedFile(file);
      setScanResult(null);
      setError('');
    }
  };

  const handleScan = async () => {
    if (!selectedFile) {
      setError('Please select a file first.');
      return;
    }

    setIsLoading(true);
    setError('');
    setScanResult(null);

    try {
      const formData = new FormData();
      formData.append('file', selectedFile);

      // --- KEY CHANGE: Point to the Vercel API Route ---
      // We use a relative path '/api/scan'. Vercel automatically routes this 
      // to the 'api' folder in your root directory.
      const response = await axios.post('/api/scan', formData, {
        headers: {
          'Content-Type': 'multipart/form-data', 
        },
        timeout: 30000, // 30 second timeout
      });

      // Handle the data from VirusTotal
      // Note: API v3 often puts the results inside data.attributes.last_analysis_results
      // or just returns an analysis ID if the scan is queued.
      const responseData = response.data;
      
      // Determine where the engine results are located in the response object
      // This logic tries to find the results whether they are at the root or nested
      let analysisResults = {};
      
      if (responseData.data && responseData.data.attributes && responseData.data.attributes.last_analysis_results) {
        // Case 1: Full report returned (GET request or Cached)
        analysisResults = responseData.data.attributes.last_analysis_results;
      } else if (responseData.data && responseData.data.id) {
        // Case 2: File was uploaded and is Queued (POST request)
        // In a real app, you would use this ID to poll for results. 
        // For now, we alert the user.
        throw new Error(`File uploaded successfully. Analysis ID: ${responseData.data.id}. (Note: To see results instantly, the backend needs to implement polling or hash-lookup).`);
      } else {
        // Case 3: Fallback or different API structure
        analysisResults = responseData || {};
      }

      // Calculate Stats
      let maliciousCount = 0;
      let harmlessCount = 0;
      let undetectedCount = 0;

      Object.values(analysisResults).forEach((engine) => {
        if (!engine) return;
        if (engine.category === 'malicious') maliciousCount++;
        else if (engine.category === 'harmless') harmlessCount++;
        else undetectedCount++;
      });

      setScanResult({
        summary: { malicious: maliciousCount, harmless: harmlessCount, undetected: undetectedCount },
        details: analysisResults,
      });
      
      setCurrentPage(1);

    } catch (err) {
      console.error('Scan error:', err);
      const serverMsg = err.response?.data?.error || err.message || 'Scan failed';
      setError(`Scan Error: ${serverMsg}`);
    } finally {
      setIsLoading(false);
    }
  };

  const totalPages = scanResult
    ? Math.max(1, Math.ceil(Object.keys(scanResult.details || {}).length / resultsPerPage))
    : 1;

  const paginatedResults = scanResult
    ? Object.entries(scanResult.details).slice(
        (currentPage - 1) * resultsPerPage,
        currentPage * resultsPerPage
      )
    : [];

  const handleNext = () => {
    if (currentPage < totalPages) setCurrentPage((p) => p + 1);
  };

  const handlePrev = () => {
    if (currentPage > 1) setCurrentPage((p) => p - 1);
  };

  return (
    <div className="scanner-container">
      <h2 className="scanner-title">VirusTotal Scanner</h2>
      <p>Upload a file to check it against antivirus engines.</p>

      <div className="upload-area">
        <label htmlFor="file-upload" className="upload-label">
          Choose File
        </label>
        <input
          id="file-upload"
          type="file"
          onChange={handleFileChange}
          accept="*/*"
        />
        {selectedFile && <span className="file-name">{selectedFile.name}</span>}
      </div>

      <button onClick={handleScan} className="scan-button" disabled={isLoading}>
        {isLoading ? 'Scanning...' : 'Scan File'}
      </button>

      <div className="status-message">
        {error && <p className="error-message">{error}</p>}
        {isLoading && <p>Uploading to server & scanning...</p>}
      </div>

      {scanResult && (
        <div className="results-container">
          <div className="results-summary">
            <div className="summary-item">
              <h3>Malicious</h3>
              <p className="summary-count malicious">{scanResult.summary.malicious}</p>
            </div>
            <div className="summary-item">
              <h3>Harmless</h3>
              <p className="summary-count harmless">{scanResult.summary.harmless}</p>
            </div>
            <div className="summary-item">
              <h3>Undetected</h3>
              <p className="summary-count">{scanResult.summary.undetected}</p>
            </div>
          </div>

          <div className="results-table-wrapper">
            <table className="results-table compact-table">
              <thead>
                <tr>
                  <th>Engine</th>
                  <th>Category</th>
                  <th>Result</th>
                </tr>
              </thead>
              <tbody>
                {paginatedResults.map(([engine, result]) => (
                  <tr key={engine}>
                    <td>{engine}</td>
                    <td>{result?.category || 'unknown'}</td>
                    <td>{result?.result || (result?.category === 'harmless' ? 'Clean' : '—')}</td>
                  </tr>
                ))}
              </tbody>
            </table>

            <div className="pagination-controls">
              <button
                className="page-button"
                onClick={handlePrev}
                disabled={currentPage === 1}
              >
                Previous
              </button>
              <span className="page-info">
                Page {currentPage} of {totalPages}
              </span>
              <button
                className="page-button"
                onClick={handleNext}
                disabled={currentPage === totalPages}
              >
                Next
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default FileScanner;