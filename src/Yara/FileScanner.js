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

  const backendURL = process.env.REACT_APP_BACKEND_URL || window.location.origin;

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

      // Do NOT manually set Content-Type for multipart/form-data — browser will set it including boundary
      const response = await axios.post(`${backendURL.replace(/\/$/, '')}/scan`, formData, {
        timeout: 5 * 60 * 1000, // 5 minutes in case VT takes long
      });

      // response.data expected to be object of vendors -> { category, result }
      const vtData = response.data || {};
      let maliciousCount = 0;
      let harmlessCount = 0;
      let undetectedCount = 0;

      Object.values(vtData).forEach((engine) => {
        if (!engine) {
          undetectedCount++;
          return;
        }
        if (engine.category === 'malicious') maliciousCount++;
        else if (engine.category === 'harmless') harmlessCount++;
        else undetectedCount++;
      });

      setScanResult({
        summary: { malicious: maliciousCount, harmless: harmlessCount, undetected: undetectedCount },
        details: vtData,
      });
      setCurrentPage(1);
    } catch (err) {
      console.error('Scan error:', err);
      const serverMsg = err.response?.data?.details || err.message || 'Scan failed';
      setError(`Scan error: ${serverMsg}`);
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
        {isLoading && <p>Scan in progress, this may take a minute...</p>}
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
