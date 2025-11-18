import React, { useState } from 'react';
import axios from 'axios';
import './FileScanner.css';

function FileScanner() {
  const [selectedFile, setSelectedFile] = useState(null);
  const [scanResult, setScanResult] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [statusMessage, setStatusMessage] = useState(''); // New status text
  const [error, setError] = useState('');
  const [currentPage, setCurrentPage] = useState(1);
  const resultsPerPage = 10;

  const handleFileChange = (event) => {
    const file = event.target.files && event.target.files[0];
    if (file) {
      setSelectedFile(file);
      setScanResult(null);
      setError('');
      setStatusMessage('');
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
    setStatusMessage('Uploading file and awaiting VirusTotal analysis...');

    try {
      const formData = new FormData();
      formData.append('file', selectedFile);

      // Frontend now waits for the backend to complete the full scan
      const response = await axios.post('/api/scan', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
        timeout: 70 * 1000, // Frontend timeout should be longer than backend polling (70 seconds)
      });

      // Backend now sends the raw analysis results directly
      const analysisResults = response.data;
      
      processResults(analysisResults);
      setStatusMessage('Scan completed!');

    } catch (err) {
      console.error('Scan error:', err);
      // Backend error will now contain more specific details
      setError(`Scan Error: ${err.response?.data?.details || err.response?.data?.error || err.message}`);
      setStatusMessage('');
    } finally {
      setIsLoading(false);
    }
  };

  const processResults = (analysisResults) => {
      let maliciousCount = 0;
      let harmlessCount = 0;
      let undetectedCount = 0;

      // Ensure analysisResults is an object before iterating
      if (typeof analysisResults !== 'object' || analysisResults === null) {
          console.error("Invalid analysisResults received:", analysisResults);
          setError("Failed to process scan results: Invalid data format.");
          return;
      }

      Object.values(analysisResults).forEach((engine) => {
        if (!engine) { // Some engines might be null/undefined if not run
            undetectedCount++;
            return;
        }
        if (engine.category === 'malicious') maliciousCount++;
        else if (engine.category === 'harmless') harmlessCount++;
        else undetectedCount++;
      });

      setScanResult({
        summary: { malicious: maliciousCount, harmless: harmlessCount, undetected: undetectedCount },
        details: analysisResults,
      });
      setCurrentPage(1);
  }

  // --- PAGINATION LOGIC (Remains the same) ---
  const totalPages = scanResult
    ? Math.max(1, Math.ceil(Object.keys(scanResult.details || {}).length / resultsPerPage))
    : 1;

  const paginatedResults = scanResult
    ? Object.entries(scanResult.details).slice(
        (currentPage - 1) * resultsPerPage,
        currentPage * resultsPerPage
      )
    : [];

  const handleNext = () => { if (currentPage < totalPages) setCurrentPage((p) => p + 1); };
  const handlePrev = () => { if (currentPage > 1) setCurrentPage((p) => p - 1); };

  return (
    <div className="scanner-container">
      <h2 className="scanner-title">VirusTotal Scanner</h2>
      <p>Upload a file to check it against antivirus engines.</p>

      <div className="upload-area">
        <label htmlFor="file-upload" className="upload-label">Choose File</label>
        <input id="file-upload" type="file" onChange={handleFileChange} accept="*/*" />
        {selectedFile && <span className="file-name">{selectedFile.name}</span>}
      </div>

      <button onClick={handleScan} className="scan-button" disabled={isLoading}>
        {isLoading ? 'Scanning...' : 'Scan File'}
      </button>

      <div className="status-message">
        {error && <p className="error-message">{error}</p>}
        {isLoading && (
            <div className="loading-box">
                <div className="spinner"></div>
                <p>{statusMessage}</p>
            </div>
        )}
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
              <button className="page-button" onClick={handlePrev} disabled={currentPage === 1}>Previous</button>
              <span className="page-info">Page {currentPage} of {totalPages}</span>
              <button className="page-button" onClick={handleNext} disabled={currentPage === totalPages}>Next</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default FileScanner;