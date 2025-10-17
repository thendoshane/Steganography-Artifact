import React, { useState } from 'react';
import axios from 'axios';
import './MLScanner.css'; // We'll create this file next

function MLScanner() {
  const [selectedFile, setSelectedFile] = useState(null);
  const [scanResult, setScanResult] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');

  const handleFileChange = (event) => {
    const file = event.target.files[0];
    if (file) {
      setSelectedFile(file);
      setScanResult(null);
      setError('');
    }
  };

  const handleScan = async () => {
    if (!selectedFile) {
      setError('Please select an image file to analyze.');
      return;
    }

    setIsLoading(true);
    setError('');
    setScanResult(null);

    const formData = new FormData();
    formData.append('file', selectedFile);

    try {
      const response = await axios.post('http://localhost:3001/ml-scan', formData);
      setScanResult(response.data);
    } catch (err) {
      const serverError = err.response?.data?.details || 'An error occurred during analysis.';
      setError(serverError);
      console.error('ML Scan Error:', err);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="scanner-container ml-scanner">
      <div className="scanner-card">
        <h2>ML Anomaly Scanner</h2>
        <p>Upload an image to perform a statistical analysis and detect anomalies that may indicate steganography.</p>

        <div className="upload-area">
          <label htmlFor="ml-file-upload" className="upload-label">
            Choose Image
          </label>
          <input id="ml-file-upload" type="file" onChange={handleFileChange} accept="image/*" />
          {selectedFile && <span className="file-name">{selectedFile.name}</span>}
        </div>

        <button onClick={handleScan} className="scan-btn" disabled={isLoading}>
          {isLoading ? 'Analyzing...' : 'Analyze Image Features'}
        </button>

        <div className="status-message">
          {isLoading && <div className="loader"></div>}
          {error && <p className="error-message">{error}</p>}
        </div>

        {scanResult && (
          <div className="results-container">
            <h3>Analysis Results</h3>
            <div className={`anomaly-status ${scanResult.isAnomaly ? 'anomaly-found' : 'no-anomaly'}`}>
              <strong>Status:</strong> {scanResult.isAnomaly ? 'Anomaly Detected' : 'No Anomaly Detected'}
            </div>
            <p className="anomaly-reason"><strong>Reasoning:</strong> {scanResult.anomalyReason}</p>
            <div className="features-grid">
              <h4>Extracted Features:</h4>
              <div className="feature-item">
                <span className="feature-label">Image Entropy</span>
                <span className="feature-value">{scanResult.features.entropy}</span>
              </div>
              <div className="feature-item">
                <span className="feature-label">Image Dimensions</span>
                <span className="feature-value">{scanResult.features.width} x {scanResult.features.height} px</span>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default MLScanner;

