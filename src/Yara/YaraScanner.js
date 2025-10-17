import React, { useState } from 'react';
import axios from 'axios';
import './YaraScanner.css';

function YaraScanner() {
  const [selectedFile, setSelectedFile] = useState(null);
  const [yaraRule, setYaraRule] = useState('');
  const [scanResult, setScanResult] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');

  const handleFileChange = (event) => {
    const file = event.target.files && event.target.files[0];
    setSelectedFile(file || null);
    setScanResult(null);
    setError('');
  };

  const handleRuleChange = (event) => {
    setYaraRule(event.target.value);
  };

  const handleScan = async () => {
    setError('');
    if (!selectedFile) {
      setError('Please select a file to scan.');
      return;
    }
    if (!yaraRule.trim()) {
      setError('Please provide a YARA rule.');
      return;
    }

    setIsLoading(true);
    setScanResult(null);

    try {
      const formData = new FormData();
      // ensure field name matches backend (commonly 'file')
      formData.append('file', selectedFile, selectedFile.name);
      formData.append('yaraRule', yaraRule);

      // Debugging: log formData entries (files show as File objects)
      for (const pair of formData.entries()) {
        console.log('FormData:', pair[0], pair[1]);
      }

      // IMPORTANT: do NOT set 'Content-Type' manually for multipart/form-data.
      // Let the browser set the boundary automatically.
      const response = await axios.post('http://localhost:3001/yara-scan', formData);

      setScanResult(response.data);
    } catch (err) {
      console.error('YARA scan error:', err);
      const serverData = err.response?.data;
      const serverMsg =
        serverData?.details ||
        serverData?.error ||
        serverData?.message ||
        err.message ||
        'Unknown error from server';
      setError(`Rule Error: ${serverMsg}`);
    } finally {
      setIsLoading(false);
    }
  };

  const placeholderRule = `rule HarmlessPopup
{
    strings:
        $text = "Oops! This is a test payload" ascii wide
    condition:
        $text
}`;

  return (
    <div className="yara-scanner-container">
      <h2>Custom YARA Rule Scanner</h2>
      <p>Upload a file and provide a YARA rule to perform a targeted scan.</p>

      <div className="yara-controls">
        <div className="yara-file-input">
          <label htmlFor="yara-file">Step 1: Upload File</label>
          {/* add name="file" to help servers that use form field names */}
          <input id="yara-file" name="file" type="file" onChange={handleFileChange} />
          {selectedFile && <div className="file-name-small">Selected: {selectedFile.name}</div>}
        </div>

        <div className="yara-rule-editor">
          <label htmlFor="yara-rule">Step 2: Write YARA Rule</label>
          <textarea
            id="yara-rule"
            value={yaraRule}
            onChange={handleRuleChange}
            placeholder={placeholderRule}
            rows="10"
          />
        </div>
      </div>

      <button className="scan-button" onClick={handleScan} disabled={isLoading}>
        {isLoading ? 'Scanning...' : 'Run YARA Scan'}
      </button>

      {isLoading && <div className="loader"></div>}
      {error && <p className="error-message">{error}</p>}

      {scanResult && (
        <div className="yara-results-container">
          <h3>Scan Results</h3>
          {scanResult.rules && scanResult.rules.length > 0 ? (
            <div className="match-found">
              <p><strong>Match Found!</strong> The following rule(s) matched the file:</p>
              <ul>
                {scanResult.rules.map((rule, idx) => (
                  <li key={rule.id ?? idx}>{rule.id ?? JSON.stringify(rule)}</li>
                ))}
              </ul>
            </div>
          ) : (
            <div className="no-match">
              <p><strong>No Match.</strong> The provided YARA rule did not match the file.</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default YaraScanner;
