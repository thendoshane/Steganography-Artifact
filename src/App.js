import React, { useState } from 'react';
import './App.css';
import john from './Images/lucas.jpg';

// Import all four components
import FileScanner from './Yara/FileScanner';
import YaraScanner from './Yara/YaraScanner';
import MLScanner from './Yara/MLScanner';
import StegoCreator from './Yara/StegoCreator';

function App() {
  // Default to the creator tab for a clear workflow
  const [activeTab, setActiveTab] = useState('creator');

  const renderContent = () => {
    switch (activeTab) {
      case 'creator':
        return <StegoCreator />;
      case 'virustotal':
        return <FileScanner />;
      case 'yara':
        return <YaraScanner />;
      case 'ml':
        return <MLScanner />;
      default:
        return <StegoCreator />;
    }
  };

  return (
    <div className="app-container" style={{ backgroundImage: `url(${john})` }}>
      <header className="app-header">
        <h1>AI-Generated Steganography Detection System</h1>
        <p>A multi-layered approach to identifying concealed threats.</p>
      </header>

      <div className="tab-container">
        <button
          className={`tab-button ${activeTab === 'creator' ? 'active' : ''}`}
          onClick={() => setActiveTab('creator')}
        >
          Stego Image Creator
        </button>
        <button
          className={`tab-button ${activeTab === 'virustotal' ? 'active' : ''}`}
          onClick={() => setActiveTab('virustotal')}
        >
          VirusTotal Scanner
        </button>
        <button
          className={`tab-button ${activeTab === 'yara' ? 'active' : ''}`}
          onClick={() => setActiveTab('yara')}
        >
          YARA Rule Scanner
        </button>
        <button
          className={`tab-button ${activeTab === 'ml' ? 'active' : ''}`}
          onClick={() => setActiveTab('ml')}
        >
          ML Anomaly Detection
        </button>
      </div>

      <main className="content-area">
        {renderContent()}
      </main>
    </div>
  );
}

export default App;