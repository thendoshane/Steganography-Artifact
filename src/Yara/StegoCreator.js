import React, { useState, useRef } from 'react';
import './StegoCreator.css';

// Helper function to load an image and return a promise
const loadImage = (src) => {
  return new Promise((resolve, reject) => {
    const img = new Image();
    img.crossOrigin = "anonymous"; // Handle potential CORS issues with images
    img.onload = () => resolve(img);
    img.onerror = (err) => reject(err);
    img.src = src;
  });
};

function StegoCreator() {
  const [coverImage, setCoverImage] = useState(null);
  const [payloadText, setPayloadText] = useState('');
  const [stegoImage, setStegoImage] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const canvasRef = useRef(null);

  const harmlessPayload = 'MsgBox "Oops! This is a test payload from a research project.", 48, "Benign Test"';

  const handleImageChange = (event) => {
    const file = event.target.files[0];
    if (file && file.type.startsWith('image/')) {
      const reader = new FileReader();
      reader.onload = (e) => {
        setCoverImage(e.target.result);
        setStegoImage(null);
        setError('');
      };
      reader.readAsDataURL(file);
    } else {
      setError('Please select a valid image file (e.g., PNG, JPG).');
      setCoverImage(null);
    }
  };

  const handleTextChange = (event) => {
    setPayloadText(event.target.value);
  };

  // --- NEW FUNCTION ---
  // Generates a string of random characters to simulate high-entropy data
  const generateHighEntropyPayload = async () => {
    if (!coverImage) {
        setError("Please upload an image first to determine payload capacity.");
        return;
    }
    try {
        const img = await loadImage(coverImage);
        // Calculate 25% of the image's maximum LSB capacity in bytes
        const maxCapacity = Math.floor((img.width * img.height * 3) / 8);
        const payloadSize = Math.floor(maxCapacity * 0.25);
        if (payloadSize === 0) {
            setError("Image is too small to generate a meaningful payload.");
            return;
        }
        let randomPayload = '';
        const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()';
        for (let i = 0; i < payloadSize; i++) {
            randomPayload += characters.charAt(Math.floor(Math.random() * characters.length));
        }
        setPayloadText(randomPayload);
        setError(''); // Clear previous errors
    } catch (e) {
        setError("Could not process the image to determine capacity.");
    }
  };
  // --- END OF NEW FUNCTION ---

  const embedPayload = async () => {
    if (!coverImage || !payloadText) {
      setError('Please provide a cover image and a text payload.');
      return;
    }

    setIsLoading(true);
    setError('');
    setStegoImage(null);

    try {
      const canvas = canvasRef.current;
      const ctx = canvas.getContext('2d');
      const img = await loadImage(coverImage);

      canvas.width = img.width;
      canvas.height = img.height;
      ctx.drawImage(img, 0, 0);

      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const data = imageData.data;

      const payloadBytes = [...payloadText].map(char => char.charCodeAt(0));
      payloadBytes.push(0);

      if ((payloadBytes.length * 8) > (data.length * 0.75)) {
        setError('Payload is too large for this image.');
        setIsLoading(false);
        return;
      }

      let dataIndex = 0;
      for (let i = 0; i < payloadBytes.length; i++) {
        const byte = payloadBytes[i];
        for (let j = 0; j < 8; j++) {
          while ((dataIndex + 1) % 4 === 0) {
            dataIndex++;
          }
          if (dataIndex >= data.length) {
            throw new Error("Image capacity exceeded unexpectedly.");
          }
          const bit = (byte >> j) & 1;
          data[dataIndex] = (data[dataIndex] & 0xFE) | bit;
          dataIndex++;
        }
      }

      ctx.putImageData(imageData, 0, 0);
      setStegoImage(canvas.toDataURL('image/png'));
    } catch (e) {
      setError('An error occurred during embedding. The image might be invalid.');
      console.error("Embedding Error:", e);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="scanner-container stego-creator">
      <div className="scanner-card">
        <h2>Stego Image Creator (LSB)</h2>
        <p>Embed a text payload into an image to create test samples for your detection system.</p>
        <div className="creator-grid">
          <div className="input-group">
            <label>1. Upload Cover Image</label>
            <input type="file" onChange={handleImageChange} accept="image/*" className="file-input" />
            {coverImage && <img src={coverImage} alt="Cover Preview" className="image-preview" />}
          </div>
          <div className="input-group">
            <label>2. Provide Text Payload</label>
            <textarea
              value={payloadText}
              onChange={handleTextChange}
              placeholder="Paste your payload here, or generate one."
              rows="6"
            ></textarea>
            <div className="button-group">
              <button onClick={() => setPayloadText(harmlessPayload)} className="load-sample-btn">Load Harmless Sample</button>
              {/* This is the new button */}
              <button onClick={generateHighEntropyPayload} className="load-sample-btn high-entropy">Generate High-Entropy Payload</button>
            </div>
          </div>
        </div>
        <button onClick={embedPayload} className="scan-btn" disabled={isLoading || !coverImage || !payloadText}>
          {isLoading ? 'Embedding...' : 'Create Stego Image'}
        </button>
        {isLoading && <div className="loader"></div>}
        {error && <p className="error-message">{error}</p>}
        {stegoImage && (
          <div className="results-container">
            <h3>Stego Image Ready</h3>
            <p>The payload has been embedded. You can now save the image and test it in the scanners.</p>
            <img src={stegoImage} alt="Stego Result" className="image-preview" />
            <a href={stegoImage} download="stego_image.png" className="download-btn">Download Stego Image</a>
          </div>
        )}
        <canvas ref={canvasRef} style={{ display: 'none' }}></canvas>
      </div>
    </div>
  );
}

export default StegoCreator;

