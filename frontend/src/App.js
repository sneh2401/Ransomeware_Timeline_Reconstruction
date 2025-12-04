import React, { useState } from "react";
import axios from "axios";
import "./App.css";
import ForensicDashboard from "./ForensicDashboard";

function App() {
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [files, setFiles] = useState([]);
  const [showDashboard, setShowDashboard] = useState(false);

  const handleFileChange = (e) => {
    setFiles(Array.from(e.target.files));
    setError(null);
    setShowDashboard(false);
    setResult(null);
  };

  const handleAnalyze = async () => {
    if (!files.length) {
      setError("Please upload at least one log file.");
      return;
    }
    setError(null);
    setResult(null);
    setLoading(true);
    setShowDashboard(false);
    
    try {
      const formData = new FormData();
      files.forEach((file) => formData.append("logfiles", file));
      const response = await axios.post("http://127.0.0.1:5000/analyze", formData, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      setResult(response.data);
      setShowDashboard(true);
    } catch (err) {
      setError(err.response?.data?.message || "Failed to connect to backend");
    } finally {
      setLoading(false);
    }
  };

  const handleReset = () => {
    setFiles([]);
    setResult(null);
    setError(null);
    setShowDashboard(false);
  };

  return (
    <div className="app-container">
      {!showDashboard ? (
        <>
          <h1>🕵️‍♂️ Forensic Log Analyzer</h1>
          <div className="upload-container">
            <input type="file" multiple onChange={handleFileChange} accept=".log,.txt" />
          </div>

          {files.length > 0 && (
            <div className="files-table-wrap">
              <h3>Uploaded Files ({files.length})</h3>
              <table className="files-table">
                <thead>
                  <tr>
                    <th>#</th>
                    <th>Filename</th>
                    <th>Size (bytes)</th>
                    <th>Type</th>
                  </tr>
                </thead>
                <tbody>
                  {files.map((file, idx) => (
                    <tr key={idx}>
                      <td>{idx + 1}</td>
                      <td>{file.name}</td>
                      <td>{file.size.toLocaleString()}</td>
                      <td>{file.type || "log"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          <div className="button-container">
            <button onClick={handleAnalyze} disabled={loading}>
              {loading ? <div className="spinner"></div> : "Run Analysis"}
            </button>
            {files.length > 0 && (
              <button onClick={handleReset} className="reset-btn">
                Clear Files
              </button>
            )}
          </div>

          {error && <div className="error">{error}</div>}

          {loading && (
            <div className="loading-message">
              <p>🔍 Analyzing log files...</p>
              <p className="sub-text">This may take a few moments</p>
            </div>
          )}
        </>
      ) : (
        <>
          <div className="dashboard-header">
            <button onClick={handleReset} className="back-btn">
              ← Back to Upload
            </button>
            <button 
              onClick={() => {
                const dataStr = JSON.stringify(result, null, 2);
                const dataBlob = new Blob([dataStr], { type: 'application/json' });
                const url = URL.createObjectURL(dataBlob);
                const link = document.createElement('a');
                link.href = url;
                link.download = 'forensic-analysis-results.json';
                link.click();
              }}
              className="download-btn"
            >
              Download JSON
            </button>
          </div>
          <ForensicDashboard data={result} />
        </>
      )}
    </div>
  );
}

export default App;