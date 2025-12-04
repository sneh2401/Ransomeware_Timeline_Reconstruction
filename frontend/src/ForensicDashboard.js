import React, { useState, useMemo } from 'react';
import { Activity, Shield, AlertTriangle, Clock, FileText, Target, TrendingUp } from 'lucide-react';
import './ForensicDashboard.css';

const ForensicDashboard = ({ data }) => {
  const [selectedLog, setSelectedLog] = useState('all');
  const [selectedSeverity, setSelectedSeverity] = useState('all');
  const [expandedEvent, setExpandedEvent] = useState(null);

  const severityColors = {
    CRITICAL: 'critical',
    HIGH: 'high',
    MEDIUM: 'medium',
    LOW: 'low'
  };

  // Process the data from API
  const processedData = useMemo(() => {
    if (!data || !data.results) return null;

    const results = data.results.map(result => ({
      ...result,
      displayName: result.file.split('_').slice(1).join('_').replace('.log', '') || result.file
    }));

    return { ...data, results };
  }, [data]);

  // Get all anomalies sorted by timestamp
  const getAllAnomalies = () => {
    if (!processedData || !processedData.results) return [];
    
    let allAnomalies = [];
    processedData.results.forEach(result => {
      if (result.data && result.data.anomalies) {
        result.data.anomalies.forEach(anomaly => {
          allAnomalies.push({
            ...anomaly,
            source: result.displayName
          });
        });
      }
    });
    return allAnomalies.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
  };

  const filteredAnomalies = useMemo(() => {
    return getAllAnomalies().filter(anomaly => {
      const logMatch = selectedLog === 'all' || anomaly.source.toLowerCase().includes(selectedLog.toLowerCase());
      const severityMatch = selectedSeverity === 'all' || anomaly.severity === selectedSeverity;
      return logMatch && severityMatch;
    });
  }, [selectedLog, selectedSeverity, processedData]);

  // Calculate summary statistics
  const stats = useMemo(() => {
    if (!processedData || !processedData.results) return null;

    return {
      totalAnomalies: processedData.results.reduce((sum, r) => sum + (r.data.summary?.anomalies_detected || 0), 0),
      totalCritical: processedData.results.reduce((sum, r) => sum + (r.data.summary?.critical_anomalies || 0), 0),
      totalEvents: processedData.results.reduce((sum, r) => sum + (r.data.summary?.total_events || 0), 0),
      duration: processedData.results[0]?.data.attribution?.timeline_duration || 'N/A'
    };
  }, [processedData]);

  if (!processedData || !stats) {
    return <div className="error">No data available</div>;
  }

  const formatTimestamp = (timestamp) => {
    const date = new Date(timestamp);
    return date.toLocaleString('en-US', { 
      month: 'short', 
      day: 'numeric', 
      year: 'numeric',
      hour: '2-digit', 
      minute: '2-digit',
      second: '2-digit'
    });
  };

  const formatTechniqueName = (technique) => {
    return technique
      .split('_')
      .map(word => word.charAt(0).toUpperCase() + word.slice(1))
      .join(' ');
  };

  return (
    <div className="forensic-dashboard">
      <div className="dashboard-container">
        {/* Header */}
        <div className="dashboard-header-section">
          <div className="header-title">
            <Shield className="header-icon" />
            <div>
              <h1>Forensic Timeline Reconstruction</h1>
              <p className="header-subtitle">Security Incident Analysis Dashboard</p>
            </div>
          </div>
        </div>

        {/* Summary Cards */}
        <div className="stats-grid">
          <div className="stat-card">
            <div className="stat-content">
              <div>
                <p className="stat-label">Total Events</p>
                <p className="stat-value stat-value-blue">{stats.totalEvents}</p>
              </div>
              <Activity className="stat-icon stat-icon-blue" />
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-content">
              <div>
                <p className="stat-label">Anomalies Detected</p>
                <p className="stat-value stat-value-orange">{stats.totalAnomalies}</p>
              </div>
              <AlertTriangle className="stat-icon stat-icon-orange" />
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-content">
              <div>
                <p className="stat-label">Critical Events</p>
                <p className="stat-value stat-value-red">{stats.totalCritical}</p>
              </div>
              <Target className="stat-icon stat-icon-red" />
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-content">
              <div>
                <p className="stat-label">Timeline Duration</p>
                <p className="stat-value stat-value-purple">{stats.duration.split(',')[0]}</p>
              </div>
              <Clock className="stat-icon stat-icon-purple" />
            </div>
          </div>
        </div>

        {/* Attribution Section - List Format */}
        <div className="card attribution-card">
          <h2 className="card-title">
            <TrendingUp className="title-icon" />
            Threat Attribution Analysis
          </h2>
          <div className="attribution-grid">
            {processedData.results.map((result, idx) => (
              <div key={idx} className="attribution-item">
                <h3 className="attribution-source">{result.displayName}</h3>
                
                <div className="attribution-details">
                  {/* Attribution */}
                  <div className="attribution-row">
                    <span className="attribution-label">Attribution</span>
                    <span className="attribution-threat">
                      {result.data.attribution?.possible_attribution?.join(', ') || 'Unknown'}
                    </span>
                  </div>

                  {/* Sophistication Level */}
                  <div className="attribution-row">
                    <span className="attribution-label">Sophistication</span>
                    <span className="attribution-sophistication">
                      {result.data.attribution?.sophistication_level || 'N/A'}
                    </span>
                  </div>

                  {/* Timeline Duration */}
                  <div className="attribution-row">
                    <span className="attribution-label">Timeline Duration</span>
                    <span className="attribution-value">
                      {result.data.attribution?.timeline_duration || 'N/A'}
                    </span>
                  </div>

                  {/* Total Events */}
                  <div className="attribution-row">
                    <span className="attribution-label">Total Events</span>
                    <span className="attribution-value">
                      {result.data.summary?.total_events || 0}
                    </span>
                  </div>

                  {/* Anomalies Detected */}
                  <div className="attribution-row">
                    <span className="attribution-label">Anomalies Detected</span>
                    <span className="attribution-value">
                      {result.data.summary?.anomalies_detected || 0} 
                      <span className="anomaly-breakdown">
                        {' '}(Critical: {result.data.summary?.critical_anomalies || 0})
                      </span>
                    </span>
                  </div>

                  {/* MITRE ATT&CK Techniques - SINGLE SECTION */}
                  {result.data.attribution?.techniques_used && result.data.attribution.techniques_used.length > 0 && (
                    <div className="attribution-row full-width">
                      <span className="attribution-label">MITRE ATT&CK Techniques</span>
                      <div className="techniques-list">
                        {result.data.attribution.techniques_used.map((technique, i) => (
                          <span key={i} className="technique-badge technique-badge-mitre">
                            {formatTechniqueName(technique)}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Filters */}
        <div className="card filters-card">
          <div className="filters-container">
            <div className="filter-group">
              <label className="filter-label">Filter by Log Source</label>
              <select 
                className="filter-select"
                value={selectedLog}
                onChange={(e) => setSelectedLog(e.target.value)}
              >
                <option value="all">All Sources</option>
                {processedData.results.map((result, idx) => (
                  <option key={idx} value={result.displayName}>{result.displayName}</option>
                ))}
              </select>
            </div>
            <div className="filter-group">
              <label className="filter-label">Filter by Severity</label>
              <select 
                className="filter-select"
                value={selectedSeverity}
                onChange={(e) => setSelectedSeverity(e.target.value)}
              >
                <option value="all">All Severities</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>
            </div>
          </div>
        </div>

        {/* Timeline Events */}
        <div className="card timeline-card">
          <h2 className="card-title">
            <FileText className="title-icon" />
            Timeline Events ({filteredAnomalies.length})
          </h2>
          
          <div className="timeline-events">
            {filteredAnomalies.length === 0 ? (
              <p className="no-events">No events match the selected filters</p>
            ) : (
              filteredAnomalies.map((anomaly, idx) => (
                <div 
                  key={idx} 
                  className={`event-item ${severityColors[anomaly.severity]} ${expandedEvent === idx ? 'expanded' : ''}`}
                  onClick={() => setExpandedEvent(expandedEvent === idx ? null : idx)}
                >
                  <div className="event-content">
                    <div className="event-main">
                      <div className="event-badges">
                        <span className={`severity-badge ${severityColors[anomaly.severity]}`}>
                          {anomaly.severity}
                        </span>
                        <span className="type-badge">{anomaly.type}</span>
                        <span className="source-badge">{anomaly.source}</span>
                      </div>
                      <p className="event-details">{anomaly.details}</p>
                      <p className="event-timestamp">
                        <Clock className="clock-icon" />
                        {formatTimestamp(anomaly.timestamp)}
                      </p>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default ForensicDashboard;
