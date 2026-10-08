import React, { useState, useEffect, useRef } from 'react';
import { Shield, Activity, Upload, Database, Layers, Search, RefreshCw, CheckCircle2, FileCode, AlertOctagon, AlertTriangle, CpuIcon, Clock, Binary, GitFork, Sparkles, HelpCircle, TrendingUp, TrendingDown, Minus } from 'lucide-react';
import { createScan, fetchScans, fetchScanById, analyzeScan, fetchScanReport, triggerDynamicAnalysis, fetchDynamicAnalysis, runDynamicInference, fetchDynamicInference, runEnsembleInference, fetchEnsembleInference, runExplanation, fetchExplanation } from '../../services/api';

export default function DashboardOverview() {
  const [scans, setScans] = useState([]);
  const [totalScans, setTotalScans] = useState(0);
  const [loading, setLoading] = useState(false);
  const [filenameInput, setFilenameInput] = useState('sample_pe_binary.exe');
  const [searchScanId, setSearchScanId] = useState('');
  const [selectedScan, setSelectedScan] = useState(null);
  const [reportResult, setReportResult] = useState(null);
  const [dynamicResult, setDynamicResult] = useState(null);
  const [dynamicInferenceResult, setDynamicInferenceResult] = useState(null);
  const [ensembleResult, setEnsembleResult] = useState(null);
  const [explanationResult, setExplanationResult] = useState(null);
  const [statusMessage, setStatusMessage] = useState(null);
  const [selectedFile, setSelectedFile] = useState(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [dynamicLoading, setDynamicLoading] = useState(false);
  const [inferenceLoading, setInferenceLoading] = useState(false);
  const [ensembleLoading, setEnsembleLoading] = useState(false);
  const [explanationLoading, setExplanationLoading] = useState(false);

  const pollingTimerRef = useRef(null);

  async function loadScans() {
    setLoading(true);
    const data = await fetchScans(1, 10);
    setScans(data.items || []);
    setTotalScans(data.total || 0);
    setLoading(false);
  }

  useEffect(() => {
    loadScans();
    return () => {
      stopPolling();
    };
  }, []);

  function stopPolling() {
    if (pollingTimerRef.current) {
      clearInterval(pollingTimerRef.current);
      pollingTimerRef.current = null;
    }
  }

  function startPolling(scanId) {
    stopPolling();
    pollingTimerRef.current = setInterval(async () => {
      try {
        const doc = await fetchScanById(scanId);
        setSelectedScan(doc);
        loadScans();

        if (doc.status === 'COMPLETED') {
          stopPolling();
          setAnalyzing(false);
          try {
            const rpt = await fetchScanReport(scanId);
            setReportResult(rpt);
            setStatusMessage({ type: 'success', text: `Scan analysis completed! Classification: ${rpt.classification}, Risk: ${rpt.risk_category}` });
          } catch {
            setReportResult(null);
          }
        } else if (doc.status === 'FAILED') {
          stopPolling();
          setAnalyzing(false);
          setReportResult(null);
          setStatusMessage({ type: 'error', text: `Scan analysis failed: ${doc.error || 'Unknown analysis error'}` });
        } else {
          setStatusMessage({ type: 'info', text: `Scan is processing via Celery worker... Current state: ${doc.status}` });
        }
      } catch (err) {
        stopPolling();
        setAnalyzing(false);
        setStatusMessage({ type: 'error', text: `Polling failed: ${err.message}` });
      }
    }, 2500);
  }

  async function handleCreateScan(e) {
    e.preventDefault();
    if (!filenameInput.trim()) return;
    try {
      setStatusMessage({ type: 'info', text: 'Creating scan record...' });
      const created = await createScan({
        filename: filenameInput.trim(),
        file_size: 102400
      });
      setStatusMessage({ type: 'success', text: `Scan created! ID: ${created.scan_id}` });
      loadScans();
      handleLookupScan(created.scan_id);
    } catch (err) {
      setStatusMessage({ type: 'error', text: err.message });
    }
  }

  async function handleLookupScan(idToSearch) {
    stopPolling();
    const id = idToSearch || searchScanId.trim();
    if (!id) return;
    try {
      const doc = await fetchScanById(id);
      setSelectedScan(doc);

      if (doc.status === 'COMPLETED' || doc.status === 'FEATURE_EXTRACTION' || doc.status === 'DYNAMIC_ANALYSIS') {
        try {
          const rpt = await fetchScanReport(doc.scan_id);
          setReportResult(rpt);
        } catch {
          setReportResult(null);
        }
        try {
          const dyn = await fetchDynamicAnalysis(doc.scan_id);
          setDynamicResult(dyn);
        } catch {
          setDynamicResult(null);
        }
        try {
          const inf = await fetchDynamicInference(doc.scan_id);
          setDynamicInferenceResult(inf);
        } catch {
          setDynamicInferenceResult(null);
        }
        try {
          const ens = await fetchEnsembleInference(doc.scan_id);
          setEnsembleResult(ens);
        } catch {
          setEnsembleResult(null);
        }
        try {
          const exp = await fetchExplanation(doc.scan_id);
          setExplanationResult(exp);
        } catch {
          setExplanationResult(null);
        }
      } else if (['QUEUED', 'STATIC_ANALYSIS', 'ML_INFERENCE', 'REPORT_GENERATION'].includes(doc.status)) {
        setReportResult(null);
        setDynamicResult(null);
        setDynamicInferenceResult(null);
        setEnsembleResult(null);
        setExplanationResult(null);
        setAnalyzing(true);
        startPolling(doc.scan_id);
      } else {
        setReportResult(null);
        setDynamicResult(null);
        setDynamicInferenceResult(null);
        setEnsembleResult(null);
        setExplanationResult(null);
      }
    } catch (err) {
      setStatusMessage({ type: 'error', text: err.message });
      setSelectedScan(null);
      setReportResult(null);
      setDynamicResult(null);
      setDynamicInferenceResult(null);
      setEnsembleResult(null);
      setExplanationResult(null);
    }
  }

  async function handleRunDynamicAnalysis() {
    if (!selectedScan) return;
    try {
      setDynamicLoading(true);
      setStatusMessage({ type: 'info', text: 'Enqueuing dynamic sandbox analysis...' });
      await triggerDynamicAnalysis(selectedScan.scan_id);
      setStatusMessage({ type: 'success', text: `Dynamic sandbox job enqueued! Polling status...` });
      startPolling(selectedScan.scan_id);
    } catch (err) {
      setStatusMessage({ type: 'error', text: err.message });
    } finally {
      setDynamicLoading(false);
    }
  }

  async function handleRunDynamicInference() {
    if (!selectedScan) return;
    try {
      setInferenceLoading(true);
      setStatusMessage({ type: 'info', text: 'Executing Dynamic LSTM sequence inference...' });
      const inf = await runDynamicInference(selectedScan.scan_id);
      setDynamicInferenceResult(inf);
      setStatusMessage({ type: 'success', text: `Dynamic LSTM inference complete! P(malware) = ${inf.malware_probability}` });
    } catch (err) {
      setStatusMessage({ type: 'error', text: err.message });
    } finally {
      setInferenceLoading(false);
    }
  }

  async function handleRunEnsembleInference() {
    if (!selectedScan) return;
    try {
      setEnsembleLoading(true);
      setStatusMessage({ type: 'info', text: 'Executing Multimodal Ensemble decision...' });
      const ens = await runEnsembleInference(selectedScan.scan_id);
      setEnsembleResult(ens);
      setStatusMessage({ type: 'success', text: `Multimodal Ensemble decision complete! P(malware) = ${ens.ensemble_probability}` });
    } catch (err) {
      setStatusMessage({ type: 'error', text: err.message });
    } finally {
      setEnsembleLoading(false);
    }
  }

  async function handleRunExplanation() {
    if (!selectedScan) return;
    try {
      setExplanationLoading(true);
      setStatusMessage({ type: 'info', text: 'Generating Explainable AI report & SHAP attributions...' });
      const exp = await runExplanation(selectedScan.scan_id);
      setExplanationResult(exp);
      setStatusMessage({ type: 'success', text: `Explainable AI report generated successfully!` });
    } catch (err) {
      setStatusMessage({ type: 'error', text: err.message });
    } finally {
      setExplanationLoading(false);
    }
  }

  async function handleExecutePipeline(e) {
    e.preventDefault();
    if (!selectedScan || !selectedFile) {
      setStatusMessage({ type: 'error', text: 'Please select a scan record and choose a PE file to analyze.' });
      return;
    }
    try {
      setAnalyzing(true);
      setStatusMessage({ type: 'info', text: 'Enqueuing Celery worker task via Redis broker...' });
      const scanRes = await analyzeScan(selectedScan.scan_id, selectedFile);
      setSelectedScan(scanRes);
      setReportResult(null);
      setStatusMessage({ type: 'info', text: `Task enqueued successfully! Status: ${scanRes.status}. Polling for progress...` });
      startPolling(scanRes.scan_id);
    } catch (err) {
      setAnalyzing(false);
      setStatusMessage({ type: 'error', text: err.message });
    }
  }

  function getRiskBadgeColor(category) {
    switch (category) {
      case 'CRITICAL':
        return 'bg-rose-950/80 border-rose-500/50 text-rose-300';
      case 'HIGH':
        return 'bg-amber-950/80 border-amber-500/50 text-amber-300';
      case 'MEDIUM':
        return 'bg-yellow-950/80 border-yellow-500/50 text-yellow-300';
      case 'LOW':
      default:
        return 'bg-emerald-950/80 border-emerald-500/50 text-emerald-300';
    }
  }

  return (
    <div className="space-y-6">
      {/* Top Hero Banner */}
      <div className="glass-panel p-6 rounded-2xl border border-cyan-500/20 bg-gradient-to-r from-cyan-950/30 via-slate-900/60 to-slate-900/80 relative overflow-hidden">
        <div className="absolute right-0 top-0 translate-x-8 -translate-y-8 w-64 h-64 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none"></div>
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 relative z-10">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <span className="px-2.5 py-0.5 rounded-full text-xs font-mono bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
                PHASE 10 BEHAVIORAL SEQUENCE DATASET + LSTM MODEL
              </span>
              <span className="text-slate-400 text-xs font-mono">• Dynamic Behavioral Sequence Classification</span>
            </div>
            <h1 className="text-2xl md:text-3xl font-bold tracking-tight text-white flex items-center gap-3">
              <Shield className="w-8 h-8 text-cyan-400 stroke-[1.75]" />
              PolyShield AI Malware Detection Platform
            </h1>
            <p className="text-slate-400 text-sm mt-1 max-w-2xl">
              Decoupled static PE analysis, static ML baseline, and PyTorch LSTM dynamic behavioral event sequence classification.
            </p>
          </div>
        </div>
      </div>

      {/* Mandatory Engineering Evaluation Disclosure Banner */}
      <div className="p-4 rounded-xl bg-amber-950/40 border border-amber-500/40 text-amber-200 text-xs font-mono flex items-start gap-3">
        <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
        <div>
          <span className="font-bold text-amber-300">Engineering Evaluation Model Notice:</span>
          <p className="mt-1 text-amber-200/90">
            Both ML models (<code className="text-amber-400">static_baseline_v2.0</code> & <code className="text-amber-400">dynamic_lstm_v1.0</code>) use synthetic engineering fixtures. Metrics represent engineering pipeline smoke evaluation and are not benchmark-ready for real-world malware.
          </p>
        </div>
      </div>

      {/* Creation & Lookup Bar */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Scan Creator Form */}
        <div className="glass-panel p-5 rounded-xl space-y-4 border border-slate-800">
          <h3 className="text-base font-semibold text-white flex items-center gap-2">
            <Upload className="w-4 h-4 text-cyan-400" />
            Create Scan Metadata Record
          </h3>
          <form onSubmit={handleCreateScan} className="flex gap-2">
            <input
              type="text"
              value={filenameInput}
              onChange={(e) => setFilenameInput(e.target.value)}
              placeholder="e.g. suspicious_installer.exe"
              className="flex-1 px-4 py-2 rounded-xl bg-slate-900/80 border border-slate-700 text-sm font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
            />
            <button
              type="submit"
              className="px-4 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-sm transition-all flex items-center gap-2 cursor-pointer whitespace-nowrap"
            >
              Create Scan
            </button>
          </form>
        </div>

        {/* Scan Lookup */}
        <div className="glass-panel p-5 rounded-xl space-y-4 border border-slate-800">
          <h3 className="text-base font-semibold text-white flex items-center gap-2">
            <Search className="w-4 h-4 text-cyan-400" />
            Lookup Scan by UUID
          </h3>
          <div className="flex gap-2">
            <input
              type="text"
              value={searchScanId}
              onChange={(e) => setSearchScanId(e.target.value)}
              placeholder="Enter scan_id UUID..."
              className="flex-1 px-4 py-2 rounded-xl bg-slate-900/80 border border-slate-700 text-sm font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
            />
            <button
              onClick={() => handleLookupScan()}
              className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-cyan-400 border border-slate-700 text-sm font-semibold transition-all flex items-center gap-2 cursor-pointer"
            >
              Lookup
            </button>
          </div>
        </div>
      </div>

      {statusMessage && (
        <div className={`p-4 rounded-xl border text-sm font-mono ${
          statusMessage.type === 'error' ? 'bg-rose-950/40 border-rose-500/40 text-rose-300' :
          statusMessage.type === 'success' ? 'bg-emerald-950/40 border-emerald-500/40 text-emerald-300' :
          'bg-cyan-950/40 border-cyan-500/40 text-cyan-300'
        }`}>
          {statusMessage.text}
        </div>
      )}

      {/* Selected Scan Inspector & Execution Box */}
      {selectedScan && (
        <div className="glass-panel p-5 rounded-xl space-y-4 border border-cyan-500/30">
          <div className="flex justify-between items-center border-b border-slate-800 pb-3">
            <div>
              <span className="text-xs font-mono text-slate-400">ACTIVE SCAN INSPECTOR</span>
              <h3 className="text-lg font-bold text-white font-mono">{selectedScan.scan_id}</h3>
            </div>
            <div className="flex items-center gap-2">
              {analyzing && <RefreshCw className="w-4 h-4 text-cyan-400 animate-spin" />}
              <span className={`px-3 py-1 rounded-full text-xs font-mono border ${
                selectedScan.status === 'COMPLETED' ? 'bg-emerald-950/80 border-emerald-500/50 text-emerald-300' :
                selectedScan.status === 'FAILED' ? 'bg-rose-950/80 border-rose-500/50 text-rose-300' :
                'bg-cyan-950/80 border-cyan-500/50 text-cyan-300'
              }`}>
                STATUS: {selectedScan.status}
              </span>
            </div>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs font-mono">
            <div className="bg-slate-900/60 p-3 rounded-lg border border-slate-800">
              <span className="text-slate-400">Filename:</span>
              <div className="text-slate-200 font-semibold truncate mt-1">{selectedScan.filename}</div>
            </div>
            <div className="bg-slate-900/60 p-3 rounded-lg border border-slate-800">
              <span className="text-slate-400">File Size:</span>
              <div className="text-slate-200 font-semibold mt-1">{selectedScan.file_size || 0} bytes</div>
            </div>
            <div className="bg-slate-900/60 p-3 rounded-lg border border-slate-800">
              <span className="text-slate-400">Created:</span>
              <div className="text-slate-200 font-semibold mt-1">{new Date(selectedScan.created_at).toLocaleTimeString()}</div>
            </div>
            <div className="bg-slate-900/60 p-3 rounded-lg border border-slate-800">
              <span className="text-slate-400">Model Version:</span>
              <div className="text-cyan-400 font-semibold truncate mt-1">{selectedScan.model_version || 'static_baseline_v2.0'}</div>
            </div>
          </div>

          {/* End-to-End Pipeline Action */}
          <div className="p-4 rounded-xl bg-slate-900/80 border border-cyan-500/20 space-y-3">
            <h4 className="text-sm font-semibold text-white flex items-center gap-2">
              <FileCode className="w-4 h-4 text-cyan-400" />
              Enqueue Asynchronous Scan Pipeline (`POST /api/v1/scans/{'{scan_id}'}/analyze`)
            </h4>
            <form onSubmit={handleExecutePipeline} className="flex flex-col sm:flex-row gap-3">
              <input
                type="file"
                accept=".exe,.dll,.sys"
                onChange={(e) => setSelectedFile(e.target.files[0])}
                className="text-xs font-mono text-slate-300 file:mr-4 file:py-2 file:px-4 file:rounded-xl file:border-0 file:text-xs file:font-semibold file:bg-cyan-500/20 file:text-cyan-400 hover:file:bg-cyan-500/30 cursor-pointer"
              />
              <button
                type="submit"
                disabled={analyzing}
                className="px-4 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-slate-950 font-semibold text-xs transition-all flex items-center gap-2 cursor-pointer whitespace-nowrap"
              >
                {analyzing ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    Processing Async Task...
                  </>
                ) : 'Enqueue Celery Analysis Task'}
              </button>
            </form>
          </div>

          {/* Static ML & Analysis Report Display */}
          {reportResult && (
            <div className="space-y-6 border-t border-slate-800 pt-5">
              <div className="flex justify-between items-center">
                <h4 className="text-base font-bold text-white flex items-center gap-2">
                  <CpuIcon className="w-5 h-5 text-cyan-400" />
                  Static ML Inference & Risk Assessment Report
                </h4>
                <span className={`px-3 py-1 rounded-full text-xs font-mono border ${getRiskBadgeColor(reportResult.risk_category)}`}>
                  RISK: {reportResult.risk_category} ({reportResult.risk_score}/100)
                </span>
              </div>

              {/* Inference Metrics Grid */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4 text-xs font-mono">
                <div className="bg-slate-900/80 p-4 rounded-xl border border-slate-800">
                  <span className="text-slate-400">Classification</span>
                  <div className={`text-lg font-bold mt-1 ${reportResult.classification === 'MALICIOUS' ? 'text-rose-400' : 'text-emerald-400'}`}>
                    {reportResult.classification}
                  </div>
                </div>

                <div className="bg-slate-900/80 p-4 rounded-xl border border-slate-800">
                  <span className="text-slate-400">P(Malware) Probability</span>
                  <div className="text-lg font-bold text-amber-400 mt-1">
                    {(reportResult.malware_score * 100).toFixed(1)}%
                  </div>
                </div>

                <div className="bg-slate-900/80 p-4 rounded-xl border border-slate-800">
                  <span className="text-slate-400">P(Benign) Probability</span>
                  <div className="text-lg font-bold text-emerald-400 mt-1">
                    {(reportResult.benign_score * 100).toFixed(1)}%
                  </div>
                </div>

                <div className="bg-slate-900/80 p-4 rounded-xl border border-slate-800">
                  <span className="text-slate-400">Decision Threshold</span>
                  <div className="text-lg font-bold text-slate-200 mt-1">
                    {reportResult.threshold}
                  </div>
                </div>
              </div>
            </div>
          )}

                              {/* Dynamic Sandbox Telemetry & Dynamic ML Model Section */}
          <div className="mt-6 pt-6 border-t border-slate-800 space-y-6">
            <div className="flex justify-between items-center">
              <h4 className="text-sm font-bold text-white font-mono flex items-center gap-2">
                <Activity className="w-4 h-4 text-amber-400" />
                Dynamic Sandbox Telemetry (Phase 9)
              </h4>
              <button
                onClick={handleRunDynamicAnalysis}
                disabled={dynamicLoading}
                className="px-3 py-1.5 rounded-lg bg-amber-500/20 text-amber-300 hover:bg-amber-500/30 border border-amber-500/30 text-xs font-mono transition-all cursor-pointer flex items-center gap-1.5"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${dynamicLoading ? 'animate-spin' : ''}`} />
                Run Dynamic Sandbox Analysis
              </button>
            </div>

            {dynamicResult ? (
              <div className="space-y-4">
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs font-mono">
                  <div className="bg-slate-900/80 p-3 rounded-lg border border-slate-800">
                    <span className="text-slate-500">Provider</span>
                    <div className="text-amber-400 font-bold mt-0.5">{dynamicResult.dynamic_result?.provider || 'mock'}</div>
                  </div>
                  <div className="bg-slate-900/80 p-3 rounded-lg border border-slate-800">
                    <span className="text-slate-500">Schema</span>
                    <div className="text-cyan-400 font-bold mt-0.5">dynamic-v1</div>
                  </div>
                  <div className="bg-slate-900/80 p-3 rounded-lg border border-slate-800">
                    <span className="text-slate-500">Process Events</span>
                    <div className="text-slate-200 font-bold mt-0.5">{dynamicResult.dynamic_result?.process_events?.length || 0}</div>
                  </div>
                  <div className="bg-slate-900/80 p-3 rounded-lg border border-slate-800">
                    <span className="text-slate-500">Network Events</span>
                    <div className="text-slate-200 font-bold mt-0.5">{dynamicResult.dynamic_result?.network_events?.length || 0}</div>
                  </div>
                </div>

                <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800 text-xs font-mono space-y-1 text-slate-300">
                  <div>Filesystem Events: <span className="text-cyan-400">{dynamicResult.dynamic_result?.filesystem_events?.length || 0}</span> | Registry Events: <span className="text-cyan-400">{dynamicResult.dynamic_result?.registry_events?.length || 0}</span> | API Traces: <span className="text-cyan-400">{dynamicResult.dynamic_result?.api_events?.length || 0}</span></div>
                  <div>Telemetry Hash (SHA-256): <span className="text-emerald-400">{dynamicResult.dynamic_result?.telemetry_sha256 ? dynamicResult.dynamic_result.telemetry_sha256.substring(0, 16) + '...' : 'N/A'}</span></div>
                </div>

                {/* Phase 10 Dynamic Behavioral Model (LSTM Sequence Classifier) */}
                <div className="mt-6 p-4 rounded-xl bg-purple-950/30 border border-purple-500/30 space-y-4">
                  <div className="flex justify-between items-center">
                    <h5 className="text-sm font-bold text-purple-300 font-mono flex items-center gap-2">
                      <Binary className="w-4 h-4 text-purple-400" />
                      Dynamic Behavioral Model — PyTorch LSTM (Phase 10)
                    </h5>
                    <button
                      onClick={handleRunDynamicInference}
                      disabled={inferenceLoading}
                      className="px-3 py-1.5 rounded-lg bg-purple-500/20 text-purple-300 hover:bg-purple-500/30 border border-purple-500/30 text-xs font-mono transition-all cursor-pointer flex items-center gap-1.5"
                    >
                      <RefreshCw className={`w-3.5 h-3.5 ${inferenceLoading ? 'animate-spin' : ''}`} />
                      Run Dynamic LSTM Inference
                    </button>
                  </div>

                  {dynamicInferenceResult ? (
                    <div className="space-y-3">
                      <div className="grid grid-cols-1 md:grid-cols-4 gap-3 text-xs font-mono">
                        <div className="bg-slate-900/80 p-3 rounded-lg border border-slate-800">
                          <span className="text-slate-400">Classification</span>
                          <div className={`text-base font-bold mt-1 ${dynamicInferenceResult.classification === 'malware' ? 'text-rose-400' : 'text-emerald-400'}`}>
                            {dynamicInferenceResult.classification?.toUpperCase()}
                          </div>
                        </div>

                        <div className="bg-slate-900/80 p-3 rounded-lg border border-slate-800">
                          <span className="text-slate-400">P(Malware) Prob</span>
                          <div className="text-base font-bold text-amber-400 mt-1">
                            {((dynamicInferenceResult.malware_probability || 0) * 100).toFixed(1)}%
                          </div>
                        </div>

                        <div className="bg-slate-900/80 p-3 rounded-lg border border-slate-800">
                          <span className="text-slate-400">Sequence Length</span>
                          <div className="text-base font-bold text-cyan-400 mt-1">
                            {dynamicInferenceResult.sequence_length || 0} events
                          </div>
                        </div>

                        <div className="bg-slate-900/80 p-3 rounded-lg border border-slate-800">
                          <span className="text-slate-400">Unknown Event Rate</span>
                          <div className="text-base font-bold text-slate-200 mt-1">
                            {((dynamicInferenceResult.unknown_event_rate || 0) * 100).toFixed(1)}%
                          </div>
                        </div>
                      </div>

                      <div className="p-3 rounded-lg bg-slate-900/70 border border-purple-500/20 text-xs font-mono flex items-center justify-between text-purple-200">
                        <div>Model: <span className="font-semibold text-purple-300">{dynamicInferenceResult.model_version || 'dynamic_lstm_v1.0'}</span> | Threshold: <span className="font-semibold text-purple-300">{dynamicInferenceResult.threshold || 0.5}</span></div>
                        <span className="px-2.5 py-0.5 rounded-full bg-amber-500/10 border border-amber-500/30 text-amber-300 text-[10px]">
                          {dynamicInferenceResult.evaluation_status || 'ENGINEERING_SMOKE_EVALUATION'}
                        </span>
                      </div>
                    </div>
                  ) : (
                    <div className="p-3 rounded-lg bg-slate-900/40 border border-slate-800 text-xs font-mono text-slate-400">
                      Dynamic LSTM sequence inference has not been run for this scan yet. Click &quot;Run Dynamic LSTM Inference&quot; to encode telemetry into sequence tokens and execute PyTorch model.
                    </div>
                  )}
                </div>

                {/* Phase 11 Multimodal Ensemble Decision Card */}
                <div className="mt-6 p-4 rounded-xl bg-slate-900/90 border border-cyan-500/40 space-y-4 font-mono">
                  <div className="flex justify-between items-center">
                    <h5 className="text-sm font-bold text-cyan-300 font-mono flex items-center gap-2">
                      <GitFork className="w-4 h-4 text-cyan-400" />
                      PolyShield Multimodal Ensemble Decision (Phase 11)
                    </h5>
                    <button
                      onClick={handleRunEnsembleInference}
                      disabled={ensembleLoading}
                      className="px-3 py-1.5 rounded-lg bg-cyan-500/20 text-cyan-300 hover:bg-cyan-500/30 border border-cyan-500/30 text-xs font-mono transition-all cursor-pointer flex items-center gap-1.5"
                    >
                      <RefreshCw className={`w-3.5 h-3.5 ${ensembleLoading ? 'animate-spin' : ''}`} />
                      Run Multimodal Ensemble Decision
                    </button>
                  </div>

                  {ensembleResult ? (
                    <div className="space-y-4 text-xs">
                      <div className="flex justify-between items-center p-3 rounded-lg bg-slate-950/80 border border-slate-800">
                        <div>
                          <span className="text-[10px] text-slate-400">ENSEMBLE CLASSIFICATION</span>
                          <div className={`text-base font-bold mt-0.5 ${ensembleResult.ensemble_classification === 'malware' ? 'text-rose-400' : 'text-emerald-400'}`}>
                            {ensembleResult.ensemble_classification?.toUpperCase()}
                          </div>
                        </div>
                        <span className={`px-3 py-1 rounded-full text-xs font-mono border ${getRiskBadgeColor(ensembleResult.risk_level)}`}>
                          RISK: {ensembleResult.risk_level}
                        </span>
                      </div>

                      <div className="space-y-2">
                        <div>
                          <div className="flex justify-between text-[11px] mb-0.5">
                            <span className="text-slate-400">Static Model P(malware):</span>
                            <span className="text-cyan-400 font-bold">{ensembleResult.static_probability !== null ? `${(ensembleResult.static_probability * 100).toFixed(1)}%` : 'N/A'}</span>
                          </div>
                          <div className="w-full bg-slate-800 rounded-full h-2">
                            <div className="bg-cyan-500 h-2 rounded-full" style={{ width: `${(ensembleResult.static_probability || 0) * 100}%` }}></div>
                          </div>
                        </div>

                        <div>
                          <div className="flex justify-between text-[11px] mb-0.5">
                            <span className="text-slate-400">Dynamic LSTM P(malware):</span>
                            <span className="text-purple-400 font-bold">{ensembleResult.dynamic_probability !== null ? `${(ensembleResult.dynamic_probability * 100).toFixed(1)}%` : 'N/A'}</span>
                          </div>
                          <div className="w-full bg-slate-800 rounded-full h-2">
                            <div className="bg-purple-500 h-2 rounded-full" style={{ width: `${(ensembleResult.dynamic_probability || 0) * 100}%` }}></div>
                          </div>
                        </div>

                        <div>
                          <div className="flex justify-between text-[11px] font-bold mb-0.5 text-amber-300">
                            <span>Ensemble P(malware):</span>
                            <span>{(ensembleResult.ensemble_probability * 100).toFixed(1)}%</span>
                          </div>
                          <div className="w-full bg-slate-800 rounded-full h-2.5 border border-amber-500/40">
                            <div className="bg-amber-400 h-2.5 rounded-full" style={{ width: `${(ensembleResult.ensemble_probability || 0) * 100}%` }}></div>
                          </div>
                        </div>
                      </div>
                    </div>
                  ) : (
                    <div className="p-3 rounded-lg bg-slate-900/40 border border-slate-800 text-xs font-mono text-slate-400">
                      Click &quot;Run Multimodal Ensemble Decision&quot; to compute equal-weighted fusion probability.
                    </div>
                  )}
                </div>

                {/* Phase 12 Explainable AI / SHAP + Behavioral Attribution Card */}
                <div className="mt-6 p-4 rounded-xl bg-slate-900/90 border border-purple-500/40 space-y-4 font-mono">
                  <div className="flex justify-between items-center">
                    <h5 className="text-sm font-bold text-purple-300 font-mono flex items-center gap-2">
                      <Sparkles className="w-4 h-4 text-purple-400" />
                      Why PolyShield Made This Decision (Phase 12 — Explainable AI)
                    </h5>
                    <button
                      onClick={handleRunExplanation}
                      disabled={explanationLoading}
                      className="px-3 py-1.5 rounded-lg bg-purple-500/20 text-purple-300 hover:bg-purple-500/30 border border-purple-500/30 text-xs font-mono transition-all cursor-pointer flex items-center gap-1.5"
                    >
                      <RefreshCw className={`w-3.5 h-3.5 ${explanationLoading ? 'animate-spin' : ''}`} />
                      Generate Explanation Report
                    </button>
                  </div>

                  {explanationResult ? (
                    <div className="space-y-4 text-xs">
                      <div className="p-3 rounded-lg bg-slate-950/80 border border-purple-500/30 text-slate-300">
                        <span className="text-[10px] text-purple-400 font-bold uppercase tracking-wider block mb-1">DECISION SYNTHESIS</span>
                        <p>{explanationResult.decision_summary}</p>
                      </div>

                      {/* 1. OBSERVED EVIDENCE vs 2. MODEL ATTRIBUTION */}
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        {/* Observed Evidence Panel */}
                        <div className="p-3.5 rounded-lg bg-slate-950/90 border border-cyan-500/30 space-y-3">
                          <div className="flex justify-between items-center border-b border-cyan-500/20 pb-2">
                            <span className="text-[11px] font-bold text-cyan-300 flex items-center gap-1.5">
                              <Database className="w-3.5 h-3.5" />
                              1. OBSERVED EVIDENCE
                            </span>
                            <span className="px-2 py-0.5 rounded text-[9px] bg-cyan-950 text-cyan-300 border border-cyan-500/30">
                              MEASURED FACTS
                            </span>
                          </div>
                          <p className="text-[10px] text-slate-400">Actual structural features and telemetry recorded by the analysis engine. These are raw facts, NOT SHAP attributions.</p>
                          <div className="space-y-2">
                            {explanationResult.observed_evidence?.map((item, idx) => (
                              <div key={idx} className="p-2 rounded bg-slate-900/60 border border-slate-800 flex justify-between items-center text-[11px]">
                                <div>
                                  <div className="text-cyan-200 font-semibold">{item.metric_name}</div>
                                  <div className="text-[9px] text-slate-400">{item.description}</div>
                                </div>
                                <div className="font-bold text-white text-right px-2 py-1 rounded bg-slate-950 border border-slate-800">
                                  {item.metric_value}
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>

                        {/* Model Attribution Panel */}
                        <div className="p-3.5 rounded-lg bg-slate-950/90 border border-purple-500/30 space-y-3">
                          <div className="flex justify-between items-center border-b border-purple-500/20 pb-2">
                            <span className="text-[11px] font-bold text-purple-300 flex items-center gap-1.5">
                              <CpuIcon className="w-3.5 h-3.5" />
                              2. MODEL ATTRIBUTION (SHAP & IG)
                            </span>
                            <span className="px-2 py-0.5 rounded text-[9px] bg-purple-950 text-purple-300 border border-purple-500/30">
                              MODEL WEIGHTS
                            </span>
                          </div>
                          <p className="text-[10px] text-slate-400">Quantifies marginal feature/event attributions toward model outputs. Derived locally via TreeExplainer & Captum.</p>

                          {/* Static SHAP Attributions */}
                          {explanationResult.static_explanation && (
                            <div className="space-y-1.5">
                              <div className="text-[10px] font-bold text-purple-300 flex justify-between">
                                <span>Top Static SHAP Attributions (base={explanationResult.static_explanation.base_value})</span>
                                <span>P(malware)={explanationResult.static_explanation.model_output}</span>
                              </div>
                              {explanationResult.static_explanation.top_k_attributions?.map((attr, idx) => (
                                <div key={idx} className="p-1.5 rounded bg-slate-900/60 border border-slate-800 flex justify-between items-center text-[11px]">
                                  <div className="flex items-center gap-1.5">
                                    <span className="text-slate-500">#{attr.rank}</span>
                                    <span className="text-slate-200 font-semibold">{attr.feature}</span>
                                    <span className="text-[9px] text-slate-400">({attr.value})</span>
                                  </div>
                                  <div className="flex items-center gap-1 font-bold">
                                    {attr.direction === 'POSITIVE' ? (
                                      <span className="text-rose-400 flex items-center gap-0.5"><TrendingUp className="w-3 h-3" />+{attr.contribution}</span>
                                    ) : attr.direction === 'NEGATIVE' ? (
                                      <span className="text-emerald-400 flex items-center gap-0.5"><TrendingDown className="w-3 h-3" />{attr.contribution}</span>
                                    ) : (
                                      <span className="text-slate-400 flex items-center gap-0.5"><Minus className="w-3 h-3" />0.0</span>
                                    )}
                                  </div>
                                </div>
                              ))}
                            </div>
                          )}

                          {/* Dynamic Sequence Attributions */}
                          {explanationResult.dynamic_explanation && (
                            <div className="space-y-1.5 pt-2 border-t border-slate-800">
                              <div className="text-[10px] font-bold text-purple-300 flex justify-between">
                                <span>Top Dynamic Sequence Attributions</span>
                                <span>P(malware)={explanationResult.dynamic_explanation.model_output}</span>
                              </div>
                              {explanationResult.dynamic_explanation.top_k_attributions?.map((attr, idx) => (
                                <div key={idx} className="p-1.5 rounded bg-slate-900/60 border border-slate-800 flex justify-between items-center text-[11px]">
                                  <div className="flex items-center gap-1.5">
                                    <span className="text-slate-500">#{attr.rank}</span>
                                    <span className="text-purple-300 font-semibold">{attr.event_type}</span>
                                    <span className="text-[9px] text-slate-400">({attr.relative_time_ms}ms)</span>
                                  </div>
                                  <div className="flex items-center gap-1 font-bold">
                                    {attr.direction === 'POSITIVE' ? (
                                      <span className="text-rose-400 flex items-center gap-0.5"><TrendingUp className="w-3 h-3" />+{attr.contribution}</span>
                                    ) : attr.direction === 'NEGATIVE' ? (
                                      <span className="text-emerald-400 flex items-center gap-0.5"><TrendingDown className="w-3 h-3" />{attr.contribution}</span>
                                    ) : (
                                      <span className="text-slate-400 flex items-center gap-0.5"><Minus className="w-3 h-3" />0.0</span>
                                    )}
                                  </div>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      </div>

                      {/* Ensemble Decomposition Panel */}
                      <div className="p-3 rounded-lg bg-slate-950/80 border border-amber-500/30 space-y-2">
                        <span className="text-[10px] text-amber-300 font-bold uppercase tracking-wider block">3. ENSEMBLE COMPONENT DECOMPOSITION</span>
                        <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-[11px]">
                          <div className="p-2 rounded bg-slate-900/60 border border-slate-800">
                            <span className="text-slate-400">Static Contribution:</span>
                            <div className="text-cyan-400 font-bold mt-0.5">
                              {explanationResult.ensemble_decomposition?.static_component_contribution !== null ? explanationResult.ensemble_decomposition.static_component_contribution : 'N/A'}
                            </div>
                          </div>
                          <div className="p-2 rounded bg-slate-900/60 border border-slate-800">
                            <span className="text-slate-400">Dynamic Contribution:</span>
                            <div className="text-purple-400 font-bold mt-0.5">
                              {explanationResult.ensemble_decomposition?.dynamic_component_contribution !== null ? explanationResult.ensemble_decomposition.dynamic_component_contribution : 'N/A'}
                            </div>
                          </div>
                          <div className="p-2 rounded bg-slate-950/80 border border-slate-800">
                            <span className="text-slate-400">Ensemble Result:</span>
                            <div className="text-amber-300 font-bold mt-0.5">
                              {explanationResult.ensemble_decomposition?.ensemble_probability}
                            </div>
                          </div>
                        </div>
                      </div>

                      {/* Disclaimers & Limitations */}
                      <div className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800 text-[10px] text-slate-400 space-y-1">
                        <div><strong className="text-slate-300">Causal Policy:</strong> {explanationResult.limitations?.causal_claim_policy}</div>
                        <div><strong className="text-slate-300">Facts vs Attributions:</strong> {explanationResult.limitations?.observed_vs_attribution_distinction}</div>
                        <div><strong className="text-slate-300">Synthetic Warning:</strong> {explanationResult.limitations?.synthetic_dataset_disclosure}</div>
                      </div>
                    </div>
                  ) : (
                    <div className="p-3 rounded-lg bg-slate-900/40 border border-slate-800 text-xs text-slate-400 font-mono">
                      Click &quot;Generate Explanation Report&quot; to compute SHAP TreeExplainer attributions, Captum sequence event attributions, and observed evidence breakdown.
                    </div>
                  )}
                </div>
              </div>
            ) : (
              <div className="p-4 rounded-xl bg-slate-900/40 border border-slate-800 text-xs font-mono text-slate-400">
                No dynamic analysis telemetry recorded yet. Click &quot;Run Dynamic Sandbox Analysis&quot; above to enqueue background sandbox telemetry collection.
              </div>
            )}
          </div>
        </div>
      )}

      {/* Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="glass-panel glass-panel-hover p-5 rounded-xl">
          <div className="flex justify-between items-start">
            <div>
              <p className="text-slate-400 text-xs uppercase tracking-wider font-mono">Total Scan Records</p>
              <h3 className="text-2xl font-bold text-white mt-1">{totalScans}</h3>
            </div>
            <div className="p-2.5 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
              <Activity className="w-5 h-5" />
            </div>
          </div>
          <p className="text-cyan-400 text-xs font-mono mt-3">
            MongoDB Database
          </p>
        </div>

        <div className="glass-panel glass-panel-hover p-5 rounded-xl">
          <div className="flex justify-between items-start">
            <div>
              <p className="text-slate-400 text-xs uppercase tracking-wider font-mono">Worker Infrastructure</p>
              <h3 className="text-2xl font-bold text-emerald-400 mt-1">Celery + Redis</h3>
            </div>
            <div className="p-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
              <Clock className="w-5 h-5" />
            </div>
          </div>
          <p className="text-slate-400 text-xs font-mono mt-3">
            Async Queue Broker
          </p>
        </div>

        <div className="glass-panel glass-panel-hover p-5 rounded-xl">
          <div className="flex justify-between items-start">
            <div>
              <p className="text-slate-400 text-xs uppercase tracking-wider font-mono">Dynamic ML Model</p>
              <h3 className="text-2xl font-bold text-purple-400 mt-1">PyTorch LSTM</h3>
            </div>
            <div className="p-2.5 rounded-lg bg-purple-500/10 border border-purple-500/20 text-purple-400">
              <Binary className="w-5 h-5" />
            </div>
          </div>
          <p className="text-purple-400 text-xs font-mono mt-3">
            Sequence Classifier (Phase 10)
          </p>
        </div>

        <div className="glass-panel glass-panel-hover p-5 rounded-xl">
          <div className="flex justify-between items-start">
            <div>
              <p className="text-slate-400 text-xs uppercase tracking-wider font-mono">Host Protection</p>
              <h3 className="text-2xl font-bold text-emerald-400 mt-1">100% No-Exec</h3>
            </div>
            <div className="p-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
              <Database className="w-5 h-5" />
            </div>
          </div>
          <p className="text-emerald-400 text-xs font-mono mt-3">
            Telemetry Sequence Parsing
          </p>
        </div>
      </div>

      {/* Recent Scans Table */}
      <div className="glass-panel p-5 rounded-xl space-y-4">
        <div className="flex justify-between items-center">
          <h3 className="text-base font-semibold text-white">Recent Scan Records</h3>
          <button
            onClick={loadScans}
            className="p-2 rounded-lg bg-slate-800 text-slate-300 hover:text-white border border-slate-700 transition-all cursor-pointer flex items-center gap-1.5 text-xs font-mono"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-900/80 text-slate-400 border-b border-slate-800">
              <tr>
                <th className="p-3">Scan ID</th>
                <th className="p-3">Filename</th>
                <th className="p-3">Status</th>
                <th className="p-3">Created</th>
                <th className="p-3">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {scans.length === 0 ? (
                <tr>
                  <td colSpan="5" className="p-6 text-center text-slate-500">
                    No scan records found. Create one above to test.
                  </td>
                </tr>
              ) : (
                scans.map((scan) => (
                  <tr key={scan.scan_id} className="hover:bg-slate-800/40">
                    <td className="p-3 text-cyan-400 font-semibold">{scan.scan_id.substring(0, 8)}...</td>
                    <td className="p-3 text-slate-200">{scan.filename}</td>
                    <td className="p-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                        scan.status === 'COMPLETED' ? 'bg-emerald-950 text-emerald-400 border border-emerald-500/30' :
                        scan.status === 'FAILED' ? 'bg-rose-950 text-rose-400 border border-rose-500/30' :
                        'bg-cyan-950 text-cyan-400 border border-cyan-500/30'
                      }`}>
                        {scan.status}
                      </span>
                    </td>
                    <td className="p-3 text-slate-400">{new Date(scan.created_at).toLocaleTimeString()}</td>
                    <td className="p-3">
                      <button
                        onClick={() => handleLookupScan(scan.scan_id)}
                        className="text-cyan-400 hover:text-cyan-300 underline cursor-pointer"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

