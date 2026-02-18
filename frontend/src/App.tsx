import { useState, useCallback } from 'react';
import { Shield } from 'lucide-react';
import {
  ComplianceBanner,
  QuantumSafetyDonut,
  PrimitivesDonut,
  FunctionsDonut,
  CryptoBubbleChart,
  AssetListView,
  ReadinessScoreCard,
  CBOMUploader,
  NetworkScanner,
  CBOMHeader,
} from './components';
import {
  CBOMDocument,
  QuantumReadinessScore,
  ComplianceSummary,
  NetworkScanResult,
  UploadResponse,
} from './types';
import { SAMPLE_CBOM } from './sampleData';

export default function App() {
  const [cbom, setCbom] = useState<CBOMDocument | null>(null);
  const [readinessScore, setReadinessScore] = useState<QuantumReadinessScore | null>(null);
  const [compliance, setCompliance] = useState<ComplianceSummary | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleUpload = useCallback(async (file: File) => {
    setIsLoading(true);
    setError(null);

    try {
      const formData = new FormData();
      formData.append('cbom', file);

      const resp = await fetch('/api/upload', {
        method: 'POST',
        body: formData,
      });

      const data: UploadResponse = await resp.json();

      if (data.success && data.cbom) {
        setCbom(data.cbom);
        setReadinessScore(data.readinessScore || null);
        setCompliance(data.compliance || null);
      } else {
        // Try parsing locally if backend is unavailable
        const text = await file.text();
        handleLocalParse(text);
      }
    } catch {
      // Backend might not be running – parse client-side
      try {
        const text = await file.text();
        handleLocalParse(text);
      } catch (parseErr) {
        setError(`Failed to parse CBOM: ${(parseErr as Error).message}`);
      }
    } finally {
      setIsLoading(false);
    }
  }, []);

  function handleLocalParse(jsonText: string) {
    let data = JSON.parse(jsonText);

    // Unwrap API response wrapper format: { success, cbom, readinessScore, ... }
    if (data.success !== undefined && data.cbom) {
      // If the file is a saved API response, extract the inner CBOM
      const wrappedScore = data.readinessScore;
      const wrappedCompliance = data.compliance;
      data = data.cbom;

      // If the wrapper already contains score/compliance, use them directly
      if (wrappedScore && wrappedCompliance) {
        const doc: CBOMDocument = {
          bomFormat: data.bomFormat || 'CycloneDX',
          specVersion: data.specVersion || '1.6',
          serialNumber: data.serialNumber,
          version: data.version || 1,
          metadata: data.metadata || { timestamp: new Date().toISOString() },
          components: data.components || [],
          cryptoAssets: data.cryptoAssets || [],
          dependencies: data.dependencies,
        };
        setCbom(doc);
        setReadinessScore(wrappedScore);
        setCompliance(wrappedCompliance);
        return;
      }
    }

    // Basic client-side CBOM parsing
    const doc: CBOMDocument = {
      bomFormat: data.bomFormat || 'CycloneDX',
      specVersion: data.specVersion || '1.6',
      serialNumber: data.serialNumber,
      version: data.version || 1,
      metadata: data.metadata || { timestamp: new Date().toISOString() },
      components: data.components || [],
      cryptoAssets: data.cryptoAssets || [],
      dependencies: data.dependencies,
    };

    // If no cryptoAssets but has components with crypto-properties, map them
    if (doc.cryptoAssets.length === 0 && doc.components.length > 0) {
      for (const comp of doc.components as any[]) {
        const cp = comp.cryptoProperties || comp['crypto-properties'];
        if (cp) {
          doc.cryptoAssets.push({
            id: comp['bom-ref'] || crypto.randomUUID(),
            name: comp.name,
            type: comp.type || 'crypto-asset',
            cryptoProperties: {
              assetType: cp.assetType || cp['asset-type'] || 'algorithm',
              algorithmProperties: cp.algorithmProperties,
            },
            location: comp.evidence?.occurrences?.[0] ? {
              fileName: comp.evidence.occurrences[0].location || '',
              lineNumber: comp.evidence.occurrences[0].line,
            } : undefined,
            quantumSafety: 'unknown' as any,
          });
        }
      }
    }

    // Client-side readiness calculation
    const safe = doc.cryptoAssets.filter(a => a.quantumSafety === 'quantum-safe').length;
    const notSafe = doc.cryptoAssets.filter(a => a.quantumSafety === 'not-quantum-safe').length;
    const unknown = doc.cryptoAssets.filter(a => a.quantumSafety === 'unknown').length;
    const total = doc.cryptoAssets.length;

    setCbom(doc);
    setReadinessScore({
      score: total > 0 ? Math.round(((safe + unknown * 0.5) / total) * 100) : 100,
      totalAssets: total,
      quantumSafe: safe,
      notQuantumSafe: notSafe,
      unknown,
    });
    setCompliance({
      isCompliant: notSafe === 0,
      policy: 'NIST Post-Quantum Cryptography',
      source: 'Basic Local Compliance Service',
      totalAssets: total,
      compliantAssets: safe,
      nonCompliantAssets: notSafe,
      unknownAssets: unknown,
    });
  }

  function loadSampleData() {
    setIsLoading(true);
    setTimeout(() => {
      handleLocalParse(JSON.stringify(SAMPLE_CBOM));
      setIsLoading(false);
    }, 500);
  }

  function handleNetworkScan(result: NetworkScanResult) {
    if (!cbom) return;
    // Add network asset to CBOM
    const newAsset = {
      id: crypto.randomUUID(),
      name: result.cipherSuite,
      type: 'network',
      cryptoProperties: {
        assetType: 'protocol',
        protocolProperties: {
          type: 'tls',
          version: result.protocol,
          cipherSuites: [{ name: result.cipherSuite }],
        },
      },
      location: { fileName: `${result.host}:${result.port}` },
      quantumSafety: result.isQuantumSafe ? 'quantum-safe' as const : 'not-quantum-safe' as const,
    };

    const updatedCbom = {
      ...cbom,
      cryptoAssets: [...cbom.cryptoAssets, newAsset as any],
    };
    setCbom(updatedCbom);

    // Recalculate score
    const assets = updatedCbom.cryptoAssets;
    const safe = assets.filter(a => a.quantumSafety === 'quantum-safe').length;
    const notSafe = assets.filter(a => a.quantumSafety === 'not-quantum-safe').length;
    const unknown = assets.filter(a => a.quantumSafety === 'unknown').length;
    const total = assets.length;

    setReadinessScore({
      score: total > 0 ? Math.round(((safe + unknown * 0.5) / total) * 100) : 100,
      totalAssets: total,
      quantumSafe: safe,
      notQuantumSafe: notSafe,
      unknown,
    });
    setCompliance(prev => prev ? {
      ...prev,
      totalAssets: total,
      compliantAssets: safe,
      nonCompliantAssets: notSafe,
      unknownAssets: unknown,
      isCompliant: notSafe === 0,
    } : null);
  }

  return (
    <div className="min-h-screen bg-qg-dark">
      {/* Header */}
      <header className="border-b border-qg-border">
        <div className="max-w-7xl mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Shield className="w-7 h-7 text-qg-accent" />
            <div>
              <h1 className="text-lg font-bold text-white tracking-tight">QuantumGuard</h1>
              <p className="text-xs text-gray-500">CBOM Hub</p>
            </div>
          </div>
          <p className="text-xs text-gray-500">
            Explore the use of cryptography in software with Cryptography Bills of Materials (CBOM)
          </p>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 py-6 space-y-6">
        {/* Upload Section */}
        {!cbom && (
          <div className="space-y-4">
            <CBOMUploader onUpload={handleUpload} isLoading={isLoading} />
            <p className="text-sm text-gray-500 text-center">
              If you do not have a CBOM, visualize our{' '}
              <button
                onClick={loadSampleData}
                className="text-qg-accent hover:underline font-medium"
              >
                sample CBOM file →
              </button>
            </p>
          </div>
        )}

        {error && (
          <div className="bg-qg-red/10 border border-qg-red/30 rounded-lg px-4 py-3 text-qg-red text-sm">
            {error}
          </div>
        )}

        {/* Dashboard */}
        {cbom && (
          <div className="space-y-6 animate-fade-in">
            {/* CBOM Header */}
            <CBOMHeader cbom={cbom} />

            {/* Compliance Banner */}
            <ComplianceBanner compliance={compliance} />

            {/* Charts Row */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              <QuantumSafetyDonut assets={cbom.cryptoAssets} />
              <CryptoBubbleChart assets={cbom.cryptoAssets} />
              <PrimitivesDonut assets={cbom.cryptoAssets} />
              <FunctionsDonut assets={cbom.cryptoAssets} />
            </div>

            {/* Score + Network Scanner Row */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <ReadinessScoreCard score={readinessScore} />
              <NetworkScanner onScanComplete={handleNetworkScan} />
            </div>

            {/* Asset List */}
            <AssetListView assets={cbom.cryptoAssets} />

            {/* Upload another */}
            <div className="pt-4 border-t border-qg-border">
              <p className="text-sm text-gray-500 mb-3">Upload another CBOM:</p>
              <CBOMUploader onUpload={handleUpload} isLoading={isLoading} />
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-qg-border mt-12 py-6">
        <div className="max-w-7xl mx-auto px-4 text-center text-xs text-gray-600">
          <p>QuantumGuard CBOM Hub — Cryptographic Bill of Materials Analyzer</p>
          <p className="mt-1">CycloneDX 1.6 Standard · NIST PQC Compliance</p>
        </div>
      </footer>
    </div>
  );
}
