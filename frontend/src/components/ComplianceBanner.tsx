import { AlertTriangle, CheckCircle, Info } from 'lucide-react';
import { ComplianceSummary } from '../types';

interface ComplianceBannerProps {
  compliance: ComplianceSummary | null;
}

export default function ComplianceBanner({ compliance }: ComplianceBannerProps) {
  if (!compliance) return null;

  const isCompliant = compliance.isCompliant;

  return (
    <div
      className={`w-full rounded-lg px-4 py-3 flex items-center gap-3 animate-fade-in ${
        isCompliant
          ? 'bg-qg-green/10 border border-qg-green/30'
          : 'bg-qg-red/10 border border-qg-red/30'
      }`}
    >
      {isCompliant ? (
        <CheckCircle className="w-5 h-5 text-qg-green flex-shrink-0" />
      ) : (
        <AlertTriangle className="w-5 h-5 text-qg-red flex-shrink-0 animate-pulse-glow" />
      )}

      <div className="flex-1">
        <span className={`font-semibold ${isCompliant ? 'text-qg-green' : 'text-qg-red'}`}>
          {isCompliant ? 'Compliant' : 'Not compliant'}
        </span>
        <span className="text-gray-400 mx-2">–</span>
        <span className="text-gray-300">
          {isCompliant
            ? `This CBOM complies with the policy "${compliance.policy}".`
            : `This CBOM does not comply with the policy "${compliance.policy}".`}
        </span>
      </div>

      <div className="flex items-center gap-1 text-xs text-gray-500">
        <Info className="w-3 h-3" />
        <span>Source: {compliance.source}</span>
      </div>
    </div>
  );
}
