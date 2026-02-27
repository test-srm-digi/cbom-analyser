import { Zap, Loader2, Sparkles } from 'lucide-react';
import s from './shared.module.scss';

interface Props {
  children: React.ReactNode;
  onShowMe?: () => void;
  loading?: boolean;
}

export default function AiBanner({ children, onShowMe, loading }: Props) {
  return (
    <div className={s.aiBanner}>
      <Zap className={s.aiBannerIcon} />
      <span className={s.aiBannerText}>{children}</span>
      <button className={s.aiBannerBtn} onClick={onShowMe} disabled={loading}>
        {loading
          ? <><Loader2 className={s.aiBannerBtnSpin} /> Analysing…</>
          : <><Sparkles className={s.aiBannerBtnIcon} /> Show me</>}
      </button>
    </div>
  );
}
