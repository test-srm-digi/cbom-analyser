import { Zap } from 'lucide-react';
import s from './shared.module.scss';

interface Props {
  children: React.ReactNode;
}

export default function AiBanner({ children }: Props) {
  return (
    <div className={s.aiBanner}>
      <Zap className={s.aiBannerIcon} />
      <span className={s.aiBannerText}>{children}</span>
      <button className={s.aiBannerBtn}>Show me</button>
    </div>
  );
}
