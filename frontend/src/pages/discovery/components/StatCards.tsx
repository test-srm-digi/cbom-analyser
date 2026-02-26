import { Database, ShieldCheck, AlertTriangle } from 'lucide-react';
import type { StatCardConfig } from '../types';
import s from './shared.module.scss';

interface Props {
  cards: StatCardConfig[];
}

const iconMap = {
  default: <Database className={s.statIcon} />,
  success: <ShieldCheck className={s.statIconSuccess} />,
  danger:  <AlertTriangle className={s.statIconDanger} />,
};

const cardClass = {
  default: s.statCard,
  success: s.statCardSuccess,
  danger:  s.statCardDanger,
};

const valueClass = {
  default: s.statValue,
  success: s.statValueSuccess,
  danger:  s.statValueDanger,
};

export default function StatCards({ cards }: Props) {
  return (
    <div className={s.stats}>
      {cards.map((card) => (
        <div key={card.title} className={cardClass[card.variant]}>
          <div className={s.statHeader}>
            <span className={s.statTitle}>{card.title}</span>
            {iconMap[card.variant]}
          </div>
          <span className={valueClass[card.variant]}>{card.value}</span>
          <span className={s.statSub}>{card.sub}</span>
        </div>
      ))}
    </div>
  );
}
