import { Clock, type LucideIcon } from 'lucide-react';
import s from './PlaceholderPage.module.scss';

interface PlaceholderPageProps {
  section: string;
  title: string;
  description: string;
  icon: LucideIcon;
  features?: string[];
}

export default function PlaceholderPage({
  section,
  title,
  description,
  icon: Icon,
  features = [],
}: PlaceholderPageProps) {
  return (
    <div className={s.page}>
      <div className={s.header}>
        <div className={s.breadcrumb}>
          <span>{section}</span>
          <span className={s.sep}>›</span>
          <span className={s.current}>{title}</span>
        </div>
        <h1 className={s.title}>{title}</h1>
        <p className={s.subtitle}>{section}</p>
      </div>

      <div className={s.card}>
        <div className={s.iconWrap}>
          <Icon size={28} />
        </div>
        <span className={s.badge}>
          <Clock size={12} />
          Coming Soon
        </span>
        <h2 className={s.cardTitle}>{title}</h2>
        <p className={s.cardDesc}>{description}</p>

        {features.length > 0 && (
          <div className={s.features}>
            {features.map((f) => (
              <div key={f} className={s.feature}>
                <Icon size={16} className={s.featureIcon} />
                <span className={s.featureText}>{f}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
