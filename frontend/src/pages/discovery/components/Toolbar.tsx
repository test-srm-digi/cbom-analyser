import { Search, Download, SlidersHorizontal, RotateCcw } from 'lucide-react';
import s from './shared.module.scss';

interface Props {
  search: string;
  setSearch: (v: string) => void;
  placeholder: string;
  onExport?: () => void;
  onReset?: () => void;
  resetLoading?: boolean;
}

export default function Toolbar({ search, setSearch, placeholder, onExport, onReset, resetLoading }: Props) {
  return (
    <div className={s.toolbar}>
      <div className={s.searchBar}>
        <Search className={s.searchIcon} />
        <input
          className={s.searchInput}
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder={placeholder}
        />
      </div>
      <button className={s.exportBtn} onClick={onExport}>
        <Download className={s.exportIcon} />
        Export
      </button>
      <button className={s.filterToggle}>
        <SlidersHorizontal className={s.filterIcon} />
      </button>
      {onReset && (
        <button
          className={s.resetBtn}
          onClick={onReset}
          disabled={resetLoading}
          title="Clear all data and return to the empty state"
        >
          <RotateCcw className={`${s.resetIcon}${resetLoading ? ` ${s.spinning}` : ''}`} />
          {resetLoading ? 'Clearing…' : 'Reset Data'}
        </button>
      )}
    </div>
  );
}
