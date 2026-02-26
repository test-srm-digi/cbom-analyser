import { Search, Download, SlidersHorizontal } from 'lucide-react';
import s from './shared.module.scss';

interface Props {
  search: string;
  setSearch: (v: string) => void;
  placeholder: string;
}

export default function Toolbar({ search, setSearch, placeholder }: Props) {
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
      <button className={s.exportBtn}>
        <Download className={s.exportIcon} />
        Export
      </button>
      <button className={s.filterToggle}>
        <SlidersHorizontal className={s.filterIcon} />
      </button>
    </div>
  );
}
