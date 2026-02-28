import { useState, useRef, useEffect, useCallback, useMemo } from 'react';
import { Search, Check, ChevronDown } from 'lucide-react';
import s from './SearchableSelect.module.scss';

export interface SelectOption {
  value: string;
  label: string;
  description?: string;
}

interface Props {
  options: SelectOption[];
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  searchPlaceholder?: string;
  disabled?: boolean;
}

/**
 * Lightweight searchable dropdown that matches the project design system.
 * Keyboard-navigable: arrow keys, Enter to select, Escape to close.
 */
export default function SearchableSelect({
  options,
  value,
  onChange,
  placeholder = 'Select…',
  searchPlaceholder = 'Search…',
  disabled = false,
}: Props) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [hlIdx, setHlIdx] = useState(0);
  const wrapperRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  /* ── Filtered options ──────────────────────────────────── */
  const filtered = useMemo(() => {
    if (!query) return options;
    const q = query.toLowerCase();
    return options.filter(
      (o) => o.label.toLowerCase().includes(q) || o.value.toLowerCase().includes(q) || (o.description ?? '').toLowerCase().includes(q),
    );
  }, [options, query]);

  /* ── Selected label ────────────────────────────────────── */
  const selectedLabel = useMemo(
    () => options.find((o) => o.value === value)?.label,
    [options, value],
  );

  /* ── Open / close ──────────────────────────────────────── */
  const openDropdown = useCallback(() => {
    if (disabled) return;
    setOpen(true);
    setQuery('');
    setHlIdx(0);
    requestAnimationFrame(() => inputRef.current?.focus());
  }, [disabled]);

  const closeDropdown = useCallback(() => {
    setOpen(false);
    setQuery('');
  }, []);

  const selectOption = useCallback(
    (val: string) => {
      onChange(val);
      closeDropdown();
    },
    [onChange, closeDropdown],
  );

  /* ── Click outside ─────────────────────────────────────── */
  useEffect(() => {
    if (!open) return;
    const handler = (e: MouseEvent) => {
      if (wrapperRef.current && !wrapperRef.current.contains(e.target as Node)) {
        closeDropdown();
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [open, closeDropdown]);

  /* ── Keyboard nav ──────────────────────────────────────── */
  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (!open) {
        if (e.key === 'Enter' || e.key === ' ' || e.key === 'ArrowDown') {
          e.preventDefault();
          openDropdown();
        }
        return;
      }

      switch (e.key) {
        case 'ArrowDown':
          e.preventDefault();
          setHlIdx((i) => Math.min(i + 1, filtered.length - 1));
          break;
        case 'ArrowUp':
          e.preventDefault();
          setHlIdx((i) => Math.max(i - 1, 0));
          break;
        case 'Enter':
          e.preventDefault();
          if (filtered[hlIdx]) selectOption(filtered[hlIdx].value);
          break;
        case 'Escape':
          e.preventDefault();
          closeDropdown();
          break;
      }
    },
    [open, openDropdown, closeDropdown, selectOption, filtered, hlIdx],
  );

  /* ── Scroll highlighted into view ──────────────────────── */
  useEffect(() => {
    if (!open || !listRef.current) return;
    const el = listRef.current.children[hlIdx] as HTMLElement | undefined;
    el?.scrollIntoView({ block: 'nearest' });
  }, [hlIdx, open]);

  /* ── Reset highlight when query changes ────────────────── */
  useEffect(() => setHlIdx(0), [query]);

  return (
    <div className={s.wrapper} ref={wrapperRef} onKeyDown={handleKeyDown}>
      {/* Trigger */}
      <button
        type="button"
        className={`${s.trigger}${open ? ` ${s.open}` : ''}`}
        onClick={() => (open ? closeDropdown() : openDropdown())}
        disabled={disabled}
        tabIndex={0}
      >
        <span className={`${s.triggerText}${!selectedLabel ? ` ${s.placeholder}` : ''}`}>
          {selectedLabel ?? placeholder}
        </span>
        <ChevronDown className={`${s.chevron}${open ? ` ${s.up}` : ''}`} size={10} />
      </button>

      {/* Dropdown */}
      {open && (
        <div className={s.dropdown}>
          <div className={s.searchBox}>
            <Search size={13} className={s.searchIcon} />
            <input
              ref={inputRef}
              className={s.searchInput}
              type="text"
              placeholder={searchPlaceholder}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              autoComplete="off"
              spellCheck={false}
            />
          </div>
          <div className={s.optionsList} ref={listRef}>
            {filtered.length === 0 ? (
              <div className={s.noResults}>No matches found</div>
            ) : (
              filtered.map((opt, i) => (
                <div
                  key={opt.value}
                  className={`${s.option}${i === hlIdx ? ` ${s.highlighted}` : ''}${opt.value === value ? ` ${s.selected}` : ''}`}
                  onMouseEnter={() => setHlIdx(i)}
                  onClick={() => selectOption(opt.value)}
                >
                  <span className={s.optionCheck}>
                    {opt.value === value ? <Check size={13} /> : null}
                  </span>
                  {opt.label}
                </div>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
}
