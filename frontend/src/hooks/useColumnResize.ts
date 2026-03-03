import { useState, useRef, useCallback } from 'react';

/**
 * Reusable hook for drag-to-resize table columns.
 *
 * Usage:
 *   const { colWidths, onResizeStart } = useColumnResize(COL_MIN);
 *
 *   <colgroup>
 *     {columns.map((_, i) => (
 *       <col key={i} style={{ width: colWidths[i] || COL_MIN[i], minWidth: COL_MIN[i] }} />
 *     ))}
 *   </colgroup>
 *
 *   <th>
 *     Label
 *     <span className={s.resizeHandle} onMouseDown={(e) => onResizeStart(e, colIdx)} />
 *   </th>
 */
export function useColumnResize(colMin: Record<number, number>) {
  const [colWidths, setColWidths] = useState<Record<number, number>>({});
  const resizingCol = useRef<{ idx: number; startX: number; startW: number } | null>(null);

  const onResizeStart = useCallback((e: React.MouseEvent, colIdx: number) => {
    e.preventDefault();
    e.stopPropagation();
    const th = (e.target as HTMLElement).parentElement!;
    const startW = th.offsetWidth;
    resizingCol.current = { idx: colIdx, startX: e.clientX, startW };

    const onMove = (ev: MouseEvent) => {
      if (!resizingCol.current) return;
      const diff = ev.clientX - resizingCol.current.startX;
      const min = colMin[colIdx] ?? 80;
      const newW = Math.max(min, resizingCol.current.startW + diff);
      setColWidths(prev => ({ ...prev, [colIdx]: newW }));
    };

    const onUp = () => {
      resizingCol.current = null;
      document.removeEventListener('mousemove', onMove);
      document.removeEventListener('mouseup', onUp);
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
    };

    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup', onUp);
  }, [colMin]);

  return { colWidths, onResizeStart };
}
