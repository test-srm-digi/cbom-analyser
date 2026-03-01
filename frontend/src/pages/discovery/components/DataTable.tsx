import { type ReactNode, useState, useMemo } from 'react';
import { ArrowUpDown } from 'lucide-react';
import Pagination from '../../../components/Pagination';
import s from './shared.module.scss';

interface Column<T> {
  key: string;
  label: string;
  sortable?: boolean;
  render: (item: T) => ReactNode;
  headerStyle?: React.CSSProperties;
  cellStyle?: React.CSSProperties;
}

interface Props<T> {
  title: string;
  count: number;
  columns: Column<T>[];
  data: T[];
  rowKey: (item: T) => string;
  onRowClick?: (item: T) => void;
  /** Default page size (default: 25) */
  defaultPageSize?: number;
}

export default function DataTable<T>({ title, count, columns, data, rowKey, onRowClick, defaultPageSize = 25 }: Props<T>) {
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(defaultPageSize);

  // Reset to page 1 when data changes
  const dataLen = data.length;
  const [prevLen, setPrevLen] = useState(dataLen);
  if (dataLen !== prevLen) { setPrevLen(dataLen); setPage(1); }

  const paged = useMemo(() => {
    const start = (page - 1) * pageSize;
    return data.slice(start, start + pageSize);
  }, [data, page, pageSize]);

  return (
    <div className={s.tableCard}>
      <h3 className={s.tableTitle}>{title} ({count})</h3>
      <table className={s.table}>
        <thead>
          <tr>
            {columns.map((col) => (
              <th key={col.key} style={col.headerStyle}>
                {col.label}
                {col.sortable !== false && <ArrowUpDown className={s.sortIcon} />}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {paged.map((item) => (
            <tr
              key={rowKey(item)}
              onClick={onRowClick ? () => onRowClick(item) : undefined}
              style={onRowClick ? { cursor: 'pointer' } : undefined}
            >
              {columns.map((col) => (
                <td key={col.key} style={col.cellStyle}>
                  {col.render(item)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
      <Pagination
        page={page}
        total={data.length}
        pageSize={pageSize}
        onPageChange={setPage}
        onPageSizeChange={setPageSize}
      />
    </div>
  );
}
