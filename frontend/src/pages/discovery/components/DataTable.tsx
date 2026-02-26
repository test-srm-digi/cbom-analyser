import { type ReactNode } from 'react';
import { ArrowUpDown } from 'lucide-react';
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
}

export default function DataTable<T>({ title, count, columns, data, rowKey }: Props<T>) {
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
          {data.map((item) => (
            <tr key={rowKey(item)}>
              {columns.map((col) => (
                <td key={col.key} style={col.cellStyle}>
                  {col.render(item)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
