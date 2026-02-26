import { useMemo } from 'react';
import { Eye, ExternalLink } from 'lucide-react';
import { StatCards, Toolbar, AiBanner, DataTable, QsBadge, DeviceStatusBadge } from '../components';
import { DEVICES } from '../data';
import type { DiscoveryDevice, StatCardConfig } from '../types';
import s from '../components/shared.module.scss';

interface Props {
  search: string;
  setSearch: (v: string) => void;
}

export default function DevicesTab({ search, setSearch }: Props) {
  const total      = DEVICES.length;
  const qsSafe     = DEVICES.filter((d) => d.quantumSafe).length;
  const violations = DEVICES.filter((d) => !d.quantumSafe).length;
  const weakKeys   = DEVICES.filter((d) => d.keyLength === '1024 bits').length;

  const filtered = useMemo(() => {
    if (!search) return DEVICES;
    const q = search.toLowerCase();
    return DEVICES.filter(
      (d) =>
        d.deviceName.toLowerCase().includes(q) ||
        d.manufacturer.toLowerCase().includes(q) ||
        d.deviceType.toLowerCase().includes(q) ||
        d.certAlgorithm.toLowerCase().includes(q),
    );
  }, [search]);

  const stats: StatCardConfig[] = [
    { title: 'Total Devices',     value: total,      sub: 'Managed by DigiCert Device Trust Manager',                       variant: 'default' },
    { title: 'Quantum-ready',     value: qsSafe,     sub: `${qsSafe} of ${total} devices with PQC certificates/firmware`,   variant: 'success' },
    { title: 'Vulnerable Devices', value: violations, sub: `Includes ${weakKeys} devices with 1024-bit keys`,               variant: 'danger' },
  ];

  const columns = [
    { key: 'deviceName',       label: 'Device Name',        render: (d: DiscoveryDevice) => <span style={{ fontWeight: 500 }}>{d.deviceName}</span> },
    { key: 'deviceType',       label: 'Type',               render: (d: DiscoveryDevice) => d.deviceType },
    { key: 'manufacturer',     label: 'Manufacturer',       render: (d: DiscoveryDevice) => d.manufacturer },
    { key: 'firmwareVersion',  label: 'Firmware',           render: (d: DiscoveryDevice) => <span className={s.mono}>{d.firmwareVersion}</span> },
    { key: 'certAlgorithm',   label: 'Cert Algorithm',     render: (d: DiscoveryDevice) => d.certAlgorithm },
    { key: 'keyLength',       label: 'Key Length',          render: (d: DiscoveryDevice) => d.keyLength },
    { key: 'enrollmentStatus', label: 'Status',             render: (d: DiscoveryDevice) => <DeviceStatusBadge status={d.enrollmentStatus} /> },
    { key: 'quantumSafe',     label: 'Quantum-safe',       render: (d: DiscoveryDevice) => <QsBadge safe={d.quantumSafe} />, sortable: false },
    { key: 'source',          label: 'Source',              render: (d: DiscoveryDevice) => <span className={s.sourceLink}>{d.source}</span> },
    {
      key: 'actions',
      label: 'Actions',
      sortable: false,
      headerStyle: { textAlign: 'right' as const },
      render: (_d: DiscoveryDevice) => (
        <div className={s.actions}>
          <button className={s.actionBtn}><Eye className={s.actionIcon} /></button>
          <button className={s.actionBtn}><ExternalLink className={s.actionIcon} /></button>
        </div>
      ),
    },
  ];

  return (
    <>
      <StatCards cards={stats} />

      {weakKeys > 0 && (
        <AiBanner>
          <strong>{weakKeys} devices</strong> use <strong>1024-bit RSA keys</strong> — these are critically weak and should be re-enrolled with ML-DSA or at minimum 2048-bit RSA certificates via Device Trust Manager.
        </AiBanner>
      )}

      <Toolbar
        search={search}
        setSearch={setSearch}
        placeholder="Search by device name, type, manufacturer, or algorithm..."
      />

      <DataTable
        title="Devices"
        count={filtered.length}
        columns={columns}
        data={filtered}
        rowKey={(d) => d.id}
      />
    </>
  );
}
