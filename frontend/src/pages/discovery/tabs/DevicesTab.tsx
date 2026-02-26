import { useMemo } from 'react';
import { Eye, ExternalLink } from 'lucide-react';
import { StatCards, Toolbar, AiBanner, DataTable, QsBadge, DeviceStatusBadge, EmptyState } from '../components';
import type { IntegrationStep } from '../components';
import { DEVICES } from '../data';
import { useGetDevicesQuery, useBulkCreateDevicesMutation } from '../../../store/api';
import type { DiscoveryDevice, StatCardConfig } from '../types';
import s from '../components/shared.module.scss';

interface Props {
  search: string;
  setSearch: (v: string) => void;
}

const STEPS: IntegrationStep[] = [
  { step: 1, title: 'Navigate to Integrations', description: 'Go to the Integrations page and locate "DigiCert Device Trust Manager" in the catalog.' },
  { step: 2, title: 'Enter DTM credentials', description: 'Provide your DigiCert ONE tenant URL, API key, and optionally filter by device group or enrollment profile.' },
  { step: 3, title: 'Test & sync', description: 'Click "Test Connection" to verify DTM API access, then "Save & Sync" to import your IoT/OT device fleet.' },
  { step: 4, title: 'Review device inventory', description: 'Device certificates, firmware versions, enrollment status, and PQC readiness will appear here after sync.' },
];

export default function DevicesTab({ search, setSearch }: Props) {
  const { data: apiData = [], isLoading } = useGetDevicesQuery();
  const [bulkCreate, { isLoading: isSampleLoading }] = useBulkCreateDevicesMutation();
  const data = apiData;
  const loaded = data.length > 0;

  const total      = data.length;
  const qsSafe     = data.filter((d) => d.quantumSafe).length;
  const violations = data.filter((d) => !d.quantumSafe).length;
  const weakKeys   = data.filter((d) => d.keyLength === '1024 bits').length;

  const filtered = useMemo(() => {
    if (!search) return data;
    const q = search.toLowerCase();
    return data.filter(
      (d) =>
        d.deviceName.toLowerCase().includes(q) ||
        d.manufacturer.toLowerCase().includes(q) ||
        d.deviceType.toLowerCase().includes(q) ||
        d.certAlgorithm.toLowerCase().includes(q),
    );
  }, [search, data]);

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

  if (isLoading) return null;

  if (!loaded) {
    return (
      <EmptyState
        title="Devices"
        integrationName="DigiCert Device Trust Manager"
        integrationDescription="Import your IoT and OT device fleet from DTM. Discover device certificates, firmware crypto capabilities, enrollment status, and identify devices needing PQC migration."
        steps={STEPS}
        loading={isSampleLoading}
        onLoadSample={() => bulkCreate({ integrationId: 'sample', items: DEVICES.map(({ id, ...rest }) => rest) })}
      />
    );
  }

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
