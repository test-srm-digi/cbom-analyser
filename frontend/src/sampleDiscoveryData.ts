import type {
  Integration,
  DiscoveryCertificate,
  DiscoveryEndpoint,
  DiscoverySoftware,
} from './types';

/* ── Integrations ─────────────────────────────────────────── */

export const SAMPLE_INTEGRATIONS: Integration[] = [
  {
    id: 'tlm',
    name: 'DigiCert Trust Lifecycle',
    description: 'Import certificates and cryptographic assets from DigiCert Trust Lifecycle Manager',
    status: 'connected',
    configUrl: 'https://one.digicert.com',
    lastImport: '12/01/2024, 16:00:00',
    enabled: true,
  },
  {
    id: 'stm',
    name: 'DigiCert Software Trust',
    description: 'Import software signing certificates and code signing assets from DigiCert Software Trust Manager',
    status: 'connected',
    configUrl: 'https://one.digicert.com',
    lastImport: '12/01/2024, 14:45:00',
    enabled: true,
  },
  {
    id: 'dtm',
    name: 'DigiCert Device Trust',
    description: 'Import device certificates and IoT cryptographic assets from DigiCert Device Trust Manager',
    status: 'connected',
    configUrl: 'https://one.digicert.com',
    lastImport: '12/01/2024, 14:15:00',
    enabled: true,
  },
];

/* ── Certificates ─────────────────────────────────────────── */

export const SAMPLE_CERTIFICATES: DiscoveryCertificate[] = [
  { id: 'c1',  commonName: 'Production Web Portal',          caVendor: 'DigiCert',   status: 'Issued', keyAlgorithm: 'RSA',   keyLength: '2048 bits', quantumSafe: false, source: 'DigiCert Trust Lifecycle' },
  { id: 'c2',  commonName: 'Database Server Primary',         caVendor: 'DigiCert',   status: 'Issued', keyAlgorithm: 'RSA',   keyLength: '2048 bits', quantumSafe: false, source: 'DigiCert Trust Lifecycle' },
  { id: 'c3',  commonName: 'Payment Gateway',                 caVendor: 'GlobalSign',  status: 'Issued', keyAlgorithm: 'RSA',   keyLength: '4096 bits', quantumSafe: false, source: 'DigiCert Trust Lifecycle' },
  { id: 'c4',  commonName: 'Quantum Safe Infrastructure',     caVendor: 'DigiCert',   status: 'Issued', keyAlgorithm: 'ML-DSA', keyLength: '768 bits',  quantumSafe: true,  source: 'DigiCert Trust Lifecycle' },
  { id: 'c5',  commonName: 'Quantum Ready Microservice',      caVendor: 'DigiCert',   status: 'Issued', keyAlgorithm: 'ML-DSA', keyLength: '768 bits',  quantumSafe: true,  source: 'DigiCert Trust Lifecycle' },
  { id: 'c6',  commonName: 'Mail Server Exchange',            caVendor: 'Sectigo',     status: 'Issued', keyAlgorithm: 'RSA',   keyLength: '2048 bits', quantumSafe: false, source: 'DigiCert Trust Lifecycle' },
  { id: 'c7',  commonName: 'VPN Gateway Corporate',           caVendor: 'Self signed', status: 'Issued', keyAlgorithm: 'ECDSA', keyLength: 'P-384 bits', quantumSafe: false, source: 'DigiCert Trust Lifecycle' },
  { id: 'c8',  commonName: 'File Storage Server',             caVendor: 'DigiCert',   status: 'Issued', keyAlgorithm: 'RSA',   keyLength: '2048 bits', quantumSafe: false, source: 'DigiCert Trust Lifecycle' },
  { id: 'c9',  commonName: 'Monitoring Platform',             caVendor: 'GlobalSign',  status: 'Issued', keyAlgorithm: 'ECDSA', keyLength: 'P-256 bits', quantumSafe: false, source: 'DigiCert Trust Lifecycle' },
  { id: 'c10', commonName: 'Logging Service',                 caVendor: 'DigiCert',   status: 'Issued', keyAlgorithm: 'RSA',   keyLength: '3072 bits', quantumSafe: false, source: 'DigiCert Trust Lifecycle' },
  { id: 'c11', commonName: 'API Gateway Primary',             caVendor: 'DigiCert',   status: 'Issued', keyAlgorithm: 'RSA',   keyLength: '2048 bits', quantumSafe: false, source: 'DigiCert Trust Lifecycle' },
  { id: 'c12', commonName: 'CI/CD Pipeline Runner',           caVendor: 'DigiCert',   status: 'Issued', keyAlgorithm: 'RSA',   keyLength: '2048 bits', quantumSafe: false, source: 'DigiCert Trust Lifecycle' },
  { id: 'c13', commonName: 'Internal SSO Provider',           caVendor: 'DigiCert',   status: 'Issued', keyAlgorithm: 'RSA',   keyLength: '2048 bits', quantumSafe: false, source: 'DigiCert Trust Lifecycle' },
  { id: 'c14', commonName: 'CDN Edge Node',                   caVendor: 'DigiCert',   status: 'Issued', keyAlgorithm: 'ECDSA', keyLength: 'P-256 bits', quantumSafe: false, source: 'DigiCert Software Trust' },
  { id: 'c15', commonName: 'Backup Service',                  caVendor: 'DigiCert',   status: 'Issued', keyAlgorithm: 'RSA',   keyLength: '2048 bits', quantumSafe: false, source: 'DigiCert Software Trust' },
  { id: 'c16', commonName: 'Container Registry',              caVendor: 'DigiCert',   status: 'Issued', keyAlgorithm: 'RSA',   keyLength: '2048 bits', quantumSafe: false, source: 'DigiCert Software Trust' },
  { id: 'c17', commonName: 'Message Queue Broker',            caVendor: 'GlobalSign',  status: 'Issued', keyAlgorithm: 'RSA',   keyLength: '2048 bits', quantumSafe: false, source: 'DigiCert Software Trust' },
  { id: 'c18', commonName: 'Load Balancer External',          caVendor: 'DigiCert',   status: 'Issued', keyAlgorithm: 'RSA',   keyLength: '4096 bits', quantumSafe: false, source: 'DigiCert Software Trust' },
  { id: 'c19', commonName: 'DNS Server Primary',              caVendor: 'DigiCert',   status: 'Issued', keyAlgorithm: 'RSA',   keyLength: '2048 bits', quantumSafe: false, source: 'DigiCert Device Trust' },
  { id: 'c20', commonName: 'Kubernetes API Server',           caVendor: 'DigiCert',   status: 'Issued', keyAlgorithm: 'ECDSA', keyLength: 'P-384 bits', quantumSafe: false, source: 'DigiCert Device Trust' },
  { id: 'c21', commonName: 'PQC Gateway Service',             caVendor: 'DigiCert',   status: 'Issued', keyAlgorithm: 'ML-DSA', keyLength: '768 bits',  quantumSafe: true,  source: 'DigiCert Device Trust' },
  { id: 'c22', commonName: 'LDAP Directory Server',           caVendor: 'DigiCert',   status: 'Issued', keyAlgorithm: 'RSA',   keyLength: '2048 bits', quantumSafe: false, source: 'DigiCert Trust Lifecycle' },
  { id: 'c23', commonName: 'Redis Cache Cluster',             caVendor: 'Sectigo',     status: 'Issued', keyAlgorithm: 'RSA',   keyLength: '2048 bits', quantumSafe: false, source: 'DigiCert Trust Lifecycle' },
  { id: 'c24', commonName: 'Elasticsearch Indexer',           caVendor: 'DigiCert',   status: 'Issued', keyAlgorithm: 'RSA',   keyLength: '2048 bits', quantumSafe: false, source: 'DigiCert Trust Lifecycle' },
  { id: 'c25', commonName: 'Notification Service',            caVendor: 'DigiCert',   status: 'Issued', keyAlgorithm: 'RSA',   keyLength: '2048 bits', quantumSafe: false, source: 'DigiCert Trust Lifecycle' },
  { id: 'c26', commonName: 'Analytics Pipeline',              caVendor: 'GlobalSign',  status: 'Issued', keyAlgorithm: 'RSA',   keyLength: '2048 bits', quantumSafe: false, source: 'DigiCert Software Trust' },
  { id: 'c27', commonName: 'Compliance Dashboard',            caVendor: 'DigiCert',   status: 'Issued', keyAlgorithm: 'RSA',   keyLength: '2048 bits', quantumSafe: false, source: 'DigiCert Software Trust' },
  { id: 'c28', commonName: 'Secrets Manager Vault',           caVendor: 'DigiCert',   status: 'Issued', keyAlgorithm: 'RSA',   keyLength: '4096 bits', quantumSafe: false, source: 'DigiCert Trust Lifecycle' },
  { id: 'c29', commonName: 'Event Streaming Platform',        caVendor: 'DigiCert',   status: 'Issued', keyAlgorithm: 'ECDSA', keyLength: 'P-256 bits', quantumSafe: false, source: 'DigiCert Trust Lifecycle' },
  { id: 'c30', commonName: 'Data Warehouse Service',          caVendor: 'DigiCert',   status: 'Issued', keyAlgorithm: 'RSA',   keyLength: '2048 bits', quantumSafe: false, source: 'DigiCert Trust Lifecycle' },
];

/* ── Endpoints ────────────────────────────────────────────── */

export const SAMPLE_ENDPOINTS: DiscoveryEndpoint[] = [
  { id: 'e1',  hostname: 'analytics-01.corp.local',          ipAddress: '10.50.1.25',      port: 443, tlsVersion: 'TLS 1.2', keyAgreement: 'x25519',    quantumSafe: false, source: 'DigiCert TLM - Network scan' },
  { id: 'e2',  hostname: 'api-gateway-01.corp.local',        ipAddress: '192.168.2.50',    port: 443, tlsVersion: 'TLS 1.2', keyAgreement: 'x25519',    quantumSafe: false, source: 'DigiCert TLM - API discovery' },
  { id: 'e3',  hostname: 'auth-server-01.corp.local',        ipAddress: '172.30.5.50',     port: 443, tlsVersion: 'TLS 1.3', keyAgreement: 'x25519',    quantumSafe: false, source: 'DigiCert TLM - System scan' },
  { id: 'e4',  hostname: 'backup-server-01.corp.local',      ipAddress: '10.30.5.75',      port: 443, tlsVersion: 'TLS 1.3', keyAgreement: 'secp256r1', quantumSafe: false, source: 'DigiCert TLM - Network scan' },
  { id: 'e5',  hostname: 'cache-server-01.corp.local',       ipAddress: '172.40.8.100',    port: 443, tlsVersion: 'TLS 1.2', keyAgreement: 'x25519',    quantumSafe: false, source: 'DigiCert TLM - System scan' },
  { id: 'e6',  hostname: 'cdn-edge-01.corp.local',           ipAddress: '10.20.1.101',     port: 443, tlsVersion: 'TLS 1.2', keyAgreement: 'secp256r1', quantumSafe: false, source: 'DigiCert TLM - CA import' },
  { id: 'e7',  hostname: 'cms-server-01.corp.local',         ipAddress: '192.168.200.10',  port: 443, tlsVersion: 'TLS 1.1', keyAgreement: 'secp256r1', quantumSafe: false, source: 'DigiCert TLM - API discovery' },
  { id: 'e8',  hostname: 'crm-server-01.corp.local',         ipAddress: '192.168.150.75',  port: 443, tlsVersion: 'TLS 1.2', keyAgreement: 'secp256r1', quantumSafe: false, source: 'DigiCert TLM - API discovery' },
  { id: 'e9',  hostname: 'database-01.corp.local',           ipAddress: '10.0.1.25',       port: 443, tlsVersion: 'TLS 1.2', keyAgreement: 'secp256r1', quantumSafe: false, source: 'DigiCert TLM - CA import' },
  { id: 'e10', hostname: 'docker-registry-01.corp.local',    ipAddress: '10.40.2.15',      port: 443, tlsVersion: 'TLS 1.2', keyAgreement: 'x25519',    quantumSafe: false, source: 'DigiCert TLM - CA import' },
  { id: 'e11', hostname: 'file-server-01.corp.local',        ipAddress: '192.168.50.20',   port: 443, tlsVersion: 'TLS 1.1', keyAgreement: 'x25519',    quantumSafe: false, source: 'DigiCert TLM - System scan' },
  { id: 'e12', hostname: 'git-server-01.corp.local',         ipAddress: '10.10.3.40',      port: 443, tlsVersion: 'TLS 1.2', keyAgreement: 'x25519',    quantumSafe: false, source: 'DigiCert TLM - Network scan' },
  { id: 'e13', hostname: 'jenkins-01.corp.local',            ipAddress: '172.20.4.60',     port: 443, tlsVersion: 'TLS 1.2', keyAgreement: 'secp256r1', quantumSafe: false, source: 'DigiCert TLM - API discovery' },
  { id: 'e14', hostname: 'k8s-api-01.corp.local',            ipAddress: '10.60.1.10',      port: 443, tlsVersion: 'TLS 1.3', keyAgreement: 'x25519',    quantumSafe: false, source: 'DigiCert TLM - Network scan' },
  { id: 'e15', hostname: 'ldap-01.corp.local',               ipAddress: '192.168.1.100',   port: 443, tlsVersion: 'TLS 1.2', keyAgreement: 'secp256r1', quantumSafe: false, source: 'DigiCert TLM - CA import' },
  { id: 'e16', hostname: 'loadbalancer-01.corp.local',       ipAddress: '10.0.0.1',        port: 443, tlsVersion: 'TLS 1.3', keyAgreement: 'x25519',    quantumSafe: false, source: 'DigiCert TLM - Network scan' },
  { id: 'e17', hostname: 'mail-01.corp.local',               ipAddress: '192.168.10.50',   port: 443, tlsVersion: 'TLS 1.2', keyAgreement: 'secp256r1', quantumSafe: false, source: 'DigiCert TLM - System scan' },
  { id: 'e18', hostname: 'monitoring-01.corp.local',         ipAddress: '172.16.5.80',     port: 443, tlsVersion: 'TLS 1.2', keyAgreement: 'x25519',    quantumSafe: false, source: 'DigiCert TLM - Network scan' },
  { id: 'e19', hostname: 'mq-broker-01.corp.local',          ipAddress: '10.70.3.25',      port: 443, tlsVersion: 'TLS 1.2', keyAgreement: 'secp256r1', quantumSafe: false, source: 'DigiCert TLM - API discovery' },
  { id: 'e20', hostname: 'pqc-gateway-01.corp.local',        ipAddress: '10.80.1.5',       port: 443, tlsVersion: 'TLS 1.3', keyAgreement: 'ML-KEM-768', quantumSafe: true, source: 'DigiCert TLM - Network scan' },
  { id: 'e21', hostname: 'pqc-service-01.corp.local',        ipAddress: '10.80.1.10',      port: 443, tlsVersion: 'TLS 1.3', keyAgreement: 'ML-KEM-768', quantumSafe: true, source: 'DigiCert TLM - Network scan' },
  { id: 'e22', hostname: 'pqc-infra-01.corp.local',          ipAddress: '10.80.1.15',      port: 443, tlsVersion: 'TLS 1.3', keyAgreement: 'ML-KEM-1024', quantumSafe: true, source: 'DigiCert TLM - System scan' },
  { id: 'e23', hostname: 'proxy-01.corp.local',              ipAddress: '10.0.0.5',        port: 443, tlsVersion: 'TLS 1.2', keyAgreement: 'x25519',    quantumSafe: false, source: 'DigiCert TLM - Network scan' },
  { id: 'e24', hostname: 'redis-01.corp.local',              ipAddress: '172.16.10.20',    port: 443, tlsVersion: 'TLS 1.2', keyAgreement: 'secp256r1', quantumSafe: false, source: 'DigiCert TLM - CA import' },
  { id: 'e25', hostname: 'search-01.corp.local',             ipAddress: '10.90.2.30',      port: 443, tlsVersion: 'TLS 1.2', keyAgreement: 'x25519',    quantumSafe: false, source: 'DigiCert TLM - System scan' },
  { id: 'e26', hostname: 'vault-01.corp.local',              ipAddress: '10.0.0.50',       port: 443, tlsVersion: 'TLS 1.3', keyAgreement: 'x25519',    quantumSafe: false, source: 'DigiCert TLM - Network scan' },
  { id: 'e27', hostname: 'vpn-gateway-01.corp.local',        ipAddress: '10.0.0.2',        port: 443, tlsVersion: 'TLS 1.2', keyAgreement: 'secp256r1', quantumSafe: false, source: 'DigiCert TLM - Network scan' },
];

/* ── Software ─────────────────────────────────────────────── */

export const SAMPLE_SOFTWARE: DiscoverySoftware[] = [
  { id: 's1',  name: 'OpenSSL',           version: '1.1.1w',  vendor: 'OpenSSL Project',  cryptoLibraries: ['libssl', 'libcrypto'],  quantumSafe: false, source: 'DigiCert Software Trust' },
  { id: 's2',  name: 'OpenSSL',           version: '3.2.0',   vendor: 'OpenSSL Project',  cryptoLibraries: ['libssl', 'libcrypto'],  quantumSafe: false, source: 'DigiCert Software Trust' },
  { id: 's3',  name: 'Bouncy Castle',     version: '1.77',    vendor: 'Legion of BC',     cryptoLibraries: ['bcprov', 'bcpkix'],     quantumSafe: true,  source: 'DigiCert Software Trust' },
  { id: 's4',  name: 'liboqs',            version: '0.9.0',   vendor: 'Open Quantum Safe', cryptoLibraries: ['liboqs'],              quantumSafe: true,  source: 'DigiCert Software Trust' },
  { id: 's5',  name: 'GnuTLS',            version: '3.8.2',   vendor: 'GNU Project',      cryptoLibraries: ['libgnutls'],            quantumSafe: false, source: 'DigiCert Software Trust' },
  { id: 's6',  name: 'wolfSSL',           version: '5.6.6',   vendor: 'wolfSSL Inc.',     cryptoLibraries: ['wolfssl'],              quantumSafe: true,  source: 'DigiCert Software Trust' },
  { id: 's7',  name: 'NSS',               version: '3.95',    vendor: 'Mozilla',          cryptoLibraries: ['libnss3', 'libnspr4'],  quantumSafe: false, source: 'DigiCert Software Trust' },
  { id: 's8',  name: 'Java Keytool',      version: '21.0.1',  vendor: 'Oracle',           cryptoLibraries: ['java.security'],        quantumSafe: false, source: 'DigiCert Software Trust' },
  { id: 's9',  name: 'Go crypto',         version: '1.21.5',  vendor: 'Google',           cryptoLibraries: ['crypto/tls'],           quantumSafe: false, source: 'DigiCert Software Trust' },
  { id: 's10', name: 'Libsodium',         version: '1.0.19',  vendor: 'Frank Denis',      cryptoLibraries: ['libsodium'],            quantumSafe: false, source: 'DigiCert Software Trust' },
];
