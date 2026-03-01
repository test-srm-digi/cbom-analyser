/**
 * Configuration & Artifact Crypto Patterns
 *
 * Inspired by PQCA cbomkit-theia's plugin architecture:
 * - certificates: X.509 certificate files (PEM, DER, CRT, CER)
 * - secrets: Private key files, keystores, secrets (PEM, KEY, PFX, JKS, P12)
 * - javasecurity: java.security configuration files
 * - opensslconf: OpenSSL configuration files
 * - tlsconfig: TLS/SSL configuration in application config files
 * - cryptoconfig: Crypto algorithm config in application.yml, web.config, etc.
 *
 * These patterns scan non-source-code files for crypto-relevant configuration.
 */
import { CryptoPrimitive, CryptoFunction, AssetType } from '../../../types';
import { CryptoPattern } from '../scannerTypes';

// ─── Certificate & Key File Content Patterns ─────────────────────────────────

export const configPatterns: CryptoPattern[] = [
  // ════════════════════════════════════════════════════════════════════════
  // ── PEM-encoded certificates & keys ─────────────────────────────────────
  // ════════════════════════════════════════════════════════════════════════
  { pattern: /-----BEGIN CERTIFICATE-----/g, algorithm: 'X.509', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.CERTIFICATE },
  { pattern: /-----BEGIN X509 CRL-----/g, algorithm: 'X.509-CRL', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.CERTIFICATE },
  { pattern: /-----BEGIN TRUSTED CERTIFICATE-----/g, algorithm: 'X.509', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.CERTIFICATE },

  // Private keys
  { pattern: /-----BEGIN RSA PRIVATE KEY-----/g, algorithm: 'RSA', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.KEYGEN, assetType: AssetType.PRIVATE_KEY },
  { pattern: /-----BEGIN EC PRIVATE KEY-----/g, algorithm: 'ECDSA', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.KEYGEN, assetType: AssetType.PRIVATE_KEY },
  { pattern: /-----BEGIN PRIVATE KEY-----/g, algorithm: 'PKCS8-Private-Key', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.KEYGEN, assetType: AssetType.PRIVATE_KEY },
  { pattern: /-----BEGIN ENCRYPTED PRIVATE KEY-----/g, algorithm: 'PKCS8-Encrypted-Private-Key', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.KEYGEN, assetType: AssetType.PRIVATE_KEY },
  { pattern: /-----BEGIN DSA PRIVATE KEY-----/g, algorithm: 'DSA', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.KEYGEN, assetType: AssetType.PRIVATE_KEY },
  { pattern: /-----BEGIN OPENSSH PRIVATE KEY-----/g, algorithm: 'SSH-Private-Key', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.KEYGEN, assetType: AssetType.PRIVATE_KEY },

  // Public keys
  { pattern: /-----BEGIN PUBLIC KEY-----/g, algorithm: 'Public-Key', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PUBLIC_KEY },
  { pattern: /-----BEGIN RSA PUBLIC KEY-----/g, algorithm: 'RSA', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PUBLIC_KEY },

  // PKCS / CMS
  { pattern: /-----BEGIN PKCS7-----/g, algorithm: 'PKCS7', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.RELATED_MATERIAL },
  { pattern: /-----BEGIN CERTIFICATE REQUEST-----/g, algorithm: 'CSR', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.CERTIFICATE },

  // ════════════════════════════════════════════════════════════════════════
  // ── java.security configuration (cbomkit-theia: javasecurity plugin) ────
  // ════════════════════════════════════════════════════════════════════════

  // Security provider registration
  { pattern: /security\.provider\.\d+=(\S+)/g, algorithm: 'Java-Security-Provider', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, extractAlgorithm: true },

  // Disabled algorithms
  { pattern: /jdk\.tls\.disabledAlgorithms\s*=\s*([^\n\\]+)/g, algorithm: 'TLS-Disabled-Algorithms', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL, extractAlgorithm: true },
  { pattern: /jdk\.certpath\.disabledAlgorithms\s*=\s*([^\n\\]+)/g, algorithm: 'Certpath-Disabled-Algorithms', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.CERTIFICATE, extractAlgorithm: true },
  { pattern: /jdk\.jar\.disabledAlgorithms\s*=\s*([^\n\\]+)/g, algorithm: 'JAR-Disabled-Algorithms', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, extractAlgorithm: true },

  // Key/keystore configuration
  { pattern: /keystore\.type\s*=\s*(\S+)/g, algorithm: 'KeyStore', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.RELATED_MATERIAL, extractAlgorithm: true },
  { pattern: /ssl\.KeyManagerFactory\.algorithm\s*=\s*(\S+)/g, algorithm: 'KeyManagerFactory', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL, extractAlgorithm: true },
  { pattern: /ssl\.TrustManagerFactory\.algorithm\s*=\s*(\S+)/g, algorithm: 'TrustManagerFactory', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL, extractAlgorithm: true },

  // SecureRandom seed source
  { pattern: /securerandom\.source\s*=\s*(\S+)/g, algorithm: 'SecureRandom-Source', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.KEYGEN, extractAlgorithm: true },
  { pattern: /securerandom\.strongAlgorithms\s*=\s*([^\n]+)/g, algorithm: 'SecureRandom-Strong', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.KEYGEN, extractAlgorithm: true },

  // ════════════════════════════════════════════════════════════════════════
  // ── OpenSSL configuration (cbomkit-theia: opensslconf plugin) ───────────
  // ════════════════════════════════════════════════════════════════════════

  // Default algorithms in openssl.cnf
  { pattern: /default_md\s*=\s*(\w+)/g, algorithm: 'OpenSSL-Default-Hash', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION, extractAlgorithm: true },
  { pattern: /default_bits\s*=\s*(\d+)/g, algorithm: 'OpenSSL-Default-KeySize', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.KEYGEN, extractAlgorithm: true },

  // Cipher lists / cipher strings
  { pattern: /CipherString\s*=\s*([^\n]+)/g, algorithm: 'OpenSSL-CipherString', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL, extractAlgorithm: true },
  { pattern: /Ciphersuites\s*=\s*([^\n]+)/g, algorithm: 'OpenSSL-CipherSuites', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL, extractAlgorithm: true },
  { pattern: /MinProtocol\s*=\s*(\w+)/g, algorithm: 'OpenSSL-MinProtocol', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL, extractAlgorithm: true },
  { pattern: /MaxProtocol\s*=\s*(\w+)/g, algorithm: 'OpenSSL-MaxProtocol', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL, extractAlgorithm: true },

  // Curves / groups
  { pattern: /Curves\s*=\s*([^\n]+)/g, algorithm: 'OpenSSL-Curves', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE, extractAlgorithm: true },
  { pattern: /Groups\s*=\s*([^\n]+)/g, algorithm: 'OpenSSL-Groups', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE, extractAlgorithm: true },

  // FIPS mode
  { pattern: /(?:fips\s*=\s*yes|fips\s*=\s*1|OPENSSL_FIPS)/g, algorithm: 'FIPS-Mode', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER },

  // ════════════════════════════════════════════════════════════════════════
  // ── Application config: YAML / Properties / TOML / JSON ─────────────────
  // ════════════════════════════════════════════════════════════════════════

  // Spring Boot / Java application.properties / application.yml
  { pattern: /server\.ssl\.protocol\s*[:=]\s*(\w+)/g, algorithm: 'TLS', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL, extractAlgorithm: true },
  { pattern: /server\.ssl\.enabled-protocols\s*[:=]\s*([^\n,]+)/g, algorithm: 'TLS', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL, extractAlgorithm: true },
  { pattern: /server\.ssl\.ciphers\s*[:=]\s*([^\n]+)/g, algorithm: 'TLS-Ciphers', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL, extractAlgorithm: true },
  { pattern: /server\.ssl\.key-store-type\s*[:=]\s*(\w+)/g, algorithm: 'KeyStore', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.RELATED_MATERIAL, extractAlgorithm: true },
  { pattern: /server\.ssl\.key-store\s*[:=]\s*(\S+)/g, algorithm: 'KeyStore-File', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.RELATED_MATERIAL, extractAlgorithm: true },

  // .NET appsettings.json / web.config
  { pattern: /"SslProtocols"\s*:\s*"([^"]+)"/g, algorithm: 'TLS', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL, extractAlgorithm: true },

  // Nginx TLS configuration
  { pattern: /ssl_protocols\s+([^;]+);/g, algorithm: 'TLS', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL, extractAlgorithm: true },
  { pattern: /ssl_ciphers\s+['"]?([^;'"]+)/g, algorithm: 'TLS-Ciphers', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL, extractAlgorithm: true },
  { pattern: /ssl_certificate\s+(\S+);/g, algorithm: 'X.509', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.CERTIFICATE, extractAlgorithm: true },
  { pattern: /ssl_certificate_key\s+(\S+);/g, algorithm: 'Private-Key', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PRIVATE_KEY, extractAlgorithm: true },

  // Apache httpd TLS configuration
  { pattern: /SSLProtocol\s+([^\n]+)/g, algorithm: 'TLS', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL, extractAlgorithm: true },
  { pattern: /SSLCipherSuite\s+([^\n]+)/g, algorithm: 'TLS-Ciphers', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL, extractAlgorithm: true },
  { pattern: /SSLCertificateFile\s+(\S+)/g, algorithm: 'X.509', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.CERTIFICATE, extractAlgorithm: true },
  { pattern: /SSLCertificateKeyFile\s+(\S+)/g, algorithm: 'Private-Key', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PRIVATE_KEY, extractAlgorithm: true },

  // Docker / Kubernetes TLS
  { pattern: /tls\.crt|tls\.key|ca\.crt|server\.crt|server\.key|client\.crt|client\.key/g, algorithm: 'TLS-File-Reference', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.CERTIFICATE },

  // ════════════════════════════════════════════════════════════════════════
  // ── SSH configuration ───────────────────────────────────────────────────
  // ════════════════════════════════════════════════════════════════════════
  { pattern: /(?:Host)?KeyAlgorithms\s+([^\n]+)/g, algorithm: 'SSH-Key-Algorithms', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL, extractAlgorithm: true },
  { pattern: /KexAlgorithms\s+([^\n]+)/g, algorithm: 'SSH-Key-Exchange', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE, assetType: AssetType.PROTOCOL, extractAlgorithm: true },
  { pattern: /Ciphers\s+([^\n]+)/g, algorithm: 'SSH-Ciphers', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT, assetType: AssetType.PROTOCOL, extractAlgorithm: true },
  { pattern: /MACs\s+([^\n]+)/g, algorithm: 'SSH-MACs', primitive: CryptoPrimitive.MAC, cryptoFunction: CryptoFunction.TAG, assetType: AssetType.PROTOCOL, extractAlgorithm: true },
];

/**
 * File extensions that the config scanner should examine.
 * These are non-source-code files containing crypto configuration.
 */
export const CONFIG_EXTENSIONS: string[] = [
  // Certificates & keys
  '.pem', '.crt', '.cer', '.der', '.key', '.pub',
  '.p12', '.pfx', '.jks', '.keystore', '.bks', '.truststore',
  // Java security config
  '.security',
  // OpenSSL config
  '.cnf', '.conf',
  // Application config
  '.yml', '.yaml', '.properties', '.toml',
  // Web server config
  '.nginx', '.htaccess',
  // SSH config
  '.config',
  // Rust manifest
  // '.toml' already included
];

/**
 * Specific filenames the config scanner should examine regardless of extension.
 */
export const CONFIG_FILENAMES: string[] = [
  'java.security',
  'openssl.cnf',
  'openssl.conf',
  'application.properties',
  'application.yml',
  'application.yaml',
  'application-prod.yml',
  'application-prod.properties',
  'appsettings.json',
  'appsettings.Production.json',
  'web.config',
  'nginx.conf',
  'httpd.conf',
  'ssl.conf',
  'sshd_config',
  'ssh_config',
  'Cargo.toml',
  'go.sum',
];
