/**
 * Context Scanners
 *
 * Functions that scan file content for contextual algorithm clues
 * (BouncyCastle providers, X.509 certs, WebCrypto, etc.)
 */

/**
 * Extract algorithms from WebCrypto (crypto.subtle) API calls.
 */
export function scanWebCryptoContext(fileText: string): string | null {
  const algoRefs: string[] = [];
  let m: RegExpExecArray | null;

  // crypto.subtle.<method>({ name: 'ALGO', ... })
  const subtleCallRe = /crypto\.subtle\.(\w+)\s*\(\s*\{[^}]*name\s*:\s*['"]([^'"]+)['"]/g;
  while ((m = subtleCallRe.exec(fileText)) !== null) {
    const label = `${m[2]} (${m[1]})`;
    if (!algoRefs.includes(label)) algoRefs.push(label);
  }

  // { name: "ECDSA", namedCurve: "P-256" }
  const algoObjRe = /\{\s*name\s*:\s*['"]([^'"]+)['"][^}]*(?:modulusLength|namedCurve|length|hash|saltLength|counter|iv|label)\s*:/g;
  while ((m = algoObjRe.exec(fileText)) !== null) {
    if (!algoRefs.some(r => r.startsWith(m![1]))) algoRefs.push(m![1]);
  }

  // crypto.subtle.digest('SHA-256', data)
  const digestRe = /crypto\.subtle\.digest\s*\(\s*['"]([^'"]+)['"]/g;
  while ((m = digestRe.exec(fileText)) !== null) {
    const label = `${m[1]} (digest)`;
    if (!algoRefs.includes(label)) algoRefs.push(label);
  }

  // importKey with algorithm
  const importKeyRe = /crypto\.subtle\.importKey\s*\([^)]*\{\s*name\s*:\s*['"]([^'"]+)['"]/g;
  while ((m = importKeyRe.exec(fileText)) !== null) {
    const label = `${m[1]} (importKey)`;
    if (!algoRefs.includes(label)) algoRefs.push(label);
  }

  // namedCurve references
  const curvesRe = /namedCurve\s*:\s*['"]([^'"]+)['"]/g;
  while ((m = curvesRe.exec(fileText)) !== null) {
    const label = `EC:${m[1]}`;
    if (!algoRefs.includes(label)) algoRefs.push(label);
  }

  // modulusLength for RSA key sizes
  const modulusRe = /modulusLength\s*:\s*(\d+)/g;
  const keySizes: string[] = [];
  while ((m = modulusRe.exec(fileText)) !== null) {
    if (!keySizes.includes(m[1])) keySizes.push(m[1]);
  }

  if (algoRefs.length > 0) {
    let desc = `WebCrypto (crypto.subtle) algorithms found in file: ${algoRefs.join(', ')}.`;
    if (keySizes.length > 0) desc += ` Key sizes: ${keySizes.join(', ')}-bit.`;
    desc += ' Review each algorithm for PQC readiness.';
    return desc;
  }
  return 'WebCrypto (crypto.subtle) detected but could not determine specific algorithms from the file. Check crypto.subtle.encrypt/sign/generateKey calls for the algorithm parameter.';
}

/**
 * Extract algorithms from X.509 certificate usage patterns.
 */
export function scanX509Context(fileText: string, existingAlgoRefs: string[]): string | null {
  const algoRefs = [...existingAlgoRefs];
  let m;

  const sigAlgRe = /getSigAlg(?:Name|OID)\s*\(\s*\)/g;
  if (sigAlgRe.test(fileText)) {
    if (!algoRefs.includes('getSigAlgName()')) algoRefs.push('getSigAlgName()');
  }

  const sigLiteralRe = /["']((?:SHA\d+with\w+|MD5with\w+|Ed25519|Ed448|ML-DSA-\d+|SLH-DSA-\w+))['"]/g;
  while ((m = sigLiteralRe.exec(fileText)) !== null) {
    if (!algoRefs.includes(m[1])) algoRefs.push(m[1]);
  }

  const contentSignerRe = /JcaContentSignerBuilder\s*\(\s*["']([^"']+)["']/g;
  while ((m = contentSignerRe.exec(fileText)) !== null) {
    if (!algoRefs.includes(m[1])) algoRefs.push(m[1]);
  }

  const certBuilderRe = /(?:Jca)?X509v3CertificateBuilder/g;
  if (certBuilderRe.test(fileText) && !algoRefs.includes('X509v3CertificateBuilder')) {
    algoRefs.push('X509v3CertificateBuilder');
  }

  const algIdRe = /AlgorithmIdentifier\s*\(\s*(?:new\s+ASN1ObjectIdentifier\s*\(\s*)?["']([^"']+)["']/g;
  while ((m = algIdRe.exec(fileText)) !== null) {
    if (!algoRefs.includes(m[1])) algoRefs.push(m[1]);
  }

  const csrRe = /PKCS10CertificationRequest|JcaPKCS10CertificationRequestBuilder/g;
  if (csrRe.test(fileText)) {
    if (!algoRefs.includes('PKCS10/CSR')) algoRefs.push('PKCS10/CSR');
  }

  const keyTypeRe = /\b(RSA(?:Public|Private)Key|EC(?:Public|Private)Key|EdDSAPublicKey|EdDSAPrivateKey)\b/g;
  while ((m = keyTypeRe.exec(fileText)) !== null) {
    if (!algoRefs.includes(m[1])) algoRefs.push(m[1]);
  }

  const xdhRe = /\b(X25519|X448|XDH)\b/g;
  while ((m = xdhRe.exec(fileText)) !== null) {
    if (!algoRefs.includes(m[1])) algoRefs.push(m[1]);
  }

  if (algoRefs.length > 0) {
    return `X.509 certificate operations in this file use: ${algoRefs.join(', ')}. Review each for PQC readiness.`;
  }
  return 'X.509 certificate detected but could not determine the signature algorithm from this file. Check the certificate signing algorithm and key type used.';
}

/**
 * Scan nearby lines for crypto-relevant context clues.
 * For provider/certificate/WebCrypto detections, scans the entire file.
 * For other patterns, scans ±30 lines.
 */
export function scanNearbyContext(lines: string[], matchLine: number, assetName: string): string | null {
  const isProvider = assetName.toLowerCase().includes('provider');
  const isCertificate = assetName === 'X.509';
  const isWebCrypto = assetName === 'WebCrypto';
  const wholeFile = isProvider || isCertificate || isWebCrypto;
  const start = wholeFile ? 0 : Math.max(0, matchLine - 30);
  const end = wholeFile ? lines.length : Math.min(lines.length, matchLine + 30);
  const nearbyText = lines.slice(start, end).join('\n');

  if (isWebCrypto) {
    return scanWebCryptoContext(nearbyText);
  }

  const algoRefs: string[] = [];
  let m;

  // getInstance("...") calls
  const getInstanceRe = /(?:Cipher|Signature|KeyPairGenerator|KeyFactory|KeyAgreement|MessageDigest|Mac|KeyGenerator|SecretKeyFactory)\.getInstance\s*\(\s*"([^"]+)"/g;
  while ((m = getInstanceRe.exec(nearbyText)) !== null) {
    if (!algoRefs.includes(m[1])) algoRefs.push(m[1]);
  }

  // Signature algorithm references
  const sigAlgoRe = /(SHA\d+with\w+|MD5with\w+|Ed25519|Ed448|ECDSA|RSA|DSA)/g;
  while ((m = sigAlgoRe.exec(nearbyText)) !== null) {
    if (!algoRefs.includes(m[1])) algoRefs.push(m[1]);
  }

  // KeyStore type
  const ksMatch = nearbyText.match(/KeyStore\.getInstance\s*\(\s*"([^"]+)"/);
  if (ksMatch && !algoRefs.includes(ksMatch[1])) algoRefs.push(`KeyStore:${ksMatch[1]}`);

  if (isCertificate) {
    return scanX509Context(nearbyText, algoRefs);
  }

  if (isProvider) {
    // BC provider patterns
    const bcProviderRe = /getInstance\s*\(\s*"([^"]+)"\s*,\s*(?:"BC"|"BouncyCastle"|[Bb]c\w*|new\s+BouncyCastleProvider\s*\(\s*\)|BouncyCastleProvider\.PROVIDER_NAME)\s*\)/g;
    while ((m = bcProviderRe.exec(nearbyText)) !== null) {
      if (!algoRefs.includes(m[1])) algoRefs.unshift(m[1]);
    }

    const bcClassRe = /new\s+((?:JcaContentSignerBuilder|JcaDigestCalculatorProviderBuilder|JcaX509CertificateConverter|JcaX509v3CertificateBuilder|JcePBESecretKeyDecryptorBuilder|JcePKCSPBEInputDecryptorProviderBuilder|BcRSAContentVerifierProviderBuilder|BcECContentVerifierProviderBuilder)\s*\(\s*"?([^")\s]*)"?)/g;
    while ((m = bcClassRe.exec(nearbyText)) !== null) {
      const className = m[1].split('(')[0].trim();
      const arg = m[2]?.trim();
      const label = arg ? `${className}(${arg})` : className;
      if (!algoRefs.includes(label)) algoRefs.push(label);
    }

    const bcPemRe = /(?:PEMParser|PEMKeyPair|JcePEMDecryptorProviderBuilder|JcaPEMKeyConverter)/g;
    while ((m = bcPemRe.exec(nearbyText)) !== null) {
      if (!algoRefs.includes(m[0])) algoRefs.push(m[0]);
    }

    const hasProvider = /Security\.(?:addProvider|insertProviderAt)\s*\(/.test(nearbyText);
    if (algoRefs.length > 0) {
      const prefix = hasProvider
        ? 'BouncyCastle provider registered. Algorithms used through it'
        : 'BouncyCastle provider referenced. Algorithms found in same file';
      return `${prefix}: ${algoRefs.join(', ')}. Review each for PQC readiness.`;
    }
    return 'BouncyCastle provider registered/referenced but no specific algorithm usage found in this file. Check other files that import from this class.';
  }

  if (algoRefs.length > 0) {
    return `${assetName} used alongside: ${algoRefs.join(', ')}. Review these algorithms for PQC readiness.`;
  }
  return null;
}
