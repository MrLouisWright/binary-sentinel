// Authenticode (PE signature) parsing and verification. Pure JS + node:crypto; no network, no OS trust store.
import { createHash, X509Certificate, verify as cryptoVerify } from 'node:crypto';
import { parse, children, value, raw, oid, intHex, ctx } from './asn1.js';

const OID = {
  signedData: '1.2.840.113549.1.7.2', spcIndirect: '1.3.6.1.4.1.311.2.1.4', messageDigest: '1.2.840.113549.1.9.4', contentType: '1.2.840.113549.1.9.3',
  signingTime: '1.2.840.113549.1.9.5', counterSignature: '1.2.840.113549.1.9.6', rfc3161: '1.3.6.1.4.1.311.3.3.1', spcSpOpus: '1.3.6.1.4.1.311.2.1.12', nested: '1.3.6.1.4.1.311.2.4.1',
};
const DIGESTS = { '1.2.840.113549.2.5': 'md5', '1.3.14.3.2.26': 'sha1', '2.16.840.1.101.3.4.2.1': 'sha256', '2.16.840.1.101.3.4.2.2': 'sha384', '2.16.840.1.101.3.4.2.3': 'sha512' };

/**
 * Authenticode image hash (PE/COFF spec): the file minus the checksum field, the security directory entry and the certificate table.
 * @param {Uint8Array} buf @param {string} alg @param {{ checksumOffset: number, securityEntryOffset: number, certOffset: number, certSize: number }} layout
 */
export function imageHash(buf, alg, { checksumOffset, securityEntryOffset, certOffset, certSize }) {
  const h = createHash(alg);
  const certStart = certSize ? certOffset : buf.length;
  h.update(buf.subarray(0, checksumOffset));
  h.update(buf.subarray(checksumOffset + 4, securityEntryOffset));
  h.update(buf.subarray(securityEntryOffset + 8, certStart));
  if (certSize && certOffset + certSize < buf.length) h.update(buf.subarray(certOffset + certSize));
  return h.digest('hex');
}

/** Locate checksum / security directory fields in a PE. */
export function peLayout(buf) {
  const lf = buf.readUInt32LE(0x3c); const opt = lf + 24; const p64 = buf.readUInt16LE(opt) === 0x20b;
  const nd = p64 ? opt + 108 : opt + 92; const securityEntryOffset = nd + 4 + 4 * 8;
  return { checksumOffset: opt + 64, securityEntryOffset, certOffset: buf.readUInt32LE(securityEntryOffset), certSize: buf.readUInt32LE(securityEntryOffset + 4) };
}

/** Parse WIN_CERTIFICATE entries from the certificate table. */
export function certificateTable(buf, layout = peLayout(buf)) {
  const out = []; let o = layout.certOffset; const end = Math.min(buf.length, layout.certOffset + layout.certSize);
  while (o + 8 <= end) {
    const len = buf.readUInt32LE(o); const rev = buf.readUInt16LE(o + 4); const type = buf.readUInt16LE(o + 6);
    if (len < 8 || o + len > end) break;
    out.push({ revision: rev, type, data: buf.subarray(o + 8, o + len) });
    o += Math.ceil(len / 8) * 8;
  }
  return out;
}

const time = (n) => { const s = Buffer.from(value(n)).toString('latin1'); const m = n.tag === 23 ? s.match(/^(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)?Z$/) : s.match(/^(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)?/); if (!m) return null; const y = n.tag === 23 ? (Number(m[1]) >= 50 ? 1900 : 2000) + Number(m[1]) : Number(m[1]); return new Date(Date.UTC(y, m[2] - 1, m[3], m[4], m[5], m[6] || 0)).toISOString(); };

/** Parse one PKCS#7 SignedData blob (an Authenticode signature). */
export function parseSignedData(der) {
  const ci = children(parse(der));
  if (oid(ci[0]) !== OID.signedData) throw new Error('not PKCS#7 SignedData');
  const sd = children(children(ci[1])[0]);
  let i = 1; const digestAlgs = children(sd[i++]).map((a) => DIGESTS[oid(children(a)[0])] || oid(children(a)[0]));
  const eci = children(sd[i++]); const contentType = oid(eci[0]);
  if (contentType !== OID.spcIndirect) throw new Error(`unexpected content type ${contentType}`);
  let spc = children(eci[1])[0]; if (spc.tag === 4) spc = parse(value(spc)); // tolerate OCTET STRING wrapping
  const spcParts = children(spc); const di = children(spcParts[1]);
  const fileDigestAlg = DIGESTS[oid(children(di[0])[0])] || oid(children(di[0])[0]);
  const fileDigest = Buffer.from(value(di[1])).toString('hex');
  const certs = []; let n;
  while ((n = sd[i]) && n.cls === 2) { if (n.tag === 0) for (const c of children(n)) if (c.tag === 16) { try { certs.push(new X509Certificate(Buffer.from(raw(c)))); } catch { /* skip */ } } i++; }
  const signers = children(sd[i]).map((si) => {
    const p = children(si); let k = 1;
    const sid = children(p[k++]); const issuerDer = Buffer.from(raw(sid[0])); const serial = intHex(sid[1]);
    const digest = DIGESTS[oid(children(p[k++])[0])];
    let authAttrs = null; const attrs = {};
    if (p[k].cls === 2 && p[k].tag === 0) {
      authAttrs = p[k];
      for (const a of children(p[k])) { const ap = children(a); const id = oid(ap[0]); const v = children(ap[1])[0]; attrs[id] = v; }
      k++;
    }
    const sigAlg = oid(children(p[k++])[0]); const signature = Buffer.from(value(p[k++]));
    const unauth = {}; if (p[k] && p[k].cls === 2 && p[k].tag === 1) for (const a of children(p[k])) { const ap = children(a); unauth[oid(ap[0])] = children(ap[1]); }
    return { issuerDer, serial, digest, authAttrs, attrs, sigAlg, signature, unauth };
  });
  return { digestAlgs, fileDigestAlg, fileDigest, spc: { value: Buffer.from(value(spc)) }, certs, signers };
}

const certIssuerDer = (c) => { const tbs = children(children(parse(c.raw))[0]); const k = tbs[0].cls === 2 ? 1 : 0; return Buffer.from(raw(tbs[k + 2])); };
const serialOf = (c) => c.serialNumber.replace(/^0+(?=.)/, '').toUpperCase();

/**
 * Verify every Authenticode signature of a PE file.
 * Checks the image hash, the signed message digest and the signer's signature; reports signer, chain, timestamp and validity.
 * Trust in a root CA is NOT evaluated (no OS store): `selfSigned` and `chain` tell you what is there.
 * @param {Uint8Array} buf
 * @param {{ now?: Date|string }} [opts]
 * @returns {{ signed: boolean, valid: boolean, signatures: object[], errors: string[] }}
 */
export function verifyAuthenticode(buf, { now = new Date() } = {}) {
  buf = Buffer.from(buf.buffer, buf.byteOffset, buf.byteLength);
  const res = { signed: false, valid: false, signatures: [], errors: [] };
  let layout; try { layout = peLayout(buf); } catch (e) { res.errors.push(`not a PE: ${e.message}`); return res; }
  if (!layout.certSize) return res;
  res.signed = true;
  if (layout.certOffset + layout.certSize > buf.length) { res.errors.push('certificate table extends past end of file'); return res; }
  const blobs = certificateTable(buf, layout).filter((c) => c.type === 2);
  if (!blobs.length) { res.errors.push('no PKCS#7 signature in the certificate table'); return res; }
  const queue = blobs.map((b) => b.data);
  while (queue.length && res.signatures.length < 8) {
    const der = queue.shift(); const sig = { valid: false, errors: [] }; res.signatures.push(sig);
    let sd; try { sd = parseSignedData(der); } catch (e) { sig.errors.push(`malformed signature: ${e.message}`); continue; }
    sig.digestAlgorithm = sd.fileDigestAlg;
    const actual = DIGESTS[Object.keys(DIGESTS).find((k) => DIGESTS[k] === sd.fileDigestAlg)] ? imageHash(buf, sd.fileDigestAlg, layout) : null;
    sig.imageHashMatches = actual === sd.fileDigest;
    if (!sig.imageHashMatches) sig.errors.push(`file was modified after signing (image ${sd.fileDigestAlg} ${actual} != signed ${sd.fileDigest})`);
    const si = sd.signers[0];
    if (!si) { sig.errors.push('no SignerInfo'); continue; }
    const signer = sd.certs.find((c) => serialOf(c) === si.serial && certIssuerDer(c).equals(si.issuerDer));
    if (!signer) sig.errors.push('signer certificate is not included');
    if (si.authAttrs) {
      const md = si.attrs[OID.messageDigest];
      const mdOk = md && Buffer.from(value(md)).equals(createHash(si.digest).update(sd.spc.value).digest());
      if (!mdOk) sig.errors.push('signed message digest does not match the SpcIndirectData content');
      if (signer) {
        const set = Buffer.from(raw(si.authAttrs)); set[0] = 0x31;
        let ok = false; try { ok = cryptoVerify(si.digest, set, signer.publicKey, si.signature); } catch (e) { sig.errors.push(`signature check failed: ${e.message}`); }
        if (!ok) sig.errors.push('signer signature does not verify');
        sig.signatureVerified = ok;
      }
      if (si.attrs[OID.signingTime]) sig.signingTime = time(si.attrs[OID.signingTime]);
    } else sig.errors.push('no authenticated attributes');
    if (signer) {
      sig.signer = { subject: signer.subject, issuer: signer.issuer, serial: serialOf(signer), validFrom: new Date(signer.validFrom).toISOString(), validTo: new Date(signer.validTo).toISOString(), fingerprint256: signer.fingerprint256 };
      sig.selfSigned = signer.subject === signer.issuer && (() => { try { return signer.verify(signer.publicKey); } catch { return false; } })();
      const chain = [signer]; let cur = signer;
      while (chain.length < 10) { const up = sd.certs.find((c) => !chain.includes(c) && cur.checkIssued(c) && (() => { try { return cur.verify(c.publicKey); } catch { return false; } })()); if (!up) break; chain.push(up); cur = up; }
      sig.chain = chain.map((c) => c.subject.split('\n').find((l) => l.startsWith('CN='))?.slice(3) || c.subject);
      const t = new Date(now);
      sig.expired = t > new Date(signer.validTo); sig.notYetValid = t < new Date(signer.validFrom);
    }
    sig.timestamped = !!(si.unauth[OID.counterSignature] || si.unauth[OID.rfc3161]);
    for (const n of si.unauth[OID.nested] || []) queue.push(Buffer.from(raw(n)));
    sig.valid = sig.errors.length === 0;
  }
  res.valid = res.signatures.length > 0 && res.signatures.every((s) => s.valid);
  res.errors = res.signatures.flatMap((s) => s.errors);
  return res;
}
