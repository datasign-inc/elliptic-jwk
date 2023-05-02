import base64url from "base64url";
import pkg, { eddsa } from "elliptic";
import crypto from "crypto";
import { CRV, CurveEC, KTY, PrivateJwk, PublicJwk } from "./types";

const { ec: EC, eddsa: EdDSA } = pkg;

const curveNameMap: { [key in CRV]: string } = {
  secp256k1: "secp256k1",
  Ed25519: "ed25519",
  "P-256": "p256",
  "P-384": "p384",
  X25519: "curve25519",
};
const curveKtyMap: { [key in CRV]: KTY } = {
  secp256k1: "EC",
  "P-256": "EC",
  "P-384": "EC",
  Ed25519: "OKP",
  X25519: "OKP",
};

// -------------------------- Common -------------------------------
export const publicJwkFromPrivate = (privateKey: PrivateJwk) => {
  const { d, ...rest } = privateKey;
  return { ...rest };
};
const ecCurveSet: Set<CurveEC> = new Set(["secp256k1", "P-256"]);

const isCurveEC = (crv: CRV): crv is CurveEC => {
  return crv === "secp256k1" || crv === "P-256" || crv === "P-384";
};
export const toPrivateJwk = (privateKey: string, crv: CRV) => {
  if (isCurveEC(crv)) {
    return toPrivateEcJwk(privateKey, crv);
  } else {
    return toPrivateEdDsaJwk(privateKey);
  }
};
export const newPrivateJwk = (crv: CRV) => {
  if (isCurveEC(crv)) {
    return newPrivateEcJwk(crv);
  } else {
    return newPrivateEdDsaJwk();
  }
};
// -------------------------- EC -------------------------------
const privateKeyToECKeyPair = (privateKey: string, crv: CRV) => {
  const ec = new EC(curveNameMap[crv]);
  return ec.keyFromPrivate(privateKey);
};
export const generateECKeyPair = (crv: CRV = "secp256k1") => {
  const ec = new EC(curveNameMap[crv]);
  return ec.genKeyPair();
};

const _toPublicEcJwk = (keyPair: pkg.ec.KeyPair, crv: CurveEC): PublicJwk => {
  const _key = keyPair.getPublic();
  const kty = curveKtyMap[crv];
  return {
    kty,
    crv,
    x: base64url.encode(_key.getX().toArrayLike(Buffer, "be", 32)),
    y: base64url.encode(_key.getY().toArrayLike(Buffer, "be", 32)),
  };
};
const toPublicEcJwk = (privateKey: string, crv: CurveEC): PublicJwk => {
  const keyPair = privateKeyToECKeyPair(privateKey, crv);
  return _toPublicEcJwk(keyPair, crv);
};
const toPrivateEcJwk = (privateKey: string, crv: CurveEC): PrivateJwk => {
  const keyPair = privateKeyToECKeyPair(privateKey, crv);
  const publicJwk = _toPublicEcJwk(keyPair, crv);
  const d = base64url.encode(
    keyPair.getPrivate().toArrayLike(Buffer, "be", 32)
  );
  return {
    ...publicJwk,
    d,
  };
};
const newPrivateEcJwk = (crv: CurveEC): PrivateJwk => {
  const keyPair = generateECKeyPair(crv);
  const publicJwk = _toPublicEcJwk(keyPair, crv);
  const d = base64url.encode(
    keyPair.getPrivate().toArrayLike(Buffer, "be", 32)
  );
  return {
    ...publicJwk,
    d,
  };
};

// -------------------------- EdDsa -------------------------------
const privateKeyToEdDSAKeyPair = (privateKey: string) => {
  const ec = new EdDSA("ed25519");
  return ec.keyFromSecret(privateKey);
};
// not test yet
export const generateEdDSAKeyPair = () => {
  const buf = crypto.randomBytes(32);
  const hex = buf.toString("hex");
  // const hex = "0x" + buf.toString("hex");
  const ec = new EdDSA("ed25519");
  return ec.keyFromSecret(hex);
};
const newPrivateEdDsaJwk = (): PrivateJwk => {
  const keyPair = generateEdDSAKeyPair();
  const publicJwk = _toPublicEdDsaJwk(keyPair);
  const d = base64url.encode(keyPair.getSecret());
  return {
    ...publicJwk,
    d,
  };
};

const _toPublicEdDsaJwk = (keyPair: pkg.eddsa.KeyPair): PublicJwk => {
  const kty = "OKP";
  return {
    kty,
    crv: "Ed25519",
    x: base64url.encode(keyPair.getPublic()),
  };
};
const toPublicEdDsaJwk = (privateKey: string): PublicJwk => {
  const keyPair = privateKeyToEdDSAKeyPair(privateKey);
  return _toPublicEdDsaJwk(keyPair);
};
const toPrivateEdDsaJwk = (privateKey: string): PrivateJwk => {
  const keyPair = privateKeyToEdDSAKeyPair(privateKey);
  const publicJwk = _toPublicEdDsaJwk(keyPair);
  const d = base64url.encode(keyPair.getSecret());
  return {
    ...publicJwk,
    d,
  };
};
