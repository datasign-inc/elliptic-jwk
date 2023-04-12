import base64url from "base64url";
import pkg, { eddsa } from "elliptic";
import crypto from "crypto";
import { CRV, PrivateJwk, PublicJwk } from "./types";

type EcCrv = Exclude<CRV, "Ed25519">;

const { ec: EC, eddsa: EdDSA } = pkg;

const curveNameMap: { [key in CRV]: string } = {
  secp256k1: "secp256k1",
  Ed25519: "ed25519",
  "P-256": "p256",
};

// -------------------------- Common -------------------------------
export const publicJwkFromPrivate = (privateKey: PrivateJwk) => {
  const { d, ...rest } = privateKey;
  return { ...rest };
};
export const toPrivateJwk: {
  (privateKey: string, crv: EcCrv): PrivateJwk;
  (privateKey: string): PrivateJwk;
} = (privateKey: string, crv?: EcCrv) => {
  if (crv) {
    return toPrivateEcJwk(privateKey, crv);
  } else {
    return toPrivateEdDsaJwk(privateKey);
  }
};
export const newPrivateJwk: {
  (crv: EcCrv): PrivateJwk;
  (): PrivateJwk;
} = (crv?: EcCrv) => {
  if (crv) {
    return newPrivateEcJwk(crv);
  } else {
    return newPrivateEdDsaJwk();
  }
};
// -------------------------- EC -------------------------------
const privateKeyToECKeyPair = (privateKey: string, crv: CRV) => {
  const ec = new EC(curveNameMap[crv]);
  return ec.keyFromPrivate(privateKey);
  // return ec.keyFromPrivate(Buffer.from(privateKey, "hex"));
  // return ec.keyFromPrivate(base64url.toBuffer(privateKey));
};
export const generateECKeyPair = (crv: CRV = "secp256k1") => {
  const ec = new EC(curveNameMap[crv]);
  return ec.genKeyPair();
};

const foo: {
  (): string;
  (x: string): string;
  (x: number, y: string): string;
} = (x?: string | number, y?) => {
  if (typeof x === "string") {
    console.log(x);
    return x;
  } else if (typeof y === "string") {
    return Number(x).toString();
  } else {
    console.log("foo");
    return "";
  }
};
const _toPublicEcJwk = (keyPair: pkg.ec.KeyPair, crv: EcCrv): PublicJwk => {
  const _key = keyPair.getPublic();
  const kty = "EC";
  return {
    kty,
    crv,
    x: base64url.encode(_key.getX().toArrayLike(Buffer, "be", 32)),
    y: base64url.encode(_key.getY().toArrayLike(Buffer, "be", 32)),
  };
};
const toPublicEcJwk = (privateKey: string, crv: EcCrv): PublicJwk => {
  const keyPair = privateKeyToECKeyPair(privateKey, crv);
  return _toPublicEcJwk(keyPair, crv);
};
const toPrivateEcJwk = (privateKey: string, crv: EcCrv): PrivateJwk => {
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
const newPrivateEcJwk = (crv: EcCrv): PrivateJwk => {
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
  // const buf = new Uint8Array(crypto.randomBytes(32).buffer);
  // const num = new BN(buf).toNumber();
  // const hex = buf.toString("hex");
  const hex = buf.toString("hex");
  // const hex = "0x" + buf.toString("hex");
  console.log({ hex, len: buf.length });
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

// export default {
//   newPrivateJwk,
//   toPrivateJwk,
//   publicJwkFromPrivate,
// };
