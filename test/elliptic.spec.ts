import pkg, { eddsa } from "elliptic";
import { importJWK, CompactSign, compactVerify } from "jose";

import {
  toPrivateJwk,
  newPrivateJwk,
  publicJwkFromPrivate,
} from "../src/ec/elliptic";
import { assert } from "chai";

const { ec: EC, eddsa: EdDSA } = pkg;

describe("test with issued key", () => {
  const privateKeyHex =
    "7c43fb7cea9a6b2a0b6f97c6c6313c9e067e2933eb45a5101760544874b15790";
  it("secp256k1", async () => {
    const privateJwk = toPrivateJwk(privateKeyHex, "secp256k1");
    // const privateJwk = ec.toPrivateEcJwk(privateKeyHex, "secp256k1");
    // @ts-ignore
    const privateKey = await importJWK(privateJwk);
    const data = "test";
    const encoder = new TextEncoder();
    const jws = new CompactSign(encoder.encode(data));
    jws.setProtectedHeader({
      alg: "ES256K",
      kid: "key-1",
    });
    const signedData = await jws.sign(privateKey);
    const publicJwk = publicJwkFromPrivate(privateJwk);
    // @ts-ignore
    const publicKey = await importJWK(publicJwk);
    const { payload, protectedHeader } = await compactVerify(
      signedData,
      publicKey
    );
    const decodedData = new TextDecoder().decode(payload);
    assert.equal(decodedData, "test");
    assert.equal(protectedHeader.alg, "ES256K");
  });
  it("Ed25519", async () => {
    const privateJwk = toPrivateJwk(privateKeyHex);
    // const privateJwk = ec.toPrivateEdDsaJwk(privateKeyHex);
    // @ts-ignore
    const privateKey = await importJWK(privateJwk);
    const data = "test";
    const encoder = new TextEncoder();
    const jws = new CompactSign(encoder.encode(data));
    jws.setProtectedHeader({
      alg: "EdDSA",
      kid: "key-1",
    });
    const signedData = await jws.sign(privateKey);
    const publicJwk = publicJwkFromPrivate(privateJwk);
    // @ts-ignore
    const publicKey = await importJWK(publicJwk);
    const { payload, protectedHeader } = await compactVerify(
      signedData,
      publicKey
    );
    const decodedData = new TextDecoder().decode(payload);
    assert.equal(decodedData, "test");
    assert.equal(protectedHeader.alg, "EdDSA");
  });
});
describe("test with new key", () => {
  it("secp256k1", async () => {
    const privateJwk = newPrivateJwk("secp256k1");
    // @ts-ignore
    const privateKey = await importJWK(privateJwk);
    const data = "test";
    const encoder = new TextEncoder();
    const jws = new CompactSign(encoder.encode(data));
    jws.setProtectedHeader({
      alg: "ES256K",
      kid: "key-1",
    });
    const signedData = await jws.sign(privateKey);
    const publicJwk = publicJwkFromPrivate(privateJwk);
    // @ts-ignore
    const publicKey = await importJWK(publicJwk);
    const { payload, protectedHeader } = await compactVerify(
      signedData,
      publicKey
    );
    const decodedData = new TextDecoder().decode(payload);
    assert.equal(decodedData, "test");
    assert.equal(protectedHeader.alg, "ES256K");
  });

  it("Ed25519", async () => {
    const privateJwk = newPrivateJwk();
    // @ts-ignore
    const privateKey = await importJWK(privateJwk);
    const data = "test";
    const encoder = new TextEncoder();
    const jws = new CompactSign(encoder.encode(data));
    jws.setProtectedHeader({
      alg: "EdDSA",
      kid: "key-1",
    });
    const signedData = await jws.sign(privateKey);
    const publicJwk = publicJwkFromPrivate(privateJwk);
    // @ts-ignore
    const publicKey = await importJWK(publicJwk);
    const { payload, protectedHeader } = await compactVerify(
      signedData,
      publicKey
    );
    const decodedData = new TextDecoder().decode(payload);
    assert.equal(decodedData, "test");
    assert.equal(protectedHeader.alg, "EdDSA");
  });
});
