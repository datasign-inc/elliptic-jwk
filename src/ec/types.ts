export type CRV = "secp256k1" | "P-256" | "Ed25519";

export interface PublicJwk {
  kty: "EC" | "OKP";
  // The crv type compatible with ion-tools
  // https://github.com/decentralized-identity/ion-tools#iongeneratekeypair-async
  crv: CRV;
  x: string;
  y?: string;
}
export interface PrivateJwk extends PublicJwk {
  d: string;
}
