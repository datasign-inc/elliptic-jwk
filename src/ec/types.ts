export type CurveEC = "secp256k1" | "P-256" | "P-384";
export type CurveOKP = "Ed25519" | "X25519";
export type CRV = CurveEC | CurveOKP;
export type KTY = "EC" | "OKP";

export interface PublicJwk {
  kty: KTY;
  // The crv type compatible with ion-tools
  // https://github.com/decentralized-identity/ion-tools#iongeneratekeypair-async
  crv: CRV;
  x: string;
  y?: string;
}
export interface PrivateJwk extends PublicJwk {
  d: string;
}
