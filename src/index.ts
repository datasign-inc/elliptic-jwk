// import ec from "./ec/elliptic";
import * as ec from "./ec/elliptic.js";
export type { PublicJwk, PrivateJwk, CRV } from "./ec/types";
export const { toPrivateJwk, newPrivateJwk, publicJwkFromPrivate } = ec;
export default ec;
