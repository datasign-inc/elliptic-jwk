# elliptic-jwk

This library is a wrapper around the elliptic curve cryptography library ([indutny/elliptic](https://github.com/indutny/elliptic)) and provides support for working with JSON Web Keys (JWKs).

## Installation

You can install the library using npm:

```bash
npm install elliptic-jwk
```

## Usage
To use the library, you first need to import it into your project:

```typescript
import { toPrivateJwk, publicJwkFromPrivate } from "elliptic-jwk";
```

`toPrivateJwk(privateKey: string, curve: string): object`

This function takes a hexadecimal string `privateKey` and the name of an elliptic curve `curve` as arguments, and returns a JWK representation of the private key.

Example:
```typescript
const privateKey = '<hex string private key>';
const curve = "secp256k1";
const privateJwk = toPrivateJwk(privateKey, curve);
console.log(privateJwk);
```

Output:
```json
{
    "kty": "EC",
    "d": "<base64 encoded string private key>",
    "crv": "secp256k1",
    "x": "<base64 encoded string x>",
    "y": "<base64 encoded string y>"
}
```

`publicJwkFromPrivate(privateJwk: object): object`

This function takes a JWK representation of a private key `privateJwk` as an argument, and returns a JWK representation of the corresponding public key.

Example:
```typescript
const privateKey = '<hex string private key>';
const curve = "secp256k1";
const privateJwk = toPrivateJwk(privateKey, curve);
const publicKeyJwk = publicJwkFromPrivate(privateJwk);
console.log(publicKeyJwk);
```

Output:
```json
{
    "kty": "EC",
    "crv": "secp256k1",
    "x": "<base64 encoded string x>",
    "y": "<base64 encoded string y>"
}
```
