# mpc-crypto-lib

This library provides data encryption functionalities for multi-party computation (MPC). Its primary purpose is to input a row of data, perform arithmetic secret sharing, and then hybrid encrypt (RFC-9180) the shares of each node with their respective public keys. Finally, all the encrypted shares are outputted as a single-string cipher.

This Typescript module works in both web browsers and Node.js.

## Run Tests

```sh
npm install
npm run build
npm test
```

## Install

```sh
npm i mpc-crypto-lib
```

## Cell Types

| Type      | Supported | Description                                                                                                                           |
| --------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| `number`  | **Yes**   | All numbers, both decimals and integers, are converted to a fixed-point `BigInt` representation.                                      |
| `string`  | **Yes**   | Strings are hashed to non-cryptographically collision-resistant 64-bit `BigInts`. It will, therefore, only support equal comparisons. |
| `boolean` | **Yes**   | Represented as `BigInt(0)` for false, and `BigInt(1)` for true.                                                                       |

## Example

```js
import {
  toBigIntRow,
  secretShareAndEncrypt,
  generateKeyPair,
  decryptOneParty,
  defaultPrime,
} from "mpc-crypto-lib";

async function demo() {
  // Generate key pair for MPC node 1
  const kp1 = await generateKeyPair();

  // Generate key pair for MPC node 1
  const kp2 = await generateKeyPair();

  // Input data
  const orignalRow = { a: "abc", b: true, c: 12.3 };

  // Convert cells to BigInt
  const mpcRow = await toBigIntRow(orignalRow);

  // Encrypt row with MPC public keys
  const cipher = await secretShareAndEncrypt(mpcRow, [
    kp1.publicKey,
    kp2.publicKey,
  ]);

  // MPC node 1 decrypts its secret shares
  const row1 = await decryptOneParty(cipher, kp1.privateKey, kp1.publicKey);

  // MPC node 2 decrypts its secret shares
  const row2 = await decryptOneParty(cipher, kp2.privateKey, kp2.publicKey);

  console.log((row1.a + row2.a) % defaultPrime === mpcRow.a); // true
}

demo();
```

## Acknowledgment

This project was supported by the National Science Foundation under grant #2026461.
