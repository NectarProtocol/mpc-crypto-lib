# mpc-crypto-lib

This library provides data encryption functionalities for multi-party computation (MPC). Its primary purpose is to input a row of data, perform arithmetic secret sharing, and then hybrid encrypt the shares of each node with their respective public keys. Finally, all the encrypted shares are outputted as a single-string cipher.

This Typescript module works in both web browsers and Node.js.

## Setup

```sh
npm install
npm run build
npm test
```

## Cell types

| Type      | Supported | Description                                                                                                                           |
| --------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| `number`  | **Yes**   | All numbers, both decimals and integers, are converted to a fixed-point `BigInt` representation.                                      |
| `string`  | **Yes**   | Strings are hashed to non-cryptographically collision-resistant 64-bit `BigInts`. It will, therefore, only support equal comparisons. |
| `boolean` | **Yes**   | Represented as `BigInt(0)` for false, and `BigInt(1)` for true.                                                                       |

## Example

```js
import {
  toBigIntRow,
  encrypt,
  generateKeyPair,
  decryptOneParty,
  defaultPrime,
} from "./index";

async function demo() {
  // Generate key pair for MPC node 1
  const kp1 = await generateKeyPair();

  // Generate key pair for MPC node 1
  const kp2 = await generateKeyPair();

  // Input data
  const orignalRow = { a: "abc", b: true, c: 123 };

  // Convert cells to BigInt
  const mpcRow = await toBigIntRow(orignalRow);

  // Encrypt row with MPC public keys
  const cipher = await encrypt(mpcRow, [kp1.publicKey, kp2.publicKey]);

  // MPC 1 decrypt its secret shares
  const row1 = await decryptOneParty(cipher, kp1.privateKey, kp1.publicKey);

  // MPC 2 decrypt its secret shares
  const row2 = await decryptOneParty(cipher, kp2.privateKey, kp2.publicKey);

  console.log((row1.a + row2.a) % defaultPrime === mpcRow.a); // true
}

demo();
```
