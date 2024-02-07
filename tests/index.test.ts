/**
 * Copyright 2024 Tamarin Health
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import {
  secretShare,
  randomBigInt,
  defaultPrime,
  parsePrivateKey,
  stringifyPrivateKey,
  generateKeyPair,
  hybridEncrypt,
  hybridDecrypt,
  secretShareAndEncrypt,
  decryptOneParty,
  toBigIntRow,
} from "../src/index";

test("should generate a bigint", () => {
  const result = randomBigInt();
  expect(typeof result).toBe("bigint");
});

test("should return valid arithmetic shares", () => {
  const value = BigInt(42);
  const result = secretShare(value, 2);
  const sum = result[0] + result[1];
  expect(sum % defaultPrime).toEqual(value);
});

test("should stringify and parse private key", async () => {
  const keyHex = "1".repeat(64);
  const privateKey = await parsePrivateKey(keyHex);
  const keyHex2 = await stringifyPrivateKey(privateKey);
  expect(keyHex2).toBe(keyHex);
});

test("should generate a key pair", async () => {
  const keyPair = await generateKeyPair();
  expect(keyPair.privateKey).toBeTruthy();
  expect(keyPair.publicKey).toBeTruthy();
});

test("should hybrid encrypt and decrypt", async () => {
  const value = "Hello!";
  const { privateKey, publicKey } = await generateKeyPair();
  const secret = await hybridEncrypt(value, publicKey);
  const value2 = await hybridDecrypt(secret, privateKey);
  expect(value2).toBe(value);
});

test("should encrypt and decrypt a row", async () => {
  const keyPair1 = await generateKeyPair();
  const keyPair2 = await generateKeyPair();
  const orignalRow = { a: BigInt(10), b: BigInt(-20) };
  const cipher = await secretShareAndEncrypt(orignalRow, [
    keyPair1.publicKey,
    keyPair2.publicKey,
  ]);
  const row1 = await decryptOneParty(
    cipher,
    keyPair1.privateKey,
    keyPair1.publicKey
  );
  const row2 = await decryptOneParty(
    cipher,
    keyPair2.privateKey,
    keyPair2.publicKey
  );
  expect((row1.a + row2.a) % defaultPrime).toEqual(orignalRow.a);
  expect((row1.b + row2.b) % defaultPrime).toEqual(orignalRow.b);
});

test("should correctly transform the input row", async () => {
  const keyPair = await generateKeyPair();
  const orignalRow = { a: "abc", b: true, c: 123 };
  const mpcRow = await toBigIntRow(orignalRow);
  await expect(secretShareAndEncrypt(mpcRow, [keyPair.publicKey])).resolves.not.toThrow();
});
