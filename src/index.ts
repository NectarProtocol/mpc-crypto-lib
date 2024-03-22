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

import * as crypto from "crypto";
import { AeadId, CipherSuite, KdfId, KemId } from "hpke-js";

const hpkeSuite = new CipherSuite({
  kem: KemId.DhkemP256HkdfSha256,
  kdf: KdfId.HkdfSha256,
  aead: AeadId.Aes128Gcm,
});

/**
 * Represents the hybrid cipher of a row.
 */
export type HybridCipher = {
  cipher: string;
  encapsulatedKey: string;
};

/**
 * Default prime number used in arithmetic secret sharing.
 */
export const defaultPrime = BigInt("170141183460469231731687303715885907969");

/**
 * Generates a random BigInt within [ 0, defaultPrime ~ 2^128 - 1 ]
 * @returns A BigInt value.
 */
export function randomBigInt(): bigint {
  const array = new Uint32Array(4);
  crypto.getRandomValues(array);
  let n = BigInt(array[0]);
  for (let i = 1; i < 4; i++) {
    n = n << BigInt(32);
    n += BigInt(array[i]);
  }
  return n % defaultPrime;
}

/**
 * Performs an arithmetic secret sharing of a given value.
 * @param value - The value to be secret-shared.
 * @param n - The number of parties involved in sharing.
 * @returns An array of BigInt values with the shares.
 * @throws {Error} If the value is incompatible.
 */
export function secretShare(value: bigint, n: number): bigint[] {
  if (!Number.isSafeInteger(n) || n < 1) {
    throw Error("Incorrect party number");
  }
  if (value >= defaultPrime || -value >= defaultPrime) {
    throw Error("Value too large for modulus");
  }
  const sx: bigint[] = [];
  for (let i = 0; i < n - 1; i++) {
    sx.push(randomBigInt());
  }
  const sumSx = sx.reduce((acc, val) => acc + val, BigInt(0));
  sx.push((value - sumSx) % defaultPrime);
  const finalSumSx = sx.reduce((acc, val) => acc + val, BigInt(0));
  if (finalSumSx % defaultPrime !== value) {
    throw Error("Arithmetic secret sharing failed");
  }
  return sx;
}

/**
 * Converts a hexadecimal string to a Uint8Array.
 * @param s - The hexadecimal string to convert.
 * @returns A Uint8Array representing the converted bytes.
 * @throws {Error} If the input is not a valid hexadecimal string.
 */
export function hexToBytes(s: string): Uint8Array {
  // hpke-js/test/utils.ts:hexToBytes
  const v = s.trim();
  if (v.length === 0) {
    return new Uint8Array([]);
  }
  const res = v.match(/[\da-f]{2}/gi);
  if (res === null) {
    throw Error("Not a hex string");
  }
  return new Uint8Array(res.map((h) => parseInt(h, 16)));
}

/**
 * Converts a Uint8Array to a hexadecimal string.
 * @param v - The Uint8Array to convert.
 * @returns A hexadecimal string representing the converted bytes.
 */
export function bytesToHex(v: Uint8Array): string {
  // hpke-js/test/utils.ts:bytesToHex
  return [...v].map((x) => x.toString(16).padStart(2, "0")).join("");
}

/**
 * Generates a key pair for HPKE encryption.
 * @returns An object containing the key pair in hexadecimal string format.
 */
export async function generateKeyPair() {
  const keyPair = await hpkeSuite.kem.generateKeyPair();
  return {
    privateKey: await stringifyPrivateKey(keyPair.privateKey),
    publicKey: await stringifyPublicKey(keyPair.publicKey),
  };
}

/**
 * Converts a CryptoKey object representing a private key to a hexadecimal string.
 * @param key - The private key as a CryptoKey object.
 * @returns The private key in hexadecimal string format.
 */
export async function stringifyPrivateKey(key: CryptoKey): Promise<string> {
  const keyBuffer = await hpkeSuite.kem.serializePrivateKey(key);
  const keyBytes = new Uint8Array(keyBuffer);
  return bytesToHex(keyBytes);
}

/**
 * Converts a CryptoKey object representing a public key to a hexadecimal string.
 * @param key - The public key as a CryptoKey object.
 * @returns The public key in hexadecimal string format.
 */
export async function stringifyPublicKey(key: CryptoKey): Promise<string> {
  const keyBuffer = await hpkeSuite.kem.serializePublicKey(key);
  const keyBytes = new Uint8Array(keyBuffer);
  return bytesToHex(keyBytes);
}

/**
 * Converts a private key from hexadecimal string format to a CryptoKey object.
 * @param privateKey - The private key in hexadecimal string format.
 * @returns The parsed private key as a CryptoKey object.
 */
export async function parsePrivateKey(privateKey: string): Promise<CryptoKey> {
  const keyBytes = hexToBytes(privateKey);
  return await hpkeSuite.kem.deserializePrivateKey(keyBytes);
}

/**
 * Converts a public key from hexadecimal string format to a CryptoKey object.
 * @param publicKey - The public key in hexadecimal string format.
 * @returns The parsed public key as a CryptoKey object.
 */
export async function parsePublicKey(publicKey: string): Promise<CryptoKey> {
  const keyBytes = hexToBytes(publicKey);
  return await hpkeSuite.kem.deserializePublicKey(keyBytes);
}

/**
 * Encrypts a message (e.g., a secret shared row) using HPKE hybrid encryption.
 * @param value - The string to be encrypted.
 * @param publicKey - The recipient's public key in hexadecimal string format.
 * @returns A HybridCipher object containing the ciphertext and encapsulated key.
 */
export async function hybridEncrypt(
  value: string,
  publicKey: string
): Promise<HybridCipher> {
  const recipientPublicKey = await parsePublicKey(publicKey);
  const sender = await hpkeSuite.createSenderContext({ recipientPublicKey });
  const textEncoder = new TextEncoder();
  const valueBytes = textEncoder.encode(value);
  const cipherBuffer = await sender.seal(valueBytes);
  const cipherBytes = new Uint8Array(cipherBuffer);
  const enKeyBytes = new Uint8Array(sender.enc);
  return {
    cipher: bytesToHex(cipherBytes),
    encapsulatedKey: bytesToHex(enKeyBytes),
  };
}

/**
 * Decrypts a message (e.g., a secret shared row) using HPKE hybrid decryption.
 * @param secret - The HybridCipher object containing the ciphertext and encapsulated key.
 * @param privateKey - The recipient's private key in hexadecimal string format.
 * @returns The decrypted message as a string.
 */
export async function hybridDecrypt(
  secret: HybridCipher,
  privateKey: string
): Promise<string> {
  const key = await parsePrivateKey(privateKey);
  const recipient = await hpkeSuite.createRecipientContext({
    recipientKey: key,
    enc: hexToBytes(secret.encapsulatedKey),
  });
  const cipherBytes = hexToBytes(secret.cipher);
  const valueBuffer = await recipient.open(cipherBytes);
  const textDecoder = new TextDecoder();
  return textDecoder.decode(valueBuffer);
}

/**
 * Secret shares a row of data and then encrypts it with HPKE.
 * @param row - The row of data to be encrypted.
 * @param publicKeys - An array of public keys corresponding to each party.
 * @returns A serialized JSON string representing the encrypted data.
 */
export async function secretShareAndEncrypt(
  row: Record<string, bigint>,
  publicKeys: string[]
): Promise<string> {
  // Ensure every cell is a bigint
  for (const key in row) {
    if (typeof row[key] !== "bigint") {
      throw Error("Expected bigint value");
    }
  }

  // Ensure all public keys are unique
  if (new Set(publicKeys).size !== publicKeys.length) {
    throw Error("Expected public keys to be unique");
  }

  // Map each cell to a secret share array
  const n = publicKeys.length;
  const m1: Record<string, bigint[]> = {};
  for (const key in row) {
    m1[key] = secretShare(row[key], n);
  }

  // Create a row for each party
  const m2: Record<string, HybridCipher> = {};
  for (let party = 0; party < n; party++) {
    const sRow: Record<string, string> = {};
    for (const key in row) {
      sRow[key] = m1[key][party].toString();
    }
    const publicKey = publicKeys[party];
    const jSRow = JSON.stringify(sRow);
    m2[publicKey] = await hybridEncrypt(jSRow, publicKey);
  }

  // Serialize and return
  return JSON.stringify(m2);
}

/**
 * Decrypts a row of data to access the secret shares associated with the key pair.
 * @param cipher - The encrypted data in JSON format.
 * @param privateKey - The private key of the party in hexadecimal string format.
 * @param publicKey - The public key of the party in hexadecimal string format.
 * @returns The decrypted row of data as a Record<string, bigint>.
 */
export async function decryptOneParty(
  cipher: string,
  privateKey: string,
  publicKey: string
): Promise<Record<string, bigint>> {
  const m2 = JSON.parse(cipher) as Record<string, HybridCipher>;
  const jSRow = await hybridDecrypt(m2[publicKey], privateKey);
  const sRow = JSON.parse(jSRow) as Record<string, string>;
  const bRow: Record<string, bigint> = {};
  for (const key in sRow) {
    bRow[key] = BigInt(sRow[key]);
  }
  return bRow;
}

/**
 * Converts a string message to a fixed-size hash value represented as a BigInt.
 * NOTE: Hashes are not cryptographically collision-resistant!
 * @param message - The string message to be hashed.
 * @returns The hashed value as a BigInt.
 */
export async function stringToHash(message: string): Promise<bigint> {
  const encoder = new TextEncoder();
  const data = encoder.encode(message);
  const buffer = await crypto.subtle.digest("SHA-256", data);
  const bytes = new Uint8Array(buffer).slice(0, 8);
  const hex = `0x${bytesToHex(bytes)}`;
  return BigInt(hex); // Range: [ 0, 2^64 - 1 ]
}

/**
 * Converts a number to a fixed-point BigInt representation.
 * @param n - The number to be converted.
 * @returns The fixed-point representation of the number as a BigInt.
 * @throws {Error} If the input number is too large.
 */
export async function numberToFixPoint(n: number): Promise<bigint> {
  if (Math.abs(n) >= 2 ** 32) {
    throw Error("Input number too large");
  }
  const fixedPoint = Math.floor(n * 2 ** 31);
  return BigInt(fixedPoint);
}

/**
 * Converts various types of values (number, boolean, string) to BigInt.
 * @param n - The value to be converted.
 * @returns The value converted to BigInt.
 * @throws {Error} If the input type is not supported.
 */
export async function toBigIntValue(
  n: number | boolean | string
): Promise<bigint> {
  if (typeof n === "number") {
    return await numberToFixPoint(n);
  } else if (typeof n === "boolean") {
    return BigInt(n);
  } else if (typeof n === "string") {
    return await stringToHash(n);
  } else {
    throw Error("Unsupported type");
  }
}

/**
 * Converts a row of data containing numbers, booleans, or strings to BigInt representation.
 * @param row - The row of data to be converted.
 * @returns The row of data with values converted to BigInt.
 */
export async function toBigIntRow(
  row: Record<string, number | boolean | string>
): Promise<Record<string, bigint>> {
  const biRow: Record<string, bigint> = {};
  for (const key in row) {
    biRow[key] = await toBigIntValue(row[key]);
  }
  return biRow;
}
