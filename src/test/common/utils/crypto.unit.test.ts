// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

'use strict';

import { assert } from 'chai';
import { CryptoUtils } from '../../../client/common/utils/crypto';

suite('CryptoUtils Tests', () => {
    let cryptoUtils: CryptoUtils;

    setup(() => {
        cryptoUtils = new CryptoUtils();
    });

    suite('getRandomPrivateKey', () => {
        test('Should generate a private key with default length', () => {
            const key = cryptoUtils.getRandomPrivateKey();
            assert.equal(key.length, 64); // 32 bytes * 2 (hex encoding)
            assert.match(key, /^[0-9a-f]+$/i);
        });

        test('Should generate a private key with custom length', () => {
            const key = cryptoUtils.getRandomPrivateKey(16);
            assert.equal(key.length, 32); // 16 bytes * 2 (hex encoding)
            assert.match(key, /^[0-9a-f]+$/i);
        });

        test('Should generate different keys on subsequent calls', () => {
            const key1 = cryptoUtils.getRandomPrivateKey();
            const key2 = cryptoUtils.getRandomPrivateKey();
            assert.notEqual(key1, key2);
        });
    });

    suite('getSecp256k1PrivateKey', () => {
        test('Should generate a valid secp256k1 private key', () => {
            const key = cryptoUtils.getSecp256k1PrivateKey();
            assert.equal(key.length, 64); // 32 bytes * 2 (hex encoding)
            assert.match(key, /^[0-9a-f]+$/i);
        });

        test('Should generate different keys on subsequent calls', () => {
            const key1 = cryptoUtils.getSecp256k1PrivateKey();
            const key2 = cryptoUtils.getSecp256k1PrivateKey();
            assert.notEqual(key1, key2);
        });
    });

    suite('getEd25519PrivateKey', () => {
        test('Should generate a valid ed25519 private key', () => {
            const key = cryptoUtils.getEd25519PrivateKey();
            assert.equal(key.length, 64); // 32 bytes * 2 (hex encoding)
            assert.match(key, /^[0-9a-f]+$/i);
        });

        test('Should generate different keys on subsequent calls', () => {
            const key1 = cryptoUtils.getEd25519PrivateKey();
            const key2 = cryptoUtils.getEd25519PrivateKey();
            assert.notEqual(key1, key2);
        });
    });

    suite('validatePrivateKeyFormat', () => {
        test('Should validate correct 32-byte hex keys', () => {
            const validKey = 'a'.repeat(64);
            assert.isTrue(cryptoUtils.validatePrivateKeyFormat(validKey));
        });

        test('Should validate correct 16-byte hex keys', () => {
            const validKey = 'a'.repeat(32);
            assert.isTrue(cryptoUtils.validatePrivateKeyFormat(validKey));
        });

        test('Should reject invalid hex characters', () => {
            const invalidKey = 'g'.repeat(64);
            assert.isFalse(cryptoUtils.validatePrivateKeyFormat(invalidKey));
        });

        test('Should reject invalid length', () => {
            const shortKey = 'a'.repeat(30);
            assert.isFalse(cryptoUtils.validatePrivateKeyFormat(shortKey));
        });

        test('Should reject empty string', () => {
            assert.isFalse(cryptoUtils.validatePrivateKeyFormat(''));
        });
    });

    suite('validateAddressFormat', () => {
        test('Should validate generic addresses of reasonable length', () => {
            const address = 'a'.repeat(30);
            assert.isTrue(cryptoUtils.validateAddressFormat(address, 'generic'));
        });

        test('Should validate Bitcoin P2PKH addresses', () => {
            const address = '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2';
            assert.isTrue(cryptoUtils.validateAddressFormat(address, 'bitcoin'));
        });

        test('Should validate Bitcoin Bech32 addresses', () => {
            const address = 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4';
            assert.isTrue(cryptoUtils.validateAddressFormat(address, 'bitcoin'));
        });

        test('Should validate Ethereum addresses', () => {
            const address = '0x742d35Cc6634C0532925a3b8D3Ac3f4532d456d9';
            assert.isTrue(cryptoUtils.validateAddressFormat(address, 'ethereum'));
        });

        test('Should reject invalid Ethereum addresses', () => {
            const address = '0x742d35Cc6634C0532925a3b8D3Ac3f4532d456d'; // Too short
            assert.isFalse(cryptoUtils.validateAddressFormat(address, 'ethereum'));
        });

        test('Should reject addresses that are too short', () => {
            const address = 'short';
            assert.isFalse(cryptoUtils.validateAddressFormat(address, 'generic'));
        });

        test('Should reject addresses that are too long', () => {
            const address = 'a'.repeat(150);
            assert.isFalse(cryptoUtils.validateAddressFormat(address, 'generic'));
        });
    });

    suite('generateSeed', () => {
        test('Should generate a seed with default length', () => {
            const seed = cryptoUtils.generateSeed();
            assert.equal(seed.length, 128); // 64 bytes * 2 (hex encoding)
            assert.match(seed, /^[0-9a-f]+$/i);
        });

        test('Should generate a seed with custom length', () => {
            const seed = cryptoUtils.generateSeed(32);
            assert.equal(seed.length, 64); // 32 bytes * 2 (hex encoding)
            assert.match(seed, /^[0-9a-f]+$/i);
        });

        test('Should generate different seeds on subsequent calls', () => {
            const seed1 = cryptoUtils.generateSeed();
            const seed2 = cryptoUtils.generateSeed();
            assert.notEqual(seed1, seed2);
        });
    });

    suite('calculateHash', () => {
        test('Should calculate SHA256 hash of string', () => {
            const data = 'Hello, World!';
            const hash = cryptoUtils.calculateHash(data);
            assert.equal(hash.length, 64); // SHA256 produces 32 bytes = 64 hex chars
            assert.match(hash, /^[0-9a-f]+$/i);
        });

        test('Should calculate SHA256 hash of buffer', () => {
            const data = Buffer.from('Hello, World!');
            const hash = cryptoUtils.calculateHash(data);
            assert.equal(hash.length, 64);
            assert.match(hash, /^[0-9a-f]+$/i);
        });

        test('Should calculate MD5 hash when specified', () => {
            const data = 'Hello, World!';
            const hash = cryptoUtils.calculateHash(data, 'md5');
            assert.equal(hash.length, 32); // MD5 produces 16 bytes = 32 hex chars
            assert.match(hash, /^[0-9a-f]+$/i);
        });

        test('Should produce consistent hashes for same input', () => {
            const data = 'Test data';
            const hash1 = cryptoUtils.calculateHash(data);
            const hash2 = cryptoUtils.calculateHash(data);
            assert.equal(hash1, hash2);
        });

        test('Should produce different hashes for different inputs', () => {
            const hash1 = cryptoUtils.calculateHash('data1');
            const hash2 = cryptoUtils.calculateHash('data2');
            assert.notEqual(hash1, hash2);
        });
    });

    suite('generateTransactionId', () => {
        test('Should generate a valid UUID', () => {
            const id = cryptoUtils.generateTransactionId();
            const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
            assert.match(id, uuidRegex);
        });

        test('Should generate different IDs on subsequent calls', () => {
            const id1 = cryptoUtils.generateTransactionId();
            const id2 = cryptoUtils.generateTransactionId();
            assert.notEqual(id1, id2);
        });
    });
});