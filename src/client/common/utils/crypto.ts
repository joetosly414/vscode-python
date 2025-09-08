// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

'use strict';

import * as crypto from 'crypto';
import { injectable } from 'inversify';
import { ICryptoUtils } from '../types';

/**
 * Cryptographic utilities for Python cryptocurrency development support
 */
@injectable()
export class CryptoUtils implements ICryptoUtils {
    /**
     * Generate a cryptographically secure random private key
     * @param length Key length in bytes (default: 32 for 256-bit keys)
     * @returns Hex-encoded private key
     */
    public getRandomPrivateKey(length: number = 32): string {
        const key = crypto.randomBytes(length);
        return key.toString('hex');
    }

    /**
     * Generate a random private key suitable for secp256k1 curve
     * @returns 32-byte hex-encoded private key
     */
    public getSecp256k1PrivateKey(): string {
        let key: Buffer;
        do {
            key = crypto.randomBytes(32);
        } while (this.isValidSecp256k1Key(key));
        
        return key.toString('hex');
    }

    /**
     * Generate a random private key suitable for ed25519 curve
     * @returns 32-byte hex-encoded private key
     */
    public getEd25519PrivateKey(): string {
        return crypto.randomBytes(32).toString('hex');
    }

    /**
     * Validate if a hex string is a valid private key format
     * @param privateKey Hex-encoded private key
     * @returns True if valid format
     */
    public validatePrivateKeyFormat(privateKey: string): boolean {
        // Check if it's a valid hex string of appropriate length
        const hexRegex = /^[0-9a-fA-F]+$/;
        return hexRegex.test(privateKey) && [32, 64].includes(privateKey.length);
    }

    /**
     * Validate if a string looks like a cryptocurrency address
     * @param address Address string to validate
     * @param addressType Type of address (bitcoin, ethereum, etc.)
     * @returns True if format appears valid
     */
    public validateAddressFormat(address: string, addressType: string = 'generic'): boolean {
        switch (addressType.toLowerCase()) {
            case 'bitcoin':
                return this.validateBitcoinAddress(address);
            case 'ethereum':
                return this.validateEthereumAddress(address);
            case 'generic':
            default:
                return address.length > 20 && address.length < 100;
        }
    }

    /**
     * Generate a secure random seed for key derivation
     * @param length Seed length in bytes (default: 64)
     * @returns Hex-encoded seed
     */
    public generateSeed(length: number = 64): string {
        return crypto.randomBytes(length).toString('hex');
    }

    /**
     * Calculate hash for transaction or message signing
     * @param data Data to hash
     * @param algorithm Hash algorithm (default: sha256)
     * @returns Hex-encoded hash
     */
    public calculateHash(data: string | Buffer, algorithm: string = 'sha256'): string {
        const hash = crypto.createHash(algorithm);
        hash.update(data);
        return hash.digest('hex');
    }

    /**
     * Generate a UUID for transaction or session identification
     * @returns UUID string
     */
    public generateTransactionId(): string {
        return crypto.randomUUID();
    }

    private isValidSecp256k1Key(key: Buffer): boolean {
        // secp256k1 private key must be less than the curve order
        const curveOrder = Buffer.from('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141', 'hex');
        return key.compare(curveOrder) >= 0 || key.equals(Buffer.alloc(32, 0));
    }

    private validateBitcoinAddress(address: string): boolean {
        // Basic Bitcoin address validation (simplified)
        const base58Regex = /^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$/;
        const bech32Regex = /^(bc1|tb1)[a-zA-HJ-NP-Z0-9]+$/;
        
        return (address.length >= 26 && address.length <= 35 && base58Regex.test(address)) ||
               (address.length >= 42 && address.length <= 62 && bech32Regex.test(address));
    }

    private validateEthereumAddress(address: string): boolean {
        // Basic Ethereum address validation
        const ethRegex = /^0x[a-fA-F0-9]{40}$/;
        return ethRegex.test(address);
    }
}