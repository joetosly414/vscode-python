// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

'use strict';

import { Uri } from 'vscode';

export const ICryptoDevelopmentService = Symbol('ICryptoDevelopmentService');

export interface ICryptoDevelopmentService {
    /**
     * Create a new cryptocurrency project with basic structure
     */
    createCryptoProject(projectPath: Uri, projectType: 'wallet' | 'defi' | 'trading'): Promise<void>;

    /**
     * Generate crypto utility functions in current Python file
     */
    insertCryptoUtilities(document: Uri, utilities: string[]): Promise<void>;

    /**
     * Validate cryptocurrency development dependencies
     */
    validateCryptoDependencies(projectPath: Uri): Promise<string[]>;

    /**
     * Generate secure random values for development
     */
    generateDevelopmentKeys(): { privateKey: string; seed: string; transactionId: string };
}

/**
 * Types of cryptocurrency projects that can be created
 */
export type CryptoProjectType = 'wallet' | 'defi' | 'trading';

/**
 * Available crypto utility functions that can be inserted
 */
export type CryptoUtilityType = 'random_key' | 'validate_address' | 'hash_message' | 'derive_address';

/**
 * Development keys structure
 */
export interface DevelopmentKeys {
    privateKey: string;
    seed: string;
    transactionId: string;
}

/**
 * Project structure for crypto development
 */
export interface CryptoProjectStructure {
    path: string;
    content: string;
}