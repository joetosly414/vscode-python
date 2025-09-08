// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

'use strict';

import { injectable, inject } from 'inversify';
import { QuickPickItem, window, workspace } from 'vscode';
import { IExtensionSingleActivationService } from '../../../activation/types';
import { Commands } from '../../constants';
import { IApplicationShell, ICommandManager, IClipboard } from '../types';
import { IDisposableRegistry } from '../../types';
import { ICryptoDevelopmentService } from '../../../crypto/types';

interface CryptoProjectQuickPickItem extends QuickPickItem {
    projectType: 'wallet' | 'defi' | 'trading';
}

interface CryptoUtilityQuickPickItem extends QuickPickItem {
    utilityType: string;
}

@injectable()
export class CryptoDevelopmentCommandHandler implements IExtensionSingleActivationService {
    public readonly supportedWorkspaceTypes = { untrustedWorkspace: false, virtualWorkspace: false };

    constructor(
        @inject(ICommandManager) private readonly commandManager: ICommandManager,
        @inject(IApplicationShell) private readonly appShell: IApplicationShell,
        @inject(IDisposableRegistry) private readonly disposables: IDisposableRegistry,
        @inject(ICryptoDevelopmentService) private readonly cryptoService: ICryptoDevelopmentService,
        @inject(IClipboard) private readonly clipboard: IClipboard,
    ) {}

    public async activate(): Promise<void> {
        this.disposables.push(
            this.commandManager.registerCommand(Commands.Crypto_CreateProject as any, this.createCryptoProject, this),
            this.commandManager.registerCommand(Commands.Crypto_InsertUtilities as any, this.insertCryptoUtilities, this),
            this.commandManager.registerCommand(Commands.Crypto_ValidateDependencies as any, this.validateCryptoDependencies, this),
            this.commandManager.registerCommand(Commands.Crypto_GenerateKeys as any, this.generateCryptoKeys, this),
        );
    }

    public async createCryptoProject(): Promise<void> {
        // Get project type from user
        const projectTypeItems: CryptoProjectQuickPickItem[] = [
            {
                label: 'Wallet',
                description: 'Create a cryptocurrency wallet project with address management',
                projectType: 'wallet',
            },
            {
                label: 'DeFi Protocol',
                description: 'Create a DeFi project with smart contract interactions',
                projectType: 'defi',
            },
            {
                label: 'Trading Bot',
                description: 'Create an automated trading bot project',
                projectType: 'trading',
            },
        ];

        const selectedType = await window.showQuickPick(projectTypeItems, {
            placeHolder: 'Select the type of crypto project to create',
            canPickMany: false,
        });

        if (!selectedType) {
            return;
        }

        // Get project location
        const folderUris = await window.showOpenDialog({
            canSelectFolders: true,
            canSelectFiles: false,
            canSelectMany: false,
            openLabel: 'Select Project Location',
        });

        if (!folderUris || folderUris.length === 0) {
            return;
        }

        const projectPath = folderUris[0];

        try {
            await this.cryptoService.createCryptoProject(projectPath, selectedType.projectType);
            
            // Ask if user wants to open the project
            const openProject = await this.appShell.showInformationMessage(
                'Crypto project created successfully! Would you like to open it?',
                'Open Project',
                'Cancel'
            );

            if (openProject === 'Open Project') {
                await this.commandManager.executeCommand('vscode.openFolder' as any, projectPath);
            }
        } catch (error) {
            await this.appShell.showErrorMessage(
                `Failed to create crypto project: ${error instanceof Error ? error.message : String(error)}`
            );
        }
    }

    public async insertCryptoUtilities(): Promise<void> {
        const activeEditor = window.activeTextEditor;
        if (!activeEditor) {
            await this.appShell.showWarningMessage('Please open a Python file first');
            return;
        }

        if (activeEditor.document.languageId !== 'python') {
            await this.appShell.showWarningMessage('This command only works with Python files');
            return;
        }

        const utilityItems: CryptoUtilityQuickPickItem[] = [
            {
                label: 'Generate Random Private Key',
                description: 'Function to generate cryptographically secure private keys',
                utilityType: 'random_key',
            },
            {
                label: 'Validate Address',
                description: 'Function to validate cryptocurrency addresses',
                utilityType: 'validate_address',
            },
            {
                label: 'Hash Message',
                description: 'Function to hash messages for signing',
                utilityType: 'hash_message',
            },
            {
                label: 'Derive Address',
                description: 'Function to derive address from public key',
                utilityType: 'derive_address',
            },
        ];

        const selectedUtilities = await window.showQuickPick(utilityItems, {
            placeHolder: 'Select crypto utilities to insert',
            canPickMany: true,
        });

        if (!selectedUtilities || selectedUtilities.length === 0) {
            return;
        }

        try {
            const utilities = selectedUtilities.map(item => item.utilityType);
            await this.cryptoService.insertCryptoUtilities(activeEditor.document.uri, utilities);
            await this.appShell.showInformationMessage(
                `Inserted ${utilities.length} crypto utility function(s) into the file`
            );
        } catch (error) {
            await this.appShell.showErrorMessage(
                `Failed to insert crypto utilities: ${error instanceof Error ? error.message : String(error)}`
            );
        }
    }

    public async validateCryptoDependencies(): Promise<void> {
        const workspaceFolders = workspace.workspaceFolders;
        if (!workspaceFolders || workspaceFolders.length === 0) {
            await this.appShell.showWarningMessage('Please open a workspace first');
            return;
        }

        const projectPath = workspaceFolders[0].uri;

        try {
            const missingDeps = await this.cryptoService.validateCryptoDependencies(projectPath);
            
            if (missingDeps.length === 0) {
                await this.appShell.showInformationMessage('All required crypto dependencies are present!');
            } else {
                const message = `Missing crypto dependencies: ${missingDeps.join(', ')}`;
                const action = await this.appShell.showWarningMessage(
                    message,
                    'Show Installation Command',
                    'Cancel'
                );

                if (action === 'Show Installation Command') {
                    const installCommand = `pip install ${missingDeps.join(' ')}`;
                    await this.appShell.showInformationMessage(
                        `Run this command to install missing dependencies: ${installCommand}`,
                        'Copy to Clipboard'
                    ).then(async (result) => {
                        if (result === 'Copy to Clipboard') {
                            await this.clipboard.writeText(installCommand);
                        }
                    });
                }
            }
        } catch (error) {
            await this.appShell.showErrorMessage(
                `Failed to validate dependencies: ${error instanceof Error ? error.message : String(error)}`
            );
        }
    }

    public async generateCryptoKeys(): Promise<void> {
        try {
            const keys = this.cryptoService.generateDevelopmentKeys();
            
            const keyInfo = [
                `Private Key: ${keys.privateKey}`,
                `Seed: ${keys.seed}`,
                `Transaction ID: ${keys.transactionId}`,
                '',
                '⚠️ Warning: These are for development only! Never use in production.',
            ].join('\n');

            const action = await this.appShell.showInformationMessage(
                'Development keys generated successfully!',
                'Show Keys',
                'Copy Private Key',
                'Cancel'
            );

            if (action === 'Show Keys') {
                await this.appShell.showInformationMessage(keyInfo);
            } else if (action === 'Copy Private Key') {
                await this.clipboard.writeText(keys.privateKey);
                await this.appShell.showInformationMessage('Private key copied to clipboard');
            }
        } catch (error) {
            await this.appShell.showErrorMessage(
                `Failed to generate keys: ${error instanceof Error ? error.message : String(error)}`
            );
        }
    }
}