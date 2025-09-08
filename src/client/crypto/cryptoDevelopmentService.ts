// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

'use strict';

import { injectable, inject } from 'inversify';
import { Uri, workspace, window, WorkspaceEdit, Position } from 'vscode';
import { ICryptoUtils } from '../common/types';
import { IFileSystem } from '../common/platform/types';
import { IApplicationShell } from '../common/application/types';
import { ICryptoDevelopmentService } from './types';

/**
 * Service providing cryptocurrency development support for Python projects
 */
@injectable()
export class CryptoDevelopmentService implements ICryptoDevelopmentService {
    constructor(
        @inject(ICryptoUtils) private readonly cryptoUtils: ICryptoUtils,
        @inject(IFileSystem) private readonly fileSystem: IFileSystem,
        @inject(IApplicationShell) private readonly appShell: IApplicationShell,
    ) {}

    /**
     * Create a new cryptocurrency project with basic structure
     */
    public async createCryptoProject(projectPath: Uri, projectType: 'wallet' | 'defi' | 'trading'): Promise<void> {
        const projectStructure = this.getProjectStructure(projectType);
        
        for (const file of projectStructure) {
            const filePath = Uri.joinPath(projectPath, file.path);
            await this.ensureDirectoryExists(filePath);
            await this.fileSystem.writeFile(filePath.fsPath, file.content);
        }

        await this.appShell.showInformationMessage(
            `Cryptocurrency ${projectType} project created at ${projectPath.fsPath}`
        );
    }

    /**
     * Generate crypto utility functions in current Python file
     */
    public async insertCryptoUtilities(document: Uri, utilities: string[]): Promise<void> {
        const editor = await window.showTextDocument(document);
        const edit = new WorkspaceEdit();
        
        for (const utility of utilities) {
            const code = this.getCryptoUtilityCode(utility);
            if (code) {
                const position = new Position(editor.document.lineCount, 0);
                edit.insert(document, position, code + '\n\n');
            }
        }

        await workspace.applyEdit(edit);
    }

    /**
     * Validate cryptocurrency development dependencies
     */
    public async validateCryptoDependencies(projectPath: Uri): Promise<string[]> {
        const missingDeps: string[] = [];
        const requiredDeps = ['cryptography', 'ecdsa', 'hashlib'];

        try {
            const requirementsPath = Uri.joinPath(projectPath, 'requirements.txt');
            if (await this.fileSystem.fileExists(requirementsPath.fsPath)) {
                const content = await this.fileSystem.readFile(requirementsPath.fsPath);
                const requirements = content.toString().split('\n');
                
                for (const dep of requiredDeps) {
                    if (!requirements.some((req: string) => req.includes(dep))) {
                        missingDeps.push(dep);
                    }
                }
            } else {
                missingDeps.push(...requiredDeps);
            }
        } catch (error) {
            missingDeps.push(...requiredDeps);
        }

        return missingDeps;
    }

    /**
     * Generate secure random values for development
     */
    public generateDevelopmentKeys(): { privateKey: string; seed: string; transactionId: string } {
        return {
            privateKey: this.cryptoUtils.getSecp256k1PrivateKey(),
            seed: this.cryptoUtils.generateSeed(32),
            transactionId: this.cryptoUtils.generateTransactionId(),
        };
    }

    private getProjectStructure(projectType: string): Array<{ path: string; content: string }> {
        const baseFiles = [
            {
                path: 'requirements.txt',
                content: this.getRequirementsContent(),
            },
            {
                path: 'README.md',
                content: this.getReadmeContent(projectType),
            },
            {
                path: 'src/__init__.py',
                content: '',
            },
            {
                path: 'src/crypto_utils.py',
                content: this.getCryptoUtilsTemplate(),
            },
            {
                path: 'tests/__init__.py',
                content: '',
            },
            {
                path: 'tests/test_crypto_utils.py',
                content: this.getCryptoTestsTemplate(),
            },
        ];

        switch (projectType) {
            case 'wallet':
                return [
                    ...baseFiles,
                    {
                        path: 'src/wallet.py',
                        content: this.getWalletTemplate(),
                    },
                    {
                        path: 'src/address_manager.py',
                        content: this.getAddressManagerTemplate(),
                    },
                ];
            case 'defi':
                return [
                    ...baseFiles,
                    {
                        path: 'src/defi_protocol.py',
                        content: this.getDefiProtocolTemplate(),
                    },
                    {
                        path: 'src/smart_contract.py',
                        content: this.getSmartContractTemplate(),
                    },
                ];
            case 'trading':
                return [
                    ...baseFiles,
                    {
                        path: 'src/trading_bot.py',
                        content: this.getTradingBotTemplate(),
                    },
                    {
                        path: 'src/market_data.py',
                        content: this.getMarketDataTemplate(),
                    },
                ];
            default:
                return baseFiles;
        }
    }

    private getCryptoUtilityCode(utility: string): string | null {
        const utilities: Record<string, string> = {
            'random_key': `
def generate_random_private_key():
    """Generate a cryptographically secure random private key."""
    import secrets
    return secrets.token_hex(32)`,
            
            'validate_address': `
def validate_address(address: str, address_type: str = 'ethereum') -> bool:
    """Validate cryptocurrency address format."""
    import re
    if address_type.lower() == 'ethereum':
        return bool(re.match(r'^0x[a-fA-F0-9]{40}$', address))
    elif address_type.lower() == 'bitcoin':
        # Simplified Bitcoin address validation
        return 26 <= len(address) <= 35 and address[0] in '13bc'
    return False`,
            
            'hash_message': `
def hash_message(message: str, algorithm: str = 'sha256') -> str:
    """Calculate hash of message for signing."""
    import hashlib
    if algorithm == 'sha256':
        return hashlib.sha256(message.encode()).hexdigest()
    elif algorithm == 'keccak256':
        import sha3
        return sha3.keccak_256(message.encode()).hexdigest()
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")`,
            
            'derive_address': `
def derive_address_from_public_key(public_key: str, address_type: str = 'ethereum') -> str:
    """Derive address from public key."""
    import hashlib
    if address_type.lower() == 'ethereum':
        # Simplified Ethereum address derivation
        import sha3
        keccak = sha3.keccak_256()
        keccak.update(bytes.fromhex(public_key[2:]))  # Remove '0x' prefix
        return '0x' + keccak.hexdigest()[-40:]
    else:
        raise NotImplementedError(f"Address derivation for {address_type} not implemented")`,
        };

        return utilities[utility] || null;
    }

    private getRequirementsContent(): string {
        return `# Core cryptographic libraries
cryptography>=41.0.0
ecdsa>=0.18.0

# Optional crypto libraries
web3>=6.0.0
bitcoin>=1.1.42
pysha3>=1.0.2

# Development and testing
pytest>=7.0.0
pytest-cov>=4.0.0
black>=23.0.0
flake8>=6.0.0`;
    }

    private getReadmeContent(projectType: string): string {
        return `# Cryptocurrency ${projectType.charAt(0).toUpperCase() + projectType.slice(1)} Project

A Python-based cryptocurrency ${projectType} application.

## Features

- Secure key generation and management
- Address validation and derivation
- Transaction signing and verification
- ${projectType === 'wallet' ? 'Multi-currency wallet support' : ''}
- ${projectType === 'defi' ? 'DeFi protocol interactions' : ''}
- ${projectType === 'trading' ? 'Automated trading capabilities' : ''}

## Installation

\`\`\`bash
pip install -r requirements.txt
\`\`\`

## Usage

\`\`\`python
from src.crypto_utils import generate_random_private_key, validate_address

# Generate a new private key
private_key = generate_random_private_key()

# Validate an address
is_valid = validate_address("0x742d35Cc6634C0532925a3b8D3Ac3f4532d456d9", "ethereum")
\`\`\`

## Security Note

This is a development template. For production use, ensure proper security audits and follow best practices for key management.
`;
    }

    private getCryptoUtilsTemplate(): string {
        return `"""
Cryptocurrency utility functions for secure operations.
"""

import hashlib
import secrets
from typing import Optional, Dict, Any


class CryptoUtils:
    """Utility class for cryptocurrency operations."""
    
    @staticmethod
    def generate_random_private_key() -> str:
        """Generate a cryptographically secure random private key."""
        return secrets.token_hex(32)
    
    @staticmethod
    def generate_seed(length: int = 64) -> str:
        """Generate a random seed for key derivation."""
        return secrets.token_hex(length)
    
    @staticmethod
    def hash_data(data: str, algorithm: str = 'sha256') -> str:
        """Calculate hash of data."""
        if algorithm == 'sha256':
            return hashlib.sha256(data.encode()).hexdigest()
        elif algorithm == 'md5':
            return hashlib.md5(data.encode()).hexdigest()
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    @staticmethod
    def validate_private_key(private_key: str) -> bool:
        """Validate private key format."""
        try:
            # Check if it's valid hex of appropriate length
            bytes.fromhex(private_key)
            return len(private_key) in [32, 64]  # 16 or 32 bytes
        except ValueError:
            return False
    
    @staticmethod
    def validate_address(address: str, address_type: str = 'ethereum') -> bool:
        """Validate cryptocurrency address format."""
        import re
        
        if address_type.lower() == 'ethereum':
            return bool(re.match(r'^0x[a-fA-F0-9]{40}$', address))
        elif address_type.lower() == 'bitcoin':
            # Simplified Bitcoin address validation
            return 26 <= len(address) <= 35 and address[0] in '13bc'
        else:
            return 20 < len(address) < 100  # Generic validation


def generate_transaction_id() -> str:
    """Generate a unique transaction ID."""
    import uuid
    return str(uuid.uuid4())
`;
    }

    private getCryptoTestsTemplate(): string {
        return `"""
Tests for cryptocurrency utility functions.
"""

import pytest
from src.crypto_utils import CryptoUtils, generate_transaction_id


class TestCryptoUtils:
    """Test cases for CryptoUtils class."""
    
    def test_generate_random_private_key(self):
        """Test private key generation."""
        key = CryptoUtils.generate_random_private_key()
        assert len(key) == 64  # 32 bytes * 2 (hex)
        assert all(c in '0123456789abcdef' for c in key.lower())
    
    def test_generate_seed(self):
        """Test seed generation."""
        seed = CryptoUtils.generate_seed()
        assert len(seed) == 128  # 64 bytes * 2 (hex)
        
        # Custom length
        seed_32 = CryptoUtils.generate_seed(32)
        assert len(seed_32) == 64  # 32 bytes * 2 (hex)
    
    def test_hash_data(self):
        """Test data hashing."""
        data = "Hello, World!"
        hash_result = CryptoUtils.hash_data(data)
        assert len(hash_result) == 64  # SHA256 = 32 bytes * 2 (hex)
        
        # Test consistency
        hash_result2 = CryptoUtils.hash_data(data)
        assert hash_result == hash_result2
    
    def test_validate_private_key(self):
        """Test private key validation."""
        valid_key = 'a' * 64  # 32 bytes
        assert CryptoUtils.validate_private_key(valid_key)
        
        invalid_key = 'g' * 64  # Invalid hex
        assert not CryptoUtils.validate_private_key(invalid_key)
        
        short_key = 'a' * 30  # Too short
        assert not CryptoUtils.validate_private_key(short_key)
    
    def test_validate_address(self):
        """Test address validation."""
        # Ethereum address
        eth_addr = "0x742d35Cc6634C0532925a3b8D3Ac3f4532d456d9"
        assert CryptoUtils.validate_address(eth_addr, "ethereum")
        
        # Invalid Ethereum address
        invalid_eth = "0x742d35Cc6634C0532925a3b8D3Ac3f4532d456d"
        assert not CryptoUtils.validate_address(invalid_eth, "ethereum")
        
        # Bitcoin address (simplified test)
        btc_addr = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
        assert CryptoUtils.validate_address(btc_addr, "bitcoin")
    
    def test_generate_transaction_id(self):
        """Test transaction ID generation."""
        tx_id = generate_transaction_id()
        assert len(tx_id) == 36  # UUID format
        assert tx_id.count('-') == 4  # UUID has 4 hyphens
        
        # Test uniqueness
        tx_id2 = generate_transaction_id()
        assert tx_id != tx_id2
`;
    }

    private getWalletTemplate(): string {
        return `"""
Basic cryptocurrency wallet implementation.
"""

from typing import Dict, List, Optional
from .crypto_utils import CryptoUtils


class Wallet:
    """Basic cryptocurrency wallet."""
    
    def __init__(self, name: str):
        self.name = name
        self.private_keys: Dict[str, str] = {}
        self.addresses: Dict[str, str] = {}
        self.balances: Dict[str, float] = {}
    
    def generate_new_address(self, currency: str = 'ethereum') -> str:
        """Generate a new address for the specified currency."""
        private_key = CryptoUtils.generate_random_private_key()
        # In a real implementation, derive address from private key
        address = f"0x{''.join([f'{ord(c):02x}' for c in self.name[:20]])}"
        
        self.private_keys[address] = private_key
        self.addresses[currency] = address
        self.balances[address] = 0.0
        
        return address
    
    def get_balance(self, address: str) -> float:
        """Get balance for an address."""
        return self.balances.get(address, 0.0)
    
    def list_addresses(self) -> List[str]:
        """List all addresses in the wallet."""
        return list(self.addresses.values())
    
    def export_private_key(self, address: str) -> Optional[str]:
        """Export private key for an address (use with caution)."""
        return self.private_keys.get(address)
`;
    }

    private getAddressManagerTemplate(): string {
        return `"""
Address management utilities for cryptocurrency applications.
"""

from typing import Dict, List, Optional
from .crypto_utils import CryptoUtils


class AddressManager:
    """Manages cryptocurrency addresses and their metadata."""
    
    def __init__(self):
        self.addresses: Dict[str, Dict] = {}
    
    def add_address(self, address: str, currency: str, label: str = "") -> bool:
        """Add an address to the manager."""
        if not CryptoUtils.validate_address(address, currency):
            return False
        
        self.addresses[address] = {
            'currency': currency,
            'label': label,
            'created_at': self._get_timestamp(),
            'transactions': []
        }
        return True
    
    def get_addresses_by_currency(self, currency: str) -> List[str]:
        """Get all addresses for a specific currency."""
        return [
            addr for addr, data in self.addresses.items()
            if data['currency'].lower() == currency.lower()
        ]
    
    def update_label(self, address: str, label: str) -> bool:
        """Update the label for an address."""
        if address in self.addresses:
            self.addresses[address]['label'] = label
            return True
        return False
    
    def remove_address(self, address: str) -> bool:
        """Remove an address from the manager."""
        if address in self.addresses:
            del self.addresses[address]
            return True
        return False
    
    def _get_timestamp(self) -> float:
        """Get current timestamp."""
        import time
        return time.time()
`;
    }

    private getDefiProtocolTemplate(): string {
        return `"""
DeFi protocol interaction utilities.
"""

from typing import Dict, Any, Optional
from .crypto_utils import CryptoUtils, generate_transaction_id


class DefiProtocol:
    """Base class for DeFi protocol interactions."""
    
    def __init__(self, protocol_name: str, network: str = 'ethereum'):
        self.protocol_name = protocol_name
        self.network = network
        self.gas_price = 20  # gwei
    
    def prepare_transaction(self, from_address: str, to_address: str, 
                          amount: float, data: str = "") -> Dict[str, Any]:
        """Prepare a transaction for the protocol."""
        return {
            'from': from_address,
            'to': to_address,
            'value': amount,
            'data': data,
            'gas_price': self.gas_price,
            'nonce': self._get_nonce(from_address),
            'transaction_id': generate_transaction_id()
        }
    
    def estimate_gas(self, transaction: Dict[str, Any]) -> int:
        """Estimate gas for a transaction."""
        # Simplified gas estimation
        base_gas = 21000
        if transaction.get('data'):
            base_gas += len(transaction['data']) * 16
        return base_gas
    
    def sign_transaction(self, transaction: Dict[str, Any], 
                        private_key: str) -> str:
        """Sign a transaction (placeholder implementation)."""
        # In a real implementation, this would use cryptographic signing
        tx_hash = CryptoUtils.hash_data(str(transaction))
        return f"signed_{tx_hash[:16]}"
    
    def _get_nonce(self, address: str) -> int:
        """Get nonce for an address."""
        # In a real implementation, query the blockchain
        return 0
`;
    }

    private getSmartContractTemplate(): string {
        return `"""
Smart contract interaction utilities.
"""

from typing import Dict, Any, List
from .crypto_utils import CryptoUtils


class SmartContract:
    """Smart contract interaction helper."""
    
    def __init__(self, contract_address: str, abi: List[Dict] = None):
        self.contract_address = contract_address
        self.abi = abi or []
        self.functions: Dict[str, Dict] = {}
        self._parse_abi()
    
    def call_function(self, function_name: str, *args, **kwargs) -> Any:
        """Call a read-only contract function."""
        if function_name not in self.functions:
            raise ValueError(f"Function {function_name} not found in ABI")
        
        # Simulate function call
        return f"Result of {function_name}({args}, {kwargs})"
    
    def prepare_transaction(self, function_name: str, from_address: str, 
                          *args, **kwargs) -> Dict[str, Any]:
        """Prepare a transaction to call a contract function."""
        if function_name not in self.functions:
            raise ValueError(f"Function {function_name} not found in ABI")
        
        function_data = self._encode_function_call(function_name, *args)
        
        return {
            'from': from_address,
            'to': self.contract_address,
            'data': function_data,
            'value': kwargs.get('value', 0),
            'gas': kwargs.get('gas', 100000)
        }
    
    def _parse_abi(self):
        """Parse ABI to extract function signatures."""
        for item in self.abi:
            if item.get('type') == 'function':
                name = item.get('name')
                if name:
                    self.functions[name] = item
    
    def _encode_function_call(self, function_name: str, *args) -> str:
        """Encode function call data."""
        # Simplified encoding - in reality would use proper ABI encoding
        function_sig = CryptoUtils.hash_data(function_name)[:8]
        args_encoded = ''.join([str(arg) for arg in args])
        return f"0x{function_sig}{args_encoded}"
`;
    }

    private getTradingBotTemplate(): string {
        return `"""
Cryptocurrency trading bot implementation.
"""

from typing import Dict, List, Optional, Tuple
from .crypto_utils import CryptoUtils, generate_transaction_id
from .market_data import MarketData


class TradingBot:
    """Automated cryptocurrency trading bot."""
    
    def __init__(self, name: str, initial_balance: float = 1000.0):
        self.name = name
        self.balance = initial_balance
        self.positions: Dict[str, float] = {}
        self.trade_history: List[Dict] = []
        self.market_data = MarketData()
        self.risk_limit = 0.02  # 2% risk per trade
    
    def analyze_market(self, symbol: str) -> Dict[str, Any]:
        """Analyze market conditions for a trading pair."""
        price_data = self.market_data.get_price_history(symbol, 24)
        
        if not price_data:
            return {'signal': 'HOLD', 'confidence': 0.0}
        
        # Simple moving average strategy
        short_ma = sum(price_data[-5:]) / 5
        long_ma = sum(price_data[-20:]) / 20
        current_price = price_data[-1]
        
        if short_ma > long_ma * 1.02:
            return {'signal': 'BUY', 'confidence': 0.7, 'price': current_price}
        elif short_ma < long_ma * 0.98:
            return {'signal': 'SELL', 'confidence': 0.7, 'price': current_price}
        else:
            return {'signal': 'HOLD', 'confidence': 0.5, 'price': current_price}
    
    def execute_trade(self, symbol: str, action: str, amount: float) -> bool:
        """Execute a trade order."""
        analysis = self.analyze_market(symbol)
        current_price = analysis.get('price', 0)
        
        if action.upper() == 'BUY':
            cost = amount * current_price
            if cost <= self.balance:
                self.balance -= cost
                self.positions[symbol] = self.positions.get(symbol, 0) + amount
                self._record_trade(symbol, 'BUY', amount, current_price)
                return True
        
        elif action.upper() == 'SELL':
            if self.positions.get(symbol, 0) >= amount:
                revenue = amount * current_price
                self.balance += revenue
                self.positions[symbol] -= amount
                self._record_trade(symbol, 'SELL', amount, current_price)
                return True
        
        return False
    
    def calculate_portfolio_value(self) -> float:
        """Calculate total portfolio value."""
        total_value = self.balance
        
        for symbol, amount in self.positions.items():
            current_price = self.market_data.get_current_price(symbol)
            total_value += amount * current_price
        
        return total_value
    
    def get_risk_metrics(self) -> Dict[str, float]:
        """Calculate risk metrics for the portfolio."""
        portfolio_value = self.calculate_portfolio_value()
        
        return {
            'total_value': portfolio_value,
            'cash_ratio': self.balance / portfolio_value,
            'position_count': len(self.positions),
            'largest_position': max(self.positions.values()) if self.positions else 0
        }
    
    def _record_trade(self, symbol: str, action: str, amount: float, price: float):
        """Record a trade in the history."""
        trade = {
            'id': generate_transaction_id(),
            'timestamp': self._get_timestamp(),
            'symbol': symbol,
            'action': action,
            'amount': amount,
            'price': price,
            'total': amount * price
        }
        self.trade_history.append(trade)
    
    def _get_timestamp(self) -> float:
        """Get current timestamp."""
        import time
        return time.time()
`;
    }

    private getMarketDataTemplate(): string {
        return `"""
Market data utilities for cryptocurrency trading.
"""

import random
import time
from typing import Dict, List, Optional


class MarketData:
    """Mock market data provider for cryptocurrency prices."""
    
    def __init__(self):
        self.base_prices = {
            'BTC/USD': 50000.0,
            'ETH/USD': 3000.0,
            'ADA/USD': 0.5,
            'DOT/USD': 25.0,
            'LINK/USD': 20.0
        }
        self.price_cache: Dict[str, List[float]] = {}
    
    def get_current_price(self, symbol: str) -> float:
        """Get current price for a trading pair."""
        base_price = self.base_prices.get(symbol, 100.0)
        
        # Add some random volatility
        volatility = random.uniform(-0.05, 0.05)
        return base_price * (1 + volatility)
    
    def get_price_history(self, symbol: str, hours: int = 24) -> List[float]:
        """Get historical price data for a symbol."""
        if symbol in self.price_cache:
            return self.price_cache[symbol][-hours:]
        
        # Generate mock historical data
        base_price = self.base_prices.get(symbol, 100.0)
        prices = []
        
        for i in range(hours):
            # Simulate price movement
            change = random.uniform(-0.02, 0.02)
            if i == 0:
                price = base_price
            else:
                price = prices[-1] * (1 + change)
            prices.append(price)
        
        self.price_cache[symbol] = prices
        return prices
    
    def get_order_book(self, symbol: str, depth: int = 10) -> Dict[str, List]:
        """Get order book data for a symbol."""
        current_price = self.get_current_price(symbol)
        
        bids = []
        asks = []
        
        for i in range(depth):
            bid_price = current_price * (1 - (i + 1) * 0.001)
            ask_price = current_price * (1 + (i + 1) * 0.001)
            
            bids.append([bid_price, random.uniform(0.1, 10.0)])
            asks.append([ask_price, random.uniform(0.1, 10.0)])
        
        return {
            'bids': bids,
            'asks': asks,
            'timestamp': time.time()
        }
    
    def get_ticker(self, symbol: str) -> Dict[str, float]:
        """Get ticker information for a symbol."""
        current_price = self.get_current_price(symbol)
        price_24h_ago = current_price * random.uniform(0.95, 1.05)
        
        return {
            'symbol': symbol,
            'price': current_price,
            'change_24h': current_price - price_24h_ago,
            'change_24h_percent': ((current_price - price_24h_ago) / price_24h_ago) * 100,
            'high_24h': current_price * random.uniform(1.0, 1.1),
            'low_24h': current_price * random.uniform(0.9, 1.0),
            'volume_24h': random.uniform(1000000, 10000000),
            'timestamp': time.time()
        }
`;
    }

    private async ensureDirectoryExists(filePath: Uri): Promise<void> {
        const directory = Uri.joinPath(filePath, '..');
        try {
            await this.fileSystem.createDirectory(directory.fsPath);
        } catch (error) {
            // Directory might already exist
        }
    }
}