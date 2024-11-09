# Python RSA Asymmetric Encryption Implementation

A robust and secure implementation of RSA asymmetric encryption in Python, providing a clean interface for key generation, encryption, and decryption operations using the `cryptography` library.

## Features

- 2048-bit RSA key pair generation
- PEM format key serialization and deserialization
- Secure message encryption and decryption using OAEP padding
- Type hints for better code maintainability
- Comprehensive error handling
- File-based key storage and retrieval

## Installation

```bash
pip install cryptography
```

## Requirements

- Python 3.7+
- cryptography library

## Usage

Basic example of encrypting and decrypting a message:

```python
# Create an encryption system instance
enc_sys = AsymmetricEncryption()

# Save generated keys
enc_sys.save_keys()

# Load keys from files
public_key = enc_sys.load_public_key("public_key.pem")
private_key = enc_sys.load_private_key("private_key.pem")

# Encrypt a message
message = "Hello, this is a secret message!"
encrypted_msg = enc_sys.encrypt_message(message, public_key)

# Decrypt the message
decrypted_msg = enc_sys.decrypt_message(encrypted_msg, private_key)
```

## Technical Details

### Key Generation
- Uses RSA algorithm with a 2048-bit key size
- Public exponent (e) fixed at 65537 (standard value for efficiency)
- Leverages Python's `cryptography` library backend for secure random number generation

### Encryption Process
- Implements OAEP (Optimal Asymmetric Encryption Padding)
- Uses SHA256 for both the primary hash function and MGF1
- Message encoding in UTF-8 before encryption

### Security Features
- Secure key serialization using PKCS#8 format for private keys
- SubjectPublicKeyInfo format for public keys
- No encryption used for stored private keys (in this implementation - consider adding encryption in production)

## Class Documentation

### AsymmetricEncryption

#### Methods

##### `__init__(self) -> None`
Initializes the encryption system by generating a new RSA key pair.

##### `save_keys(self) -> None`
Saves both private and public keys to PEM files in the current directory.

##### `load_private_key(file_path: str) -> RSAPrivateKey`
Static method that loads a private key from a PEM file.

##### `load_public_key(file_path: str) -> RSAPublicKey`
Static method that loads a public key from a PEM file.

##### `print_private_key(self) -> None`
Outputs the private key in PEM format to stdout.

##### `print_public_key(self) -> None`
Outputs the public key in PEM format to stdout.

##### `encrypt_message(message: str, public_key: RSAPublicKey) -> bytes`
Static method that encrypts a string message using the provided public key.

##### `decrypt_message(encrypted_message: bytes, private_key: RSAPrivateKey) -> str`
Static method that decrypts an encrypted message using the provided private key.

## Security Considerations

1. **Private Key Storage**: This implementation saves private keys unencrypted. In a production environment, consider:
   - Encrypting private keys with a strong password
   - Using secure key storage solutions (HSM, key vaults)
   - Implementing proper key rotation procedures

2. **Key Size**: The implementation uses 2048-bit keys, which are currently considered secure. However:
   - Consider using 4096-bit keys for more sensitive applications
   - Regular review of key size requirements based on current security standards

3. **Error Handling**: Implement appropriate error handling for:
   - File I/O operations
   - Encryption/decryption operations
   - Key validation

## Best Practices

1. **Key Management**:
   - Regularly rotate keys
   - Implement secure key distribution mechanisms
   - Use separate key pairs for different purposes

2. **Message Size**:
   - Be aware of RSA encryption size limitations
   - For larger messages, consider using hybrid encryption (RSA + symmetric encryption)

3. **Production Use**:
   - Add proper logging
   - Implement robust error handling
   - Consider adding key password protection
   - Add input validation

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

[MIT License](LICENSE)
