# https://claude.ai/chat/34febae9-b7e4-44bb-80f7-cea6226e6171

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
    BestAvailableEncryption
)
from cryptography.exceptions import InvalidKey
import logging
import os
from typing import Tuple, Optional
from dataclasses import dataclass

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class EncryptionResult:
    """Class for holding encryption results and metadata"""
    encrypted_data: bytes
    success: bool
    error_message: Optional[str] = None


@dataclass
class DecryptionResult:
    """Class for holding decryption results and metadata"""
    decrypted_data: Optional[str] = None
    success: bool = False
    error_message: Optional[str] = None


class EncryptionError(Exception):
    """Custom exception for encryption-related errors"""
    pass


class KeyManagementError(Exception):
    """Custom exception for key management-related errors"""
    pass


class AsymmetricEncryption:
    """
    A class to handle asymmetric encryption and decryption using RSA
    algorithm with enhanced error handling.
    """

    DEFAULT_KEY_SIZE = 2048
    DEFAULT_PUBLIC_EXPONENT = 65537
    MINIMUM_KEY_SIZE = 2048  # Minimum recommended key size for security

    def __init__(self, key_size: int = DEFAULT_KEY_SIZE) -> None:
        """
        Initializes the encryption system with error handling for key generation.

        Args:
            key_size (int): Size of the RSA key in bits. Defaults to 2048.

        Raises:
            KeyManagementError: If key generation fails or if key size is insufficient.
        """
        try:
            if key_size < self.MINIMUM_KEY_SIZE:
                raise ValueError(
                    f"Key size {key_size} is below minimum recommended size of {self.MINIMUM_KEY_SIZE}"
                )

            self.private_key: RSAPrivateKey = rsa.generate_private_key(
                public_exponent=self.DEFAULT_PUBLIC_EXPONENT,
                key_size=key_size,
                backend=default_backend()
            )
            self.public_key: RSAPublicKey = self.private_key.public_key()
            logger.info(f"Successfully generated {key_size}-bit RSA key pair")

        except ValueError as e:
            error_msg = f"Invalid parameters for key generation: {str(e)}"
            logger.error(error_msg)
            raise KeyManagementError(error_msg)
        except Exception as e:
            error_msg = f"Unexpected error during key generation: {str(e)}"
            logger.error(error_msg)
            raise KeyManagementError(error_msg)

    def save_keys(self, private_key_path: str, public_key_path: str,
                  private_key_password: Optional[bytes] = None) -> bool:
        """
        Saves the private and public keys to files with enhanced security and error handling.

        Args:
            private_key_path (str): Path to save the private key
            public_key_path (str): Path to save the public key
            private_key_password (Optional[bytes]): Optional password to encrypt the private key

        Returns:
            bool: True if keys were saved successfully, False otherwise

        Raises:
            KeyManagementError: If there are issues with key serialization or file operations
        """
        try:
            # Validate paths
            if not private_key_path or not public_key_path:
                raise ValueError("Key file paths cannot be empty")

            # Create directories only if paths contain directories
            private_key_dir = os.path.dirname(private_key_path)
            public_key_dir = os.path.dirname(public_key_path)

            if private_key_dir:
                os.makedirs(private_key_dir, exist_ok=True)
            if public_key_dir:
                os.makedirs(public_key_dir, exist_ok=True)

            # Configure private key encryption
            encryption_algorithm = (BestAvailableEncryption(private_key_password)
                                    if private_key_password
                                    else NoEncryption())

            # Save private key
            with open(private_key_path, "wb") as f:
                f.write(
                    self.private_key.private_bytes(
                        encoding=Encoding.PEM,
                        format=PrivateFormat.PKCS8,
                        encryption_algorithm=encryption_algorithm
                    )
                )

            # Save public key
            with open(public_key_path, "wb") as f:
                f.write(
                    self.public_key.public_bytes(
                        encoding=Encoding.PEM,
                        format=PublicFormat.SubjectPublicKeyInfo
                    )
                )

            logger.info(f"Successfully saved key pair to files: \n"
                        f"Private key: {private_key_path}\n"
                        f"Public key: {public_key_path}")
            return True

        except ValueError as e:
            error_msg = f"Invalid file paths: {str(e)}"
            logger.error(error_msg)
            raise KeyManagementError(error_msg)
        except PermissionError as e:
            error_msg = f"Permission denied when saving keys: {str(e)}"
            logger.error(error_msg)
            raise KeyManagementError(error_msg)
        except OSError as e:
            error_msg = f"OS error when saving keys: {str(e)}"
            logger.error(error_msg)
            raise KeyManagementError(error_msg)
        except Exception as e:
            error_msg = f"Unexpected error when saving keys: {str(e)}"
            logger.error(error_msg)
            raise KeyManagementError(error_msg)

    @staticmethod
    def load_private_key(file_path: str, password: Optional[bytes] = None) -> RSAPrivateKey:
        """
        Loads a private key from a file with error handling.

        Args:
            file_path (str): Path to the private key file
            password (Optional[bytes]): Password if the private key is encrypted

        Returns:
            RSAPrivateKey: The loaded private key

        Raises:
            KeyManagementError: If there are issues loading the private key
        """
        try:
            with open(file_path, "rb") as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=password,
                    backend=default_backend()
                )

                if not isinstance(private_key, RSAPrivateKey):
                    raise KeyManagementError("Loaded key is not an RSA private key")

                logger.info(f"Successfully loaded private key from {file_path}")
                return private_key

        except FileNotFoundError:
            error_msg = f"Private key file not found: {file_path}"
            logger.error(error_msg)
            raise KeyManagementError(error_msg)
        except ValueError as e:
            error_msg = f"Invalid private key or password: {str(e)}"
            logger.error(error_msg)
            raise KeyManagementError(error_msg)
        except Exception as e:
            error_msg = f"Unexpected error loading private key: {str(e)}"
            logger.error(error_msg)
            raise KeyManagementError(error_msg)

    @staticmethod
    def load_public_key(file_path: str) -> RSAPublicKey:
        """
        Loads a public key from a file with error handling.

        Args:
            file_path (str): Path to the public key file

        Returns:
            RSAPublicKey: The loaded public key

        Raises:
            KeyManagementError: If there are issues loading the public key
        """
        try:
            with open(file_path, "rb") as f:
                public_key = serialization.load_pem_public_key(
                    f.read(),
                    backend=default_backend()
                )

                if not isinstance(public_key, RSAPublicKey):
                    raise KeyManagementError("Loaded key is not an RSA public key")

                logger.info(f"Successfully loaded public key from {file_path}")
                return public_key

        except FileNotFoundError:
            error_msg = f"Public key file not found: {file_path}"
            logger.error(error_msg)
            raise KeyManagementError(error_msg)
        except ValueError as e:
            error_msg = f"Invalid public key: {str(e)}"
            logger.error(error_msg)
            raise KeyManagementError(error_msg)
        except Exception as e:
            error_msg = f"Unexpected error loading public key: {str(e)}"
            logger.error(error_msg)
            raise KeyManagementError(error_msg)

    @staticmethod
    def encrypt_message(message: str, public_key: RSAPublicKey) -> EncryptionResult:
        """
        Encrypts a message using the provided public key with error handling.

        Args:
            message (str): The message to encrypt
            public_key (RSAPublicKey): The public key to use for encryption

        Returns:
            EncryptionResult: Object containing encryption result and metadata
        """
        try:
            if not message:
                raise ValueError("Message cannot be empty")

            message_bytes = message.encode()
            max_message_length = (public_key.key_size // 8) - 42  # Account for OAEP padding

            if len(message_bytes) > max_message_length:
                raise ValueError(
                    f"Message length ({len(message_bytes)} bytes) exceeds maximum "
                    f"allowed length ({max_message_length} bytes) for this key size"
                )

            encrypted = public_key.encrypt(
                message_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            logger.info("Message encrypted successfully")
            return EncryptionResult(encrypted_data=encrypted, success=True)

        except ValueError as e:
            error_msg = f"Encryption failed due to invalid input: {str(e)}"
            logger.error(error_msg)
            return EncryptionResult(encrypted_data=b"", success=False, error_message=error_msg)
        except Exception as e:
            error_msg = f"Unexpected error during encryption: {str(e)}"
            logger.error(error_msg)
            return EncryptionResult(encrypted_data=b"", success=False, error_message=error_msg)

    @staticmethod
    def decrypt_message(encrypted_message: bytes, private_key: RSAPrivateKey) -> DecryptionResult:
        """
        Decrypts an encrypted message using the provided private key with error handling.

        Args:
            encrypted_message (bytes): The encrypted message to decrypt
            private_key (RSAPrivateKey): The private key to use for decryption

        Returns:
            DecryptionResult: Object containing decryption result and metadata
        """
        try:
            if not encrypted_message:
                raise ValueError("Encrypted message cannot be empty")

            decrypted_message = private_key.decrypt(
                encrypted_message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            ).decode()

            logger.info("Message decrypted successfully")
            return DecryptionResult(
                decrypted_data=decrypted_message,
                success=True
            )

        except ValueError as e:
            error_msg = f"Decryption failed due to invalid input: {str(e)}"
            logger.error(error_msg)
            return DecryptionResult(success=False, error_message=error_msg)
        except Exception as e:
            error_msg = f"Unexpected error during decryption: {str(e)}"
            logger.error(error_msg)
            return DecryptionResult(success=False, error_message=error_msg)


def main():
    """Example usage with error handling"""
    try:
        # Create an instance of the AsymmetricEncryption class
        enc_sys = AsymmetricEncryption(key_size=2048)

        # Define key file paths
        current_dir = os.path.dirname(os.path.abspath(__file__))
        private_key_path = os.path.join(current_dir, "keys", "private_key.pem")
        public_key_path = os.path.join(current_dir, "keys", "public_key.pem")

        # Save keys to files with password protection
        private_key_password = b"your-secure-password"
        enc_sys.save_keys(
            private_key_path=private_key_path,
            public_key_path=public_key_path,
            private_key_password=private_key_password
        )

        # Load the keys
        public_key = enc_sys.load_public_key(public_key_path)
        private_key = enc_sys.load_private_key(private_key_path, private_key_password)

        # Test message
        message = "Hello, this is a secret message!"
        print(f'Original message: {message}')

        # Encrypt the message
        encryption_result = enc_sys.encrypt_message(message, public_key)
        if encryption_result.success:
            print("Encryption successful!")
            encrypted_msg = encryption_result.encrypted_data
            print(f"Encrypted (hex): {encrypted_msg.hex()}")

            # Decrypt the message
            decryption_result = enc_sys.decrypt_message(encrypted_msg, private_key)
            if decryption_result.success:
                print(f"Decrypted message: {decryption_result.decrypted_data}")
            else:
                print(f"Decryption failed: {decryption_result.error_message}")
        else:
            print(f"Encryption failed: {encryption_result.error_message}")

    except KeyManagementError as e:
        print(f"Key management error: {str(e)}")
        logger.error(f"Key management error: {str(e)}")
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        logger.error(f"Unexpected error: {str(e)}", exc_info=True)


if __name__ == "__main__":
    main()