# This code was created with the help of ChatGPT
# https://chatgpt.com/c/5cab6f7a-0be2-4138-a4ca-be07dbe4a9d7

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.serialization import (Encoding, PrivateFormat,
                                                          PublicFormat, NoEncryption)


class AsymmetricEncryption:
    """A class to handle asymmetric encryption and decryption using RSA algorithm."""

    def __init__(self) -> None:
        """
        Initializes the encryption system, generating both private and public keys using RSA.
        """
        self.private_key: RSAPrivateKey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key: RSAPublicKey = self.private_key.public_key()

    def save_keys(self) -> None:
        """
        Saves the private and public keys to files in PEM format.
        """
        with open("private_key.pem", "wb") as f:
            f.write(
                self.private_key.private_bytes(
                    encoding=Encoding.PEM,
                    format=PrivateFormat.PKCS8,
                    encryption_algorithm=NoEncryption()
                )
            )

        with open("public_key.pem", "wb") as f:
            f.write(
                self.public_key.public_bytes(
                    encoding=Encoding.PEM,
                    format=PublicFormat.SubjectPublicKeyInfo
                )
            )

    @staticmethod
    def load_private_key(file_path: str) -> RSAPrivateKey:
        """
        Loads a private key from a specified file path.

        Args:
            file_path (str): Path to the file containing the private key in PEM format.

        Returns:
            RSAPrivateKey: The loaded private key.
        """
        with open(file_path, "rb") as f:
            private_key: RSAPrivateKey = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
        return private_key

    @staticmethod
    def load_public_key(file_path: str) -> RSAPublicKey:
        """
        Loads a public key from a specified file path.

        Args:
            file_path (str): Path to the file containing the public key in PEM format.

        Returns:
            RSAPublicKey: The loaded public key.
        """
        with open(file_path, "rb") as f:
            public_key: RSAPublicKey = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )
        return public_key

    def print_private_key(self) -> None:
        """
        Prints the private key in PEM format.

        This method serializes the private key stored in the class instance into
        PEM format and prints it to the standard output. This can be useful for
        debugging or verifying the key's proper storage and generation.
        """
        pem: str = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        print(pem)

    def print_public_key(self) -> None:
        """
        Prints the public key in PEM format.

        This method serializes the public key stored in the class instance into
        PEM format and prints it to the standard output. This facilitates sharing
        the public key for encryption purposes or for integration into public key
        infrastructures.
        """
        pem: str = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        print(pem)

    @staticmethod
    def encrypt_message(message: str, public_key: RSAPublicKey) -> bytes:
        """
        Encrypts a message using the provided public key.

        Args:
            message (str): The message to be encrypted.
            public_key (RSAPublicKey): The public key to use for encryption.

        Returns:
            bytes: The encrypted message.
        """
        encrypted: bytes = public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted

    @staticmethod
    def decrypt_message(encrypted_message: bytes, private_key: RSAPrivateKey) -> str:
        """
        Decrypts an encrypted message using the provided private key.

        Args:
            encrypted_message (bytes): The message to be decrypted.
            private_key (RSAPrivateKey): The private key to use for decryption.

        Returns:
            str: The decrypted message.
        """
        original_message: str = private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ).decode()
        return original_message


def main():
    """ Example usage """
    # Create an instance of the AsymmetricEncryption class.
    enc_sys = AsymmetricEncryption()

    # Save keys to files
    enc_sys.save_keys()

    # Load the public key from file.
    public_key_ = enc_sys.load_public_key("public_key.pem")

    # Load the private key from file.
    private_key_ = enc_sys.load_private_key("private_key.pem")

    # Print keys
    enc_sys.print_public_key()
    enc_sys.print_private_key()

    # Message
    message_ = "Hello, this is a secret message!"
    print(f'message: {message_}')

    # Encrypt the message
    encrypted_msg = enc_sys.encrypt_message(message_, public_key_)
    print("Encrypted:", encrypted_msg)

    # Decrypt the message.
    decrypted_msg = enc_sys.decrypt_message(encrypted_msg, private_key_)
    print("Decrypted:", decrypted_msg)


if __name__ == "__main__":
    main()
