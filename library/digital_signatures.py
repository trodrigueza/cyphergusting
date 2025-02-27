from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, dsa, ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.exceptions import InvalidSignature
import os
import hashlib

class DigitalSignature:
    SIGNATURE_ALGORITHMS = {
        'RSA': 'RSA-PSS',
        'DSA': 'DSA',
        'ECDSA': 'ECDSA with SECP256K1'
    }

    @staticmethod
    def generate_key_pair(algorithm='RSA', save_path=None):
        """
        Generate a new key pair for digital signatures
        """
        if algorithm == 'RSA':
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
        elif algorithm == 'DSA':
            private_key = dsa.generate_private_key(
                key_size=2048
            )
        elif algorithm == 'ECDSA':
            private_key = ec.generate_private_key(
                curve=ec.SECP256K1()
            )
        else:
            raise ValueError(f"Algoritmo no soportado: {algorithm}")

        public_key = private_key.public_key()

        if save_path:
            # Guardar clave privada
            priv_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            with open(os.path.join(save_path, f"private_key_{algorithm.lower()}.pem"), 'wb') as f:
                f.write(priv_pem)

            # Guardar clave pública
            pub_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            with open(os.path.join(save_path, f"public_key_{algorithm.lower()}.pem"), 'wb') as f:
                f.write(pub_pem)

        return private_key, public_key

    @staticmethod
    def load_keys(private_key_path, public_key_path):
        """
        Cargar claves desde archivos PEM
        """
        with open(private_key_path, 'rb') as f:
            private_key = load_pem_private_key(f.read(), password=None)
        
        with open(public_key_path, 'rb') as f:
            public_key = load_pem_public_key(f.read())

        return private_key, public_key

    @staticmethod
    def sign_document(private_key, file_path, algorithm='RSA'):
        """
        Firmar un documento usando la clave privada
        """
        with open(file_path, 'rb') as f:
            data = f.read()

        # Calcular el hash del documento
        file_hash = hashlib.sha256(data).digest()

        if isinstance(private_key, rsa.RSAPrivateKey):
            signature = private_key.sign(
                file_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        elif isinstance(private_key, dsa.DSAPrivateKey):
            signature = private_key.sign(
                file_hash,
                hashes.SHA256()
            )
        elif isinstance(private_key, ec.EllipticCurvePrivateKey):
            signature = private_key.sign(
                file_hash,
                ec.ECDSA(hashes.SHA256())
            )
        else:
            raise ValueError("Tipo de clave privada no soportado")

        # Guardar la firma en un archivo
        signature_path = file_path + '.sig'
        with open(signature_path, 'wb') as f:
            f.write(signature)

        return signature_path

    @staticmethod
    def verify_signature(public_key, file_path, signature_path):
        """
        Verificar la firma de un documento usando la clave pública
        """
        with open(file_path, 'rb') as f:
            data = f.read()
        
        with open(signature_path, 'rb') as f:
            signature = f.read()

        # Calcular el hash del documento
        file_hash = hashlib.sha256(data).digest()

        try:
            if isinstance(public_key, rsa.RSAPublicKey):
                public_key.verify(
                    signature,
                    file_hash,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
            elif isinstance(public_key, dsa.DSAPublicKey):
                public_key.verify(
                    signature,
                    file_hash,
                    hashes.SHA256()
                )
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                public_key.verify(
                    signature,
                    file_hash,
                    ec.ECDSA(hashes.SHA256())
                )
            else:
                raise ValueError("Tipo de clave pública no soportado")
            return True
        except InvalidSignature:
            return False

    @staticmethod
    def get_file_hash(file_path):
        """
        Calcular el hash SHA-256 de un archivo
        """
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest() 