#kd_bridge.py

import ctypes
import platform
from pathlib import Path
import os

# ==========================
# CONSTANTS
# ==========================

# Kyber768
KYBER768_PUBLICKEYBYTES = 1184
KYBER768_SECRETKEYBYTES = 2400
KYBER768_CIPHERTEXTBYTES = 1088
KYBER768_SHAREDSECRETBYTES = 32

# Dilithium3
DILITHIUM3_PUBLICKEYBYTES = 1952
DILITHIUM3_SECRETKEYBYTES = 4032
DILITHIUM3_SIGNATUREBYTES = 3309


# ==========================
# Utility
# ==========================

def _load_lib(name: str):
    """
    Load DLL / SO / DYLIB depending on platform.
    Looks relative to this file.
    """
    base_dir = Path(__file__).parent.absolute()
    lib_path = base_dir / name

    if not lib_path.exists():
        raise FileNotFoundError(
            f"Unable to find {name} in {base_dir}\n"
            f"Available: {list(base_dir.glob('*'))}"
        )

    try:
        return ctypes.CDLL(str(lib_path))
    except OSError as e:
        raise RuntimeError(f"Failed to load {lib_path}: {e}")


# ==========================
# Dilithium3 Wrapper
# ==========================

class Dilithium3:
    def __init__(self):
        system = platform.system()
        if system == "Windows":
            libname = "libpqcrystals_dilithium3_ref.dll"
        elif system == "Linux":
            libname = "libpqcrystals_dilithium3_ref.so"
        elif system == "Darwin":
            libname = "libpqcrystals_dilithium3_ref.dylib"
        else:
            raise RuntimeError(f"Unsupported OS: {system}")

        self.lib = _load_lib(libname)

        # signatures
        self.keypair_func = self.lib.pqcrystals_dilithium3_ref_keypair
        self.keypair_func.argtypes = [
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.POINTER(ctypes.c_uint8)
        ]

        self.sign_func = self.lib.pqcrystals_dilithium3_ref_signature
        self.sign_func.argtypes = [
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.POINTER(ctypes.c_size_t),
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint8)
        ]

        self.verify_func = self.lib.pqcrystals_dilithium3_ref_verify
        self.verify_func.argtypes = [
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint8)
        ]

    # ------------- KEYPAIR -------------
    def keypair(self):
        pk = (ctypes.c_uint8 * DILITHIUM3_PUBLICKEYBYTES)()
        sk = (ctypes.c_uint8 * DILITHIUM3_SECRETKEYBYTES)()

        res = self.keypair_func(pk, sk)
        if res != 0:
            raise RuntimeError("Dilithium keypair() failed")

        return bytes(pk), bytes(sk)

    # ------------- SIGNING -------------
    def sign(self, message: bytes, sk: bytes, context: bytes = b""):
        sig = (ctypes.c_uint8 * DILITHIUM3_SIGNATUREBYTES)()
        siglen = ctypes.c_size_t()

        msg_arr = (ctypes.c_uint8 * len(message))(*message)
        ctx_arr = (ctypes.c_uint8 * len(context))(*context) if context else None
        sk_arr = (ctypes.c_uint8 * len(sk))(*sk)

        ret = self.sign_func(
            sig,
            ctypes.byref(siglen),
            msg_arr, len(message),
            ctx_arr, len(context),
            sk_arr
        )

        if ret != 0:
            raise RuntimeError("Dilithium sign() failed")

        return bytes(sig)[: siglen.value]

    # ------------- VERIFICATION -------------
    def verify(self, signature: bytes, message: bytes, pk: bytes, context: bytes = b""):
        sig_arr = (ctypes.c_uint8 * len(signature))(*signature)
        msg_arr = (ctypes.c_uint8 * len(message))(*message)
        ctx_arr = (ctypes.c_uint8 * len(context))(*context) if context else None
        pk_arr = (ctypes.c_uint8 * len(pk))(*pk)

        ret = self.verify_func(
            sig_arr, len(signature),
            msg_arr, len(message),
            ctx_arr, len(context),
            pk_arr
        )

        return ret == 0  # True = valid
        

# ==========================
# Kyber768 Wrapper
# ==========================

class Kyber768:
    def __init__(self):
        system = platform.system()
        if system == "Windows":
            libname = "libpqcrystals_kyber768_ref.dll"
        elif system == "Linux":
            libname = "libpqcrystals_kyber768_ref.so"
        elif system == "Darwin":
            libname = "libpqcrystals_kyber768_ref.dylib"
        else:
            raise RuntimeError(f"Unsupported OS: {system}")

        self.lib = _load_lib(libname)

        self.keypair_func = self.lib.pqcrystals_kyber768_ref_keypair
        self.keypair_func.argtypes = [
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.POINTER(ctypes.c_uint8)
        ]

        self.enc_func = self.lib.pqcrystals_kyber768_ref_enc
        self.enc_func.argtypes = [
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.POINTER(ctypes.c_uint8)
        ]

        self.dec_func = self.lib.pqcrystals_kyber768_ref_dec
        self.dec_func.argtypes = [
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.POINTER(ctypes.c_uint8)
        ]

    # ------------- KEYPAIR -------------
    def keypair(self):
        pk = (ctypes.c_uint8 * KYBER768_PUBLICKEYBYTES)()
        sk = (ctypes.c_uint8 * KYBER768_SECRETKEYBYTES)()

        if self.keypair_func(pk, sk) != 0:
            raise RuntimeError("Kyber keypair() failed")

        return bytes(pk), bytes(sk)

    # ------------- ENCAPSULATE -------------
    def encapsulate(self, pk: bytes):
        if len(pk) != KYBER768_PUBLICKEYBYTES:
            raise ValueError("Invalid Kyber public key size")

        ct = (ctypes.c_uint8 * KYBER768_CIPHERTEXTBYTES)()
        ss = (ctypes.c_uint8 * KYBER768_SHAREDSECRETBYTES)()
        pk_arr = (ctypes.c_uint8 * len(pk))(*pk)

        if self.enc_func(ct, ss, pk_arr) != 0:
            raise RuntimeError("Kyber encapsulate() failed")

        return bytes(ct), bytes(ss)

    # ------------- DECAPSULATE -------------
    def decapsulate(self, ct: bytes, sk: bytes):
        if len(ct) != KYBER768_CIPHERTEXTBYTES:
            raise ValueError("Invalid Kyber ciphertext")
        if len(sk) != KYBER768_SECRETKEYBYTES:
            raise ValueError("Invalid Kyber secret key")

        ss = (ctypes.c_uint8 * KYBER768_SHAREDSECRETBYTES)()
        ct_arr = (ctypes.c_uint8 * len(ct))(*ct)
        sk_arr = (ctypes.c_uint8 * len(sk))(*sk)

        if self.dec_func(ss, ct_arr, sk_arr) != 0:
            raise RuntimeError("Kyber decapsulate() failed")

        return bytes(ss)
