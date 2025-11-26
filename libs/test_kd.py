import os
from kd_bridge import Kyber768, Dilithium3

print("===== Pineapple KD Test =====")
print("Working directory:", os.getcwd())

print("\n--- Loading DLLs ---")
try:
    kyb = Kyber768()
    dil = Dilithium3()
    print("DLLs loaded successfully ✔")
except Exception as e:
    print("DLL loading failed ❌")
    raise

# ============================
# 1. Test Dilithium3 Keypair
# ============================

print("\n--- Dilithium3 Keypair ---")
try:
    pk, sk = dil.keypair()
    print("Public Key:", len(pk), "bytes")
    print("Secret Key:", len(sk), "bytes")
    print("Dilithium keypair generation ✔")
except Exception as e:
    print("❌ Dilithium keypair failed")
    raise

# ============================
# 2. Sign/Verify Test
# ============================

message = b"hello pineapple quantum world"

print("\n--- Dilithium Sign/Verify ---")
try:
    sig = dil.sign(message, sk)
    print("Signature:", len(sig), "bytes")

    valid = dil.verify(sig, message, pk)
    print("Signature valid?:", valid)

    assert valid, "Dilithium signature verification failed!"
    print("Dilithium signing ✔")
except Exception as e:
    print("❌ Dilithium signing/verification failed")
    raise


# ============================
# 3. Kyber Keypair Test
# ============================

print("\n--- Kyber768 Keypair ---")
try:
    pk_k, sk_k = kyb.keypair()
    print("Public Key:", len(pk_k), "bytes")
    print("Secret Key:", len(sk_k), "bytes")
    print("Kyber keypair ✔")
except Exception as e:
    print("❌ Kyber keypair failed")
    raise


# ============================
# 4. Encapsulate/Decapsulate
# ============================

print("\n--- Kyber Encapsulate/Decapsulate ---")
try:
    ct, ss_sender = kyb.encapsulate(pk_k)
    print("Ciphertext:", len(ct), "bytes")
    print("Shared secret (sender):", ss_sender.hex())

    ss_receiver = kyb.decapsulate(ct, sk_k)
    print("Shared secret (receiver):", ss_receiver.hex())

    # Verify secrets match
    assert ss_sender == ss_receiver, "Shared secrets DO NOT MATCH!"
    print("Kyber encapsulation ✔")
except Exception as e:
    print("❌ Kyber encapsulation/decapsulation failed")
    raise


# ============================
# 5. FULL KD Handshake Simulation
# ============================

print("\n===== Full KD Handshake Test =====")

# ---- Alice side ----
print("\n[Alice] generating handshakes...")

Alice_Dil = Dilithium3()
Alice_Kyb = Kyber768()

A_dil_pk, A_dil_sk = Alice_Dil.keypair()
A_kyb_pk, A_kyb_sk = Alice_Kyb.keypair()

# Sign Kyber public key
A_sig = Alice_Dil.sign(A_kyb_pk, A_dil_sk)


# ---- Bob side ----
print("[Bob] verifying signature and encapsulating...")

Bob_Dil = Dilithium3()
Bob_Kyb = Kyber768()

# Bob verifies
valid = Bob_Dil.verify(A_sig, A_kyb_pk, A_dil_pk)
print("Bob verifies Alice Dilithium signature:", valid)
assert valid, "Bob rejected Alice's signature!"

# Bob encapsulates
ct, ss_bob = Bob_Kyb.encapsulate(A_kyb_pk)
print("Bob shared secret:", ss_bob.hex())


# ---- Alice decapsulates ----
print("[Alice] decapsulating ciphertext...")

ss_alice = Alice_Kyb.decapsulate(ct, A_kyb_sk)
print("Alice shared secret:", ss_alice.hex())

assert ss_bob == ss_alice, "Handshake shared secrets do NOT match!"

print("\n===== KD Handshake SUCCESS ✔ =====")
