# 🍍 Pineapple

> **Quantum-resistant end-to-end encrypted messaging for the post-quantum era**

Pineapple is a cutting-edge secure messaging platform that protects your communications against both classical and quantum computer attacks. Built with NIST-standardized post-quantum cryptographic algorithms and modern engineering principles, Pineapple delivers military-grade security with an elegant user experience.

---

## ✨ Features

**🔐 Military-Grade Post-Quantum Cryptography**
- NIST FIPS 203 (ML-KEM-1024) for quantum-resistant key exchange
- NIST FIPS 204 (ML-DSA/Dilithium3) for post-quantum authentication
- Hybrid classical-quantum security combining X25519 + Kyber
- Zero-knowledge architecture: your keys, your messages, your privacy

**🔄 Advanced Security Properties**
- **Forward Secrecy**: Compromised keys cant decrypt past messages
- **Post-Compromise Security**: Automatic recovery from key compromise
- **Authenticated Encryption**: Cryptographic proof messages werent tampered with
- **Deniability**: No cryptographic proof you sent specific messages

**⚡ Real-Time Secure Communication**
- Peer-to-peer TCP connections with sub-10ms latency
- Automatic session establishment and key agreement
- Support for text messages and file transfers
- Live cryptographic operation logging for transparency

**🎨 Modern User Experience**
- WhatsApp-inspired interface built with egui
- Cross-platform: Windows, Linux, macOS
- Dark mode optimized for extended use
- Zero configuration required

---

## 🔬 Cryptographic Protocols

Pineapple offers two battle-tested cryptographic modes, each designed for different security requirements:

### PQXDH Mode (Recommended)

**Post-Quantum Extended Diffie-Hellman** — Based on Signals X3DH protocol, enhanced with quantum resistance.

```
Protocol Flow:
1. Hybrid Key Exchange     → ML-KEM-1024 + X25519
2. Initial Shared Secret   → HKDF key derivation
3. Session Establishment   → Double Ratchet initialization
4. Message Encryption      → AES-256-GCM per-message keys
```

**Security Guarantees:**
- ✅ Quantum-resistant key exchange (ML-KEM-1024)
- ✅ Forward secrecy from first message
- ✅ Post-compromise security via ratcheting
- ✅ Implicit mutual authentication
- ✅ Cryptographic deniability

**Perfect for:** Long-term conversations requiring maximum security properties

### Kyber-Dilithium-AES Mode

**Direct Key Encapsulation** — Simplified protocol optimized for performance and auditability.

```
Protocol Flow:
1. Key Exchange           → ML-KEM-768 encapsulation
2. Authentication         → ML-DSA (Dilithium3) signatures
3. Shared Secret          → Direct from Kyber output
4. Message Encryption     → AES-256-GCM with session key
```

**Security Guarantees:**
- ✅ Quantum-resistant key exchange (ML-KEM-768)
- ✅ Strong authentication via post-quantum signatures
- ✅ AEAD encryption preventing tampering
- ✅ Simpler protocol, easier to audit

**Perfect for:** High-performance scenarios, security audits, or when simplicity is paramount

---

## 🚀 Quick Start

### Prerequisites

```bash
# Required tools
Rust 1.70+
Python 3.8+

# Required libraries (place in libs/ directory)
libpqcrystals_kyber768_ref.{so|dll|dylib}
libpqcrystals_dilithium3_ref.{so|dll|dylib}
```

### Installation

```bash
# Clone the repository
git clone https://github.com/SubramanyaJ/pineapple
cd pineapple

# Build release binary
cargo build --release

# Launch GUI
cargo run --bin pineapple-gui --release
```

### Your First Encrypted Conversation

**Alice (Listener):**
```
1. Launch Pineapple → Select crypto mode → Click "Start Listening"
2. Share displayed address: 192.168.1.100:5000
3. Wait for Bob to connect
4. 🎉 Quantum-safe encryption established
```

**Bob (Connector):**
```
1. Launch Pineapple → Select same crypto mode
2. Enter Alices address → Click "Connect"
3. Wait for handshake completion
4. 🎉 Start chatting securely
```

---

## 📁 Project Structure

```
hrishikesh-prasad-r-pineapple/
├── README                          # This file
├── Cargo.toml                      # Rust dependencies & build config
│
├── libs/                           # Python bridge for PQCrystals
│   ├── kd_bridge.py               # Kyber768 & Dilithium3 ctypes wrappers
│   ├── test_kd.py                 # Python-side validation tests
│   ├── libpqcrystals_kyber768_ref.{so|dll|dylib}      # ← Place here
│   └── libpqcrystals_dilithium3_ref.{so|dll|dylib}    # ← Place here
│
└── src/                            # Rust implementation
    ├── lib.rs                      # Public API surface
    ├── gui.rs                      # Main GUI application (egui)
    ├── main.rs                     # CLI entry point (optional)
    ├── build.rs                    # Cargo build hooks
    │
    ├── crypto_mode.rs              # Protocol selection enum
    ├── session.rs                  # High-level session orchestration
    ├── messages.rs                 # Message type system & serialization
    │
    ├── network.rs                  # PQXDH protocol networking
    ├── network_kd.rs               # Kyber-Dilithium protocol networking
    ├── network_kd_raw.rs           # Low-level KD primitives
    │
    ├── test_kd.rs                  # Unit tests for KD mode
    ├── test_kd_comprehensive.rs    # Integration test suite
    ├── test_kd_full.rs             # End-to-end test scenarios
    │
    ├── pqxdh/                      # 📦 Post-Quantum X3DH Module
    │   ├── mod.rs                  # Public API & orchestration
    │   ├── types.rs                # User identity, keys, bundles
    │   ├── handshake.rs            # Key agreement protocol
    │   └── conversions.rs          # Serialization utilities
    │
    ├── ratchet/                    # 📦 Double Ratchet Module
    │   ├── mod.rs                  # Ratchet state machine
    │   ├── types.rs                # Chain keys, message keys
    │   ├── kdf.rs                  # HKDF key derivation
    │   └── encryption.rs           # Message AEAD operations
    │
    └── kyber_dilithium/            # 📦 Kyber-Dilithium-AES Module
        ├── mod.rs                  # Protocol orchestration
        ├── handshake.rs            # Key exchange flow
        └── session.rs              # AES-GCM session encryption
```

### 🏗️ Architecture Overview

**Protocol Implementations**
- **`pqxdh/`** — Complete PQXDH protocol supporting hybrid ML-KEM-1024 + X25519 key exchange, compatible with Signals X3DH philosophy extended to the post-quantum world
- **`ratchet/`** — Double Ratchet algorithm providing forward secrecy via symmetric-key ratcheting and post-compromise security via Diffie-Hellman ratcheting
- **`kyber_dilithium/`** — Simplified protocol using direct Kyber768 encapsulation for shared secrets, Dilithium3 for authentication, and AES-256-GCM for efficient message encryption

**Network Layer**
- **`network.rs`** — Length-prefixed binary framing for PQXDH mode
- **`network_kd.rs`** — JSON-based protocol for Kyber-Dilithium mode
- **`network_kd_raw.rs`** — Low-level socket operations and error handling

**Python Bridge**
- **`libs/kd_bridge.py`** — Cross-platform ctypes wrapper enabling Rust to leverage optimized PQCrystals C reference implementations for Kyber768 and Dilithium3

---

## 🧪 Testing

```bash
# Run comprehensive test suite
cargo run --bin test-kd-comprehensive

# Run full integration tests
cargo run --bin test-kd-full

```



## 🤝 Contributing

Contributions are welcomed and encouraged! Areas where we would love help:

**Security & Cryptography**
- Security auditing and threat modeling
- Performance optimization of crypto operations
- Side-channel attack resistance analysis

**Development**
- Cross-platform testing (especially ARM/Apple Silicon)
- UI/UX improvements and accessibility
- Documentation and code examples

**Research**
- Protocol extensions and optimizations
- Integration with other PQC schemes
- Formal verification of implementations

Please open an issue before starting major work to discuss approach and feasibility.

---

## 📚 References & Further Reading

**Protocols & Standards**
1. [Signal Protocol Specifications](https://signal.org/docs/) — Foundation for PQXDH design
2. [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography) — Standardization project
3. [FIPS 203: ML-KEM](https://csrc.nist.gov/pubs/fips/203/final) — Kyber key encapsulation
4. [FIPS 204: ML-DSA](https://csrc.nist.gov/pubs/fips/204/final) — Dilithium signatures
5. [Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/) — Forward secrecy mechanism
6. [X3DH Key Agreement](https://signal.org/docs/specifications/x3dh/) — Asynchronous key exchange

**Academic Papers**
- Perrin, T. & Marlinspike, M. (2016). "The Double Ratchet Algorithm"
- Alkim et al. (2020). "Post-quantum key exchange - a new hope"
- Ducas et al. (2018). "CRYSTALS-Dilithium: A Lattice-Based Digital Signature Scheme"

**Implementation Resources**
- [PQCrystals](https://pq-crystals.org/) — Reference implementations
- [Open Quantum Safe](https://openquantumsafe.org/) — PQC integration library
- [CIRCL](https://github.com/cloudflare/circl) — Cloudflares crypto library

---

## ⚖️ License

License terms are currently under consideration. Please contact the maintainers for information about usage rights.

---

## 👥 Authors

**Subramanya J, Hrishikesh R Prasad **
- Email: subramanyajaradhya@gmail.com, rprasadhrishikesh@gmail.com
- GitHub: [@SubramanyaJ](https://github.com/SubramanyaJ)[@Hrishikesh-Prasad-R](https://github.com/Hrishikesh-Prasad-R)


---

## 🙏 Acknowledgments

- **Signal Foundation** for pioneering modern E2EE protocols
- **NIST PQC Team** for rigorous standardization process
- **PQCrystals Team** for production-ready reference implementations
- **Rust Community** for exceptional cryptographic libraries
- **egui Community** for a delightful GUI framework

---

## ⚠️ Important Disclaimer

**Pineapple is a research and educational project.** While it implements cryptographic protocols correctly to the best of our knowledge and uses NIST-standardized algorithms, it has **NOT undergone professional security auditing**.

**Do not use Pineapple for:**
- Communications where lives depend on secrecy
- Highly sensitive business or government communications
- Any scenario where security failure has serious consequences

**Recommended for:**
- Learning about post-quantum cryptography
- Academic research and experimentation
- Privacy-conscious personal communications (with appropriate caveats)
- Security research and protocol development

For production use, prefer battle-tested solutions like Signal, WhatsApp, or iMessage that have undergone extensive professional security audits.

---

## 📧 Contact

**Security Issues:** Please report vulnerabilities privately via email to the maintainers before public disclosure.

**General Questions:** Open an issue on GitHub or reach out via email.

**Collaboration:** We are open to academic partnerships and research collaborations.

---

<div align="center">

**Remember: Privacy is a fundamental human right.**

Built with ❤️ and lattice-based cryptography

</div>