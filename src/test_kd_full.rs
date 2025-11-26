use pyo3::Python;
use pineapple::{kyber_dilithium, network_kd};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

fn main() {
    println!("=== Full KD Test Suite ===\n");

    // Set Python path
    unsafe {
        std::env::set_var(
            "PYTHONPATH",
            std::env::current_dir()
                .unwrap()
                .join("libs")
                .to_str()
                .unwrap(),
        );
    }

    // Test 1: Python module loading
    println!("Test 1: Python module loading...");

    let module_loaded = Python::with_gil(|py| {
        py.import_bound("kd_bridge").map(|_| ())
    });

    match module_loaded {
        Ok(_) => println!("✅ Python module loaded successfully\n"),
        Err(e) => {
            println!("❌ Failed to load Python module: {}\n", e);
            return;
        }
    }

    // Test 2: Basic handshake functions
    println!("Test 2: Basic handshake functions...");
    let (listener_data, _connector_data) = Python::with_gil(|py| {
        println!("  - Generating listener keys...");
        let listener = kyber_dilithium::kd_init_handshake(py).expect("Listener init failed");
        println!("    Dilithium PK: {} bytes", listener.dilithium_pk.len());
        println!("    Kyber PK: {} bytes", listener.kyber_pk.len());
        println!("    Signature: {} bytes", listener.signature.len());

        println!("  - Generating connector keys...");
        let connector = kyber_dilithium::kd_init_handshake(py).expect("Connector init failed");
        println!("    Dilithium PK: {} bytes", connector.dilithium_pk.len());
        println!("    Kyber PK: {} bytes", connector.kyber_pk.len());
        println!("    Signature: {} bytes", connector.signature.len());

        (listener, connector)
    });
    println!("✅ Key generation successful\n");

    // Test 3: Network serialization
    println!("Test 3: Network serialization...");
    let serialized = serde_json::to_vec(&listener_data).expect("Serialization failed");
    println!("  - Serialized size: {} bytes", serialized.len());

    let deserialized: kyber_dilithium::KDHandshakeData =
        serde_json::from_slice(&serialized).expect("Deserialization failed");
    println!("  - Deserialized successfully");

    assert_eq!(listener_data.dilithium_pk, deserialized.dilithium_pk);

    println!("✅ Serialization working\n");

    // Test 4: Full network handshake
    println!("Test 4: Full network handshake...");

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    println!("  - Listener on port {}", port);

    let listener_handle = thread::spawn(move || {
        println!("  [LISTENER] Waiting for connection...");
        let (mut stream, _) = listener.accept().unwrap();
        println!("  [LISTENER] Connected!");

        // Generate keys BEFORE any network I/O
        let my_data = Python::with_gil(|py| {
            println!("  [LISTENER] Generating keys...");
            kyber_dilithium::kd_init_handshake(py).expect("Listener init")
        });

        println!("  [LISTENER] Waiting for peer data...");
        let theirs: kyber_dilithium::KDHandshakeData =
            network_kd::recv_json(&mut stream).expect("Listener recv failed");
        println!("  [LISTENER] Received peer data!");

        println!("  [LISTENER] Sending my data...");
        network_kd::send_json(&mut stream, &my_data).expect("Listener send failed");

        Python::with_gil(|py| {
            println!("  [LISTENER] Processing handshake...");
            let (ciphertext, shared) =
                kyber_dilithium::kd_process_handshake(py, &theirs).expect("Listener process failed");
            println!("  [LISTENER] Shared secret: {} bytes", shared.len());

            println!("  [LISTENER] Sending ciphertext...");
            network_kd::send_json(&mut stream, &ciphertext).expect("Listener send ct failed");

            let session = kyber_dilithium::KDSession::new(&shared);
            println!("  [LISTENER] Session created!");

            let msg = b"Hello from listener!";
            println!("  [LISTENER] Encrypting test message...");
            let ct = session.encrypt(msg).expect("Encrypt failed");
            println!("  [LISTENER] Sending encrypted message ({} bytes)...", ct.len());

            network_kd::send_json(&mut stream, &ct).expect("Send encrypted failed");

            println!("  [LISTENER] Done!");
            session
        })
    });

    thread::sleep(Duration::from_millis(200));

    println!("  [CONNECTOR] Connecting...");
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port)).expect("Connect failed");
    println!("  [CONNECTOR] Connected!");

    // Generate keys BEFORE any network I/O
    let my_data = Python::with_gil(|py| {
        println!("  [CONNECTOR] Generating keys...");
        kyber_dilithium::kd_init_handshake(py).expect("Connector init")
    });

    println!("  [CONNECTOR] Sending my data...");
    network_kd::send_json(&mut stream, &my_data).expect("Connector send failed");

    println!("  [CONNECTOR] Waiting for peer data...");
    let theirs: kyber_dilithium::KDHandshakeData =
        network_kd::recv_json(&mut stream).expect("Connector recv failed");
    println!("  [CONNECTOR] Received peer data!");

    println!("  [CONNECTOR] Waiting for ciphertext...");
    let ciphertext: Vec<u8> =
        network_kd::recv_json(&mut stream).expect("Connector recv ct failed");
    println!("  [CONNECTOR] Received ciphertext!");

    let connector_session = Python::with_gil(|py| {

        println!("  [CONNECTOR] Finishing handshake...");
        let shared = kyber_dilithium::kd_finish_handshake(
            py,
            ciphertext,
            my_data.kyber_sk.clone(),
        )
        .expect("Connector finish failed");
        println!("  [CONNECTOR] Shared secret: {} bytes", shared.len());

        let session = kyber_dilithium::KDSession::new(&shared);
        println!("  [CONNECTOR] Session created!");

        println!("  [CONNECTOR] Waiting for encrypted message...");
        let ct: Vec<u8> = network_kd::recv_json(&mut stream).expect("Recv encrypted failed");
        println!("  [CONNECTOR] Received {} bytes", ct.len());

        println!("  [CONNECTOR] Decrypting...");
        let pt = session.decrypt(&ct).expect("Decrypt failed");
        println!("  [CONNECTOR] Decrypted: {}", String::from_utf8_lossy(&pt));

        println!("  [CONNECTOR] Done!");
        session
    });

    let listener_session = listener_handle.join().unwrap();

    println!("✅ Full handshake successful\n");

    // Test 5: Bidirectional messaging
    println!("Test 5: Bidirectional messaging...");

    let msg1 = b"Message from listener";
    let ct1 = listener_session.encrypt(msg1).unwrap();
    let pt1 = connector_session.decrypt(&ct1).unwrap();
    assert_eq!(msg1.as_slice(), pt1.as_slice());
    println!("  ✅ Listener -> Connector");

    let msg2 = b"Message from connector";
    let ct2 = connector_session.encrypt(msg2).unwrap();
    let pt2 = listener_session.decrypt(&ct2).unwrap();
    assert_eq!(msg2.as_slice(), pt2.as_slice());
    println!("  ✅ Connector -> Listener");

    println!("\n🎉 ALL TESTS PASSED! 🎉");
    println!("\nKyber+Dilithium is working correctly.");
    println!("The issue must be in the GUI threading/channel logic.");
}