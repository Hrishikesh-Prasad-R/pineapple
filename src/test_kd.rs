use pyo3::Python;
use pineapple::{kyber_dilithium, network_kd};
use std::net::{TcpListener, TcpStream};
use std::thread;

fn main() {
    unsafe{std::env::set_var("PYTHONPATH", 
        std::env::current_dir()
            .unwrap()
            .join("libs")
            .to_str()
            .unwrap()
    );}
    println!("=== KD Handshake Test ===\n");

    // Start listener in background
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    println!("Listener on port {}", port);

    let handle = thread::spawn(move || {
        println!("[LISTENER] Waiting for connection...");
        let (mut stream, _) = listener.accept().unwrap();
        println!("[LISTENER] Connected!");

        Python::with_gil(|py| {
            println!("[LISTENER] Initializing KD handshake...");
            let my_data = kyber_dilithium::kd_init_handshake(py).expect("Listener init");
            println!("[LISTENER] KD init OK");

            println!("[LISTENER] Sending my data...");
            network_kd::send_json(&mut stream, &my_data).expect("Listener send");
            println!("[LISTENER] Sent!");

            println!("[LISTENER] Receiving peer data...");
            let theirs: kyber_dilithium::KDHandshakeData =
                network_kd::recv_json(&mut stream).expect("Listener recv");
            println!("[LISTENER] Received peer data!");

            println!("[LISTENER] Processing handshake...");
            let (ciphertext, shared) =
                kyber_dilithium::kd_process_handshake(py, &theirs).expect("Listener process");
            println!("[LISTENER] Shared secret length: {}", shared.len());

            println!("[LISTENER] Sending ciphertext...");
            network_kd::send_json(&mut stream, &ciphertext).expect("Listener send ct");
            println!("[LISTENER] Done!");

            let session = kyber_dilithium::KDSession::new(&shared);
            
            // Test encrypt/decrypt
            let plaintext = b"Hello from listener!";
            let ct = session.encrypt(plaintext).expect("encrypt");
            println!("[LISTENER] Encrypted {} bytes", ct.len());
            
            session
        })
    });

    thread::sleep(std::time::Duration::from_millis(100));

    // Connect
    println!("[CONNECTOR] Connecting...");
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    println!("[CONNECTOR] Connected!");

    let connector_session = Python::with_gil(|py| {
        println!("[CONNECTOR] Initializing KD handshake...");
        let my_data = kyber_dilithium::kd_init_handshake(py).expect("Connector init");
        println!("[CONNECTOR] KD init OK");

        println!("[CONNECTOR] Receiving peer data...");
        let theirs: kyber_dilithium::KDHandshakeData =
            network_kd::recv_json(&mut stream).expect("Connector recv");
        println!("[CONNECTOR] Received peer data!");

        println!("[CONNECTOR] Sending my data...");
        network_kd::send_json(&mut stream, &my_data).expect("Connector send");
        println!("[CONNECTOR] Sent!");

        println!("[CONNECTOR] Receiving ciphertext...");
        let ciphertext: Vec<u8> =
            network_kd::recv_json(&mut stream).expect("Connector recv ct");
        println!("[CONNECTOR] Received ciphertext!");

        println!("[CONNECTOR] Finishing handshake...");
        let shared = kyber_dilithium::kd_finish_handshake(py, ciphertext, my_data.kyber_pk.clone())
            .expect("Connector finish");
        println!("[CONNECTOR] Shared secret length: {}", shared.len());

        kyber_dilithium::KDSession::new(&shared)
    });

    let listener_session = handle.join().unwrap();

    println!("\n=== Testing Encryption ===");
    
    let msg = b"Test message";
    let ct = listener_session.encrypt(msg).unwrap();
    println!("Encrypted: {} bytes", ct.len());
    
    let pt = connector_session.decrypt(&ct).unwrap();
    println!("Decrypted: {}", String::from_utf8_lossy(&pt));
    
    assert_eq!(msg.as_slice(), pt.as_slice());
    
    println!("\n✅ All tests passed!");
}