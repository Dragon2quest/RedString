mod protocol;

use byteorder::{BigEndian, ByteOrder};
use local_ip_address::local_ip;
use protocol::{ControlPacket, PlatformBuffer, FRAME_TYPE_BINARY, FRAME_TYPE_TEXT};
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let my_ip = local_ip().unwrap_or([127, 0, 0, 1].into());
    let port = 7788;
    let bind_addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&bind_addr).await?;

    let platform = Arc::new(Mutex::new(PlatformBuffer::new(1024))); // Default: 1 GB Soft Limit

    println!("========================================================");
    println!("             RED STRING - THE CORE WEAVE               ");
    println!("========================================================");
    println!("[*] Desktop listening on: {}:{}", my_ip, port);
    println!("[*] Pairing Token Payload:");
    println!(
        "    {{\"ip\":\"{}\",\"port\":{},\"soft_mb\":1024}}",
        my_ip, port
    );
    println!("--------------------------------------------------------");
    println!("[*] Waiting for mobile node to weave thread...\n");

    loop {
        let (mut socket, peer_addr) = listener.accept().await?;
        println!("[+] Red String connected to mobile: {}", peer_addr);
        let platform_ref = Arc::clone(&platform);

        tokio::spawn(async move {
            let mut header_buf = [0u8; 5];
            let mut active_file: Option<File> = None;

            loop {
                // Read 5-byte frame header: [Type: 1B][Length: 4B]
                if socket.read_exact(&mut header_buf).await.is_err() {
                    println!("[-] Thread severed with: {}", peer_addr);
                    break;
                }

                let frame_type = header_buf[0];
                let payload_len = BigEndian::read_u32(&header_buf[1..5]) as usize;

                let mut payload = vec![0u8; payload_len];
                if socket.read_exact(&mut payload).await.is_err() {
                    eprintln!("[!] Packet read failed.");
                    break;
                }

                match frame_type {
                    FRAME_TYPE_TEXT => {
                        if let Ok(pkt) = serde_json::from_slice::<ControlPacket>(&payload) {
                            match pkt {
                                ControlPacket::FateWatchDelta { action, chars } => {
                                    if action == "insert" {
                                        print!("{}", chars);
                                        std::io::Write::flush(&mut std::io::stdout()).unwrap();
                                    } else if action == "delete" {
                                        print!("\x08 \x08"); // Backspace visual
                                        std::io::Write::flush(&mut std::io::stdout()).unwrap();
                                    }
                                }
                                ControlPacket::FateSyncText { sender, content } => {
                                    println!("\n[Fate Sync] {}: {}", sender, content);
                                }
                                ControlPacket::FileOffer { file_name, total_size } => {
                                    let mut p = platform_ref.lock().await;
                                    match p.can_accept(total_size) {
                                        Ok(in_flex) => {
                                            if in_flex {
                                                println!("\n[!] WARNING: File enters +15% Elastic Buffer Zone.");
                                            }
                                            println!("[Platform] Receiving incoming artifact: {} ({} bytes)", file_name, total_size);
                                            active_file = Some(File::create(format!("received_{}", file_name)).await.unwrap());
                                            p.current_usage += total_size;
                                        }
                                        Err(reason) => {
                                            eprintln!("\n[Platform Drop Rejected]: {}", reason);
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    FRAME_TYPE_BINARY => {
                        if let Some(ref mut file) = active_file {
                            if let Err(e) = file.write_all(&payload).await {
                                eprintln!("[!] Failed writing chunk to disk: {}", e);
                            }
                        }
                    }
                    _ => eprintln!("[!] Unknown frame prefix: 0x{:02X}", frame_type),
                }
            }
        });
    }
}