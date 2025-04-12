use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use pcap::{Capture, Active, Device};
use anyhow::{Result, Context};

use super::packet::Packet;

/// Information about a network device
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    /// Name of the device (e.g., "eth0", "wlan0")
    pub name: String,
    
    /// Description of the device
    pub description: Option<String>,
    
    /// Whether this device can be used in promiscuous mode
    pub supports_promiscuous: bool,
    
    /// Whether this is a loopback device
    pub is_loopback: bool,
}

/// Represents a network interface for packet capturing
pub struct Interface {
    name: String,
    capture_thread: Option<thread::JoinHandle<()>>,
    filter: Option<String>,
    capture: Option<Capture<Active>>,
    running: Option<Arc<AtomicBool>>,
}

impl Interface {
    /// Create a new network interface
    pub fn new(name: &str) -> Result<Self> {
        Ok(Self {
            name: name.to_string(),
            capture_thread: None,
            filter: None,
            capture: None,
            running: None,
        })
    }
    
    /// Set a BPF filter for packet capturing
    pub fn set_filter(&mut self, filter: &str) -> Result<()> {
        self.filter = Some(filter.to_string());
        Ok(())
    }
    
    /// List all available network devices
    pub fn list_devices() -> Result<Vec<DeviceInfo>> {
        let devices = Device::list().context("Failed to list network devices")?;
        
        let device_infos = devices.into_iter()
            .map(|dev| {
                let is_loopback = dev.name.contains("lo");
                DeviceInfo {
                    name: dev.name,
                    description: dev.desc,
                    supports_promiscuous: true, // Simplified for now
                    is_loopback, // Basit bir yaklaşım, gerçekte PCAP'in desteklediği bir yöntem kullanılmalı
                }
            })
            .collect();
            
        Ok(device_infos)
    }
    
    /// Start packet capture on this interface
    pub fn start_capture(&mut self, packet_tx: Sender<Packet>) -> Result<()> {
        // Create a new capture handle for this interface
        let interface_name = self.name.clone();
        let mut cap = Capture::from_device(interface_name.as_str())?
            .promisc(true)
            .snaplen(65535)
            .timeout(1000)
            .open()?;
        
        // Set filter if provided
        if let Some(filter) = &self.filter {
            cap.filter(filter, true)?;
        }
        
        // Store the capture handle
        self.capture = Some(cap);
        
        // Set running flag
        let running = Arc::new(AtomicBool::new(true));
        self.running = Some(running.clone());
        
        // Get a reference to the capture so we can move it into the thread
        let mut capture_ref = self.capture.take().unwrap();
        
        // Start capture thread
        let handle = thread::spawn(move || {
            // Process packets until stopped
            while running.load(Ordering::SeqCst) {
                match capture_ref.next_packet() {
                    Ok(packet_data) => {
                        // Convert raw packet to our Packet struct
                        if let Some(packet) = Packet::from_pcap_packet(&packet_data) {
                            // Send packet through channel
                            if packet_tx.send(packet).is_err() {
                                // Channel closed, stop capturing
                                break;
                            }
                        }
                    },
                    Err(pcap::Error::TimeoutExpired) => {
                        // This is normal, just continue
                        continue;
                    },
                    Err(_) => {
                        // Other errors, stop capturing
                        break;
                    }
                }
            }
        });
        
        // Store the thread handle
        self.capture_thread = Some(handle);
        
        Ok(())
    }
    
    /// Stop the packet capturing process
    pub fn stop_capture(&mut self) -> Result<()> {
        // Signal the thread to stop
        if let Some(running) = &self.running {
            running.store(false, Ordering::SeqCst);
        }
        
        // Wait for the capture thread to finish
        if let Some(thread) = self.capture_thread.take() {
            if !thread.is_finished() {
                // Give the thread a moment to clean up
                thread::sleep(Duration::from_millis(100));
                
                // Join the thread to make sure it's properly closed
                if thread.join().is_err() {
                    log::warn!("Failed to join capture thread cleanly");
                }
            }
        }
        
        Ok(())
    }
} 