mod packet;
mod interface;

pub use packet::{Packet, PacketData, Protocol};
pub use interface::{Interface, DeviceInfo};

use anyhow::Result;
use std::sync::mpsc::Sender;

/// Network capture service that implements packet capturing functionality
pub struct CaptureService {
    interface: Interface,
    running: bool,
}

impl CaptureService {
    /// Create a new network capture service on the specified interface
    pub fn new(interface_name: &str) -> Result<Self> {
        let interface = Interface::new(interface_name)?;
        
        Ok(Self {
            interface,
            running: false,
        })
    }
    
    /// Start capturing packets and send them through the channel
    pub fn start(&mut self, tx: Sender<Packet>) -> Result<()> {
        self.running = true;
        self.interface.start_capture(tx)?;
        Ok(())
    }
    
    /// Stop the capture process
    pub fn stop(&mut self) -> Result<()> {
        self.running = false;
        self.interface.stop_capture()?;
        Ok(())
    }
    
    /// Check if the capture service is currently running
    pub fn is_running(&self) -> bool {
        self.running
    }
    
    /// Set BPF filter for packet capturing
    pub fn set_filter(&mut self, filter: &str) -> Result<()> {
        self.interface.set_filter(filter)
    }
    
    /// List all available network interfaces on the system
    pub fn list_interfaces() -> Result<Vec<DeviceInfo>> {
        Interface::list_devices()
    }
} 