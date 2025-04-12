use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use std::net::IpAddr;

/// Network protocol types that can be detected and analyzed
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    TCP,
    UDP,
    ICMP,
    HTTP,
    HTTPS,
    DNS,
    DHCP,
    ARP,
    Unknown,
}

/// Represents a captured network packet with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Packet {
    /// Unique identifier for the packet
    pub id: u64,
    
    /// Timestamp when the packet was captured
    pub timestamp: DateTime<Utc>,
    
    /// The size of the packet in bytes
    pub size: usize,
    
    /// The protocol of the packet
    pub protocol: Protocol,
    
    /// Source IP address
    pub source_ip: Option<IpAddr>,
    
    /// Destination IP address
    pub dest_ip: Option<IpAddr>,
    
    /// Source port (for TCP/UDP)
    pub source_port: Option<u16>,
    
    /// Destination port (for TCP/UDP)
    pub dest_port: Option<u16>,
    
    /// The actual packet data
    pub data: PacketData,
}

/// Packet payload data with raw bytes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketData {
    /// Raw packet bytes
    pub raw_data: Vec<u8>,
    
    /// Length of the packet header
    pub header_length: usize,
}

impl Packet {
    /// Create a new packet instance
    pub fn new(
        id: u64,
        protocol: Protocol,
        size: usize,
        source_ip: Option<IpAddr>,
        dest_ip: Option<IpAddr>,
        source_port: Option<u16>,
        dest_port: Option<u16>,
        data: Vec<u8>,
        header_length: usize,
    ) -> Self {
        Self {
            id,
            timestamp: Utc::now(),
            size,
            protocol,
            source_ip,
            dest_ip,
            source_port,
            dest_port,
            data: PacketData {
                raw_data: data,
                header_length,
            },
        }
    }
    
    /// Check if this packet is part of a TCP connection
    pub fn is_tcp(&self) -> bool {
        self.protocol == Protocol::TCP
    }
    
    /// Check if this packet is part of a UDP connection
    pub fn is_udp(&self) -> bool {
        self.protocol == Protocol::UDP
    }
    
    /// Get a summary of the packet for display purposes
    pub fn summary(&self) -> String {
        let src = match self.source_ip {
            Some(ip) => format!("{}:{}", ip, self.source_port.unwrap_or(0)),
            None => "unknown".to_string(),
        };
        
        let dst = match self.dest_ip {
            Some(ip) => format!("{}:{}", ip, self.dest_port.unwrap_or(0)),
            None => "unknown".to_string(),
        };
        
        format!(
            "[{}] {:?} {} -> {} ({} bytes)",
            self.timestamp.format("%H:%M:%S%.3f"),
            self.protocol,
            src,
            dst,
            self.size
        )
    }
    
    /// Create a packet from a pcap packet
    pub fn from_pcap_packet(packet_data: &pcap::Packet) -> Option<Self> {
        // In a real implementation, this would parse the raw packet data
        // using proper packet parsing libraries
        
        // For now, we'll create a simplified packet with basic information
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
            
        let packet_id = now; // Use timestamp as ID for simplicity
        let size = packet_data.data.len();
        
        // Try to determine protocol (very simplified)
        let protocol = if size >= 54 && (packet_data.data[23] == 6 || packet_data.data[23] == 17) {
            if packet_data.data[23] == 6 {
                Protocol::TCP
            } else {
                Protocol::UDP
            }
        } else {
            Protocol::Unknown
        };
        
        // Extract IP addresses (very simplified)
        let source_ip = if size >= 34 {
            let bytes = &packet_data.data[26..30];
            Some(format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]))
        } else {
            None
        };
        
        let dest_ip = if size >= 38 {
            let bytes = &packet_data.data[30..34];
            Some(format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]))
        } else {
            None
        };
        
        // Extract ports for TCP/UDP (very simplified)
        let (source_port, dest_port) = if size >= 38 && (protocol == Protocol::TCP || protocol == Protocol::UDP) {
            let sport = ((packet_data.data[34] as u16) << 8) | packet_data.data[35] as u16;
            let dport = ((packet_data.data[36] as u16) << 8) | packet_data.data[37] as u16;
            (Some(sport), Some(dport))
        } else {
            (None, None)
        };
        
        // Create and return the packet
        Some(Self::new(
            packet_id,
            protocol,
            size,
            source_ip.map(|ip| ip.parse().ok()).flatten(),
            dest_ip.map(|ip| ip.parse().ok()).flatten(),
            source_port,
            dest_port,
            packet_data.data.to_vec(),
            0, // header_length - would normally be calculated
        ))
    }
} 