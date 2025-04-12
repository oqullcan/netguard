mod protocol;
mod anomaly;
mod signature;

pub use protocol::ProtocolAnalyzer;
pub use anomaly::AnomalyDetector;
pub use signature::SignatureDetector;

use anyhow::Result;
use std::sync::mpsc::{Sender, Receiver};
use std::thread;

use crate::capture::Packet;

/// Represents a detected security threat
#[derive(Debug, Clone)]
pub struct Threat {
    /// Unique identifier for the threat
    pub id: u64,
    
    /// Type of the threat
    pub threat_type: ThreatType,
    
    /// Severity level (1-10)
    pub severity: u8,
    
    /// Description of the threat
    pub description: String,
    
    /// Associated packet that triggered the detection
    pub associated_packet: Packet,
}

/// Types of security threats that can be detected
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThreatType {
    /// Known vulnerability signature matched
    KnownVulnerability,
    
    /// Anomalous traffic pattern detected
    AnomalyDetected,
    
    /// Potential zero-day exploit
    PotentialZeroDay,
    
    /// Protocol violation
    ProtocolViolation,
    
    /// Malformed packet
    MalformedPacket,
    
    /// DoS/DDoS attack
    DenialOfService,
    
    /// Other threat
    Other,
}

/// Main analysis service that processes captured packets
pub struct AnalysisService {
    protocol_analyzer: ProtocolAnalyzer,
    anomaly_detector: AnomalyDetector,
    signature_detector: SignatureDetector,
    analysis_thread: Option<thread::JoinHandle<()>>,
    running: bool,
    use_ml: bool,
}

impl AnalysisService {
    /// Create a new analysis service
    pub fn new() -> Self {
        Self {
            protocol_analyzer: ProtocolAnalyzer::new(),
            anomaly_detector: AnomalyDetector::new(),
            signature_detector: SignatureDetector::new(),
            analysis_thread: None,
            running: false,
            use_ml: false,
        }
    }
    
    /// Enable or disable machine learning-based detection
    pub fn enable_ml_detection(&mut self, enable: bool) {
        self.use_ml = enable;
    }
    
    /// Start the analysis service
    pub fn start(&mut self, packet_rx: Receiver<Packet>, threat_tx: Sender<Threat>) -> Result<()> {
        self.running = true;
        
        let mut protocol_analyzer = self.protocol_analyzer.clone();
        let mut anomaly_detector = self.anomaly_detector.clone();
        let signature_detector = self.signature_detector.clone();
        
        // Start analysis in a separate thread
        self.analysis_thread = Some(thread::spawn(move || {
            let mut threat_id = 0;
            
            for packet in packet_rx {
                // Process the packet with each analyzer
                
                // 1. Protocol analysis
                if let Some(violation) = protocol_analyzer.analyze(&packet) {
                    threat_id += 1;
                    let threat = Threat {
                        id: threat_id,
                        threat_type: ThreatType::ProtocolViolation,
                        severity: violation.severity,
                        description: violation.description,
                        associated_packet: packet.clone(),
                    };
                    
                    if threat_tx.send(threat).is_err() {
                        break;
                    }
                }
                
                // 2. Signature-based detection
                if let Some(signature_match) = signature_detector.detect(&packet) {
                    threat_id += 1;
                    let threat = Threat {
                        id: threat_id,
                        threat_type: ThreatType::KnownVulnerability,
                        severity: signature_match.severity,
                        description: signature_match.description,
                        associated_packet: packet.clone(),
                    };
                    
                    if threat_tx.send(threat).is_err() {
                        break;
                    }
                }
                
                // 3. Anomaly detection
                if let Some(anomaly) = anomaly_detector.detect(&packet) {
                    threat_id += 1;
                    let threat = Threat {
                        id: threat_id,
                        threat_type: if anomaly.is_potential_zero_day {
                            ThreatType::PotentialZeroDay
                        } else {
                            ThreatType::AnomalyDetected
                        },
                        severity: anomaly.severity,
                        description: anomaly.description,
                        associated_packet: packet.clone(),
                    };
                    
                    if threat_tx.send(threat).is_err() {
                        break;
                    }
                }
            }
        }));
        
        Ok(())
    }
    
    /// Stop the analysis service
    pub fn stop(&mut self) -> Result<()> {
        self.running = false;
        
        // The thread will end when the packet channel is closed
        if let Some(thread) = self.analysis_thread.take() {
            if !thread.is_finished() {
                if thread.join().is_err() {
                    log::warn!("Failed to join analysis thread cleanly");
                }
            }
        }
        
        Ok(())
    }
    
    /// Check if the analysis service is running
    pub fn is_running(&self) -> bool {
        self.running
    }
} 