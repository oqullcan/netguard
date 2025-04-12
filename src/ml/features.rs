use anyhow::Result;
use ndarray::Array1;
use serde::{Serialize, Deserialize};

/// Feature vector representing network traffic characteristics
pub type FeatureVector = Array1<f64>;

/// Types of features that can be extracted
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Feature {
    /// Packet size
    PacketSize,
    
    /// Inter-packet time
    InterPacketTime,
    
    /// TCP flags
    TcpFlags,
    
    /// Payload entropy
    PayloadEntropy,
    
    /// Header field values
    HeaderField,
    
    /// Protocol-specific features
    ProtocolFeature,
    
    /// Flow statistics
    FlowStats,
    
    /// Payload n-grams
    Ngram,
}

/// Extracts features from network data
#[derive(Debug, Clone)]
pub struct FeatureExtractor {
    /// Which features to extract
    enabled_features: Vec<Feature>,
    
    /// Normalization parameters
    normalization: Option<Normalization>,
}

/// Parameters for feature normalization
#[derive(Debug, Clone)]
struct Normalization {
    /// Mean values for each feature
    means: Vec<f64>,
    
    /// Standard deviations for each feature
    std_devs: Vec<f64>,
}

impl FeatureExtractor {
    /// Create a new feature extractor
    pub fn new() -> Self {
        // Default to all features enabled
        let enabled_features = vec![
            Feature::PacketSize,
            Feature::InterPacketTime,
            Feature::TcpFlags,
            Feature::PayloadEntropy,
            Feature::HeaderField,
            Feature::ProtocolFeature,
            Feature::FlowStats,
            Feature::Ngram,
        ];
        
        Self {
            enabled_features,
            normalization: None,
        }
    }
    
    /// Extract features from raw packet data
    pub fn extract(&self, data: &[u8]) -> Result<FeatureVector> {
        // In a real implementation, this would analyze the packet data
        // and extract the requested features
        
        // For demo purposes, we'll just create a vector of random features
        let feature_count = self.enabled_features.len();
        let mut features = vec![0.0; feature_count];
        
        // Extract some simple features
        if !data.is_empty() {
            // Simple feature: packet size
            features[0] = data.len() as f64;
            
            // Simple feature: first byte value
            if feature_count > 1 {
                features[1] = data[0] as f64;
            }
            
            // Simple feature: byte value distribution
            if feature_count > 2 {
                features[2] = self.calculate_entropy(data);
            }
            
            // Fill remaining features with placeholder values
            for i in 3..feature_count {
                features[i] = (i as f64) / (feature_count as f64);
            }
        }
        
        // Apply normalization if available
        if let Some(norm) = &self.normalization {
            for i in 0..features.len() {
                if i < norm.means.len() && i < norm.std_devs.len() && norm.std_devs[i] > 0.0 {
                    features[i] = (features[i] - norm.means[i]) / norm.std_devs[i];
                }
            }
        }
        
        Ok(Array1::from(features))
    }
    
    /// Set which features to extract
    pub fn set_enabled_features(&mut self, features: Vec<Feature>) {
        self.enabled_features = features;
    }
    
    /// Set normalization parameters
    pub fn set_normalization(&mut self, means: Vec<f64>, std_devs: Vec<f64>) {
        self.normalization = Some(Normalization { means, std_devs });
    }
    
    /// Calculate entropy of byte distribution in data
    fn calculate_entropy(&self, data: &[u8]) -> f64 {
        // Simplified entropy calculation
        if data.is_empty() {
            return 0.0;
        }
        
        // Count byte frequencies
        let mut counts = [0; 256];
        for &byte in data {
            counts[byte as usize] += 1;
        }
        
        // Calculate entropy
        let data_len = data.len() as f64;
        let mut entropy = 0.0;
        
        for &count in counts.iter() {
            if count > 0 {
                let p = count as f64 / data_len;
                entropy -= p * p.log2();
            }
        }
        
        entropy
    }
} 