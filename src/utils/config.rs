use serde::{Serialize, Deserialize};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use super::error::{NetGuardError, Result};
use crate::ml::ModelType;

/// Configuration settings for NetGuard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// General application settings
    pub general: GeneralConfig,
    
    /// Capture settings
    pub capture: CaptureConfig,
    
    /// Analysis settings
    pub analysis: AnalysisConfig,
    
    /// Reporting settings
    pub reporting: ReportingConfig,
    
    /// Machine learning settings
    pub ml: MlConfig,
    
    /// UI settings
    pub ui: UiConfig,
}

/// General application settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    /// Application log level
    pub log_level: String,
    
    /// Path to save data
    pub data_dir: PathBuf,
    
    /// Whether to check for updates
    pub check_updates: bool,
}

/// Packet capture settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureConfig {
    /// Default network interface
    pub default_interface: Option<String>,
    
    /// Whether to use promiscuous mode
    pub promiscuous_mode: bool,
    
    /// Capture buffer size
    pub buffer_size: usize,
    
    /// Packet filter (pcap format)
    pub filter: Option<String>,
    
    /// Maximum packet size to capture
    pub snapshot_length: u32,
    
    /// Whether to save captured packets
    pub save_packets: bool,
    
    /// Path to save pcap files
    pub save_path: Option<PathBuf>,
}

/// Analysis settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisConfig {
    /// Whether to enable protocol analysis
    pub protocol_analysis: bool,
    
    /// Whether to enable signature detection
    pub signature_detection: bool,
    
    /// Whether to enable anomaly detection
    pub anomaly_detection: bool,
    
    /// Whether to enable real-time alerts
    pub real_time_alerts: bool,
    
    /// Path to signature database
    pub signature_path: Option<PathBuf>,
}

/// Reporting settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportingConfig {
    /// Whether to generate reports
    pub generate_reports: bool,
    
    /// Default report format
    pub default_format: String,
    
    /// Whether to include visualizations
    pub include_visualizations: bool,
    
    /// Path to save reports
    pub report_path: Option<PathBuf>,
}

/// Machine learning settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlConfig {
    /// Whether to enable ML detection
    pub enabled: bool,
    
    /// Type of ML model to use
    pub model_type: String,
    
    /// Path to trained model
    pub model_path: Option<PathBuf>,
    
    /// Anomaly threshold
    pub anomaly_threshold: f64,
    
    /// Whether to train the model with captured data
    pub train_with_captured: bool,
}

/// UI settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiConfig {
    /// Whether to use color output
    pub use_color: bool,
    
    /// Whether to show detailed packet info
    pub show_packet_details: bool,
    
    /// Maximum threats to display
    pub max_display_threats: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            general: GeneralConfig::default(),
            capture: CaptureConfig::default(),
            analysis: AnalysisConfig::default(),
            reporting: ReportingConfig::default(),
            ml: MlConfig::default(),
            ui: UiConfig::default(),
        }
    }
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            log_level: "info".to_string(),
            data_dir: PathBuf::from("./data"),
            check_updates: true,
        }
    }
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            default_interface: None,
            promiscuous_mode: true,
            buffer_size: 65535,
            filter: None,
            snapshot_length: 65535,
            save_packets: false,
            save_path: Some(PathBuf::from("./data/captures")),
        }
    }
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            protocol_analysis: true,
            signature_detection: true,
            anomaly_detection: true,
            real_time_alerts: true,
            signature_path: Some(PathBuf::from("./data/signatures")),
        }
    }
}

impl Default for ReportingConfig {
    fn default() -> Self {
        Self {
            generate_reports: true,
            default_format: "html".to_string(),
            include_visualizations: true,
            report_path: Some(PathBuf::from("./data/reports")),
        }
    }
}

impl Default for MlConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            model_type: "isolation_forest".to_string(),
            model_path: Some(PathBuf::from("./data/models/default.model")),
            anomaly_threshold: 0.7,
            train_with_captured: false,
        }
    }
}

impl Default for UiConfig {
    fn default() -> Self {
        Self {
            use_color: true,
            show_packet_details: false,
            max_display_threats: 100,
        }
    }
}

impl Config {
    /// Load configuration from a file
    pub fn load(path: &Path) -> Result<Self> {
        let mut file = File::open(path)
            .map_err(|e| NetGuardError::ConfigError(format!("Failed to open config file: {}", e)))?;
            
        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .map_err(|e| NetGuardError::ConfigError(format!("Failed to read config file: {}", e)))?;
            
        let config = serde_json::from_str(&contents)
            .map_err(|e| NetGuardError::ConfigError(format!("Failed to parse config: {}", e)))?;
            
        Ok(config)
    }
    
    /// Save configuration to a file
    pub fn save(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| NetGuardError::ConfigError(format!("Failed to serialize config: {}", e)))?;
            
        let mut file = File::create(path)
            .map_err(|e| NetGuardError::ConfigError(format!("Failed to create config file: {}", e)))?;
            
        file.write_all(json.as_bytes())
            .map_err(|e| NetGuardError::ConfigError(format!("Failed to write config file: {}", e)))?;
            
        Ok(())
    }
    
    /// Create directories for data storage
    pub fn create_directories(&self) -> Result<()> {
        // Create main data directory
        if !self.general.data_dir.exists() {
            std::fs::create_dir_all(&self.general.data_dir)
                .map_err(|e| NetGuardError::ConfigError(format!("Failed to create data directory: {}", e)))?;
        }
        
        // Create captures directory
        if let Some(path) = &self.capture.save_path {
            if !path.exists() {
                std::fs::create_dir_all(path)
                    .map_err(|e| NetGuardError::ConfigError(format!("Failed to create captures directory: {}", e)))?;
            }
        }
        
        // Create signatures directory
        if let Some(path) = &self.analysis.signature_path {
            if !path.exists() {
                std::fs::create_dir_all(path)
                    .map_err(|e| NetGuardError::ConfigError(format!("Failed to create signatures directory: {}", e)))?;
            }
        }
        
        // Create reports directory
        if let Some(path) = &self.reporting.report_path {
            if !path.exists() {
                std::fs::create_dir_all(path)
                    .map_err(|e| NetGuardError::ConfigError(format!("Failed to create reports directory: {}", e)))?;
            }
        }
        
        // Create models directory
        if let Some(path) = &self.ml.model_path {
            if let Some(parent) = path.parent() {
                if !parent.exists() {
                    std::fs::create_dir_all(parent)
                        .map_err(|e| NetGuardError::ConfigError(format!("Failed to create models directory: {}", e)))?;
                }
            }
        }
        
        Ok(())
    }
    
    /// Get model type from string configuration
    pub fn get_model_type(&self) -> ModelType {
        match self.ml.model_type.as_str() {
            "kmeans" => ModelType::KMeans,
            "isolation_forest" => ModelType::IsolationForest,
            "one_class_svm" => ModelType::OneClassSvm,
            "local_outlier_factor" => ModelType::LocalOutlierFactor,
            "random_forest" => ModelType::RandomForest,
            _ => ModelType::IsolationForest, // Default to isolation forest
        }
    }
} 