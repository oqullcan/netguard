mod report;
mod formats;

pub use report::{Report, ReportGenerator, ReportConfig};
pub use formats::{ReportFormat, ReportWriter};

use anyhow::Result;
use std::path::Path;

use crate::analysis::Threat;

/// Reporting service for generating security reports
pub struct ReportingService {
    generator: ReportGenerator,
    config: ReportConfig,
}

impl ReportingService {
    /// Create a new reporting service
    pub fn new() -> Self {
        Self {
            generator: ReportGenerator::new(),
            config: ReportConfig::default(),
        }
    }
    
    /// Set the report configuration
    pub fn set_config(&mut self, config: ReportConfig) {
        self.config = config;
    }
    
    /// Generate a report from captured threats
    pub fn generate_report(&self, threats: &[Threat], output_path: &Path) -> Result<()> {
        // Generate the report
        let report = self.generator.generate(threats, &self.config)?;
        
        // Write the report to disk
        match self.config.format {
            formats::ReportFormat::Json => {
                let writer = formats::JsonReportWriter::new();
                writer.write(&report, output_path)?;
            },
            formats::ReportFormat::Html => {
                let writer = formats::HtmlReportWriter::new();
                writer.write(&report, output_path)?;
            },
            formats::ReportFormat::Csv => {
                let writer = formats::CsvReportWriter::new();
                writer.write(&report, output_path)?;
            },
            formats::ReportFormat::Pdf => {
                let writer = formats::PdfReportWriter::new();
                writer.write(&report, output_path)?;
            },
        }
        
        Ok(())
    }
} 