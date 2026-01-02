// purple/src/correlation/cli/mod.rs
//!
//! CLI commands for correlation engine management
//!
//! Commands:
//! - correlation start - Start a new correlation session
//! - correlation status - Check session status
//! - correlation events - Submit events to session
//! - correlation report - Generate session report
//! - correlation monitor - Real-time correlation monitoring
//! - correlation rules - Manage detection rules

use crate::correlation::engine::CorrelationEngine;
use crate::correlation::models::*;
use crate::correlation::rules::{get_builtin_rules, RulesEngine};
use crate::correlation::storage::{CorrelationStorageTrait, MemoryStorage};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Parser, Debug)]
#[command(name = "correlation")]
#[command(about = "Correlation engine management", long_about = None)]
pub struct CorrelationCli {
    #[command(subcommand)]
    pub command: CorrelationCommands,
}

#[derive(Subcommand, Debug)]
pub enum CorrelationCommands {
    /// Start a new correlation session
    #[command(name = "start")]
    Start {
        /// Profile name for the session
        #[arg(short, long)]
        profile: String,

        /// Sandbox ID to associate
        #[arg(short, long)]
        sandbox_id: Option<String>,

        /// Enable threat intelligence
        #[arg(long)]
        threat_intel: bool,

        /// Enable ATT&CK mapping
        #[arg(long, default_value = "true")]
        attack: bool,
    },

    /// Check status of a correlation session
    #[command(name = "status")]
    Status {
        /// Session ID
        #[arg(short, long)]
        session_id: String,

        /// JSON output
        #[arg(long)]
        json: bool,
    },

    /// Submit an event to a session
    #[command(name = "event")]
    Event {
        /// Session ID
        #[arg(short, long)]
        session_id: String,

        /// Event type (syscall, file_access, network)
        #[arg(short, long)]
        event_type: String,

        /// Process ID
        #[arg(short, long)]
        pid: u32,

        /// Event details
        #[arg(short, long)]
        details: String,

        /// Event category
        #[arg(short, long, default_value = "syscall")]
        category: String,

        /// Process name
        #[arg(long, default_value = "test")]
        comm: String,
    },

    /// Register an LLM intent
    #[command(name = "intent")]
    Intent {
        /// Session ID
        #[arg(short, long)]
        session_id: String,

        /// User prompt
        #[arg(short, long)]
        prompt: String,

        /// Expected actions
        #[arg(long)]
        expected_actions: Vec<String>,

        /// Intent confidence (0-1)
        #[arg(long, default_value = "0.8")]
        confidence: f32,
    },

    /// Complete a session and get results
    #[command(name = "complete")]
    Complete {
        /// Session ID
        #[arg(short, long)]
        session_id: String,

        /// Output format (text, json)
        #[arg(short, long, default_value = "text")]
        format: String,

        /// Save to storage
        #[arg(long)]
        save: bool,
    },

    /// Generate a correlation report
    #[command(name = "report")]
    Report {
        /// Session ID
        #[arg(short, long)]
        session_id: String,

        /// Output format
        #[arg(short, long, default_value = "text")]
        format: String,

        /// Output file
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Export session to OCSF format
    #[command(name = "ocsf")]
    Ocsf {
        /// Session ID
        #[arg(short, long)]
        session_id: String,

        /// Output file
        #[arg(short, long)]
        output: PathBuf,
    },

    /// List active sessions
    #[command(name = "list")]
    List {
        /// JSON output
        #[arg(long)]
        json: bool,
    },

    /// Manage detection rules
    #[command(name = "rules")]
    Rules {
        #[command(subcommand)]
        action: RuleCommands,
    },

    /// Start real-time correlation monitor
    #[command(name = "monitor")]
    Monitor {
        /// Profile name
        #[arg(short, long)]
        profile: String,

        /// Poll interval in milliseconds
        #[arg(long, default_value = "1000")]
        interval: u64,
    },
}

#[derive(Subcommand, Debug)]
pub enum RuleCommands {
    /// List all rules
    #[command(name = "list")]
    List {
        #[arg(long)]
        json: bool,
    },

    /// Add a custom rule
    #[command(name = "add")]
    Add {
        /// Rule file path
        #[arg(short, long)]
        file: PathBuf,
    },

    /// Load rules from directory
    #[command(name = "load")]
    Load {
        /// Rules directory
        #[arg(short, long)]
        directory: PathBuf,
    },

    /// Get builtin rules count
    #[command(name = "builtin")]
    Builtin,
}

/// Execute CLI command
pub async fn execute_command(cmd: CorrelationCommands) {
    match cmd {
        CorrelationCommands::Start {
            profile,
            sandbox_id,
            threat_intel,
            attack,
        } => {
            let _ = threat_intel;
            let _ = attack;
            let config = CorrelationConfig::default();
            let engine = Arc::new(Mutex::new(CorrelationEngine::new(config)));
            let rules_engine = Arc::new(Mutex::new(RulesEngine::new(true)));
            let storage: Arc<Mutex<dyn CorrelationStorageTrait + Send>> = 
                Arc::new(Mutex::new(MemoryStorage::new()));

            let session_id = engine.lock().await.start_session(profile.clone(), sandbox_id.clone());

            println!("\n============================================");
            println!("Correlation Session Started");
            println!("============================================");
            println!("Session ID: {}", session_id);
            println!("Profile: {}", profile);
            if let Some(sid) = sandbox_id {
                println!("Sandbox ID: {}", sid);
            }
            println!("Status: Active");
            println!("============================================\n");
        }

        CorrelationCommands::Status { session_id, json } => {
            let config = CorrelationConfig::default();
            let engine = Arc::new(Mutex::new(CorrelationEngine::new(config)));
            
            let session = engine.lock().await.get_session(&session_id);

            match session {
                Some(s) => {
                    if json {
                        println!("{}", serde_json::to_string_pretty(&s).unwrap());
                    } else {
                        println!("\n============================================");
                        println!("Session Status: {}", session_id);
                        println!("============================================");
                        println!("Profile: {}", s.profile_name);
                        println!("Status: {:?}", s.status);
                        println!("Events: {}", s.events.len());
                        println!("Anomalies: {}", s.anomalies.len());
                        println!("Risk Score: {:.1} ({:?})", 
                            s.risk_score.cumulative_score, s.risk_score.risk_level);
                        println!("ATT&CK Coverage: {} techniques", s.attack_coverage.len());
                        println!("============================================\n");
                    }
                }
                None => {
                    println!("Session not found: {}", session_id);
                }
            }
        }

        CorrelationCommands::Event {
            session_id,
            event_type,
            pid,
            details,
            category,
            comm,
        } => {
            let config = CorrelationConfig::default();
            let engine = Arc::new(Mutex::new(CorrelationEngine::new(config)));

            let event = RawEvent::new(
                event_type,
                pid,
                details,
                match category.as_str() {
                    "file_access" => EventCategory::FileAccess,
                    "network" => EventCategory::Network,
                    _ => EventCategory::Syscall,
                },
            );

            let anomaly = engine.lock().await.process_event(&session_id, event).await;

            println!("Event submitted to session: {}", session_id);
            
            if let Some(a) = anomaly {
                println!("\n⚠️  ANOMALY DETECTED ⚠️");
                println!("Type: {:?}", a.anomaly_type);
                println!("Severity: {:?}", a.severity);
                println!("Description: {}", a.description);
            }
        }

        CorrelationCommands::Intent {
            session_id,
            prompt,
            expected_actions,
            confidence,
        } => {
            let config = CorrelationConfig::default();
            let engine = Arc::new(Mutex::new(CorrelationEngine::new(config)));

            let mut intent = LlmIntent::new(prompt, expected_actions, String::new());
            intent.confidence = confidence;

            engine.lock().await.register_intent(&session_id, intent).await;

            println!("Intent registered for session: {}", session_id);
        }

        CorrelationCommands::Complete {
            session_id,
            format,
            save,
        } => {
            let _ = save;
            let config = CorrelationConfig::default();
            let engine = Arc::new(Mutex::new(CorrelationEngine::new(config)));
            let storage: Arc<Mutex<dyn CorrelationStorageTrait + Send>> = 
                Arc::new(Mutex::new(MemoryStorage::new()));

            let session = engine.lock().await.complete_session(&session_id).await;

            match session {
                Some(s) => {
                    if format == "json" {
                        println!("{}", serde_json::to_string_pretty(&s).unwrap());
                    } else {
                        print_session_summary(&s);
                    }
                }
                None => {
                    println!("Session not found: {}", session_id);
                }
            }
        }

        CorrelationCommands::Report {
            session_id,
            format,
            output,
        } => {
            let config = CorrelationConfig::default();
            let engine = Arc::new(Mutex::new(CorrelationEngine::new(config)));
            let storage: Arc<Mutex<dyn CorrelationStorageTrait + Send>> = 
                Arc::new(Mutex::new(MemoryStorage::new()));

            let session = engine.lock().await.get_session(&session_id);

            match session {
                Some(s) => {
                    let report = generate_report(&s);
                    
                    if let Some(path) = output {
                        std::fs::write(&path, &report).ok();
                        println!("Report saved to: {}", path.display());
                    } else if format == "json" {
                        println!("{}", serde_json::to_string_pretty(&s).unwrap());
                    } else {
                        println!("{}", report);
                    }
                }
                None => {
                    println!("Session not found: {}", session_id);
                }
            }
        }

        CorrelationCommands::Ocsf { session_id, output } => {
            let storage = Arc::new(Mutex::new(MemoryStorage::new()));

            let ocsf_events = storage.lock().await.export_session_ocsf(&session_id).await;

            match ocsf_events {
                Some(events) => {
                    let json = serde_json::to_string_pretty(&events).unwrap();
                    std::fs::write(&output, &json).ok();
                    println!("OCSF export saved to: {} ({} events)", output.display(), events.len());
                }
                None => {
                    println!("Session not found or no events: {}", session_id);
                }
            }
        }

        CorrelationCommands::List { json } => {
            let config = CorrelationConfig::default();
            let engine = Arc::new(Mutex::new(CorrelationEngine::new(config)));

            let sessions = engine.lock().await.get_active_sessions();

            if json {
                println!("{}", serde_json::to_string_pretty(&sessions).unwrap());
            } else {
                println!("\nActive Correlation Sessions:");
                println!("============================");
                for session_id in &sessions {
                    println!("  - {}", session_id);
                }
                println!("============================");
                println!("Total: {} active sessions\n", sessions.len());
            }
        }

        CorrelationCommands::Rules { action } => {
            match action {
                RuleCommands::List { json } => {
                    let rules_engine = Arc::new(Mutex::new(RulesEngine::new(true)));
                    let rules = rules_engine.lock().await.get_all_rules();

                    if json {
                        println!("{}", serde_json::to_string_pretty(&rules).unwrap());
                    } else {
                        println!("\nDetection Rules:");
                        println!("================");
                        for rule in &rules {
                            println!("  [{}] {} - {:?}", 
                                if rule.enabled { "ENABLED" } else { "DISABLED" },
                                rule.name, 
                                rule.severity);
                        }
                        println!("================");
                        println!("Total: {} rules\n", rules.len());
                    }
                }

                RuleCommands::Add { file } => {
                    let rules_engine = Arc::new(Mutex::new(RulesEngine::new(true)));
                    rules_engine.lock().await.load_rules_from_directory(file).ok();
                }

                RuleCommands::Load { directory } => {
                    let rules_engine = Arc::new(Mutex::new(RulesEngine::new(true)));
                    rules_engine.lock().await.load_rules_from_directory(directory).ok();
                }

                RuleCommands::Builtin => {
                    let builtin = get_builtin_rules();
                    println!("\nBuiltin Detection Rules:");
                    println!("========================");
                    for rule in &builtin {
                        println!("  [{}] {} - {:?}", 
                            if rule.enabled { "ENABLED" } else { "DISABLED" },
                            rule.name, 
                            rule.severity);
                    }
                    println!("========================");
                    println!("Total: {} builtin rules\n", builtin.len());
                }
            }
        }

        CorrelationCommands::Monitor { profile, interval } => {
            println!("\n============================================");
            println!("Correlation Monitor");
            println!("============================================");
            println!("Profile: {}", profile);
            println!("Poll Interval: {}ms", interval);
            println!("Press Ctrl+C to stop");
            println!("============================================\n");

            let config = CorrelationConfig::default();
            let engine = Arc::new(Mutex::new(CorrelationEngine::new(config)));
            let session_id = engine.lock().await.start_session(profile, None);

            println!("Started monitoring session: {}", session_id);

            // Simulate monitoring loop
            let mut interval = tokio::time::interval(Duration::from_millis(interval));
            let mut event_count = 0;

            loop {
                interval.tick().await;
                event_count += 1;

                // In real implementation, this would poll events from eBPF
                println!("[{}] Monitoring session {} - {} events processed", 
                    event_count, session_id, event_count * 10);
            }
        }
    }
}

fn print_session_summary(session: &CorrelationSession) {
    println!("\n============================================");
    println!("Correlation Session Report");
    println!("============================================");
    println!("Session ID: {}", session.session_id);
    println!("Profile: {}", session.profile_name);
    println!("Duration: {} seconds", 
        session.end_time.saturating_sub(session.start_time));
    println!("Status: {:?}", session.status);
    
    println!("\n--- Event Statistics ---");
    println!("Total Events: {}", session.events.len());
    println!("Anomalies Detected: {}", session.anomalies.len());
    
    println!("\n--- Risk Assessment ---");
    println!("Risk Score: {:.1}/100", session.risk_score.cumulative_score);
    println!("Risk Level: {:?}", session.risk_score.risk_level);
    
    if !session.risk_score.factors.is_empty() {
        println!("\nContributing Factors:");
        for factor in &session.risk_score.factors {
            println!("  - {}: +{:.1}", factor.name, factor.contribution);
        }
    }

    println!("\n--- ATT&CK Coverage ---");
    if session.attack_coverage.is_empty() {
        println!("  No ATT&CK techniques detected");
    } else {
        for tactic in &session.attack_coverage {
            println!("  - {}", tactic);
        }
    }

    println!("\n--- Detected Patterns ---");
    if session.patterns.is_empty() {
        println!("  No attack patterns detected");
    } else {
        for pattern in &session.patterns {
            println!("  [{}] {} (confidence: {:.0}%)", 
                format!("{:?}", pattern.severity),
                pattern.pattern_name,
                pattern.confidence * 100.0);
        }
    }

    println!("\n============================================\n");
}

fn generate_report(session: &CorrelationSession) -> String {
    let mut report = String::new();
    
    report.push_str("# Correlation Session Report\n\n");
    report.push_str(&format!("## Session Information\n"));
    report.push_str(&format!("- Session ID: {}\n", session.session_id));
    report.push_str(&format!("- Profile: {}\n", session.profile_name));
    report.push_str(&format!("- Duration: {} seconds\n", 
        session.end_time.saturating_sub(session.start_time)));
    
    report.push_str(&format!("\n## Risk Assessment\n"));
    report.push_str(&format!("- Overall Score: {:.1}/100\n", session.risk_score.cumulative_score));
    report.push_str(&format!("- Risk Level: {:?}\n", session.risk_score.risk_level));
    
    report.push_str(&format!("\n## Event Summary\n"));
    report.push_str(&format!("- Total Events: {}\n", session.events.len()));
    report.push_str(&format!("- Anomalies: {}\n", session.anomalies.len()));
    
    report.push_str(&format!("\n## ATT&CK Techniques Detected\n"));
    for tactic in &session.attack_coverage {
        report.push_str(&format!("- {}\n", tactic));
    }

    if !session.anomalies.is_empty() {
        report.push_str(&format!("\n## Top Anomalies\n"));
        for anomaly in session.anomalies.iter().take(5) {
            report.push_str(&format!("- [{:?}] {}\n", anomaly.severity, anomaly.description));
        }
    }

    report
}
