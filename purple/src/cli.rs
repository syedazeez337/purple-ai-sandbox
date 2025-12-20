use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Set the logging level (trace, debug, info, warn, error)
    #[arg(short, long, global = true, default_value = "info")]
    pub log_level: String,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Initialize Aiguard environment
    Init,
    /// Manage profiles
    Profile {
        #[command(subcommand)]
        command: ProfileCommands,
    },
    /// Run an AI agent with a specified profile
    Run(RunArgs),
    /// Monitor eBPF events in real-time
    Monitor(MonitorArgs),
    /// Replay a recorded eBPF session
    Replay(ReplayArgs),
    /// Generate audit correlation report
    Audit(AuditArgs),
}

#[derive(Subcommand, Debug)]
pub enum ProfileCommands {
    /// Create a new profile
    Create {
        /// Name of the profile
        name: String,
    },
    /// List all available profiles
    List,
    /// Delete a profile
    Delete {
        /// Name of the profile to delete
        name: String,
    },
    /// Show detailed information about a profile
    Show {
        /// Name of the profile to show
        name: String,
    },
}

#[derive(Parser, Debug)]
pub struct RunArgs {
    /// Profile to use for running the AI agent
    #[arg(long)]
    pub profile: String,
    /// Command to execute with the AI agent
    #[arg(raw = true)] // This captures all subsequent arguments as the command
    pub command: Vec<String>,
}

#[derive(Parser, Debug)]
pub struct MonitorArgs {
    /// Profile to use for monitoring
    #[arg(short, long)]
    pub profile: String,
    /// Show correlation with LLM intents
    #[arg(long)]
    pub show_correlation: bool,
}

#[derive(Parser, Debug)]
pub struct ReplayArgs {
    /// Session ID to replay
    pub session_id: String,
}

#[derive(Parser, Debug)]
pub struct AuditArgs {
    /// Session ID to audit
    #[arg(short, long)]
    pub session: String,
    /// Output format (json or text)
    #[arg(short, long, default_value = "text")]
    pub format: String,
}
