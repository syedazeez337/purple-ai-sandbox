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
    /// Initialize Purple AI Sandbox environment
    Init,
    /// Display version information
    Version,
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
    /// Manage multiple sandbox instances
    Sandboxes {
        #[command(subcommand)]
        action: SandboxAction,
    },
    /// Correlation engine operations
    Correlation {
        #[command(subcommand)]
        command: CorrelationCommands,
    },
}

#[derive(Subcommand, Debug)]
pub enum SandboxAction {
    /// List all running sandboxes
    List,
    /// Create a new sandbox
    Create {
        #[arg(long)]
        profile: String,
        #[arg(long)]
        name: String,
    },
    /// Stop and cleanup a sandbox
    Stop {
        #[arg(long)]
        id: String,
    },
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
    /// Use direct sandbox execution (bypass manager)
    #[arg(long)]
    pub direct: bool,
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
    /// Session ID to audit (use --all for all sessions)
    #[arg(short, long)]
    pub session: Option<String>,
    /// Audit all sessions
    #[arg(long)]
    pub all: bool,
    /// Output format (json or text)
    #[arg(short, long, default_value = "text")]
    pub format: String,
}

#[derive(Subcommand, Debug)]
pub enum CorrelationCommands {
    /// Start a new correlation session
    Start {
        /// Profile name for the session
        #[arg(short, long)]
        profile: String,
        /// Sandbox ID to associate
        #[arg(short, long)]
        sandbox_id: Option<String>,
    },
    /// Check status of a correlation session
    Status {
        /// Session ID
        #[arg(short, long)]
        session_id: String,
        /// JSON output
        #[arg(long)]
        json: bool,
    },
    /// Submit an event to a session
    Event {
        /// Session ID
        #[arg(short, long)]
        session_id: String,
        /// Event type
        #[arg(short, long)]
        event_type: String,
        /// Process ID
        #[arg(short, long)]
        pid: u32,
        /// Event details
        #[arg(short, long)]
        details: String,
    },
    /// Register an LLM intent
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
    },
    /// Complete a session and get results
    Complete {
        /// Session ID
        #[arg(short, long)]
        session_id: String,
        /// Output format
        #[arg(short, long, default_value = "text")]
        format: String,
    },
    /// Generate a correlation report
    Report {
        /// Session ID
        #[arg(short, long)]
        session_id: String,
        /// Output format
        #[arg(short, long, default_value = "text")]
        format: String,
    },
    /// List active sessions
    List,
    /// Manage detection rules
    Rules {
        #[command(subcommand)]
        action: RuleCommands,
    },
}

#[derive(Subcommand, Debug)]
pub enum RuleCommands {
    /// List all rules
    List,
    /// Load rules from directory
    Load {
        /// Rules directory
        #[arg(short, long)]
        directory: String,
    },
}
