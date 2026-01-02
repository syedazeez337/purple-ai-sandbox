# Comprehensive Correlation Engine Research and Enhancement Plan

## Purple AI Sandbox - Correlation Engine Analysis

**Date**: January 2, 2026  
**Prepared for**: Purple AI Sandbox Development Team  
**Document Type**: Technical Research and Enhancement Plan

---

## 1. Executive Summary

This document presents a comprehensive analysis of the correlation engine in the Purple AI Sandbox project and provides a detailed enhancement plan. The correlation engine is a critical component that bridges the gap between AI agent intents and observed system behavior, enabling security teams to understand whether AI agents are behaving as expected or exhibiting anomalous/malicious patterns.

**Key Findings:**
- Current implementation is in **early prototype stage** with significant functionality marked as TODO
- Strong foundation exists with eBPF-based event collection and basic correlation structures
- Critical gaps in anomaly detection, threat scoring, and intent-action mapping
- No integration with existing security monitoring frameworks (SIEM, SOAR)

---

## 2. Current State Analysis

### 2.1 Architecture Overview

The current correlation engine consists of:

```
┌─────────────────────────────────────────────────────────────────┐
│                   Correlation Engine                             │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐  │
│  │ LlmIntent   │    │ Observed    │    │ CorrelationResult   │  │
│  │ Repository  │    │ Event Store │    │ Generator           │  │
│  └─────────────┘    └─────────────┘    └─────────────────────┘  │
│         │                  │                     │               │
│         └──────────────────┼─────────────────────┘               │
│                            │                                     │
│                    ┌───────▼───────┐                            │
│                    │ Time-Based    │                            │
│                    │ Window (300s) │                            │
│                    └───────────────┘                            │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 Current Implementation Files

| File | Purpose | Status |
|------|---------|--------|
| `purple/src/sandbox/ebpf/correlator.rs` | Core correlation engine | **Prototype** |
| `purple/src/sandbox/ebpf/events.rs` | Event definitions | Implemented |
| `purple/src/sandbox/ebpf/loader.rs` | eBPF event loader | Implemented |
| `purple/src/sandbox/mod.rs` | Sandbox integration | Partial |
| `purple/src/policy/mod.rs` | Policy configuration | Implemented |

### 2.3 Current Data Flow

```
LLM Intent → Register Intent → Time Window → Correlate → Results
     ↓                                                      ↓
eBPF Events → Process Events → Match by Intent ID → Anomaly Detection
```

---

## 3. Detailed Component Analysis

### 3.1 LlmIntent Structure

```rust
pub struct LlmIntent {
    pub intent_id: String,           // UUID for tracking
    pub timestamp: u64,              // Unix timestamp
    pub prompt: String,              // Original prompt
    pub expected_actions: Vec<String>, // Expected behavior patterns
}
```

**Current Limitations:**
- No semantic understanding of prompts
- Expected actions are plain strings (no structured action taxonomy)
- No confidence scores or uncertainty modeling
- No multi-turn conversation support

### 3.2 ObservedEvent Structure

```rust
pub struct ObservedEvent {
    pub event_type: String,          // "syscall", "file_access", "network"
    pub timestamp: u64,
    pub details: String,
    pub intent_id: Option<String>,   // Linked intent (currently always None)
}
```

**Current Limitations:**
- Events not linked to intents automatically
- No event severity classification
- Missing critical fields (PID, syscall number, file path, etc.)
- No event aggregation or pattern detection

### 3.3 CorrelationEngine Implementation

**Key Methods:**
- `register_intent()` - Stores intents in time-bounded queue
- `register_event()` - Stores observed events
- `cleanup_old_entries()` - Maintains 300-second window
- `correlate()` - Simple matching based on intent_id

**Critical Gaps:**
1. **No semantic correlation** - Events matched only by ID, not content
2. **No anomaly detection** - Only checks if events match expected patterns
3. **No threat scoring** - No quantitative risk assessment
4. **No pattern mining** - No behavioral pattern discovery
5. **No ML/AI integration** - No machine learning for anomaly detection

### 3.4 eBPF Event Collection

**Current Capabilities:**
- Syscall tracing (raw_syscalls:sys_enter tracepoint)
- File access tracing (do_sys_openat2 kprobe)
- Network connection tracing (tcp_connect kprobe)

**Event Types Captured:**

| Event Type | Fields | Probe Type |
|------------|--------|------------|
| SyscallEvent | pid, tid, syscall_nr, args[3], timestamp, comm | TracePoint |
| FileAccessEvent | pid, syscall, flags, filename (128 bytes) | KProbe |
| NetworkEvent | pid, source_port, dest_ip, dest_port, bytes | KProbe |

**Limitations:**
- No return value capture (success/failure)
- No argument deep parsing
- No network payload inspection
- Limited filename length (128 bytes)

---

## 4. Industry Best Practices Analysis

### 4.1 Security Correlation Engine Standards

Based on analysis of industry standards (SIEM, SOAR, XDR platforms):

**Core Capabilities Required:**
1. **Multi-Source Correlation** - Correlate events across sources
2. **Temporal Analysis** - Time-windowed pattern detection
3. **Behavioral Baselines** - ML-based anomaly detection
4. **Threat Intelligence** - IOC matching and enrichment
5. **Risk Scoring** - Quantitative threat assessment
6. **Alert Prioritization** - Intelligent alert routing

### 4.2 Recommended Frameworks

| Framework | Purpose | Integration Approach |
|-----------|---------|---------------------|
| STIX/TAXII | Threat intelligence sharing | IOC enrichment API |
| OCSF | Open Cybersecurity Schema | Event format standardization |
| Sigma Rules | Detection rule format | Anomaly detection rules |
| MITRE ATT&CK | ATT&CK mapping | Tactic/technique tagging |

### 4.3 Correlation Techniques

1. **Sequence Correlation** - Detect ordered event patterns
2. **Frequency Correlation** - Rate-based anomaly detection
3. **Statistical Correlation** - Distribution analysis
4. **Causal Correlation** - Dependency graph analysis
5. **Similarity Correlation** - Clustering similar behaviors

---

## 5. Gap Analysis

### 5.1 Functional Gaps

| Gap | Severity | Impact |
|-----|----------|--------|
| No automatic intent linking | Critical | Correlation doesn't work |
| No anomaly detection | High | Cannot detect deviations |
| No threat scoring | High | No risk quantification |
| No pattern rules | High | Limited detection capability |
| No SIEM integration | Medium | Poor operational visibility |
| No historical analysis | Medium | No baseline comparison |
| No real-time alerts | Medium | Delayed response |

### 5.2 Technical Gaps

| Gap | Severity | Technical Detail |
|-----|----------|-----------------|
| Intent ID not propagated | Critical | Events always have None intent_id |
| Simple string matching | High | No semantic understanding |
| No event enrichment | High | Missing context fields |
| In-memory only storage | Medium | No persistence/query |
| No async processing | Medium | Performance bottleneck |
| No rule engine | Medium | Inflexible detection |

### 5.3 Integration Gaps

| Gap | Severity | Description |
|-----|----------|-------------|
| No API endpoints | High | Cannot integrate with external systems |
| No audit correlation | Medium | Disconnected from audit system |
| No manager integration | Medium | Not integrated with SandboxManager |
| No CLI integration | Low | Limited CLI support |

---

## 6. Comprehensive Enhancement Plan

### 6.1 Phase 1: Foundation (Weeks 1-3)

#### 6.1.1 Core Infrastructure

**Task 1.1: Event Enrichment**
```rust
// New enriched event structure
pub struct EnrichedEvent {
    pub base: ObservedEvent,
    pub severity: EventSeverity,          // NEW
    pub category: EventCategory,          // NEW
    pub att&ck_tactics: Vec<String>,      // NEW
    pub risk_score: f32,                  // NEW
    pub enriched_fields: HashMap<String, Value>, // NEW
}
```

**Task 1.2: Intent-Event Linker**
- Implement automatic intent inference based on:
  - Process behavior patterns
  - File access patterns
  - Network connection patterns
- Use heuristic scoring to match events to intents

**Task 1.3: Time Window Improvements**
```rust
pub struct CorrelationWindow {
    pub max_events: usize,        // Event count limit
    pub window_duration: Duration, // Time window
    pub slide_interval: Duration, // Sliding window step
    pub compression_ratio: f32,   // Event aggregation
}
```

#### 6.1.2 Anomaly Detection Engine

**Task 1.4: Statistical Anomaly Detection**
- Implement baseline calculation (per-intent, per-profile)
- Detect statistical outliers (z-score, IQR methods)
- Rate-based detection (events per second thresholds)
- Sequence anomaly detection (unexpected event orders)

**Task 1.5: Rule-Based Detection**
```rust
pub struct DetectionRule {
    pub id: String,
    pub name: String,
    pub severity: Severity,
    pub conditions: Vec<RuleCondition>,
    pub actions: Vec<RuleAction>,
    pub enabled: bool,
}
```

**Pre-defined Rules:**
1. **File Exfiltration Pattern**: Multiple file reads → network out
2. **Privilege Escalation Pattern**: setuid usage → shell spawn
3. **Persistence Pattern**: Cron/wrapper creation → repeated execution
4. **Reconnaissance Pattern**: Multiple stat/read operations

### 6.2 Phase 2: Advanced Features (Weeks 4-7)

#### 6.2.1 Threat Intelligence Integration

**Task 2.1: IOC Enrichment**
```rust
pub struct ThreatIntelligence {
    pub ioc_database: HashSet<String>,    // IPs, domains, hashes
    pub enrichment_api: Option<ApiClient>,
    pub cache_ttl: Duration,
}

impl ThreatIntelligence {
    pub async fn check_ip(&self, ip: &Ipv4Addr) -> Option<ThreatIndicator> {
        // Check local cache, then external sources
    }
}
```

**Task 2.2: MITRE ATT&CK Mapping**
- Map syscalls to ATT&CK techniques
- Map file operations to ATT&CK tactics
- Map network operations to ATT&CK techniques
- Generate ATT&CK navigator compatible output

#### 6.2.2 Behavioral Analysis

**Task 2.3: Behavioral Baseline Engine**
```rust
pub struct BehavioralBaseline {
    pub profile_id: String,
    pub features: BehavioralFeatures,
    pub normal_distribution: NormalDistribution,
    pub historical_data: Vec<SessionMetrics>,
}

impl BehavioralBaseline {
    pub fn calculate_anomaly_score(&self, current: &SessionMetrics) -> f32 {
        // Mahalanobis distance or similar
    }
}
```

**Task 2.4: Sequence Pattern Mining**
- Implement sequence alignment (Needleman-Wunsch variant)
- Detect common attack patterns
- Learn from historical sessions (optional ML)

#### 6.2.3 Risk Scoring

**Task 2.5: Multi-Factor Risk Score**
```rust
pub struct RiskScore {
    pub base_score: f32,           // 0-100
    pub severity_modifier: f32,    // Event severity impact
    pub confidence_modifier: f32,  // Detection confidence
    pub temporal_modifier: f32,    // Time-based factors
    pub cumulative_score: f32,     // Aggregated score
}

impl RiskScore {
    pub fn calculate(&mut self, events: &[EnrichedEvent]) {
        // Multi-factor scoring algorithm
    }
}
```

### 6.3 Phase 3: Integration (Weeks 8-10)

#### 6.3.1 API and CLI Integration

**Task 3.1: Correlation API Endpoints**
```rust
// New API endpoints
POST /api/v1/intents           // Register LLM intent
POST /api/v1/events            // Submit observed event
GET  /api/v1/correlation/results/{session_id}
GET  /api/v1/anomalies         // List detected anomalies
GET  /api/v1/risk-score/{session_id}
```

**Task 3.2: Enhanced CLI Commands**
```bash
purple correlation start --profile ai-dev-safe
purple correlation status --session-id <uuid>
purple correlation report --session-id <uuid> --format json
purple correlation alerts --severity high
```

#### 6.3.2 SIEM Integration

**Task 3.3: OCSF Format Export**
```rust
pub struct OcsfEvent {
    pub activity_id: u32,
    pub category_name: String,
    pub class_name: String,
    pub severity: String,
    pub time: u64,
    pub raw_data: HashMap<String, Value>,
}
```

**Task 3.4: Webhook Notifications**
```rust
pub struct AlertConfig {
    pub webhook_url: String,
    pub severity_threshold: Severity,
    pub alert_types: Vec<AlertType>,
    pub retry_policy: RetryPolicy,
}
```

#### 6.3.3 Manager Integration

**Task 3.5: SandboxManager Correlation**
- Integrate correlation with SandboxManager lifecycle
- Auto-generate correlation session per sandbox
- Store correlation results with sandbox metadata
- Enable correlation queries via manager API

### 6.4 Phase 4: Production Hardening (Weeks 11-12)

#### 6.4.1 Performance and Scalability

**Task 4.1: Event Buffer Optimization**
- Implement ring buffer for high-throughput events
- Add backpressure handling
- Implement event sampling for high-volume scenarios
- Parallel processing for correlation

**Task 4.2: Persistent Storage**
```rust
pub struct CorrelationStore {
    pub events: sled::Tree<SessionKey, EventValue>,
    pub results: sled::Tree<SessionId, SessionResult>,
    pub baselines: sled::Tree<ProfileId, BaselineData>,
    pub rules: sled::Tree<RuleId, DetectionRule>,
}
```

#### 6.4.2 Testing and Quality

**Task 4.3: Comprehensive Test Suite**
- Unit tests for correlation algorithms
- Integration tests for event flow
- Performance benchmarks
- Fuzz testing for event parsing
- Red team exercise for detection coverage

**Task 4.4: Documentation**
- API documentation (OpenAPI)
- User guide for correlation features
- Administrator guide for tuning
- Developer guide for extensions

---

## 7. Implementation Specifications

### 7.1 New Module Structure

```
purple/src/
├── correlation/
│   ├── mod.rs                 # Main module exports
│   ├── engine/                # Core correlation logic
│   │   ├── mod.rs
│   │   ├── correlator.rs
│   │   ├── anomaly_detector.rs
│   │   ├── risk_scorer.rs
│   │   └── pattern_matcher.rs
│   ├── models/                # Data models
│   │   ├── mod.rs
│   │   ├── event.rs
│   │   ├── intent.rs
│   │   └── result.rs
│   ├── enrichment/            # Event enrichment
│   │   ├── mod.rs
│   │   ├── threat_intel.rs
│   │   ├── att&ck_mapper.rs
│   │   └── severity.rs
│   ├── rules/                 # Detection rules
│   │   ├── mod.rs
│   │   ├── engine.rs
│   │   └── sigma_parser.rs
│   ├── api/                   # API integration
│   │   ├── mod.rs
│   │   ├── handlers.rs
│   │   └── models.rs
│   └── storage/               # Persistence
│       ├── mod.rs
│       ├── store.rs
│       └── migrations.rs
```

### 7.2 Key Data Structures

#### 7.2.1 EnrichedEvent
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichedEvent {
    // Core fields
    pub event_type: String,
    pub timestamp: u64,
    pub details: String,
    pub intent_id: Option<String>,
    
    // Enrichment fields
    pub severity: EventSeverity,
    pub category: EventCategory,
    pub att&ck_tactics: Vec<String>,
    pub att&ck_techniques: Vec<String>,
    pub risk_score: f32,
    pub confidence: f32,
    
    // Process context
    pub pid: u32,
    pub tid: u32,
    pub comm: String,
    
    // Event-specific fields
    pub syscall_nr: Option<u64>,
    pub args: Option<Vec<u64>>,
    pub filepath: Option<PathBuf>,
    pub network_info: Option<NetworkInfo>,
}
```

#### 7.2.2 CorrelationResult
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationResult {
    pub session_id: String,
    pub intent_id: Option<String>,
    pub prompt: Option<String>,
    
    pub events: Vec<EnrichedEvent>,
    pub anomalies: Vec<Anomaly>,
    pub risk_score: f32,
    
    pub att&ck_coverage: Vec<String>,
    pub detected_patterns: Vec<DetectedPattern>,
    
    pub start_time: u64,
    pub end_time: u64,
    pub duration_seconds: u64,
}
```

#### 7.2.3 Anomaly
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anomaly {
    pub id: String,
    pub event_id: String,
    pub anomaly_type: AnomalyType,
    pub severity: Severity,
    pub description: String,
    pub evidence: Vec<Evidence>,
    pub recommended_action: Action,
    pub confidence: f32,
    pub timestamp: u64,
}
```

### 7.3 Configuration Extensions

#### 7.3.1 Policy Configuration
```yaml
correlation:
  enabled: true
  correlation_window_seconds: 300
  max_events_per_session: 10000
  
  anomaly_detection:
    enabled: true
    statistical_threshold: 3.0  # Z-score threshold
    rate_threshold: 100         # Events per second
    sequence_lookbehind: 10     # Events to consider
    
  threat_intelligence:
    enabled: true
    local_cache_ttl: 3600
    external_sources:
      - url: https://example.com/feed
        api_key: ${THREAT_INTEL_API_KEY}
        
  risk_scoring:
    base_score: 50
    severity_weights:
      critical: 30
      high: 20
      medium: 10
      low: 5
    temporal_decay: 0.9         # Score decay per hour
    
  rules:
    enabled: true
    rule_files:
      - /etc/purple/rules/*.yaml
```

---

## 8. Risk Assessment

### 8.1 Technical Risks

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Performance degradation | Medium | High | Event sampling, async processing |
| False positives | High | Medium | Confidence thresholds, tuning |
| Memory exhaustion | Low | High | Event buffering, limits |
| Integration complexity | Medium | Medium | Phased rollout, testing |

### 8.2 Security Risks

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Correlation bypass | Low | High | Multiple detection methods |
| Data leakage | Low | High | Encrypted storage, access control |
| DoS via events | Medium | High | Rate limiting, backpressure |

---

## 9. Success Criteria

### 9.1 Functional Criteria

- [ ] Intent-event automatic linking with >80% accuracy
- [ ] Anomaly detection with <5% false positive rate
- [ ] Risk scoring 0-100 scale with calibrated thresholds
- [ ] ATT&CK technique coverage for top 20 techniques
- [ ] API integration with OCSF format support

### 9.2 Performance Criteria

- [ ] Event processing: <10ms latency at 1000 events/sec
- [ ] Correlation query: <100ms for 1M events
- [ ] Memory usage: <100MB for 1M events
- [ ] Storage: Indexed query support

### 9.3 Operational Criteria

- [ ] CLI integration complete
- [ ] API documentation complete
- [ ] Test coverage >80%
- [ ] Performance benchmarks established
- [ ] Runbook documentation complete

---

## 10. Dependencies

### 10.1 External Dependencies

| Dependency | Version | Purpose |
|------------|---------|---------|
| tokio | 1.x | Async runtime |
| sled | 0.34 | Embedded database |
| serde | 1.x | Serialization |
| reqwest | 0.11 | HTTP client for threat intel |
| rustsec | 0.28 | Security advisory database |

### 10.2 Internal Dependencies

| Dependency | Purpose |
|------------|---------|
| eBPF loader | Event source |
| Policy system | Configuration |
| Sandbox manager | Session lifecycle |
| Audit system | Compliance reporting |

---

## 11. Conclusion

The Purple AI Sandbox correlation engine is at an early prototype stage with significant potential for enhancement. The proposed plan provides a structured approach to building a production-grade correlation system that can:

1. Automatically link LLM intents with observed behavior
2. Detect anomalies and potential security threats
3. Provide quantitative risk assessment
4. Integrate with existing security tooling
5. Scale to production workloads

The phased approach allows for incremental delivery of value while managing technical risk. By implementing the enhancements outlined in this plan, Purple will have a world-class correlation engine capable of securing AI agent workloads in enterprise environments.

---

## Appendix A: Recommended Reading

- MITRE ATT&CK Framework
- STIX/TAXII Specifications
- OCSF (Open Cybersecurity Schema)
- Sigma Rule Format
- Elasticsearch Common Schema

## Appendix B: Related Projects

- TheHive (Security Incident Response)
- Cortex (Analysis Engine)
- MISP (Threat Intelligence)
- Wazuh (EDR Platform)

---

**Document Version**: 1.0  
**Last Updated**: January 2, 2026  
**Author**: Purple Development Team
