// purple/src/correlation/tests/mod.rs
//!
//! Comprehensive tests for the correlation engine

#[cfg(test)]
mod unit_tests {
    use crate::correlation::engine::*;
    use crate::correlation::enrichment::*;
    use crate::correlation::models::*;
    use crate::correlation::rules::*;
    use crate::correlation::storage::*;

    // ==================== Model Tests ====================

    #[test]
    fn test_severity_numeric_values() {
        assert_eq!(Severity::Critical.numeric_value(), 100.0);
        assert_eq!(Severity::High.numeric_value(), 75.0);
        assert_eq!(Severity::Medium.numeric_value(), 50.0);
        assert_eq!(Severity::Low.numeric_value(), 25.0);
        assert_eq!(Severity::Informational.numeric_value(), 5.0);
    }

    #[test]
    fn test_risk_level_from_score() {
        assert_eq!(RiskLevel::from_score(85.0), RiskLevel::Critical);
        assert_eq!(RiskLevel::from_score(70.0), RiskLevel::High);
        assert_eq!(RiskLevel::from_score(50.0), RiskLevel::Medium);
        assert_eq!(RiskLevel::from_score(30.0), RiskLevel::Low);
        assert_eq!(RiskLevel::from_score(10.0), RiskLevel::Minimal);
    }

    #[test]
    fn test_llm_intent_creation() {
        let intent = LlmIntent::new(
            "Write code to process files".to_string(),
            vec!["openat".to_string(), "read".to_string()],
            "ai-dev-safe".to_string(),
        );

        assert!(!intent.intent_id.is_empty());
        assert_eq!(intent.prompt, "Write code to process files");
        assert_eq!(intent.expected_actions.len(), 2);
        assert_eq!(intent.profile_name, "ai-dev-safe");
        assert!(intent.confidence > 0.0);
    }

    #[test]
    fn test_raw_event_creation() {
        let event = RawEvent::new(
            "syscall".to_string(),
            1234,
            "openat file operation".to_string(),
            EventCategory::FileAccess,
        );

        assert!(!event.event_id.is_empty());
        assert_eq!(event.pid, 1234);
        assert_eq!(event.category, EventCategory::FileAccess);
    }

    #[test]
    fn test_correlation_session_creation() {
        let session = CorrelationSession::new("test-profile".to_string());

        assert!(!session.session_id.is_empty());
        assert_eq!(session.profile_name, "test-profile");
        assert_eq!(session.status, SessionStatus::Active);
        assert!(session.start_time > 0);
    }

    #[test]
    fn test_correlation_config_defaults() {
        let config = CorrelationConfig::default();

        assert_eq!(config.correlation_window_seconds, 300);
        assert_eq!(config.max_events_per_session, 10000);
        assert!(config.anomaly_detection.enabled);
        assert!(config.attack_mapping);
        assert!(config.enable_intent_linking);
    }

    // ==================== Enrichment Tests ====================

    #[tokio::test]
    async fn test_event_enricher() {
        let enricher = EventEnricher::new(ThreatIntelligenceConfig::default());

        let raw_event = RawEvent::new(
            "syscall".to_string(),
            1234,
            "Syscall[nr=59, args=(0x0, 0x0, 0x0), comm=test]".to_string(),
            EventCategory::Syscall,
        );

        let enriched = enricher.enrich(raw_event, None).await;

        assert_eq!(enriched.base.pid, 1234);
        assert!(!enriched.attack_techniques.is_empty());
        assert!(enriched.risk_score >= 0.0);
    }

    #[test]
    fn test_severity_classifier() {
        let classifier = SeverityClassifier::default();

        // Critical patterns
        let mount_event = RawEvent::new("syscall".to_string(), 1, "mount operation".to_string(), EventCategory::Syscall);
        assert_eq!(classifier.classify(&mount_event), Severity::Critical);

        let ptrace_event = RawEvent::new("syscall".to_string(), 1, "ptrace call".to_string(), EventCategory::Syscall);
        assert_eq!(classifier.classify(&ptrace_event), Severity::Critical);

        // High severity
        let exec_event = RawEvent::new("syscall".to_string(), 1, "execve call".to_string(), EventCategory::Syscall);
        assert_eq!(classifier.classify(&exec_event), Severity::High);

        // Medium severity
        let read_event = RawEvent::new("syscall".to_string(), 1, "read operation".to_string(), EventCategory::Syscall);
        assert_eq!(classifier.classify(&read_event), Severity::Medium);
    }

    #[test]
    fn test_attack_mapping_syscall() {
        let mapper = AttackMappingService::default();

        // Test execve mapping
        let techniques = mapper.map_syscall(59, &[0, 0, 0]);
        assert!(!techniques.is_empty());
        assert!(techniques.iter().any(|t| t.technique_id == "T1059"));
    }

    #[test]
    fn test_attack_mapping_file_operations() {
        let mapper = AttackMappingService::default();

        // Read operation
        let read_tech = mapper.map_file_operation("read", "/tmp/file.txt");
        assert!(read_tech.iter().any(|t| t.technique_id == "T1005"));

        // Write to etc (persistence)
        let write_tech = mapper.map_file_operation("write", "/etc/crontab");
        assert!(write_tech.iter().any(|t| t.technique_id == "T1543"));
    }

    #[test]
    fn test_attack_mapping_network() {
        let mapper = AttackMappingService::default();

        // Suspicious port
        let ssh_tech = mapper.map_network_operation("192.168.1.1", 22, 1000);
        assert!(ssh_tech.iter().any(|t| t.technique_id == "T1041"));

        // Large data transfer
        let large_transfer = mapper.map_network_operation("10.0.0.1", 443, 2000000);
        assert!(large_transfer.iter().any(|t| t.technique_id == "T1041"));
    }

    // ==================== Engine Tests ====================

    #[tokio::test]
    async fn test_correlation_engine_session_lifecycle() {
        let engine = CorrelationEngine::default();

        // Start session
        let session_id = engine.start_session("test-profile".to_string(), None);
        assert!(!session_id.is_empty());

        // Check session is active
        let active_sessions = engine.get_active_sessions();
        assert!(active_sessions.contains(&session_id));

        // Get session
        let session = engine.get_session(&session_id);
        assert!(session.is_some());
        assert_eq!(session.unwrap().status, SessionStatus::Active);

        // Complete session
        let completed = engine.complete_session(&session_id).await;
        assert!(completed.is_some());
        assert_eq!(completed.unwrap().status, SessionStatus::Completed);
    }

    #[tokio::test]
    async fn test_correlation_engine_event_processing() {
        let engine = CorrelationEngine::default();
        let session_id = engine.start_session("test-profile".to_string(), None);

        // Process some events
        for i in 0..5 {
            let event = RawEvent::new(
                "syscall".to_string(),
                1234 + i as u32,
                format!("openat operation {}", i),
                EventCategory::FileAccess,
            );
            let anomaly = engine.process_event(&session_id, event).await;
            assert!(anomaly.is_none()); // Normal events shouldn't trigger anomalies
        }

        // Complete session and check
        let session = engine.complete_session(&session_id).await.unwrap();
        assert_eq!(session.events.len(), 5);
        assert!(session.risk_score.cumulative_score > 0.0);
    }

    #[tokio::test]
    async fn test_rate_based_anomaly_detection() {
        let config = CorrelationConfig {
            anomaly_detection: AnomalyDetectionConfig {
                rate_threshold: 5, // Very low threshold for testing
                ..Default::default()
            },
            ..Default::default()
        };

        let engine = CorrelationEngine::new(config);
        let session_id = engine.start_session("test-profile".to_string(), None);

        // Send many events quickly to trigger rate anomaly
        for i in 0..10 {
            let event = RawEvent::new(
                "syscall".to_string(),
                1234,
                format!("event {}", i),
                EventCategory::Syscall,
            );
            engine.process_event(&session_id, event).await;
        }

        let session = engine.complete_session(&session_id).await.unwrap();
        assert!(session.anomalies.len() > 0);
        assert!(session.anomalies.iter().any(|a| a.anomaly_type == AnomalyType::RateExceeded));
    }

    // ==================== Rules Tests ====================

    #[test]
    fn test_rules_engine_basic_matching() {
        let engine = RulesEngine::new(true);

        // Add a test rule
        let rule = DetectionRule {
            id: "test_001".to_string(),
            name: "Test Rule".to_string(),
            description: "Test rule".to_string(),
            severity: Severity::High,
            conditions: vec![
                RuleCondition {
                    field: "category".to_string(),
                    operator: ConditionOperator::Equals,
                    value: serde_json::json!("FileAccess"),
                },
            ],
            actions: vec![RuleAction::Alert],
            enabled: true,
            tags: vec!["test".to_string()],
        };

        engine.add_rule(rule);

        // Test matching
        let event = EnrichedEvent {
            base: RawEvent::new("syscall".to_string(), 1234, "test".to_string(), EventCategory::FileAccess),
            ..Default::default()
        };

        let matches = engine.match_event(&event);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_id, "test_001");
    }

    #[test]
    fn test_sigma_rule_parsing() {
        let sigma_yaml = r#"
title: Suspicious PowerShell Download
id: sigma-powershell-001
status: stable
description: Detects suspicious PowerShell download patterns
level: high
tags:
  - attack.execution
  - attack.t1059.001
detection:
  selection:
    CommandLine|contains: 'powershell'
    CommandLine|contains: 'DownloadString'
  condition: selection
"#;

        let sigma_rule: SigmaRule = serde_yaml::from_str(sigma_yaml).unwrap();
        assert_eq!(sigma_rule.title, "Suspicious PowerShell Download");
        assert_eq!(sigma_rule.level, Some("high".to_string()));

        let detection_rule = sigma_rule.to_detection_rule().unwrap();
        assert_eq!(detection_rule.id, "sigma-powershell-001");
        assert_eq!(detection_rule.severity, Severity::High);
    }

    #[test]
    fn test_builtin_rules_count() {
        let builtin = get_builtin_rules();
        assert!(builtin.len() >= 6);
    }

    // ==================== Storage Tests ====================

    #[test]
    fn test_memory_storage_session() {
        let storage = MemoryStorage::new();

        let session = CorrelationSession::new("test-profile".to_string());
        storage.store_session(&session).unwrap();

        let retrieved = storage.get_session(&session.session_id);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().profile_name, "test-profile");
    }

    #[test]
    fn test_memory_storage_events() {
        let storage = MemoryStorage::new();
        let session_id = "test-session".to_string();

        let event = EnrichedEvent {
            base: RawEvent::new("syscall".to_string(), 1234, "test event".to_string(), EventCategory::Syscall),
            ..Default::default()
        };

        storage.store_event(&session_id, &event).unwrap();
        let events = storage.get_session_events(&session_id);
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn test_memory_storage_baseline() {
        let storage = MemoryStorage::new();
        let baseline = BehavioralBaseline::new("test-profile".to_string());

        storage.store_baseline(&baseline).unwrap();
        let retrieved = storage.get_baseline("test-profile");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().profile_name, "test-profile");
    }

    #[test]
    fn test_memory_storage_rules() {
        let storage = MemoryStorage::new();

        let rule = DetectionRule {
            id: "test_rule".to_string(),
            name: "Test Rule".to_string(),
            description: "Description".to_string(),
            severity: Severity::Medium,
            conditions: vec![],
            actions: vec![RuleAction::Log],
            enabled: true,
            tags: vec![],
        };

        storage.store_rule(&rule).unwrap();
        let rules = storage.get_all_rules();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "test_rule");
    }

    // ==================== Pattern Detection Tests ====================

    #[test]
    fn test_pattern_detection_file_exfiltration() {
        let detector = PatternDetector::default();

        // Create events simulating file exfiltration
        let mut events = Vec::new();
        
        // 15 file reads
        for _ in 0..15 {
            events.push(EnrichedEvent {
                base: RawEvent::new("file_access".to_string(), 0, "read".to_string(), EventCategory::FileAccess),
                ..Default::default()
            });
        }
        
        // 6 network connections
        for _ in 0..6 {
            events.push(EnrichedEvent {
                base: RawEvent::new("network".to_string(), 0, "connect".to_string(), EventCategory::Network),
                ..Default::default()
            });
        }

        let patterns = detector.detect_patterns(&events);
        assert!(patterns.iter().any(|p| p.pattern_name == "File Exfiltration"));
    }

    #[test]
    fn test_pattern_detection_privilege_escalation() {
        let detector = PatternDetector::default();

        let events = vec![
            EnrichedEvent {
                base: RawEvent::new("syscall".to_string(), 0, "setuid".to_string(), EventCategory::Syscall),
                attack_techniques: vec!["T1548".to_string()],
                ..Default::default()
            },
        ];

        let patterns = detector.detect_patterns(&events);
        assert!(patterns.iter().any(|p| p.pattern_name == "Privilege Escalation"));
    }

    // ==================== Statistics Tests ====================

    #[test]
    fn test_statistics_mean() {
        let data = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        assert_eq!(mean(&data), 3.0);
    }

    #[test]
    fn test_statistics_empty_mean() {
        let empty: Vec<f64> = vec![];
        assert_eq!(mean(&empty), 0.0);
    }

    #[test]
    fn test_statistics_standard_deviation() {
        let data = vec![2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0];
        let sd = standard_deviation(&data);
        assert!((sd - 2.0).abs() < 0.1);
    }

    #[test]
    fn test_statistics_z_score() {
        let z = z_score(10.0, 5.0, 2.5);
        assert_eq!(z, 2.0);
    }

    #[test]
    fn test_statistics_z_score_zero_std() {
        let z = z_score(10.0, 5.0, 0.0);
        assert_eq!(z, 0.0); // Should handle zero division
    }

    #[test]
    fn test_statistics_entropy() {
        let counts = vec![5, 3, 2];
        let entropy = entropy(&counts);
        assert!(entropy > 0.0);
        assert!(entropy <= 1.585); // Max entropy for 3 categories
    }

    // ==================== Integration Tests ====================

    #[tokio::test]
    async fn test_full_correlation_workflow() {
        let engine = CorrelationEngine::default();
        let storage = MemoryStorage::new();

        // 1. Start session
        let session_id = engine.start_session("ai-dev-safe".to_string(), Some("sandbox-123".to_string()));

        // 2. Register intent
        let intent = LlmIntent::new(
            "Read config files and process data".to_string(),
            vec!["openat".to_string(), "read".to_string(), "fstat".to_string()],
            "ai-dev-safe".to_string(),
        );
        engine.register_intent(&session_id, intent).await;

        // 3. Process events
        let events = vec![
            RawEvent::new("syscall".to_string(), 1000, "openat /etc/config.yaml".to_string(), EventCategory::FileAccess),
            RawEvent::new("syscall".to_string(), 1000, "fstat fd=3".to_string(), EventCategory::Syscall),
            RawEvent::new("syscall".to_string(), 1000, "read fd=3 bytes=1024".to_string(), EventCategory::Syscall),
        ];

        for event in events {
            engine.process_event(&session_id, event).await;
        }

        // 4. Complete session
        let session = engine.complete_session(&session_id).await.unwrap();

        // 5. Verify results
        assert_eq!(session.events.len(), 3);
        assert!(session.risk_score.cumulative_score >= 0.0);
        assert!(session.attack_coverage.len() > 0);

        // 6. Store results
        storage.store_session(&session).unwrap();
        let retrieved = storage.get_session(&session_id);
        assert!(retrieved.is_some());
    }

    #[tokio::test]
    async fn test_anomaly_detection_integration() {
        let config = CorrelationConfig {
            anomaly_detection: AnomalyDetectionConfig {
                statistical_threshold: 2.0, // Lower threshold
                rate_threshold: 3,
                ..Default::default()
            },
            ..Default::default()
        };

        let engine = CorrelationEngine::new(config);
        let session_id = engine.start_session("production".to_string(), None);

        // Simulate reconnaissance - many file operations
        for i in 0..10 {
            let event = RawEvent::new(
                "syscall".to_string(),
                999,
                format!("stat /etc/passwd{}", i),
                EventCategory::FileAccess,
            );
            engine.process_event(&session_id, event).await;
        }

        // Simulate privilege escalation attempt
        let priv_event = RawEvent::new(
            "syscall".to_string(),
            999,
            "setuid uid=0".to_string(),
            EventCategory::Syscall,
        );
        engine.process_event(&session_id, priv_event).await;

        let session = engine.complete_session(&session_id).await.unwrap();

        // Should detect anomalies
        assert!(session.anomalies.len() > 0 || session.risk_score.cumulative_score > 50.0);
        
        // Should have ATT&CK coverage
        assert!(!session.attack_coverage.is_empty());
    }
}

// ==================== Benchmark Tests ====================

#[cfg(test)]
mod benchmark_tests {
    use crate::correlation::engine::*;
    use crate::correlation::models::*;
    use crate::correlation::rules::*;
    use criterion::{black_box, criterion_group, criterion_main, Criterion};
    use tokio::runtime::Runtime;

    fn criterion_benchmark(c: &mut Criterion) {
        let rt = Runtime::new().unwrap();

        c.bench_function("correlation_engine_start_session", |b| {
            b.iter(|| {
                rt.block_on(async {
                    let engine = CorrelationEngine::default();
                    black_box(engine.start_session("bench-profile".to_string(), None));
                });
            });
        });

        c.bench_function("correlation_engine_process_event", |b| {
            b.iter(|| {
                rt.block_on(async {
                    let engine = CorrelationEngine::default();
                    let session_id = engine.start_session("bench-profile".to_string(), None);
                    
                    let event = RawEvent::new(
                        "syscall".to_string(),
                        1234,
                        "bench syscall".to_string(),
                        EventCategory::Syscall,
                    );
                    black_box(engine.process_event(&session_id, event).await);
                });
            });
        });

        c.bench_function("rules_engine_match", |b| {
            let engine = RulesEngine::new(true);
            
            let rule = DetectionRule {
                id: "bench_001".to_string(),
                name: "Bench Rule".to_string(),
                description: "Benchmark rule".to_string(),
                severity: Severity::High,
                conditions: vec![
                    RuleCondition {
                        field: "category".to_string(),
                        operator: ConditionOperator::Equals,
                        value: serde_json::json!("Syscall"),
                    },
                ],
                actions: vec![RuleAction::Alert],
                enabled: true,
                tags: vec![],
            };
            engine.add_rule(rule);

            let event = EnrichedEvent {
                base: RawEvent::new("syscall".to_string(), 1234, "bench".to_string(), EventCategory::Syscall),
                ..Default::default()
            };

            b.iter(|| {
                black_box(engine.match_event(&event));
            });
        });

        c.bench_function("statistics_z_score", |b| {
            b.iter(|| {
                black_box(z_score(10.0, 5.0, 2.5));
            });
        });
    }

    criterion_group!(benches, criterion_benchmark);
    criterion_main!(benches);
}
