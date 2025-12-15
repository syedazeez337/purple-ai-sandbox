# Architecture Overview

## High-Level Architecture

```mermaid
graph TD
    A[CLI] --> B[Policy System]
    B --> C[Sandbox Engine]
    C --> D[Namespace Manager]
    C --> E[Seccomp Filter]
    C --> F[Cgroup Manager]
    C --> G[Capability Manager]
    C --> H[Network Filter]
    C --> I[Filesystem Isolator]
    C --> J[Audit Logger]
    
    style A fill:#f9f,stroke:#333
    style B fill:#bbf,stroke:#333
    style C fill:#f96,stroke:#333
    style D fill:#6f9,stroke:#333
    style E fill:#6f9,stroke:#333
    style F fill:#6f9,stroke:#333
    style G fill:#6f9,stroke:#333
    style H fill:#6f9,stroke:#333
    style I fill:#6f9,stroke:#333
    style J fill:#6f9,stroke:#333
```

## Component Architecture

### 1. CLI Interface

The Command Line Interface provides user interaction with the sandbox system.

**Responsibilities:**
- Parse command line arguments
- Validate user input
- Display help and usage information
- Manage logging levels
- Coordinate with other components

**Key Features:**
- Profile management (create, list, show, delete)
- Sandbox execution with policy selection
- Logging level control (-l flag)
- Help system and documentation

### 2. Policy System

The Policy System handles security policy definition, validation, and compilation.

**Responsibilities:**
- Load YAML policy files
- Validate policy structure and rules
- Compile policies into executable form
- Provide policy information to other components

**Key Features:**
- YAML-based declarative policies
- Policy validation and error reporting
- Policy compilation with defaults
- Policy caching and management

### 3. Sandbox Engine

The core component that orchestrates the sandbox execution.

**Responsibilities:**
- Coordinate all security components
- Manage sandbox lifecycle
- Handle errors and cleanup
- Provide execution environment

**Key Features:**
- 8-step execution pipeline
- Error handling and recovery
- Resource management
- Process isolation

### 4. Security Components

#### Namespace Manager
- **Purpose**: Linux namespace isolation
- **Namespaces**: User, PID, Mount, Network
- **Features**: Unshare, configuration, cleanup

#### Seccomp Filter
- **Purpose**: Syscall filtering
- **Features**: 450+ syscall mappings
- **Policy**: Default-deny with allowlist

#### Cgroup Manager
- **Purpose**: Resource limits
- **Resources**: CPU, Memory, PIDs, I/O
- **Features**: Hierarchical limits, monitoring

#### Capability Manager
- **Purpose**: Privilege management
- **Policy**: Default-drop with addlist
- **Features**: Least privilege enforcement

#### Network Filter
- **Purpose**: Network isolation
- **Features**: Port filtering, firewall rules
- **Policy**: Complete isolation or selective filtering

#### Filesystem Isolator
- **Purpose**: Filesystem security
- **Features**: Bind mounts, chroot, permissions
- **Policy**: Read-only, writable, output directories

#### Audit Logger
- **Purpose**: Security monitoring
- **Features**: Comprehensive logging, audit trails
- **Policy**: Configurable detail levels

## Data Flow

```mermaid
flowchart LR
    User -->|CLI Command| CLI
    CLI -->|Load Policy| PolicySystem
    PolicySystem -->|Compiled Policy| SandboxEngine
    SandboxEngine -->|Namespace Config| NamespaceManager
    SandboxEngine -->|Syscall Rules| SeccompFilter
    SandboxEngine -->|Resource Limits| CgroupManager
    SandboxEngine -->|Capabilities| CapabilityManager
    SandboxEngine -->|Network Rules| NetworkFilter
    SandboxEngine -->|Filesystem Config| FilesystemIsolator
    SandboxEngine -->|Audit Events| AuditLogger
    
    SandboxEngine -->|Execute| AgentProcess
    AgentProcess -->|Logs| AuditLogger
    AgentProcess -->|Metrics| Monitoring
```

## Security Architecture

### Defense in Depth

```mermaid
pie title Security Layers
    "Namespaces" : 15
    "Seccomp" : 15
    "Capabilities" : 10
    "Cgroups" : 10
    "Network" : 10
    "Filesystem" : 10
    "Audit" : 10
    "Policy" : 10
    "Monitoring" : 10
```

### Isolation Levels

1. **Process Isolation**: Separate PID namespace
2. **User Isolation**: Separate user namespace
3. **Filesystem Isolation**: Chroot and bind mounts
4. **Network Isolation**: Separate network namespace
5. **Syscall Isolation**: Seccomp filtering
6. **Privilege Isolation**: Capability dropping
7. **Resource Isolation**: Cgroups limits

## Performance Considerations

### Overhead Analysis

| Component | Overhead | Impact |
|-----------|----------|--------|
| Namespaces | Low | Native kernel feature |
| Seccomp | Medium | Syscall filtering |
| Cgroups | Low | Minimal impact |
| Chroot | Very Low | Filesystem isolation |
| Logging | Configurable | Adjust levels |

### Optimization Strategies

1. **Minimize Allowed Syscalls**: Reduce seccomp overhead
2. **Use Appropriate Log Levels**: Production: error/warn, Development: debug/trace
3. **Set Reasonable Resource Limits**: Balance security and performance
4. **Leverage Kernel Features**: Use native isolation mechanisms

## Deployment Architecture

### Single Node Deployment

```mermaid
graph TD
    A[User] --> B[Purple CLI]
    B --> C[Purple Service]
    C --> D[Sandbox 1]
    C --> E[Sandbox 2]
    C --> F[Sandbox N]
    
    style A fill:#f9f
    style B fill:#bbf
    style C fill:#f96
    style D fill:#6f9
    style E fill:#6f9
    style F fill:#6f9
```

### Distributed Deployment

```mermaid
graph TD
    A[User] --> B[Load Balancer]
    B --> C[Purple Node 1]
    B --> D[Purple Node 2]
    B --> E[Purple Node N]
    C --> F[Sandbox 1]
    C --> G[Sandbox 2]
    D --> H[Sandbox 3]
    D --> I[Sandbox 4]
    
    style A fill:#f9f
    style B fill:#bbf
    style C fill:#f96
    style D fill:#f96
    style E fill:#f96
    style F fill:#6f9
    style G fill:#6f9
    style H fill:#6f9
    style I fill:#6f9
```

## Future Architecture Evolution

### Planned Enhancements

1. **Microservices Architecture**: Separate components as services
2. **API Gateway**: REST API for remote management
3. **Kubernetes Operator**: Native Kubernetes integration
4. **Plugin System**: Extensible architecture
5. **Distributed Monitoring**: Centralized logging and metrics

### Roadmap

```mermaid
gantt
    title Purple Architecture Roadmap
    dateFormat  YYYY-MM-DD
    section Current (0.1.x)
    Core Sandboxing           :a1, 2024-01-01, 30d
    Basic Security Features   :a2, 2024-01-15, 30d
    
    section Next (0.2.x)
    Advanced Security         :b1, 2024-02-01, 60d
    Resource Management       :b2, 2024-02-15, 45d
    Monitoring & Logging      :b3, 2024-03-01, 30d
    
    section Future (0.3.x)
    API & Integration         :c1, 2024-04-01, 60d
    Kubernetes Integration    :c2, 2024-04-15, 45d
    Plugin System             :c3, 2024-05-01, 30d
    
    section Long Term (1.0)
    Production Ready          :d1, 2024-06-01, 90d
    Enterprise Features       :d2, 2024-07-01, 60d
    Performance Optimization  :d3, 2024-08-01, 30d
```

## Architecture Decision Records (ADRs)

### ADR-001: Default-Deny Security Model

**Status**: Accepted
**Date**: 2024-01-01

**Context**: Need to establish a security model for the sandbox

**Decision**: Adopt a default-deny security model where all operations are denied by default and explicitly allowed operations must be specified in the policy.

**Consequences**:
- ✅ Higher security by default
- ❌ More complex policy configuration
- ✅ Better alignment with security best practices

### ADR-002: YAML Policy Format

**Status**: Accepted
**Date**: 2024-01-05

**Context**: Need to choose a configuration format for security policies

**Decision**: Use YAML for policy configuration due to its human-readable nature and widespread adoption in the security community.

**Consequences**:
- ✅ Easy to read and write
- ✅ Good tooling support
- ❌ Potential for configuration errors
- ✅ Supports complex nested structures

### ADR-003: Modular Security Components

**Status**: Accepted
**Date**: 2024-01-10

**Context**: Need to design the internal security architecture

**Decision**: Implement security as modular components (namespaces, seccomp, cgroups, etc.) that can be independently configured and updated.

**Consequences**:
- ✅ Flexible architecture
- ✅ Easier maintenance
- ✅ Better testability
- ❌ More complex coordination

## Conclusion

The Purple architecture provides a comprehensive, secure, and flexible foundation for AI agent sandboxing. The modular design allows for independent evolution of components while maintaining strong security guarantees through defense-in-depth principles.