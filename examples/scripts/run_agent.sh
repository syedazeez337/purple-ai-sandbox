#!/bin/bash

# Example script to run an AI agent with Purple sandbox

# Set default values
PROFILE="ai-dev-safe"
LOG_LEVEL="info"
AGENT_COMMAND="python3 ai_agent.py"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -p|--profile)
            PROFILE="$2"
            shift
            shift
            ;;
        -l|--log-level)
            LOG_LEVEL="$2"
            shift
            shift
            ;;
        -c|--command)
            AGENT_COMMAND="$2"
            shift
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  -p, --profile PROFILE    Specify the security profile to use (default: ai-dev-safe)"
            echo "  -l, --log-level LEVEL   Set the logging level (trace, debug, info, warn, error) (default: info)"
            echo "  -c, --command COMMAND   Set the agent command to run (default: python3 ai_agent.py)"
            echo "  -h, --help              Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Check if the profile exists
if [[ ! -f "policies/${PROFILE}.yaml" ]]; then
    echo "Error: Profile '${PROFILE}' does not exist in policies/ directory."
    echo "Available profiles:"
    ls -1 policies/*.yaml | sed 's/\.yaml$//;s/policies\///'
    exit 1
fi

# Run the agent with the specified profile and log level
echo "Running AI agent with profile: ${PROFILE}"
echo "Log level: ${LOG_LEVEL}"
echo "Command: ${AGENT_COMMAND}"
echo ""

# Use sudo if we need root privileges for namespaces
if [[ "${AGENT_COMMAND}" == *"python3"* || "${AGENT_COMMAND}" == *"python"* ]]; then
    # Python scripts might need root for some operations
    sudo purple -l ${LOG_LEVEL} run --profile ${PROFILE} -- ${AGENT_COMMAND}
else
    # Regular commands
    purple -l ${LOG_LEVEL} run --profile ${PROFILE} -- ${AGENT_COMMAND}
fi

# Check the exit status
if [[ $? -eq 0 ]]; then
    echo ""
    echo "✅ Agent executed successfully with profile: ${PROFILE}"
else
    echo ""
    echo "❌ Agent execution failed with profile: ${PROFILE}"
    echo "Check the logs for more information."
    exit 1
fi