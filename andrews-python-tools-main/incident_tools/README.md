## � Incident Simulator - Production Failure Training

**File:** `incident_tools/incident_simulator.py`

A comprehensive incident simulation tool for chaos engineering and incident response training. Safely simulate production-like failures to test system resilience and train teams for real emergencies.

### 🎯 Simulation Scenarios
- **CPU Spike** - Sustained high CPU load simulation
- **Memory Leak** - Gradual RAM consumption to test memory management
- **Disk Fill** - Rapid disk space exhaustion simulation
- **DNS Failure** - Network resolution issues and DNS blocking
- **Port Exhaustion** - Connection limit testing and port depletion
- **I/O Storm** - Heavy disk read/write activity simulation
- **Network Lag** - Latency and packet loss simulation
- **Process Bomb** - Safe process spawning for resource testing

### ⚡ Intensity Levels
- **Low** - Minimal impact, suitable for production testing
- **Medium** - Moderate impact, ideal for staging environments
- **High** - Maximum impact, recommended for dedicated test systems only

### 🔒 Safety Features
- **Auto-cleanup** - Automatic resource cleanup after simulations
- **Time limits** - Built-in duration controls to prevent runaway processes
- **Safe limits** - Reasonable caps on resource consumption
- **Emergency stop** - Immediate termination of all active simulations

### Installation & Usage
```bash
# Navigate to the incident tools directory
cd incident_tools

# Run Incident Simulator
python incident_simulator.py
```

### Interactive Commands
```bash
# Start a simulation
start cpu_spike 60 high
start memory_leak 120 medium
start disk_fill 300 low

# List available scenarios
scenarios

# View simulation history
history

# Stop all simulations immediately
stop

# Export results to JSON
export incident_log.json

# Show help
help
```

### Scenario Examples

**CPU Spike Simulation:**
```bash
incident-sim> start cpu_spike 60 high
STARTING INCIDENT SIMULATION
Scenario: High CPU Usage
Description: Simulates sustained high CPU load
Severity: High
Intensity: HIGH
Simulating high CPU usage for 60 seconds...
Simulation completed!
```

**Memory Leak Simulation:**
```bash
incident-sim> start memory_leak 120 medium
STARTING INCIDENT SIMULATION
Scenario: Memory Leak  
Description: Gradually consumes available RAM
Severity: Critical
Intensity: MEDIUM
Simulating memory leak for 120 seconds...
Allocated: 245 MB
Memory released
```

**I/O Storm Simulation:**
```bash
incident-sim> start io_storm 90 low
STARTING INCIDENT SIMULATION
Scenario: I/O Storm
Description: Creates heavy disk I/O activity
Severity: Medium
Intensity: LOW
Simulating I/O storm for 90 seconds...
I/O Ops - Reads: 156, Writes: 156
```

### API Usage
```python
from incident_simulator import IncidentTool

# Create simulator instance
simulator = IncidentTool()

# Start CPU simulation
result = simulator.StartSim('cpu_spike', duration=60, intensity='medium')

# Check simulation history
history = simulator.sim_history

# Emergency cleanup
simulator.StopAll()
```

### Monitoring & Analysis
- **Real-time feedback** - Live status updates during simulations
- **Performance metrics** - Detailed resource usage statistics
- **History tracking** - Complete log of all simulation activities
- **Export capabilities** - JSON export for analysis and reporting

### Safety Warnings
⚠️ **Use in controlled environments only!**
- Test on non-production systems when possible
- Monitor system resources during simulations
- Have recovery procedures ready
- Use low intensity settings in production environments

### Educational Use Cases
- **Incident Response Training** - Practice handling real system failures
- **Chaos Engineering** - Test system resilience and fault tolerance
- **Performance Testing** - Validate system behavior under stress
- **Team Training** - Educate teams on failure scenarios
- **Recovery Procedures** - Test backup and recovery processes