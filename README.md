# Cisco Network Topology Generation and Simulation Tool Created by Saurabh Singh

A comprehensive Python tool for automatic network topology generation, configuration validation, and network simulation based on Cisco router configuration files.

## 🎯 Overview

This tool addresses all requirements specified in the Cisco VIP 2025 Problem Statement for the Networking stream, providing:

- **Automatic Network Topology Generation**: Creates hierarchical network topologies from router configuration files
- **Configuration Validation**: Detects configuration issues like duplicate IPs, VLAN conflicts, MTU mismatches, and network loops  
- **Day-1 Network Simulation**: Simulates network startup activities (ARP, neighbor discovery, OSPF/BGP convergence)
- **Load Balancing Analysis**: Provides recommendations based on link capacity and traffic demands
- **Fault Injection Testing**: Tests network resilience and recovery capabilities
- **Multithreaded Simulation**: Uses threading to represent routers/switches with IPC communication

## 🏗️ Architecture

The tool follows a modular architecture with the following components:

```
cisco_network_topology_tool/
├── main.py                    # Main application entry point
├── src/
│   ├── config_parser.py       # Configuration file parsing
│   ├── topology_generator.py  # Network topology generation
│   ├── network_validator.py   # Configuration validation
│   ├── network_simulator.py   # Network simulation engine
│   ├── load_balancer.py      # Load balancing analysis
│   └── utils.py              # Utility functions
├── examples/
│   └── sample_configs/       # Sample configuration files
├── tests/                    # Unit tests
├── requirements.txt          # Python dependencies
└── README.md                # This file
```

## 🚀 Features

### Network Topology Generation
- Parses Cisco IOS configuration files (*.dump, *.conf, *.cfg)
- Extracts interface configurations, IP addressing, VLANs, and routing protocols
- Builds hierarchical topology (Core, Distribution, Access layers)
- Generates visual network diagrams
- Exports topology data in JSON, YAML, or text formats

### Configuration Validation
- **IP Address Validation**: Detects duplicate IPs and addressing conflicts
- **VLAN Validation**: Identifies VLAN inconsistencies and unused VLANs
- **MTU Mismatch Detection**: Finds MTU mismatches between connected interfaces
- **Network Loop Detection**: Identifies potential Layer 2 loops
- **Gateway Validation**: Verifies gateway configurations and reachability
- **Missing Component Detection**: Flags missing switch configs or network components

### Network Simulation
- **Multithreaded Device Simulation**: Each router/switch runs in its own thread
- **IPC Communication**: Uses FIFO/TCP-IP for inter-device communication
- **Day-1 Activities**: Simulates ARP discovery, OSPF hello exchanges, BGP sessions
- **Protocol State Machines**: Implements OSPF and BGP neighbor state transitions
- **Statistics Collection**: Maintains per-device statistics and logs
- **Fault Injection**: Simulates link failures and device faults
- **Pause/Resume**: Supports simulation control for testing scenarios

### Load Balancing Analysis
- **Traffic Demand Modeling**: Estimates traffic patterns between endpoints
- **Link Utilization Analysis**: Calculates current and peak utilization
- **Congestion Detection**: Identifies overutilized links
- **Alternative Path Discovery**: Finds backup paths for load balancing
- **Capacity Recommendations**: Suggests link upgrades and optimizations
- **Protocol Optimization**: Recommends ECMP, BGP, or OSPF optimizations

## 📋 Requirements

- Python 3.8 or higher
- Required packages listed in `requirements.txt`

## 🛠️ Installation

1. **Clone or download the project files**:
   ```bash
   # Create project directory
   mkdir cisco_network_tool
   cd cisco_network_tool
   
   # Copy all the provided files to this directory
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Verify installation**:
   ```bash
   python main.py --help
   ```

## 💻 Usage

### Basic Usage

1. **Generate Network Topology**:
   ```bash
   python main.py -c /path/to/config/directory --generate-topology
   ```

2. **Validate Configurations**:
   ```bash
   python main.py -c /path/to/config/directory --validate
   ```

3. **Run Network Simulation**:
   ```bash
   python main.py -c /path/to/config/directory --simulate --day1-sim
   ```

4. **Load Balancing Analysis**:
   ```bash
   python main.py -c /path/to/config/directory --load-balance
   ```

5. **Complete Analysis**:
   ```bash
   python main.py -c /path/to/config/directory --generate-topology --validate --simulate --load-balance
   ```

### Advanced Options

```bash
# Specify output directory and format
python main.py -c configs/ --generate-topology -o results/ --output-format yaml

# Increase verbosity for debugging
python main.py -c configs/ --simulate -vv

# Run with custom thread count
python main.py -c configs/ --simulate --threads 20

# Fault injection testing
python main.py -c configs/ --fault-inject
```

### Configuration File Structure

The tool expects configuration files in a directory structure like:
```
configs/
├── R1/
│   └── config.dump
├── R2/
│   └── config.dump
├── SW1.conf
└── SW2.conf
```

Supported file extensions: `.dump`, `.conf`, `.cfg`, `.txt`

## 📊 Output Files

The tool generates several output files:

- **topology.[json/yaml/txt]**: Network topology data
- **validation_results.[json/yaml/txt]**: Configuration validation report
- **simulation_results.[json/yaml/txt]**: Network simulation results
- **load_balancing_recommendations.[json/yaml/txt]**: Load balancing analysis
- **topology_diagram.png**: Visual network topology

## 🔧 Sample Configuration

To test the tool with sample configurations:

```python
from utils import create_sample_configs
sample_dir = create_sample_configs()
```

Then run:
```bash
python main.py -c examples/sample_configs --generate-topology --validate --simulate
```

## 🏃‍♂️ Example Workflow

Here's a complete example workflow:

```bash
# 1. Create sample configurations (for testing)
python -c "from utils import create_sample_configs; create_sample_configs()"

# 2. Run complete analysis
python main.py -c examples/sample_configs \
    --generate-topology \
    --validate \
    --simulate \
    --day1-sim \
    --load-balance \
    -o results \
    --output-format json \
    -v

# 3. View results
ls results/
# topology.json
# validation_results.json  
# simulation_results.json
# load_balancing_recommendations.json
# topology_diagram.png
```

## 🔍 Key Validation Checks

The tool performs these critical validation checks:

| Check Type | Description |
|------------|-------------|
| **Duplicate IPs** | Identifies IP address conflicts within VLANs |
| **VLAN Issues** | Detects incorrect VLAN labels and unused VLANs |
| **Gateway Errors** | Finds incorrect gateway addresses |
| **MTU Mismatches** | Identifies MTU size inconsistencies |
| **Network Loops** | Detects potential Layer 2 loops |
| **Missing Components** | Flags missing switch configurations |
| **Protocol Issues** | Validates OSPF/BGP configurations |

## 🎯 Load Balancing Recommendations

The tool provides intelligent recommendations:

- **Secondary Path Activation**: For congested primary links
- **Capacity Upgrades**: For bandwidth-constrained links  
- **Traffic Engineering**: MPLS-TE and IGP metric optimization
- **Protocol Optimization**: ECMP enablement, BGP implementation
- **Alternative Path Discovery**: Redundant routing options

## 🧪 Testing and Simulation

### Day-1 Simulation Features:
- **ARP Discovery**: Simulates address resolution for network discovery
- **OSPF Neighbor Discovery**: Hello packet exchanges and adjacency formation
- **BGP Session Establishment**: Peer discovery and session setup
- **Protocol Convergence**: Timing analysis for network convergence

### Fault Injection Scenarios:
- **Link Failures**: Simulate interface down scenarios
- **Device Failures**: Test device outage impact
- **MTU Issues**: Analyze fragmentation problems
- **Protocol Failures**: Test routing protocol recovery

## 🐛 Troubleshooting

Common issues and solutions:

1. **No configuration files found**:
   - Verify the config directory path
   - Ensure files have supported extensions (.dump, .conf, .cfg, .txt)

2. **Import errors**:
   - Verify all dependencies are installed: `pip install -r requirements.txt`
   - Check Python version (3.8+ required)

3. **Permission errors**:
   - Ensure read permissions on config files
   - Verify write permissions for output directory

4. **Visualization issues**:
   - Install matplotlib with GUI support
   - For headless systems, use text output format

## 📈 Performance Considerations

- **Large Networks**: Use `--threads` parameter to adjust simulation thread count
- **Memory Usage**: Large topologies may require significant memory for simulation
- **Processing Time**: Complex networks with many devices may take several minutes to process

## 🔮 Future Enhancements

Potential areas for extension:
- Support for additional vendor configurations (Juniper, Arista)
- Integration with network monitoring systems (SNMP)
- Real-time network discovery and validation
- Web-based user interface
- Integration with network automation platforms

## 📝 Cisco VIP 2025 Compliance

This tool fully addresses all requirements from the Cisco VIP 2025 Problem Statement:

✅ **Network Topology Generation**: Hierarchical topology from config files  
✅ **Bandwidth Awareness**: Link capacity analysis and traffic load validation  
✅ **Load Balancing**: Recommendations for congested links with secondary paths  
✅ **Configuration Validation**: All specified checks (IPs, VLANs, MTU, loops)  
✅ **Network Optimization**: Node aggregation and protocol recommendations  
✅ **Day-1 Simulation**: ARP, neighbor discovery, OSPF discovery  
✅ **Fault Injection**: Link failure simulation and impact analysis  
✅ **Multithreading**: Thread-based router/switch representation  
✅ **IPC Communication**: FIFO/TCP-IP metadata packet exchange  
✅ **Statistics**: Per-thread/node statistics and logging  
✅ **Pause/Resume**: Simulation control for configuration changes  

## 📄 License

This project is created for the Cisco VIP 2025 program. Please refer to Cisco's guidelines for usage and distribution.

## 🤝 Support

For issues or questions related to this tool, please refer to the Cisco VIP 2025 program resources or create detailed issue reports with:
- Configuration file samples (anonymized)
- Error logs and stack traces
- System environment details
- Expected vs actual behavior

---

**Note**: This tool is designed for educational and development purposes as part of the Cisco VIP 2025 program. For production network analysis, please validate results with additional tools and expert review.
