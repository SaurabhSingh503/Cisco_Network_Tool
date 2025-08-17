"""
Network Simulator Module

This module provides network simulation capabilities including Day-1 simulation,
fault injection, multithreaded device simulation, and IPC communication.

Based on the Cisco VIP 2025 Problem Statement requirements.
"""

import threading
import time
import queue
import socket
import json
import yaml
import logging
import random
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field, asdict
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import ipaddress
from enum import Enum

from config_parser import RouterConfig, Interface
from topology_generator import NetworkTopology, NetworkNode, NetworkLink

logger = logging.getLogger(__name__)

class DeviceState(Enum):
    """Device operational states"""
    INIT = "initializing"
    UP = "up" 
    DOWN = "down"
    FAULT = "fault"

class ProtocolState(Enum):
    """Protocol states"""
    DOWN = "down"
    INIT = "init"
    ESTABLISHING = "establishing"
    FULL = "full"
    EXCHANGE = "exchange"

@dataclass
class ARPEntry:
    """ARP table entry"""
    ip_address: str
    mac_address: str
    interface: str
    timestamp: float = field(default_factory=time.time)

@dataclass
class NeighborEntry:
    """Neighbor table entry (OSPF/BGP)"""
    neighbor_id: str
    neighbor_ip: str
    interface: str
    state: ProtocolState = ProtocolState.DOWN
    last_hello: float = field(default_factory=time.time)
    protocol: str = "ospf"

@dataclass
class SimulationEvent:
    """Simulation event"""
    timestamp: float
    event_type: str  # arp_request, hello, lsa, etc.
    source: str
    target: Optional[str] = None
    data: Dict[str, Any] = field(default_factory=dict)

@dataclass
class DeviceStats:
    """Device statistics"""
    hostname: str
    packets_sent: int = 0
    packets_received: int = 0
    arp_requests: int = 0
    hello_packets: int = 0
    lsa_packets: int = 0
    faults_detected: int = 0
    uptime: float = 0.0

@dataclass
class SimulationResults:
    """Simulation results"""
    total_time: float
    devices_simulated: int
    total_events: int
    device_stats: Dict[str, DeviceStats] = field(default_factory=dict)
    network_events: List[SimulationEvent] = field(default_factory=list)
    convergence_time: Optional[float] = None
    fault_recovery_time: Optional[float] = None

class NetworkDevice(threading.Thread):
    """Simulated network device running in its own thread"""
    
    def __init__(self, hostname: str, config: RouterConfig, node: NetworkNode, 
                 event_queue: queue.Queue, ipc_port: int):
        super().__init__(name=f"Device_{hostname}")
        self.hostname = hostname
        self.config = config
        self.node = node
        self.event_queue = event_queue
        self.ipc_port = ipc_port
        self.state = DeviceState.INIT
        
        # Device tables
        self.arp_table: Dict[str, ARPEntry] = {}
        self.neighbor_table: Dict[str, NeighborEntry] = {}
        self.routing_table: Dict[str, str] = {}
        
        # Statistics
        self.stats = DeviceStats(hostname=hostname)
        
        # Control flags
        self.running = True
        self.fault_injected = False
        
        # IPC setup
        self.ipc_socket = None
        self.logger = logging.getLogger(f"Device_{hostname}")
        
        # Simulation timing
        self.hello_interval = 10.0  # seconds
        self.arp_timeout = 300.0   # seconds
        self.last_hello = time.time()
        
    def run(self):
        """Main device simulation loop"""
        self.logger.info(f"Starting device simulation for {self.hostname}")
        start_time = time.time()
        
        try:
            # Initialize device
            self._initialize_device()
            
            # Main simulation loop
            while self.running:
                current_time = time.time()
                self.stats.uptime = current_time - start_time
                
                # Process Day-1 activities
                if self.state == DeviceState.INIT:
                    self._day1_initialization()
                    self.state = DeviceState.UP if not self.fault_injected else DeviceState.FAULT
                
                # Handle periodic activities
                if self.state == DeviceState.UP:
                    self._send_hello_packets(current_time)
                    self._update_neighbor_states(current_time)
                    self._cleanup_arp_table(current_time)
                
                # Process incoming messages
                self._process_ipc_messages()
                
                # Sleep briefly to prevent busy waiting
                time.sleep(0.1)
                
        except Exception as e:
            self.logger.error(f"Error in device simulation: {e}")
        finally:
            self._cleanup()
    
    def _initialize_device(self):
        """Initialize device for simulation"""
        self.logger.info(f"Initializing device {self.hostname}")
        
        # Setup IPC socket
        try:
            self.ipc_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.ipc_socket.bind(('localhost', self.ipc_port))
            self.ipc_socket.settimeout(0.1)  # Non-blocking
        except Exception as e:
            self.logger.error(f"Failed to setup IPC socket: {e}")
        
        # Initialize routing table with directly connected networks
        for interface in self.config.interfaces:
            if interface.subnet and interface.ip_address and not interface.shutdown:
                self.routing_table[interface.subnet] = interface.name
    
    def _day1_initialization(self):
        """Perform Day-1 simulation activities"""
        self.logger.info(f"Performing Day-1 initialization for {self.hostname}")
        
        # Send initial ARP requests
        self._send_arp_discovery()
        
        # Start OSPF/BGP neighbor discovery
        self._start_neighbor_discovery()
        
        # Initialize protocol states
        for protocol in self.config.routing_protocols:
            if protocol.protocol == 'ospf':
                self._initialize_ospf()
            elif protocol.protocol == 'bgp':
                self._initialize_bgp()
    
    def _send_arp_discovery(self):
        """Send ARP requests for network discovery"""
        for interface in self.config.interfaces:
            if interface.subnet and interface.ip_address and not interface.shutdown:
                try:
                    network = ipaddress.IPv4Network(interface.subnet)
                    # Send ARP for first few hosts in subnet
                    for host_num in range(1, min(5, network.num_addresses)):
                        target_ip = str(network.network_address + host_num)
                        if target_ip != interface.ip_address:
                            self._send_arp_request(target_ip, interface.name)
                except Exception as e:
                    self.logger.debug(f"ARP discovery error for {interface.subnet}: {e}")
    
    def _send_arp_request(self, target_ip: str, interface: str):
        """Send ARP request"""
        event = SimulationEvent(
            timestamp=time.time(),
            event_type="arp_request",
            source=self.hostname,
            target=target_ip,
            data={
                "interface": interface,
                "target_ip": target_ip
            }
        )
        self._send_event(event)
        self.stats.arp_requests += 1
        self.stats.packets_sent += 1
    
    def _start_neighbor_discovery(self):
        """Start routing protocol neighbor discovery"""
        for protocol in self.config.routing_protocols:
            if protocol.protocol == 'ospf':
                self._discover_ospf_neighbors()
            elif protocol.protocol == 'bgp':
                self._discover_bgp_neighbors()
    
    def _discover_ospf_neighbors(self):
        """Discover OSPF neighbors"""
        for interface in self.config.interfaces:
            if interface.subnet and not interface.shutdown:
                # Send hello packet to multicast address (224.0.0.5)
                self._send_hello_packet(interface.name, "ospf")
    
    def _discover_bgp_neighbors(self):
        """Discover BGP neighbors"""
        for protocol in self.config.routing_protocols:
            if protocol.protocol == 'bgp':
                for neighbor_ip in protocol.neighbors:
                    self._establish_bgp_session(neighbor_ip)
    
    def _send_hello_packet(self, interface: str, protocol: str):
        """Send routing protocol hello packet"""
        event = SimulationEvent(
            timestamp=time.time(),
            event_type=f"{protocol}_hello",
            source=self.hostname,
            data={
                "interface": interface,
                "protocol": protocol,
                "router_id": self._get_router_id(protocol)
            }
        )
        self._send_event(event)
        self.stats.hello_packets += 1
        self.stats.packets_sent += 1
    
    def _send_hello_packets(self, current_time: float):
        """Send periodic hello packets"""
        if current_time - self.last_hello >= self.hello_interval:
            for protocol in self.config.routing_protocols:
                if protocol.protocol == 'ospf':
                    for interface in self.config.interfaces:
                        if interface.subnet and not interface.shutdown:
                            self._send_hello_packet(interface.name, "ospf")
            
            self.last_hello = current_time
    
    def _establish_bgp_session(self, neighbor_ip: str):
        """Establish BGP session with neighbor"""
        neighbor = NeighborEntry(
            neighbor_id=neighbor_ip,
            neighbor_ip=neighbor_ip,
            interface="bgp",
            state=ProtocolState.ESTABLISHING,
            protocol="bgp"
        )
        self.neighbor_table[neighbor_ip] = neighbor
        
        event = SimulationEvent(
            timestamp=time.time(),
            event_type="bgp_open",
            source=self.hostname,
            target=neighbor_ip,
            data={
                "as_number": self._get_as_number(),
                "router_id": self._get_router_id("bgp")
            }
        )
        self._send_event(event)
        self.stats.packets_sent += 1
    
    def _update_neighbor_states(self, current_time: float):
        """Update neighbor states based on hello intervals"""
        timeout_threshold = 30.0  # seconds
        
        for neighbor_id, neighbor in list(self.neighbor_table.items()):
            if current_time - neighbor.last_hello > timeout_threshold:
                if neighbor.state == ProtocolState.FULL:
                    neighbor.state = ProtocolState.DOWN
                    self.logger.warning(f"Neighbor {neighbor_id} timed out")
    
    def _cleanup_arp_table(self, current_time: float):
        """Clean up expired ARP entries"""
        expired_entries = []
        for ip, entry in self.arp_table.items():
            if current_time - entry.timestamp > self.arp_timeout:
                expired_entries.append(ip)
        
        for ip in expired_entries:
            del self.arp_table[ip]
    
    def _process_ipc_messages(self):
        """Process incoming IPC messages"""
        if not self.ipc_socket:
            return
        
        try:
            data, addr = self.ipc_socket.recvfrom(1024)
            message = json.loads(data.decode())
            self._handle_message(message)
            self.stats.packets_received += 1
        except socket.timeout:
            pass  # No message available
        except Exception as e:
            self.logger.debug(f"IPC message processing error: {e}")
    
    def _handle_message(self, message: Dict[str, Any]):
        """Handle received network message"""
        msg_type = message.get('type')
        
        if msg_type == 'arp_request':
            self._handle_arp_request(message)
        elif msg_type == 'arp_reply':
            self._handle_arp_reply(message)
        elif msg_type == 'ospf_hello':
            self._handle_ospf_hello(message)
        elif msg_type == 'bgp_open':
            self._handle_bgp_open(message)
        elif msg_type == 'fault_inject':
            self._handle_fault_injection(message)
    
    def _handle_arp_request(self, message: Dict[str, Any]):
        """Handle ARP request"""
        target_ip = message.get('target_ip')
        sender = message.get('sender')
        
        # Check if we have this IP
        for interface in self.config.interfaces:
            if interface.ip_address == target_ip:
                # Send ARP reply
                reply = {
                    'type': 'arp_reply',
                    'sender': self.hostname,
                    'target_ip': target_ip,
                    'mac_address': self._generate_mac_address(interface.name),
                    'interface': interface.name
                }
                self._send_ipc_message(sender, reply)
                break
    
    def _handle_arp_reply(self, message: Dict[str, Any]):
        """Handle ARP reply"""
        ip = message.get('target_ip')
        mac = message.get('mac_address')
        interface = message.get('interface')
        
        if ip and mac:
            self.arp_table[ip] = ARPEntry(
                ip_address=ip,
                mac_address=mac,
                interface=interface
            )
            self.logger.debug(f"ARP entry added: {ip} -> {mac}")
    
    def _handle_ospf_hello(self, message: Dict[str, Any]):
        """Handle OSPF hello packet"""
        sender = message.get('sender')
        router_id = message.get('router_id')
        interface = message.get('interface')
        
        if sender and sender != self.hostname:
            neighbor_id = router_id or sender
            
            if neighbor_id not in self.neighbor_table:
                neighbor = NeighborEntry(
                    neighbor_id=neighbor_id,
                    neighbor_ip=sender,
                    interface=interface,
                    state=ProtocolState.INIT,
                    protocol="ospf"
                )
                self.neighbor_table[neighbor_id] = neighbor
                self.logger.info(f"New OSPF neighbor discovered: {neighbor_id}")
            else:
                neighbor = self.neighbor_table[neighbor_id]
                neighbor.last_hello = time.time()
                
                # Simulate state transitions
                if neighbor.state == ProtocolState.INIT:
                    neighbor.state = ProtocolState.EXCHANGE
                elif neighbor.state == ProtocolState.EXCHANGE:
                    neighbor.state = ProtocolState.FULL
                    self.logger.info(f"OSPF neighbor {neighbor_id} is now FULL")
    
    def _handle_bgp_open(self, message: Dict[str, Any]):
        """Handle BGP open message"""
        sender = message.get('sender')
        as_number = message.get('as_number')
        router_id = message.get('router_id')
        
        if sender and sender != self.hostname:
            if sender not in self.neighbor_table:
                neighbor = NeighborEntry(
                    neighbor_id=router_id or sender,
                    neighbor_ip=sender,
                    interface="bgp",
                    state=ProtocolState.ESTABLISHING,
                    protocol="bgp"
                )
                self.neighbor_table[sender] = neighbor
                self.logger.info(f"BGP session establishing with {sender}")
            
            # Send BGP open reply
            reply = {
                'type': 'bgp_open_reply',
                'sender': self.hostname,
                'as_number': self._get_as_number(),
                'router_id': self._get_router_id("bgp")
            }
            self._send_ipc_message(sender, reply)
    
    def _handle_fault_injection(self, message: Dict[str, Any]):
        """Handle fault injection"""
        fault_type = message.get('fault_type')
        
        self.logger.warning(f"Fault injected: {fault_type}")
        self.fault_injected = True
        self.stats.faults_detected += 1
        
        if fault_type == 'interface_down':
            interface_name = message.get('interface')
            for interface in self.config.interfaces:
                if interface.name == interface_name:
                    interface.shutdown = True
                    self.logger.warning(f"Interface {interface_name} is now down")
        
        elif fault_type == 'device_down':
            self.state = DeviceState.DOWN
            self.logger.warning(f"Device {self.hostname} is now down")
    
    def _send_event(self, event: SimulationEvent):
        """Send event to main simulation queue"""
        try:
            self.event_queue.put_nowait(event)
        except queue.Full:
            self.logger.warning("Event queue full, dropping event")
    
    def _send_ipc_message(self, target: str, message: Dict[str, Any]):
        """Send IPC message to another device"""
        try:
            # In a real implementation, would need to resolve target to IP:port
            # For simulation, using simple port mapping
            target_port = hash(target) % 10000 + 20000
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            data = json.dumps(message).encode()
            sock.sendto(data, ('localhost', target_port))
            sock.close()
        except Exception as e:
            self.logger.debug(f"Failed to send IPC message to {target}: {e}")
    
    def _get_router_id(self, protocol: str) -> str:
        """Get router ID for protocol"""
        for proto in self.config.routing_protocols:
            if proto.protocol == protocol and proto.router_id:
                return proto.router_id
        
        # Use highest loopback IP as router ID
        loopback_ips = []
        for interface in self.config.interfaces:
            if interface.interface_type == 'loopback' and interface.ip_address:
                loopback_ips.append(interface.ip_address)
        
        if loopback_ips:
            return max(loopback_ips)
        
        return self.hostname
    
    def _get_as_number(self) -> str:
        """Get BGP AS number"""
        for protocol in self.config.routing_protocols:
            if protocol.protocol == 'bgp':
                return protocol.process_id or "65000"
        return "65000"
    
    def _generate_mac_address(self, interface: str) -> str:
        """Generate MAC address for interface"""
        # Simple MAC generation based on hostname and interface
        hash_value = hash(f"{self.hostname}_{interface}")
        mac = f"00:50:56:{(hash_value >> 16) & 0xFF:02x}:{(hash_value >> 8) & 0xFF:02x}:{hash_value & 0xFF:02x}"
        return mac
    
    def _initialize_ospf(self):
        """Initialize OSPF protocol"""
        self.logger.info("Initializing OSPF")
        
    def _initialize_bgp(self):
        """Initialize BGP protocol"""
        self.logger.info("Initializing BGP")
    
    def _cleanup(self):
        """Cleanup device resources"""
        if self.ipc_socket:
            self.ipc_socket.close()
        self.logger.info(f"Device {self.hostname} simulation ended")
    
    def stop(self):
        """Stop device simulation"""
        self.running = False

class NetworkSimulator:
    """Network simulation engine"""
    
    def __init__(self, num_threads: int = 10):
        self.num_threads = num_threads
        self.logger = logging.getLogger(__name__)
        self.devices: List[NetworkDevice] = []
        self.event_queue = queue.Queue(maxsize=10000)
        self.simulation_events: List[SimulationEvent] = []
    
    def run_simulation(self, topology: NetworkTopology, day1: bool = True, 
                      duration: float = 60.0) -> SimulationResults:
        """
        Run network simulation
        
        Args:
            topology: Network topology to simulate
            day1: Whether to run Day-1 simulation
            duration: Simulation duration in seconds
            
        Returns:
            SimulationResults object
        """
        start_time = time.time()
        self.logger.info(f"Starting network simulation (Day-1: {day1}, Duration: {duration}s)")
        
        results = SimulationResults(
            total_time=duration,
            devices_simulated=len(topology.nodes)
        )
        
        try:
            # Create and start device threads
            self._create_device_threads(topology)
            self._start_devices()
            
            # Monitor simulation
            self._monitor_simulation(duration, results)
            
        finally:
            # Stop all devices
            self._stop_devices()
        
        # Collect results
        self._collect_results(results)
        
        end_time = time.time()
        results.total_time = end_time - start_time
        
        self.logger.info(f"Simulation completed in {results.total_time:.2f}s")
        return results
    
    def _create_device_threads(self, topology: NetworkTopology):
        """Create device simulation threads"""
        # We need to get router configs - this is a simplified approach
        # In a real implementation, we'd pass configs properly
        
        for i, node in enumerate(topology.nodes):
            # Create a simplified router config for simulation
            config = RouterConfig(hostname=node.hostname)
            config.interfaces = node.interfaces.copy()
            
            # Assign unique IPC port
            ipc_port = 20000 + i
            
            device = NetworkDevice(
                hostname=node.hostname,
                config=config,
                node=node,
                event_queue=self.event_queue,
                ipc_port=ipc_port
            )
            
            self.devices.append(device)
    
    def _start_devices(self):
        """Start all device threads"""
        for device in self.devices:
            device.start()
        
        self.logger.info(f"Started {len(self.devices)} device simulation threads")
    
    def _stop_devices(self):
        """Stop all device threads"""
        for device in self.devices:
            device.stop()
        
        # Wait for all threads to finish
        for device in self.devices:
            device.join(timeout=5.0)
        
        self.logger.info("All device simulation threads stopped")
    
    def _monitor_simulation(self, duration: float, results: SimulationResults):
        """Monitor simulation progress"""
        start_time = time.time()
        
        while time.time() - start_time < duration:
            # Process events from device threads
            try:
                while True:
                    event = self.event_queue.get_nowait()
                    self.simulation_events.append(event)
                    results.total_events += 1
            except queue.Empty:
                pass
            
            # Sleep briefly
            time.sleep(0.5)
        
        # Calculate convergence time (simplified)
        if results.total_events > 0:
            # Find when most hello exchanges completed
            hello_events = [e for e in self.simulation_events if 'hello' in e.event_type]
            if hello_events:
                results.convergence_time = max(e.timestamp for e in hello_events) - start_time
    
    def _collect_results(self, results: SimulationResults):
        """Collect simulation results from all devices"""
        for device in self.devices:
            results.device_stats[device.hostname] = device.stats
        
        results.network_events = self.simulation_events.copy()
    
    def inject_faults(self, configs: Dict[str, RouterConfig]) -> SimulationResults:
        """
        Run fault injection simulation
        
        Args:
            configs: Router configurations
            
        Returns:
            SimulationResults object
        """
        self.logger.info("Starting fault injection simulation")
        
        # Create simple topology for fault testing
        from topology_generator import TopologyGenerator
        topology_gen = TopologyGenerator()
        topology = topology_gen.generate_topology(configs)
        
        # Run initial simulation
        results = self.run_simulation(topology, day1=True, duration=30.0)
        
        # Inject faults randomly
        if self.devices:
            fault_start = time.time()
            
            # Inject interface failure
            target_device = random.choice(self.devices)
            fault_message = {
                'type': 'fault_inject',
                'fault_type': 'interface_down',
                'interface': 'GigabitEthernet0/1'
            }
            
            target_device._handle_fault_injection(fault_message)
            
            # Continue simulation to observe recovery
            recovery_start = time.time()
            time.sleep(10.0)  # Allow time for recovery
            
            results.fault_recovery_time = time.time() - recovery_start
        
        return results
    
    def save_results(self, results: SimulationResults, output_file: Path, 
                    format_type: str = 'json'):
        """Save simulation results to file"""
        results_dict = asdict(results)
        
        if format_type == 'json':
            with open(output_file, 'w') as f:
                json.dump(results_dict, f, indent=2, default=str)
        elif format_type == 'yaml':
            with open(output_file, 'w') as f:
                yaml.dump(results_dict, f, default_flow_style=False)
        elif format_type == 'text':
            with open(output_file, 'w') as f:
                f.write("NETWORK SIMULATION RESULTS\n")
                f.write("=" * 50 + "\n\n")
                
                f.write("SIMULATION SUMMARY:\n")
                f.write("-" * 20 + "\n")
                f.write(f"Total Time: {results.total_time:.2f} seconds\n")
                f.write(f"Devices Simulated: {results.devices_simulated}\n")
                f.write(f"Total Events: {results.total_events}\n")
                if results.convergence_time:
                    f.write(f"Convergence Time: {results.convergence_time:.2f} seconds\n")
                if results.fault_recovery_time:
                    f.write(f"Fault Recovery Time: {results.fault_recovery_time:.2f} seconds\n")
                f.write("\n")
                
                f.write("DEVICE STATISTICS:\n")
                f.write("-" * 20 + "\n")
                for hostname, stats in results.device_stats.items():
                    f.write(f"{hostname}:\n")
                    f.write(f"  Uptime: {stats.uptime:.2f}s\n")
                    f.write(f"  Packets Sent: {stats.packets_sent}\n")
                    f.write(f"  Packets Received: {stats.packets_received}\n")
                    f.write(f"  ARP Requests: {stats.arp_requests}\n")
                    f.write(f"  Hello Packets: {stats.hello_packets}\n")
                    f.write(f"  Faults Detected: {stats.faults_detected}\n\n")
        
        self.logger.info(f"Simulation results saved to {output_file}")