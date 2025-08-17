"""
Network Topology Generator Module

This module generates hierarchical network topologies from parsed router configurations.
It creates visual representations and data structures that can be used for simulation
and analysis.

Based on the Cisco VIP 2025 Problem Statement requirements.
"""

import json
import yaml
import logging
from typing import Dict, List, Tuple, Any, Optional
from dataclasses import dataclass, field, asdict
from collections import defaultdict
import networkx as nx
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from pathlib import Path

from config_parser import RouterConfig, Interface

logger = logging.getLogger(__name__)

@dataclass
class NetworkNode:
    """Represents a network node (router/switch)"""
    hostname: str
    device_type: str  # router, switch, l3_switch
    interfaces: List[Interface] = field(default_factory=list)
    position: Tuple[float, float] = (0, 0)
    tier: int = 0  # Network tier (0=core, 1=distribution, 2=access)

@dataclass
class NetworkLink:
    """Represents a connection between two network nodes"""
    source: str
    target: str
    source_interface: str
    target_interface: str
    subnet: str
    bandwidth: Optional[int] = None
    link_type: str = "ethernet"
    mtu: int = 1500
    utilization: float = 0.0  # Current utilization percentage

@dataclass
class NetworkTopology:
    """Complete network topology representation"""
    nodes: List[NetworkNode] = field(default_factory=list)
    links: List[NetworkLink] = field(default_factory=list)
    subnets: Dict[str, List[str]] = field(default_factory=dict)
    routing_domains: Dict[str, List[str]] = field(default_factory=dict)

class TopologyGenerator:
    """Generates network topology from configuration data"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
    def generate_topology(self, configs: Dict[str, RouterConfig]) -> NetworkTopology:
        """
        Generate network topology from router configurations
        
        Args:
            configs: Dictionary of router configurations
            
        Returns:
            NetworkTopology object
        """
        topology = NetworkTopology()
        
        # Create nodes
        self.logger.info("Creating network nodes...")
        topology.nodes = self._create_nodes(configs)
        
        # Create links
        self.logger.info("Creating network links...")
        topology.links = self._create_links(configs)
        
        # Analyze subnets
        self.logger.info("Analyzing subnets...")
        topology.subnets = self._analyze_subnets(configs)
        
        # Analyze routing domains
        self.logger.info("Analyzing routing domains...")
        topology.routing_domains = self._analyze_routing_domains(configs)
        
        # Determine network hierarchy
        self.logger.info("Determining network hierarchy...")
        self._determine_hierarchy(topology)
        
        # Calculate positions for visualization
        self.logger.info("Calculating node positions...")
        self._calculate_positions(topology)
        
        return topology
    
    def _create_nodes(self, configs: Dict[str, RouterConfig]) -> List[NetworkNode]:
        """Create network nodes from router configurations"""
        nodes = []
        
        for hostname, config in configs.items():
            # Determine device type based on interfaces and configuration
            device_type = self._determine_device_type(config)
            
            node = NetworkNode(
                hostname=hostname,
                device_type=device_type,
                interfaces=config.interfaces.copy()
            )
            
            nodes.append(node)
            
        return nodes
    
    def _determine_device_type(self, config: RouterConfig) -> str:
        """Determine device type from configuration"""
        # Check for L3 switching capabilities
        has_vlans = len(config.vlans) > 0
        has_svi = any(intf.interface_type == 'vlan' for intf in config.interfaces)
        has_routing = len(config.routing_protocols) > 0 or len(config.static_routes) > 0
        
        # Check interface types
        ethernet_count = sum(1 for intf in config.interfaces 
                           if 'ethernet' in intf.interface_type.lower())
        serial_count = sum(1 for intf in config.interfaces 
                         if 'serial' in intf.interface_type.lower())
        
        if has_vlans and has_routing:
            return 'l3_switch'
        elif has_vlans:
            return 'l2_switch'
        elif serial_count > ethernet_count:
            return 'router'
        elif ethernet_count > 0 and has_routing:
            return 'router'
        else:
            return 'switch'
    
    def _create_links(self, configs: Dict[str, RouterConfig]) -> List[NetworkLink]:
        """Create network links by analyzing IP connectivity"""
        links = []
        subnet_to_devices = defaultdict(list)
        
        # Map subnets to devices
        for hostname, config in configs.items():
            for interface in config.interfaces:
                if interface.subnet and interface.ip_address and not interface.shutdown:
                    subnet_to_devices[interface.subnet].append({
                        'hostname': hostname,
                        'interface': interface
                    })
        
        # Create links between devices on same subnet
        for subnet, devices in subnet_to_devices.items():
            if len(devices) >= 2:
                # Create point-to-point links between all devices on subnet
                for i in range(len(devices)):
                    for j in range(i + 1, len(devices)):
                        device1 = devices[i]
                        device2 = devices[j]
                        
                        # Determine link bandwidth (use minimum of both interfaces)
                        bw1 = device1['interface'].bandwidth or 100000  # Default 100Mbps
                        bw2 = device2['interface'].bandwidth or 100000
                        link_bandwidth = min(bw1, bw2)
                        
                        # Determine MTU (use minimum)
                        mtu1 = device1['interface'].mtu
                        mtu2 = device2['interface'].mtu
                        link_mtu = min(mtu1, mtu2)
                        
                        link = NetworkLink(
                            source=device1['hostname'],
                            target=device2['hostname'],
                            source_interface=device1['interface'].name,
                            target_interface=device2['interface'].name,
                            subnet=subnet,
                            bandwidth=link_bandwidth,
                            mtu=link_mtu
                        )
                        
                        links.append(link)
        
        return links
    
    def _analyze_subnets(self, configs: Dict[str, RouterConfig]) -> Dict[str, List[str]]:
        """Analyze subnet assignments"""
        subnets = defaultdict(list)
        
        for hostname, config in configs.items():
            for interface in config.interfaces:
                if interface.subnet and not interface.shutdown:
                    if hostname not in subnets[interface.subnet]:
                        subnets[interface.subnet].append(hostname)
        
        return dict(subnets)
    
    def _analyze_routing_domains(self, configs: Dict[str, RouterConfig]) -> Dict[str, List[str]]:
        """Analyze routing domains (OSPF areas, BGP AS)"""
        domains = defaultdict(list)
        
        for hostname, config in configs.items():
            for protocol in config.routing_protocols:
                if protocol.protocol == 'ospf':
                    # Extract OSPF areas from networks
                    for network in protocol.networks:
                        if 'area' in network:
                            area = network.split('area')[-1].strip()
                            domain_key = f"ospf_area_{area}"
                            if hostname not in domains[domain_key]:
                                domains[domain_key].append(hostname)
                
                elif protocol.protocol == 'bgp':
                    domain_key = f"bgp_as_{protocol.process_id}"
                    if hostname not in domains[domain_key]:
                        domains[domain_key].append(hostname)
        
        return dict(domains)
    
    def _determine_hierarchy(self, topology: NetworkTopology):
        """Determine network hierarchy (core, distribution, access)"""
        # Create NetworkX graph for analysis
        G = nx.Graph()
        
        # Add nodes
        for node in topology.nodes:
            G.add_node(node.hostname, device_type=node.device_type)
        
        # Add edges
        for link in topology.links:
            G.add_edge(link.source, link.target)
        
        # Calculate centrality measures
        degree_centrality = nx.degree_centrality(G)
        betweenness_centrality = nx.betweenness_centrality(G)
        
        # Assign tiers based on centrality and device type
        for node in topology.nodes:
            hostname = node.hostname
            degree = degree_centrality.get(hostname, 0)
            betweenness = betweenness_centrality.get(hostname, 0)
            
            # Core devices: high degree and betweenness centrality
            if degree > 0.5 and betweenness > 0.3:
                node.tier = 0  # Core
            elif degree > 0.3 or betweenness > 0.1:
                node.tier = 1  # Distribution
            else:
                node.tier = 2  # Access
            
            # Adjust based on device type
            if node.device_type == 'router' and node.tier > 1:
                node.tier = 1  # Routers are usually distribution or core
    
    def _calculate_positions(self, topology: NetworkTopology):
        """Calculate node positions for visualization"""
        # Group nodes by tier
        tiers = defaultdict(list)
        for node in topology.nodes:
            tiers[node.tier].append(node)
        
        # Position nodes in hierarchical layout
        y_positions = {0: 2.0, 1: 1.0, 2: 0.0}  # Core at top
        
        for tier, nodes in tiers.items():
            y = y_positions.get(tier, 0)
            node_count = len(nodes)
            
            if node_count == 1:
                x_positions = [0.0]
            else:
                # Spread nodes horizontally
                x_positions = []
                for i in range(node_count):
                    x = (i - (node_count - 1) / 2) * 2.0
                    x_positions.append(x)
            
            # Assign positions
            for i, node in enumerate(nodes):
                node.position = (x_positions[i], y)
    
    def visualize_topology(self, topology: NetworkTopology, output_file: Path = None):
        """Create a visual representation of the topology"""
        fig, ax = plt.subplots(1, 1, figsize=(14, 10))
        
        # Create NetworkX graph
        G = nx.Graph()
        
        # Add nodes with positions
        pos = {}
        node_colors = []
        node_sizes = []
        
        color_map = {
            'router': '#FF6B6B',      # Red
            'l3_switch': '#4ECDC4',   # Teal
            'l2_switch': '#45B7D1',   # Blue
            'switch': '#96CEB4'       # Green
        }
        
        size_map = {
            0: 3000,  # Core
            1: 2000,  # Distribution
            2: 1000   # Access
        }
        
        for node in topology.nodes:
            G.add_node(node.hostname)
            pos[node.hostname] = node.position
            node_colors.append(color_map.get(node.device_type, '#CCCCCC'))
            node_sizes.append(size_map.get(node.tier, 1500))
        
        # Add edges
        for link in topology.links:
            G.add_edge(link.source, link.target)
        
        # Draw the graph
        nx.draw_networkx_nodes(G, pos, node_color=node_colors, 
                              node_size=node_sizes, alpha=0.8, ax=ax)
        nx.draw_networkx_labels(G, pos, font_size=10, font_weight='bold', ax=ax)
        nx.draw_networkx_edges(G, pos, alpha=0.5, width=2, ax=ax)
        
        # Create legend
        legend_elements = [
            mpatches.Patch(color='#FF6B6B', label='Router'),
            mpatches.Patch(color='#4ECDC4', label='L3 Switch'),
            mpatches.Patch(color='#45B7D1', label='L2 Switch'),
            mpatches.Patch(color='#96CEB4', label='Switch')
        ]
        ax.legend(handles=legend_elements, loc='upper right')
        
        # Add tier labels
        ax.text(-5, 2.0, 'Core Layer', fontsize=12, fontweight='bold', rotation=90, ha='center')
        ax.text(-5, 1.0, 'Distribution Layer', fontsize=12, fontweight='bold', rotation=90, ha='center')
        ax.text(-5, 0.0, 'Access Layer', fontsize=12, fontweight='bold', rotation=90, ha='center')
        
        ax.set_title('Network Topology - Hierarchical View', fontsize=16, fontweight='bold', pad=20)
        ax.axis('off')
        
        # Adjust layout
        plt.tight_layout()
        
        if output_file:
            plt.savefig(output_file, dpi=300, bbox_inches='tight')
            self.logger.info(f"Topology visualization saved to {output_file}")
        
        return fig
    
    def save_topology(self, topology: NetworkTopology, output_file: Path, format_type: str = 'json'):
        """Save topology to file"""
        topology_data = asdict(topology)
        
        output_file = Path(output_file)
        
        if format_type == 'json':
            with open(output_file, 'w') as f:
                json.dump(topology_data, f, indent=2, default=str)
        elif format_type == 'yaml':
            with open(output_file, 'w') as f:
                yaml.dump(topology_data, f, default_flow_style=False)
        elif format_type == 'text':
            with open(output_file, 'w') as f:
                f.write("NETWORK TOPOLOGY REPORT\n")
                f.write("=" * 50 + "\n\n")
                
                f.write("NODES:\n")
                f.write("-" * 20 + "\n")
                for node in topology.nodes:
                    f.write(f"  {node.hostname} ({node.device_type}) - Tier {node.tier}\n")
                    f.write(f"    Interfaces: {len(node.interfaces)}\n")
                    f.write(f"    Position: {node.position}\n\n")
                
                f.write("LINKS:\n")
                f.write("-" * 20 + "\n")
                for link in topology.links:
                    f.write(f"  {link.source} <--> {link.target}\n")
                    f.write(f"    Subnet: {link.subnet}\n")
                    f.write(f"    Bandwidth: {link.bandwidth} kbps\n")
                    f.write(f"    MTU: {link.mtu}\n\n")
                
                f.write("SUBNETS:\n")
                f.write("-" * 20 + "\n")
                for subnet, devices in topology.subnets.items():
                    f.write(f"  {subnet}: {', '.join(devices)}\n")
                
                f.write("\nROUTING DOMAINS:\n")
                f.write("-" * 20 + "\n")
                for domain, devices in topology.routing_domains.items():
                    f.write(f"  {domain}: {', '.join(devices)}\n")
        
        self.logger.info(f"Topology saved to {output_file}")
    
    def get_topology_statistics(self, topology: NetworkTopology) -> Dict[str, Any]:
        """Get topology statistics"""
        stats = {
            'total_nodes': len(topology.nodes),
            'total_links': len(topology.links),
            'total_subnets': len(topology.subnets),
            'device_types': {},
            'tier_distribution': {},
            'routing_domains': len(topology.routing_domains)
        }
        
        # Count device types
        for node in topology.nodes:
            device_type = node.device_type
            stats['device_types'][device_type] = stats['device_types'].get(device_type, 0) + 1
        
        # Count tier distribution
        for node in topology.nodes:
            tier = node.tier
            tier_name = {0: 'Core', 1: 'Distribution', 2: 'Access'}.get(tier, f'Tier_{tier}')
            stats['tier_distribution'][tier_name] = stats['tier_distribution'].get(tier_name, 0) + 1
        
        return stats