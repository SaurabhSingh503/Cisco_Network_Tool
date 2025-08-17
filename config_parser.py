"""
Configuration Parser Module

This module handles parsing of Cisco router configuration files including:
- IOS configuration parsing
- Interface configuration extraction
- VLAN configuration parsing
- Routing protocol detection
- IP address and subnet extraction

Based on the Cisco VIP 2025 Problem Statement requirements.
"""

import re
import os
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from collections import defaultdict
import ipaddress

logger = logging.getLogger(__name__)

@dataclass
class Interface:
    """Network interface configuration"""
    name: str
    ip_address: Optional[str] = None
    subnet_mask: Optional[str] = None
    subnet: Optional[str] = None
    description: Optional[str] = None
    vlan: Optional[int] = None
    shutdown: bool = False
    mtu: int = 1500
    bandwidth: Optional[int] = None
    interface_type: str = "unknown"  # ethernet, serial, loopback, etc.

@dataclass
class VLANConfig:
    """VLAN configuration"""
    vlan_id: int
    name: Optional[str] = None
    interfaces: List[str] = field(default_factory=list)
    gateway: Optional[str] = None

@dataclass
class RoutingProtocol:
    """Routing protocol configuration"""
    protocol: str  # ospf, bgp, static, etc.
    process_id: Optional[str] = None
    networks: List[str] = field(default_factory=list)
    neighbors: List[str] = field(default_factory=list)
    router_id: Optional[str] = None

@dataclass
class RouterConfig:
    """Complete router configuration"""
    hostname: str
    interfaces: List[Interface] = field(default_factory=list)
    vlans: List[VLANConfig] = field(default_factory=list)
    routing_protocols: List[RoutingProtocol] = field(default_factory=list)
    static_routes: List[str] = field(default_factory=list)
    config_file_path: str = ""
    raw_config: str = ""

class ConfigParser:
    """Cisco configuration file parser"""
    
    def __init__(self, config_directory: Path):
        """
        Initialize the configuration parser
        
        Args:
            config_directory: Directory containing configuration files
        """
        self.config_directory = Path(config_directory)
        self.logger = logging.getLogger(__name__)
        
    def parse_all_configs(self) -> Dict[str, RouterConfig]:
        """
        Parse all configuration files in the directory
        
        Returns:
            Dictionary mapping hostname to RouterConfig
        """
        configs = {}
        
        # Find all config files
        config_files = []
        for pattern in ['*.dump', '*.conf', '*.cfg', '*.txt']:
            config_files.extend(self.config_directory.glob(pattern))
            config_files.extend(self.config_directory.rglob(pattern))
        
        if not config_files:
            self.logger.warning(f"No configuration files found in {self.config_directory}")
            return configs
        
        for config_file in config_files:
            try:
                self.logger.info(f"Parsing configuration file: {config_file}")
                router_config = self.parse_config_file(config_file)
                if router_config:
                    configs[router_config.hostname] = router_config
                    
            except Exception as e:
                self.logger.error(f"Error parsing {config_file}: {str(e)}")
                continue
                
        return configs
    
    def parse_config_file(self, config_file_path: Path) -> Optional[RouterConfig]:
        """
        Parse a single configuration file
        
        Args:
            config_file_path: Path to configuration file
            
        Returns:
            RouterConfig object or None if parsing fails
        """
        try:
            with open(config_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                raw_config = f.read()
        except Exception as e:
            self.logger.error(f"Cannot read config file {config_file_path}: {e}")
            return None
        
        # Extract hostname
        hostname = self._extract_hostname(raw_config)
        if not hostname:
            hostname = config_file_path.stem
        
        # Initialize router config
        router_config = RouterConfig(
            hostname=hostname,
            config_file_path=str(config_file_path),
            raw_config=raw_config
        )
        
        # Parse different sections
        router_config.interfaces = self._parse_interfaces(raw_config)
        router_config.vlans = self._parse_vlans(raw_config)
        router_config.routing_protocols = self._parse_routing_protocols(raw_config)
        router_config.static_routes = self._parse_static_routes(raw_config)
        
        return router_config
    
    def _extract_hostname(self, config_text: str) -> Optional[str]:
        """Extract hostname from configuration"""
        hostname_patterns = [
            r'hostname\s+(\S+)',
            r'set system host-name\s+(\S+)',  # Juniper
            r'System\.Hostname\s*=\s*(\S+)'   # Alternative format
        ]
        
        for pattern in hostname_patterns:
            match = re.search(pattern, config_text, re.IGNORECASE | re.MULTILINE)
            if match:
                return match.group(1)
        
        return None
    
    def _parse_interfaces(self, config_text: str) -> List[Interface]:
        """Parse interface configurations"""
        interfaces = []
        
        # Find all interface blocks
        interface_pattern = r'interface\s+(\S+)(.*?)(?=^interface\s+|\Z)'
        interface_matches = re.finditer(interface_pattern, config_text, 
                                      re.MULTILINE | re.DOTALL | re.IGNORECASE)
        
        for match in interface_matches:
            interface_name = match.group(1)
            interface_config = match.group(2)
            
            # Parse interface details
            interface = self._parse_single_interface(interface_name, interface_config)
            if interface:
                interfaces.append(interface)
        
        return interfaces
    
    def _parse_single_interface(self, name: str, config: str) -> Optional[Interface]:
        """Parse a single interface configuration"""
        interface = Interface(name=name)
        
        # Determine interface type
        interface.interface_type = self._determine_interface_type(name)
        
        # Parse IP address
        ip_pattern = r'ip address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)'
        ip_match = re.search(ip_pattern, config, re.IGNORECASE)
        if ip_match:
            interface.ip_address = ip_match.group(1)
            interface.subnet_mask = ip_match.group(2)
            
            # Calculate subnet
            try:
                network = ipaddress.IPv4Network(f"{interface.ip_address}/{interface.subnet_mask}", strict=False)
                interface.subnet = str(network)
            except Exception:
                pass
        
        # Parse description
        desc_match = re.search(r'description\s+(.+)', config, re.IGNORECASE)
        if desc_match:
            interface.description = desc_match.group(1).strip()
        
        # Parse VLAN
        vlan_patterns = [
            r'switchport access vlan\s+(\d+)',
            r'encapsulation dot1Q\s+(\d+)',
            r'vlan\s+(\d+)'
        ]
        
        for pattern in vlan_patterns:
            vlan_match = re.search(pattern, config, re.IGNORECASE)
            if vlan_match:
                interface.vlan = int(vlan_match.group(1))
                break
        
        # Check if shutdown
        if re.search(r'^\s*shutdown\s*$', config, re.MULTILINE | re.IGNORECASE):
            interface.shutdown = True
        
        # Parse MTU
        mtu_match = re.search(r'mtu\s+(\d+)', config, re.IGNORECASE)
        if mtu_match:
            interface.mtu = int(mtu_match.group(1))
        
        # Parse bandwidth
        bw_match = re.search(r'bandwidth\s+(\d+)', config, re.IGNORECASE)
        if bw_match:
            interface.bandwidth = int(bw_match.group(1))
        
        return interface
    
    def _determine_interface_type(self, name: str) -> str:
        """Determine interface type from name"""
        name_lower = name.lower()
        
        if 'gigabitethernet' in name_lower or 'gi' in name_lower:
            return 'gigabit_ethernet'
        elif 'fastethernet' in name_lower or 'fa' in name_lower:
            return 'fast_ethernet'
        elif 'ethernet' in name_lower or 'eth' in name_lower:
            return 'ethernet'
        elif 'serial' in name_lower or 'se' in name_lower:
            return 'serial'
        elif 'loopback' in name_lower or 'lo' in name_lower:
            return 'loopback'
        elif 'vlan' in name_lower:
            return 'vlan'
        elif 'tunnel' in name_lower:
            return 'tunnel'
        else:
            return 'unknown'
    
    def _parse_vlans(self, config_text: str) -> List[VLANConfig]:
        """Parse VLAN configurations"""
        vlans = []
        
        # Find VLAN definitions
        vlan_pattern = r'vlan\s+(\d+)(.*?)(?=^vlan\s+|\Z)'
        vlan_matches = re.finditer(vlan_pattern, config_text, 
                                 re.MULTILINE | re.DOTALL | re.IGNORECASE)
        
        for match in vlan_matches:
            vlan_id = int(match.group(1))
            vlan_config = match.group(2)
            
            vlan = VLANConfig(vlan_id=vlan_id)
            
            # Parse VLAN name
            name_match = re.search(r'name\s+(.+)', vlan_config, re.IGNORECASE)
            if name_match:
                vlan.name = name_match.group(1).strip()
            
            vlans.append(vlan)
        
        return vlans
    
    def _parse_routing_protocols(self, config_text: str) -> List[RoutingProtocol]:
        """Parse routing protocol configurations"""
        protocols = []
        
        # Parse OSPF
        ospf_pattern = r'router ospf\s+(\d+)(.*?)(?=^router\s+|\Z)'
        ospf_matches = re.finditer(ospf_pattern, config_text, 
                                 re.MULTILINE | re.DOTALL | re.IGNORECASE)
        
        for match in ospf_matches:
            process_id = match.group(1)
            ospf_config = match.group(2)
            
            protocol = RoutingProtocol(
                protocol='ospf',
                process_id=process_id
            )
            
            # Parse networks
            network_pattern = r'network\s+(\S+)\s+(\S+)\s+area\s+(\S+)'
            for net_match in re.finditer(network_pattern, ospf_config, re.IGNORECASE):
                network = f"{net_match.group(1)} {net_match.group(2)} area {net_match.group(3)}"
                protocol.networks.append(network)
            
            # Parse router ID
            router_id_match = re.search(r'router-id\s+(\S+)', ospf_config, re.IGNORECASE)
            if router_id_match:
                protocol.router_id = router_id_match.group(1)
            
            protocols.append(protocol)
        
        # Parse BGP
        bgp_pattern = r'router bgp\s+(\d+)(.*?)(?=^router\s+|\Z)'
        bgp_matches = re.finditer(bgp_pattern, config_text, 
                                re.MULTILINE | re.DOTALL | re.IGNORECASE)
        
        for match in bgp_matches:
            as_number = match.group(1)
            bgp_config = match.group(2)
            
            protocol = RoutingProtocol(
                protocol='bgp',
                process_id=as_number
            )
            
            # Parse neighbors
            neighbor_pattern = r'neighbor\s+(\S+)'
            for neighbor_match in re.finditer(neighbor_pattern, bgp_config, re.IGNORECASE):
                protocol.neighbors.append(neighbor_match.group(1))
            
            # Parse BGP router ID
            router_id_match = re.search(r'bgp router-id\s+(\S+)', bgp_config, re.IGNORECASE)
            if router_id_match:
                protocol.router_id = router_id_match.group(1)
            
            protocols.append(protocol)
        
        return protocols
    
    def _parse_static_routes(self, config_text: str) -> List[str]:
        """Parse static route configurations"""
        static_routes = []
        
        # Find static routes
        route_pattern = r'ip route\s+([^\r\n]+)'
        route_matches = re.finditer(route_pattern, config_text, re.IGNORECASE)
        
        for match in route_matches:
            route = match.group(1).strip()
            static_routes.append(route)
        
        return static_routes
    
    def get_network_connections(self, configs: Dict[str, RouterConfig]) -> List[Tuple[str, str, Dict]]:
        """
        Analyze configurations to determine network connections between devices
        
        Returns:
            List of tuples (device1, device2, connection_info)
        """
        connections = []
        device_subnets = defaultdict(list)
        
        # Map devices to their subnets
        for hostname, config in configs.items():
            for interface in config.interfaces:
                if interface.subnet and not interface.shutdown:
                    device_subnets[interface.subnet].append({
                        'hostname': hostname,
                        'interface': interface.name,
                        'ip': interface.ip_address
                    })
        
        # Find connections (devices on same subnet)
        for subnet, devices in device_subnets.items():
            if len(devices) >= 2:
                # Create connections between all devices on same subnet
                for i in range(len(devices)):
                    for j in range(i + 1, len(devices)):
                        device1 = devices[i]
                        device2 = devices[j]
                        
                        connection_info = {
                            'subnet': subnet,
                            'device1_interface': device1['interface'],
                            'device2_interface': device2['interface'],
                            'device1_ip': device1['ip'],
                            'device2_ip': device2['ip']
                        }
                        
                        connections.append((
                            device1['hostname'],
                            device2['hostname'],
                            connection_info
                        ))
        
        return connections
