"""
Network Validator Module

This module validates network configurations and identifies potential issues
including duplicate IPs, VLAN conflicts, MTU mismatches, network loops,
and missing components.

Based on the Cisco VIP 2025 Problem Statement requirements.
"""

import logging
from typing import Dict, List, Set, Tuple, Any, Optional
from dataclasses import dataclass, field
from collections import defaultdict
import ipaddress
import re
import json
import yaml

from config_parser import RouterConfig, Interface, VLANConfig

logger = logging.getLogger(__name__)

@dataclass
class ValidationIssue:
    """Represents a network configuration issue"""
    severity: str  # critical, warning, info
    category: str  # ip_conflict, vlan_issue, mtu_mismatch, etc.
    description: str
    affected_devices: List[str] = field(default_factory=list)
    affected_interfaces: List[str] = field(default_factory=list)
    recommendation: str = ""

@dataclass
class ValidationResults:
    """Complete validation results"""
    total_issues: int = 0
    critical_issues: int = 0
    warning_issues: int = 0
    info_issues: int = 0
    issues: List[ValidationIssue] = field(default_factory=list)
    missing_components: List[str] = field(default_factory=list)
    optimization_recommendations: List[str] = field(default_factory=list)

class NetworkValidator:
    """Network configuration validator"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def validate_all(self, configs: Dict[str, RouterConfig]) -> ValidationResults:
        """
        Perform comprehensive validation of all network configurations
        
        Args:
            configs: Dictionary of router configurations
            
        Returns:
            ValidationResults object
        """
        results = ValidationResults()
        
        self.logger.info("Starting comprehensive network validation...")
        
        # Validate IP addressing
        self.logger.info("Validating IP addressing...")
        ip_issues = self._validate_ip_addressing(configs)
        results.issues.extend(ip_issues)
        
        # Validate VLAN configurations
        self.logger.info("Validating VLAN configurations...")
        vlan_issues = self._validate_vlans(configs)
        results.issues.extend(vlan_issues)
        
        # Validate MTU settings
        self.logger.info("Validating MTU settings...")
        mtu_issues = self._validate_mtu(configs)
        results.issues.extend(mtu_issues)
        
        # Check for network loops
        self.logger.info("Checking for potential network loops...")
        loop_issues = self._check_network_loops(configs)
        results.issues.extend(loop_issues)
        
        # Validate gateway configurations
        self.logger.info("Validating gateway configurations...")
        gateway_issues = self._validate_gateways(configs)
        results.issues.extend(gateway_issues)
        
        # Check for missing components
        self.logger.info("Checking for missing network components...")
        results.missing_components = self._check_missing_components(configs)
        
        # Generate optimization recommendations
        self.logger.info("Generating optimization recommendations...")
        results.optimization_recommendations = self._generate_optimization_recommendations(configs)
        
        # Validate routing protocols
        self.logger.info("Validating routing protocols...")
        routing_issues = self._validate_routing_protocols(configs)
        results.issues.extend(routing_issues)
        
        # Calculate summary statistics
        results.total_issues = len(results.issues)
        results.critical_issues = sum(1 for issue in results.issues if issue.severity == 'critical')
        results.warning_issues = sum(1 for issue in results.issues if issue.severity == 'warning')
        results.info_issues = sum(1 for issue in results.issues if issue.severity == 'info')
        
        self.logger.info(f"Validation completed. Found {results.total_issues} issues "
                        f"({results.critical_issues} critical, {results.warning_issues} warnings)")
        
        return results
    
    def _validate_ip_addressing(self, configs: Dict[str, RouterConfig]) -> List[ValidationIssue]:
        """Validate IP addressing for conflicts and issues"""
        issues = []
        ip_assignments = defaultdict(list)
        
        # Collect all IP assignments
        for hostname, config in configs.items():
            for interface in config.interfaces:
                if interface.ip_address and not interface.shutdown:
                    ip_assignments[interface.ip_address].append({
                        'hostname': hostname,
                        'interface': interface.name,
                        'subnet': interface.subnet
                    })
        
        # Check for duplicate IP addresses
        for ip, assignments in ip_assignments.items():
            if len(assignments) > 1:
                issue = ValidationIssue(
                    severity='critical',
                    category='ip_conflict',
                    description=f"Duplicate IP address {ip} found on multiple devices",
                    affected_devices=[a['hostname'] for a in assignments],
                    affected_interfaces=[f"{a['hostname']}:{a['interface']}" for a in assignments],
                    recommendation=f"Assign unique IP addresses to each interface. "
                                 f"Consider using different subnets or IP ranges."
                )
                issues.append(issue)
        
        # Check for IP addresses outside their subnet
        for hostname, config in configs.items():
            for interface in config.interfaces:
                if interface.ip_address and interface.subnet_mask and not interface.shutdown:
                    try:
                        ip = ipaddress.IPv4Address(interface.ip_address)
                        network = ipaddress.IPv4Network(f"{interface.ip_address}/{interface.subnet_mask}", 
                                                       strict=False)
                        
                        if ip not in network:
                            issue = ValidationIssue(
                                severity='critical',
                                category='ip_addressing',
                                description=f"IP address {interface.ip_address} is outside subnet "
                                          f"{network} on {hostname}:{interface.name}",
                                affected_devices=[hostname],
                                affected_interfaces=[f"{hostname}:{interface.name}"],
                                recommendation="Correct the IP address or subnet mask configuration."
                            )
                            issues.append(issue)
                    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
                        issue = ValidationIssue(
                            severity='warning',
                            category='ip_addressing',
                            description=f"Invalid IP address or subnet mask on {hostname}:"
                                      f"{interface.name} ({interface.ip_address}/{interface.subnet_mask})",
                            affected_devices=[hostname],
                            affected_interfaces=[f"{hostname}:{interface.name}"],
                            recommendation="Check IP address and subnet mask syntax."
                        )
                        issues.append(issue)
        
        return issues
    
    def _validate_vlans(self, configs: Dict[str, RouterConfig]) -> List[ValidationIssue]:
        """Validate VLAN configurations"""
        issues = []
        vlan_assignments = defaultdict(set)
        
        # Collect VLAN assignments
        for hostname, config in configs.items():
            # Check VLAN definitions
            for vlan in config.vlans:
                vlan_assignments[vlan.vlan_id].add(hostname)
            
            # Check interface VLAN assignments
            for interface in config.interfaces:
                if interface.vlan:
                    vlan_assignments[interface.vlan].add(hostname)
        
        # Check for VLAN consistency
        for hostname, config in configs.items():
            interface_vlans = set()
            defined_vlans = set()
            
            # Get defined VLANs
            for vlan in config.vlans:
                defined_vlans.add(vlan.vlan_id)
            
            # Get interface VLANs
            for interface in config.interfaces:
                if interface.vlan:
                    interface_vlans.add(interface.vlan)
            
            # Check for VLANs used but not defined
            undefined_vlans = interface_vlans - defined_vlans
            for vlan_id in undefined_vlans:
                issue = ValidationIssue(
                    severity='warning',
                    category='vlan_issue',
                    description=f"VLAN {vlan_id} is used on interfaces but not defined on {hostname}",
                    affected_devices=[hostname],
                    recommendation=f"Define VLAN {vlan_id} in the configuration or remove VLAN assignment from interfaces."
                )
                issues.append(issue)
            
            # Check for defined but unused VLANs
            unused_vlans = defined_vlans - interface_vlans
            for vlan_id in unused_vlans:
                issue = ValidationIssue(
                    severity='info',
                    category='vlan_issue',
                    description=f"VLAN {vlan_id} is defined but not used on any interface on {hostname}",
                    affected_devices=[hostname],
                    recommendation=f"Consider removing unused VLAN {vlan_id} or assign it to interfaces."
                )
                issues.append(issue)
        
        # Check for VLAN ID conflicts (same VLAN ID with different names)
        vlan_names = defaultdict(set)
        for hostname, config in configs.items():
            for vlan in config.vlans:
                if vlan.name:
                    vlan_names[vlan.vlan_id].add(vlan.name)
        
        for vlan_id, names in vlan_names.items():
            if len(names) > 1:
                issue = ValidationIssue(
                    severity='warning',
                    category='vlan_issue',
                    description=f"VLAN {vlan_id} has inconsistent names: {', '.join(names)}",
                    affected_devices=list(vlan_assignments[vlan_id]),
                    recommendation=f"Standardize VLAN {vlan_id} name across all devices."
                )
                issues.append(issue)
        
        return issues
    
    def _validate_mtu(self, configs: Dict[str, RouterConfig]) -> List[ValidationIssue]:
        """Validate MTU settings for mismatches"""
        issues = []
        subnet_mtus = defaultdict(list)
        
        # Collect MTU settings per subnet
        for hostname, config in configs.items():
            for interface in config.interfaces:
                if interface.subnet and not interface.shutdown:
                    subnet_mtus[interface.subnet].append({
                        'hostname': hostname,
                        'interface': interface.name,
                        'mtu': interface.mtu
                    })
        
        # Check for MTU mismatches within subnets
        for subnet, interfaces in subnet_mtus.items():
            if len(interfaces) > 1:
                mtus = set(intf['mtu'] for intf in interfaces)
                if len(mtus) > 1:
                    mtu_list = sorted(mtus)
                    issue = ValidationIssue(
                        severity='critical',
                        category='mtu_mismatch',
                        description=f"MTU mismatch in subnet {subnet}: {mtu_list}",
                        affected_devices=[intf['hostname'] for intf in interfaces],
                        affected_interfaces=[f"{intf['hostname']}:{intf['interface']}" 
                                           for intf in interfaces],
                        recommendation=f"Set consistent MTU across all interfaces in subnet {subnet}. "
                                     f"Consider using MTU {max(mtu_list)} for optimal performance."
                    )
                    issues.append(issue)
        
        return issues
    
    def _check_network_loops(self, configs: Dict[str, RouterConfig]) -> List[ValidationIssue]:
        """Check for potential network loops"""
        issues = []
        
        # Build connectivity graph
        connections = defaultdict(set)
        for hostname, config in configs.items():
            for interface in config.interfaces:
                if interface.subnet and not interface.shutdown:
                    # Find other devices in same subnet
                    for other_hostname, other_config in configs.items():
                        if other_hostname != hostname:
                            for other_interface in other_config.interfaces:
                                if (other_interface.subnet == interface.subnet and 
                                    not other_interface.shutdown):
                                    connections[hostname].add(other_hostname)
        
        # Simple loop detection (triangles and squares)
        devices = list(configs.keys())
        for i, device1 in enumerate(devices):
            for j, device2 in enumerate(devices[i+1:], i+1):
                for k, device3 in enumerate(devices[j+1:], j+1):
                    # Check for triangle (3-node loop)
                    if (device2 in connections[device1] and 
                        device3 in connections[device2] and 
                        device1 in connections[device3]):
                        
                        issue = ValidationIssue(
                            severity='warning',
                            category='potential_loop',
                            description=f"Potential network loop detected: {device1} -> {device2} -> {device3} -> {device1}",
                            affected_devices=[device1, device2, device3],
                            recommendation="Ensure Spanning Tree Protocol (STP) is properly configured "
                                         "or implement redundancy with proper loop prevention."
                        )
                        issues.append(issue)
        
        return issues
    
    def _validate_gateways(self, configs: Dict[str, RouterConfig]) -> List[ValidationIssue]:
        """Validate gateway configurations"""
        issues = []
        
        for hostname, config in configs.items():
            # Check for default routes
            default_routes = [route for route in config.static_routes 
                            if route.startswith('0.0.0.0') or route.startswith('default')]
            
            if len(default_routes) > 1:
                issue = ValidationIssue(
                    severity='warning',
                    category='gateway_issue',
                    description=f"Multiple default routes configured on {hostname}",
                    affected_devices=[hostname],
                    recommendation="Consider using a single default route or implement proper routing protocol."
                )
                issues.append(issue)
            
            # Check for gateway reachability
            for interface in config.interfaces:
                if interface.ip_address and interface.subnet:
                    # Check if there's a potential gateway in the same subnet
                    gateway_found = False
                    try:
                        network = ipaddress.IPv4Network(interface.subnet)
                        # Common gateway IPs (.1, .254)
                        potential_gateways = [
                            str(network.network_address + 1),
                            str(network.broadcast_address - 1)
                        ]
                        
                        # Check if any other device could be a gateway
                        for other_hostname, other_config in configs.items():
                            if other_hostname != hostname:
                                for other_interface in other_config.interfaces:
                                    if (other_interface.subnet == interface.subnet and
                                        other_interface.ip_address in potential_gateways):
                                        gateway_found = True
                                        break
                        
                        if not gateway_found and network.num_addresses > 2:
                            issue = ValidationIssue(
                                severity='info',
                                category='gateway_issue',
                                description=f"No obvious gateway found for subnet {interface.subnet} "
                                          f"on {hostname}:{interface.name}",
                                affected_devices=[hostname],
                                affected_interfaces=[f"{hostname}:{interface.name}"],
                                recommendation="Verify gateway configuration and routing setup."
                            )
                            issues.append(issue)
                            
                    except Exception:
                        pass
        
        return issues
    
    def _check_missing_components(self, configs: Dict[str, RouterConfig]) -> List[str]:
        """Check for missing network components"""
        missing = []
        
        # Check for referenced but missing devices
        referenced_devices = set()
        configured_devices = set(configs.keys())
        
        # Extract device references from routing configurations
        for hostname, config in configs.items():
            for protocol in config.routing_protocols:
                for neighbor in protocol.neighbors:
                    # Try to extract hostname from neighbor IP
                    # This is a simplified approach
                    if re.match(r'\d+\.\d+\.\d+\.\d+', neighbor):
                        # Look for device with this IP
                        for check_hostname, check_config in configs.items():
                            for interface in check_config.interfaces:
                                if interface.ip_address == neighbor:
                                    referenced_devices.add(check_hostname)
        
        # Check for incomplete subnets (only one device)
        subnet_devices = defaultdict(list)
        for hostname, config in configs.items():
            for interface in config.interfaces:
                if interface.subnet and not interface.shutdown:
                    subnet_devices[interface.subnet].append(hostname)
        
        for subnet, devices in subnet_devices.items():
            if len(devices) == 1:
                missing.append(f"Subnet {subnet} has only one device ({devices[0]}) - missing peer device")
        
        return missing
    
    def _validate_routing_protocols(self, configs: Dict[str, RouterConfig]) -> List[ValidationIssue]:
        """Validate routing protocol configurations"""
        issues = []
        
        # Check OSPF configurations
        ospf_areas = defaultdict(list)
        for hostname, config in configs.items():
            for protocol in config.routing_protocols:
                if protocol.protocol == 'ospf':
                    # Extract area information
                    for network in protocol.networks:
                        if 'area' in network:
                            area = network.split('area')[-1].strip()
                            ospf_areas[area].append(hostname)
                    
                    # Check for missing router ID
                    if not protocol.router_id:
                        issue = ValidationIssue(
                            severity='warning',
                            category='routing_protocol',
                            description=f"OSPF router ID not configured on {hostname}",
                            affected_devices=[hostname],
                            recommendation="Configure OSPF router ID for stable neighbor relationships."
                        )
                        issues.append(issue)
        
        # Check BGP configurations
        bgp_as = defaultdict(list)
        for hostname, config in configs.items():
            for protocol in config.routing_protocols:
                if protocol.protocol == 'bgp':
                    bgp_as[protocol.process_id].append(hostname)
                    
                    # Check for missing router ID
                    if not protocol.router_id:
                        issue = ValidationIssue(
                            severity='warning',
                            category='routing_protocol',
                            description=f"BGP router ID not configured on {hostname}",
                            affected_devices=[hostname],
                            recommendation="Configure BGP router ID for stable neighbor relationships."
                        )
                        issues.append(issue)
        
        # Suggest protocol optimization
        device_count = len(configs)
        if device_count > 10:
            # Check if using OSPF where BGP might be better
            for hostname, config in configs.items():
                has_ospf = any(p.protocol == 'ospf' for p in config.routing_protocols)
                has_bgp = any(p.protocol == 'bgp' for p in config.routing_protocols)
                
                if has_ospf and not has_bgp and device_count > 20:
                    issue = ValidationIssue(
                        severity='info',
                        category='routing_optimization',
                        description=f"Consider BGP instead of OSPF for large network on {hostname}",
                        affected_devices=[hostname],
                        recommendation="BGP provides better scalability for large networks with multiple autonomous systems."
                    )
                    issues.append(issue)
        
        return issues
    
    def _generate_optimization_recommendations(self, configs: Dict[str, RouterConfig]) -> List[str]:
        """Generate network optimization recommendations"""
        recommendations = []
        
        # Node aggregation opportunities
        device_connections = defaultdict(set)
        for hostname, config in configs.items():
            for interface in config.interfaces:
                if interface.subnet and not interface.shutdown:
                    # Count connections per device
                    for other_hostname, other_config in configs.items():
                        if other_hostname != hostname:
                            for other_interface in other_config.interfaces:
                                if (other_interface.subnet == interface.subnet and 
                                    not other_interface.shutdown):
                                    device_connections[hostname].add(other_hostname)
        
        # Find devices with few connections that could be aggregated
        low_connection_devices = [device for device, connections in device_connections.items() 
                                if len(connections) <= 2]
        
        if len(low_connection_devices) > 2:
            recommendations.append(
                f"Consider aggregating devices with few connections: {', '.join(low_connection_devices[:5])}. "
                f"This could reduce network complexity and management overhead."
            )
        
        # VLAN optimization
        total_vlans = sum(len(config.vlans) for config in configs.values())
        if total_vlans > len(configs) * 10:
            recommendations.append(
                f"High VLAN count detected ({total_vlans} VLANs across {len(configs)} devices). "
                f"Consider VLAN consolidation to reduce complexity."
            )
        
        # MTU optimization
        all_mtus = set()
        for config in configs.values():
            for interface in config.interfaces:
                if not interface.shutdown:
                    all_mtus.add(interface.mtu)
        
        if len(all_mtus) > 3:
            recommendations.append(
                f"Multiple MTU values detected: {sorted(all_mtus)}. "
                f"Consider standardizing MTU across the network for optimal performance."
            )
        
        # Routing protocol recommendations
        ospf_count = sum(1 for config in configs.values() 
                        for protocol in config.routing_protocols 
                        if protocol.protocol == 'ospf')
        bgp_count = sum(1 for config in configs.values() 
                       for protocol in config.routing_protocols 
                       if protocol.protocol == 'bgp')
        
        if len(configs) > 15 and ospf_count > bgp_count * 2:
            recommendations.append(
                "For large networks, consider implementing BGP for better scalability and "
                "policy control, especially for inter-domain routing."
            )
        
        return recommendations
    
    def save_results(self, results: ValidationResults, output_file: Path, format_type: str = 'json'):
        """Save validation results to file"""
        if format_type == 'json':
            # Convert dataclasses to dict for JSON serialization
            results_dict = {
                'summary': {
                    'total_issues': results.total_issues,
                    'critical_issues': results.critical_issues,
                    'warning_issues': results.warning_issues,
                    'info_issues': results.info_issues
                },
                'issues': [
                    {
                        'severity': issue.severity,
                        'category': issue.category,
                        'description': issue.description,
                        'affected_devices': issue.affected_devices,
                        'affected_interfaces': issue.affected_interfaces,
                        'recommendation': issue.recommendation
                    }
                    for issue in results.issues
                ],
                'missing_components': results.missing_components,
                'optimization_recommendations': results.optimization_recommendations
            }
            
            with open(output_file, 'w') as f:
                json.dump(results_dict, f, indent=2)
        
        elif format_type == 'yaml':
            results_dict = {
                'summary': {
                    'total_issues': results.total_issues,
                    'critical_issues': results.critical_issues,
                    'warning_issues': results.warning_issues,
                    'info_issues': results.info_issues
                },
                'issues': [
                    {
                        'severity': issue.severity,
                        'category': issue.category,
                        'description': issue.description,
                        'affected_devices': issue.affected_devices,
                        'affected_interfaces': issue.affected_interfaces,
                        'recommendation': issue.recommendation
                    }
                    for issue in results.issues
                ],
                'missing_components': results.missing_components,
                'optimization_recommendations': results.optimization_recommendations
            }
            
            with open(output_file, 'w') as f:
                yaml.dump(results_dict, f, default_flow_style=False)
        
        elif format_type == 'text':
            with open(output_file, 'w') as f:
                f.write("NETWORK VALIDATION REPORT\n")
                f.write("=" * 50 + "\n\n")
                
                f.write("SUMMARY:\n")
                f.write("-" * 20 + "\n")
                f.write(f"Total Issues: {results.total_issues}\n")
                f.write(f"Critical Issues: {results.critical_issues}\n")
                f.write(f"Warning Issues: {results.warning_issues}\n")
                f.write(f"Info Issues: {results.info_issues}\n\n")
                
                f.write("ISSUES:\n")
                f.write("-" * 20 + "\n")
                for i, issue in enumerate(results.issues, 1):
                    f.write(f"{i}. [{issue.severity.upper()}] {issue.category}: {issue.description}\n")
                    if issue.affected_devices:
                        f.write(f"   Affected Devices: {', '.join(issue.affected_devices)}\n")
                    if issue.affected_interfaces:
                        f.write(f"   Affected Interfaces: {', '.join(issue.affected_interfaces)}\n")
                    if issue.recommendation:
                        f.write(f"   Recommendation: {issue.recommendation}\n")
                    f.write("\n")
                
                if results.missing_components:
                    f.write("MISSING COMPONENTS:\n")
                    f.write("-" * 20 + "\n")
                    for component in results.missing_components:
                        f.write(f"- {component}\n")
                    f.write("\n")
                
                if results.optimization_recommendations:
                    f.write("OPTIMIZATION RECOMMENDATIONS:\n")
                    f.write("-" * 30 + "\n")
                    for recommendation in results.optimization_recommendations:
                        f.write(f"- {recommendation}\n")
        
        self.logger.info(f"Validation results saved to {output_file}")