"""
Load Balancer Module

This module analyzes network traffic loads and provides load balancing
recommendations based on link capacity and traffic demands.

Based on the Cisco VIP 2025 Problem Statement requirements.
"""

import logging
from typing import Dict, List, Tuple, Any, Optional
from dataclasses import dataclass, field
import json
import yaml
from pathlib import Path
import random
import math

from config_parser import RouterConfig, Interface
from topology_generator import NetworkTopology, NetworkLink

logger = logging.getLogger(__name__)

@dataclass
class TrafficDemand:
    """Represents traffic demand between endpoints"""
    source: str
    destination: str
    bandwidth_requirement: int  # kbps
    traffic_type: str  # web, database, video, etc.
    priority: str  # high, medium, low
    peak_multiplier: float = 2.0  # Peak traffic multiplier

@dataclass
class LinkUtilization:
    """Link utilization information"""
    source: str
    target: str
    interface: str
    total_capacity: int  # kbps
    current_utilization: int  # kbps
    utilization_percentage: float
    peak_utilization: int  # kbps
    is_congested: bool = False
    
@dataclass
class LoadBalancingRecommendation:
    """Load balancing recommendation"""
    recommendation_type: str  # primary_path, secondary_path, capacity_upgrade
    affected_links: List[str] = field(default_factory=list)
    description: str = ""
    priority: str = "medium"  # high, medium, low
    estimated_benefit: str = ""
    implementation_notes: str = ""

@dataclass
class LoadBalancingResults:
    """Complete load balancing analysis results"""
    total_links: int = 0
    congested_links: int = 0
    average_utilization: float = 0.0
    link_utilizations: List[LinkUtilization] = field(default_factory=list)
    traffic_demands: List[TrafficDemand] = field(default_factory=list)
    recommendations: List[LoadBalancingRecommendation] = field(default_factory=list)
    alternative_paths: Dict[str, List[str]] = field(default_factory=dict)

class LoadBalancer:
    """Network load balancing analyzer and recommendation engine"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Default traffic patterns and capacities
        self.default_interface_capacities = {
            'gigabit_ethernet': 1000000,  # 1 Gbps in kbps
            'fast_ethernet': 100000,      # 100 Mbps in kbps
            'ethernet': 10000,            # 10 Mbps in kbps
            'serial': 1544,               # T1 line in kbps
            'unknown': 100000             # Default to 100 Mbps
        }
        
        self.traffic_type_patterns = {
            'web': {'base_bw': 1000, 'peak_mult': 3.0, 'priority': 'medium'},
            'database': {'base_bw': 5000, 'peak_mult': 2.0, 'priority': 'high'},
            'video': {'base_bw': 10000, 'peak_mult': 1.5, 'priority': 'high'},
            'backup': {'base_bw': 50000, 'peak_mult': 1.2, 'priority': 'low'},
            'voice': {'base_bw': 64, 'peak_mult': 1.1, 'priority': 'high'},
            'file_transfer': {'base_bw': 20000, 'peak_mult': 2.5, 'priority': 'low'}
        }
    
    def analyze_and_recommend(self, configs: Dict[str, RouterConfig]) -> LoadBalancingResults:
        """
        Analyze network load and generate recommendations
        
        Args:
            configs: Router configurations
            
        Returns:
            LoadBalancingResults object
        """
        self.logger.info("Starting load balancing analysis...")
        
        results = LoadBalancingResults()
        
        # Generate topology for analysis
        from topology_generator import TopologyGenerator
        topology_generator = TopologyGenerator()
        topology = topology_generator.generate_topology(configs)
        
        # Analyze link capacities and utilization
        self.logger.info("Analyzing link capacities...")
        results.link_utilizations = self._analyze_link_utilization(topology, configs)
        
        # Generate traffic demands
        self.logger.info("Generating traffic demand estimates...")
        results.traffic_demands = self._generate_traffic_demands(topology, configs)
        
        # Calculate traffic loads on links
        self.logger.info("Calculating traffic loads...")
        self._calculate_traffic_loads(results.link_utilizations, results.traffic_demands, topology)
        
        # Find alternative paths
        self.logger.info("Finding alternative paths...")
        results.alternative_paths = self._find_alternative_paths(topology)
        
        # Generate load balancing recommendations
        self.logger.info("Generating load balancing recommendations...")
        results.recommendations = self._generate_recommendations(results.link_utilizations, 
                                                               results.alternative_paths, topology)
        
        # Calculate summary statistics
        self._calculate_summary_stats(results)
        
        self.logger.info(f"Load balancing analysis completed. Found {len(results.recommendations)} recommendations.")
        
        return results
    
    def _analyze_link_utilization(self, topology: NetworkTopology, 
                                 configs: Dict[str, RouterConfig]) -> List[LinkUtilization]:
        """Analyze current link utilization"""
        utilizations = []
        
        for link in topology.links:
            # Determine link capacity
            source_capacity = self._get_interface_capacity(link.source, link.source_interface, configs)
            target_capacity = self._get_interface_capacity(link.target, link.target_interface, configs)
            
            # Use minimum capacity of both ends
            total_capacity = min(source_capacity, target_capacity)
            
            # Simulate current utilization (in real implementation, this would come from SNMP)
            current_util = self._simulate_current_utilization(total_capacity)
            utilization_pct = (current_util / total_capacity) * 100
            peak_util = current_util * 1.8  # Assume peak is 80% higher
            
            utilization = LinkUtilization(
                source=link.source,
                target=link.target,
                interface=link.source_interface,
                total_capacity=total_capacity,
                current_utilization=current_util,
                utilization_percentage=utilization_pct,
                peak_utilization=min(peak_util, total_capacity),
                is_congested=utilization_pct > 80.0
            )
            
            utilizations.append(utilization)
        
        return utilizations
    
    def _get_interface_capacity(self, hostname: str, interface_name: str, 
                               configs: Dict[str, RouterConfig]) -> int:
        """Get interface capacity in kbps"""
        if hostname in configs:
            config = configs[hostname]
            for interface in config.interfaces:
                if interface.name == interface_name:
                    if interface.bandwidth:
                        return interface.bandwidth
                    else:
                        # Use default based on interface type
                        return self.default_interface_capacities.get(
                            interface.interface_type, 
                            self.default_interface_capacities['unknown']
                        )
        
        return self.default_interface_capacities['unknown']
    
    def _simulate_current_utilization(self, total_capacity: int) -> int:
        """Simulate current link utilization"""
        # Generate realistic utilization between 10% and 90%
        utilization_factor = random.uniform(0.1, 0.9)
        
        # Add some variability based on capacity (higher capacity links tend to have lower utilization)
        if total_capacity > 500000:  # > 500 Mbps
            utilization_factor *= 0.6  # High capacity links less utilized
        elif total_capacity < 50000:  # < 50 Mbps
            utilization_factor *= 1.2  # Low capacity links more utilized
        
        utilization_factor = min(utilization_factor, 0.95)  # Cap at 95%
        
        return int(total_capacity * utilization_factor)
    
    def _generate_traffic_demands(self, topology: NetworkTopology, 
                                 configs: Dict[str, RouterConfig]) -> List[TrafficDemand]:
        """Generate estimated traffic demands between endpoints"""
        demands = []
        
        # Identify endpoint types
        endpoints = self._classify_endpoints(topology, configs)
        
        # Generate traffic patterns between different endpoint types
        for i, (source, source_type) in enumerate(endpoints.items()):
            for j, (target, target_type) in enumerate(endpoints.items()):
                if i >= j:  # Avoid duplicate pairs and self-connections
                    continue
                
                # Determine traffic type and requirements based on endpoint types
                traffic_patterns = self._determine_traffic_patterns(source_type, target_type)
                
                for traffic_type, pattern in traffic_patterns.items():
                    demand = TrafficDemand(
                        source=source,
                        destination=target,
                        bandwidth_requirement=pattern['base_bw'],
                        traffic_type=traffic_type,
                        priority=pattern['priority'],
                        peak_multiplier=pattern['peak_mult']
                    )
                    demands.append(demand)
        
        return demands
    
    def _classify_endpoints(self, topology: NetworkTopology, 
                           configs: Dict[str, RouterConfig]) -> Dict[str, str]:
        """Classify network endpoints by their likely function"""
        endpoints = {}
        
        for node in topology.nodes:
            hostname = node.hostname
            
            # Classify based on device type and configuration
            if node.device_type == 'router':
                if node.tier == 0:  # Core router
                    endpoints[hostname] = 'core_router'
                elif node.tier == 1:  # Distribution router
                    endpoints[hostname] = 'distribution_router'
                else:
                    endpoints[hostname] = 'edge_router'
                    
            elif node.device_type == 'l3_switch':
                if node.tier <= 1:
                    endpoints[hostname] = 'distribution_switch'
                else:
                    endpoints[hostname] = 'access_switch'
                    
            elif 'switch' in node.device_type:
                endpoints[hostname] = 'access_switch'
            else:
                endpoints[hostname] = 'unknown'
        
        return endpoints
    
    def _determine_traffic_patterns(self, source_type: str, target_type: str) -> Dict[str, Dict]:
        """Determine traffic patterns between endpoint types"""
        patterns = {}
        
        # Define traffic patterns based on endpoint types
        if source_type in ['access_switch', 'edge_router'] and target_type in ['core_router', 'distribution_router']:
            # Uplink traffic: web, database access
            patterns['web'] = self.traffic_type_patterns['web']
            patterns['database'] = self.traffic_type_patterns['database']
        
        elif source_type == 'access_switch' and target_type == 'access_switch':
            # Inter-VLAN or peer communication
            patterns['file_transfer'] = self.traffic_type_patterns['file_transfer']
            patterns['voice'] = self.traffic_type_patterns['voice']
        
        elif 'core' in source_type or 'core' in target_type:
            # Core network traffic: high volume
            patterns['video'] = self.traffic_type_patterns['video']
            patterns['backup'] = self.traffic_type_patterns['backup']
        
        else:
            # Default patterns
            patterns['web'] = self.traffic_type_patterns['web']
        
        return patterns
    
    def _calculate_traffic_loads(self, link_utilizations: List[LinkUtilization],
                                traffic_demands: List[TrafficDemand],
                                topology: NetworkTopology):
        """Calculate traffic loads on each link based on demands"""
        # This is a simplified traffic engineering calculation
        # In reality, would use proper routing algorithms and traffic matrices
        
        # Create a simple routing table
        routing_paths = self._calculate_shortest_paths(topology)
        
        # Route each traffic demand and accumulate load on links
        for demand in traffic_demands:
            path = routing_paths.get((demand.source, demand.destination), [])
            if len(path) > 1:
                # Add load to each link in the path
                demand_bw = demand.bandwidth_requirement
                
                for i in range(len(path) - 1):
                    source_node = path[i]
                    target_node = path[i + 1]
                    
                    # Find corresponding link utilization
                    for util in link_utilizations:
                        if ((util.source == source_node and util.target == target_node) or
                            (util.source == target_node and util.target == source_node)):
                            
                            # Add demand to current utilization
                            util.current_utilization += demand_bw
                            util.peak_utilization += int(demand_bw * demand.peak_multiplier)
                            
                            # Recalculate percentages
                            util.utilization_percentage = (util.current_utilization / util.total_capacity) * 100
                            util.is_congested = util.utilization_percentage > 80.0
                            
                            break
    
    def _calculate_shortest_paths(self, topology: NetworkTopology) -> Dict[Tuple[str, str], List[str]]:
        """Calculate shortest paths between all node pairs"""
        import networkx as nx
        
        # Create NetworkX graph
        G = nx.Graph()
        
        # Add nodes and edges
        for node in topology.nodes:
            G.add_node(node.hostname)
        
        for link in topology.links:
            G.add_edge(link.source, link.target)
        
        # Calculate all shortest paths
        paths = {}
        nodes = list(G.nodes())
        
        for i, source in enumerate(nodes):
            for j, target in enumerate(nodes):
                if i != j:
                    try:
                        path = nx.shortest_path(G, source, target)
                        paths[(source, target)] = path
                    except nx.NetworkXNoPath:
                        paths[(source, target)] = []
        
        return paths
    
    def _find_alternative_paths(self, topology: NetworkTopology) -> Dict[str, List[str]]:
        """Find alternative paths for load balancing"""
        import networkx as nx
        
        # Create NetworkX graph
        G = nx.Graph()
        
        for node in topology.nodes:
            G.add_node(node.hostname)
        
        for link in topology.links:
            G.add_edge(link.source, link.target, weight=1)
        
        alternative_paths = {}
        
        # Find alternative paths for critical node pairs
        critical_pairs = self._identify_critical_node_pairs(topology)
        
        for source, target in critical_pairs:
            try:
                # Find multiple paths using k-shortest paths
                all_paths = list(nx.all_simple_paths(G, source, target, cutoff=5))
                
                # Sort by length and take top alternatives
                all_paths.sort(key=len)
                alternative_paths[f"{source}-{target}"] = all_paths[:3]  # Keep top 3 paths
                
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                alternative_paths[f"{source}-{target}"] = []
        
        return alternative_paths
    
    def _identify_critical_node_pairs(self, topology: NetworkTopology) -> List[Tuple[str, str]]:
        """Identify critical node pairs that need redundant paths"""
        critical_pairs = []
        
        # Identify core and distribution nodes
        core_nodes = [node.hostname for node in topology.nodes if node.tier == 0]
        dist_nodes = [node.hostname for node in topology.nodes if node.tier == 1]
        
        # Core-to-distribution connections are critical
        for core in core_nodes:
            for dist in dist_nodes:
                critical_pairs.append((core, dist))
        
        # Core-to-core connections
        for i, core1 in enumerate(core_nodes):
            for core2 in core_nodes[i+1:]:
                critical_pairs.append((core1, core2))
        
        return critical_pairs
    
    def _generate_recommendations(self, link_utilizations: List[LinkUtilization],
                                 alternative_paths: Dict[str, List[str]],
                                 topology: NetworkTopology) -> List[LoadBalancingRecommendation]:
        """Generate load balancing recommendations"""
        recommendations = []
        
        # Identify congested links
        congested_links = [util for util in link_utilizations if util.is_congested]
        
        # Recommendation 1: Activate secondary paths for congested links
        for util in congested_links:
            link_id = f"{util.source}-{util.target}"
            alt_paths = alternative_paths.get(link_id, [])
            
            if len(alt_paths) > 1:  # Has alternative paths
                recommendation = LoadBalancingRecommendation(
                    recommendation_type="secondary_path",
                    affected_links=[link_id],
                    description=f"Activate secondary path for congested link {link_id} "
                               f"(Current utilization: {util.utilization_percentage:.1f}%)",
                    priority="high" if util.utilization_percentage > 90 else "medium",
                    estimated_benefit=f"Reduce utilization by ~{util.utilization_percentage * 0.4:.1f}%",
                    implementation_notes=f"Configure load balancing across paths: {alt_paths[1]}"
                )
                recommendations.append(recommendation)
        
        # Recommendation 2: Capacity upgrades for heavily utilized links
        heavy_links = [util for util in link_utilizations if util.utilization_percentage > 70]
        
        for util in heavy_links:
            if util.total_capacity < 1000000:  # Less than 1 Gbps
                recommendation = LoadBalancingRecommendation(
                    recommendation_type="capacity_upgrade",
                    affected_links=[f"{util.source}-{util.target}"],
                    description=f"Consider upgrading link capacity on {util.source}-{util.target} "
                               f"from {util.total_capacity//1000} Mbps to higher bandwidth",
                    priority="medium" if util.utilization_percentage < 85 else "high",
                    estimated_benefit="Increase available bandwidth and reduce congestion risk",
                    implementation_notes="Upgrade to Gigabit Ethernet or higher capacity interface"
                )
                recommendations.append(recommendation)
        
        # Recommendation 3: Traffic engineering for unbalanced loads
        self._add_traffic_engineering_recommendations(recommendations, link_utilizations, topology)
        
        # Recommendation 4: Protocol-specific recommendations
        self._add_protocol_recommendations(recommendations, topology)
        
        return recommendations
    
    def _add_traffic_engineering_recommendations(self, recommendations: List[LoadBalancingRecommendation],
                                               link_utilizations: List[LinkUtilization],
                                               topology: NetworkTopology):
        """Add traffic engineering recommendations"""
        # Identify load imbalances
        avg_utilization = sum(util.utilization_percentage for util in link_utilizations) / len(link_utilizations)
        
        highly_utilized = [util for util in link_utilizations if util.utilization_percentage > avg_utilization * 1.5]
        lightly_utilized = [util for util in link_utilizations if util.utilization_percentage < avg_utilization * 0.5]
        
        if highly_utilized and lightly_utilized:
            recommendation = LoadBalancingRecommendation(
                recommendation_type="traffic_engineering",
                affected_links=[f"{util.source}-{util.target}" for util in highly_utilized[:3]],
                description=f"Load imbalance detected. Some links >150% of average "
                           f"({avg_utilization:.1f}%) while others <50%",
                priority="medium",
                estimated_benefit="More balanced network utilization and improved performance",
                implementation_notes="Implement traffic engineering with MPLS-TE or adjust IGP metrics"
            )
            recommendations.append(recommendation)
    
    def _add_protocol_recommendations(self, recommendations: List[LoadBalancingRecommendation],
                                    topology: NetworkTopology):
        """Add routing protocol-specific recommendations"""
        # Check if network would benefit from ECMP
        node_count = len(topology.nodes)
        link_count = len(topology.links)
        
        # If there's sufficient redundancy, recommend ECMP
        if link_count > node_count * 1.2:  # More than 20% redundant links
            recommendation = LoadBalancingRecommendation(
                recommendation_type="protocol_optimization",
                affected_links=[],
                description="Network has sufficient redundancy for Equal-Cost Multi-Path (ECMP) routing",
                priority="medium",
                estimated_benefit="Automatic load balancing across equal-cost paths",
                implementation_notes="Enable ECMP in OSPF configuration with 'maximum-paths' command"
            )
            recommendations.append(recommendation)
        
        # Check for BGP optimization opportunities
        core_nodes = [node for node in topology.nodes if node.tier == 0]
        if len(core_nodes) > 2:
            recommendation = LoadBalancingRecommendation(
                recommendation_type="protocol_optimization",
                affected_links=[],
                description="Multiple core nodes detected - consider BGP for better traffic control",
                priority="low",
                estimated_benefit="Fine-grained traffic engineering and policy control",
                implementation_notes="Implement iBGP between core routers for advanced traffic engineering"
            )
            recommendations.append(recommendation)
    
    def _calculate_summary_stats(self, results: LoadBalancingResults):
        """Calculate summary statistics"""
        if results.link_utilizations:
            results.total_links = len(results.link_utilizations)
            results.congested_links = sum(1 for util in results.link_utilizations if util.is_congested)
            results.average_utilization = sum(util.utilization_percentage 
                                            for util in results.link_utilizations) / results.total_links
    
    def save_recommendations(self, results: LoadBalancingResults, output_file: Path, 
                           format_type: str = 'json'):
        """Save load balancing recommendations to file"""
        if format_type == 'json':
            results_dict = {
                'summary': {
                    'total_links': results.total_links,
                    'congested_links': results.congested_links,
                    'average_utilization': results.average_utilization
                },
                'link_utilizations': [
                    {
                        'source': util.source,
                        'target': util.target,
                        'interface': util.interface,
                        'total_capacity_mbps': util.total_capacity // 1000,
                        'utilization_percentage': util.utilization_percentage,
                        'is_congested': util.is_congested
                    }
                    for util in results.link_utilizations
                ],
                'recommendations': [
                    {
                        'type': rec.recommendation_type,
                        'affected_links': rec.affected_links,
                        'description': rec.description,
                        'priority': rec.priority,
                        'estimated_benefit': rec.estimated_benefit,
                        'implementation_notes': rec.implementation_notes
                    }
                    for rec in results.recommendations
                ],
                'alternative_paths': results.alternative_paths
            }
            
            with open(output_file, 'w') as f:
                json.dump(results_dict, f, indent=2)
        
        elif format_type == 'yaml':
            results_dict = {
                'summary': {
                    'total_links': results.total_links,
                    'congested_links': results.congested_links,
                    'average_utilization': results.average_utilization
                },
                'link_utilizations': [
                    {
                        'source': util.source,
                        'target': util.target,
                        'interface': util.interface,
                        'total_capacity_mbps': util.total_capacity // 1000,
                        'utilization_percentage': util.utilization_percentage,
                        'is_congested': util.is_congested
                    }
                    for util in results.link_utilizations
                ],
                'recommendations': [
                    {
                        'type': rec.recommendation_type,
                        'affected_links': rec.affected_links,
                        'description': rec.description,
                        'priority': rec.priority,
                        'estimated_benefit': rec.estimated_benefit,
                        'implementation_notes': rec.implementation_notes
                    }
                    for rec in results.recommendations
                ],
                'alternative_paths': results.alternative_paths
            }
            
            with open(output_file, 'w') as f:
                yaml.dump(results_dict, f, default_flow_style=False)
        
        elif format_type == 'text':
            with open(output_file, 'w') as f:
                f.write("LOAD BALANCING RECOMMENDATIONS\n")
                f.write("=" * 50 + "\n\n")
                
                f.write("SUMMARY:\n")
                f.write("-" * 20 + "\n")
                f.write(f"Total Links: {results.total_links}\n")
                f.write(f"Congested Links: {results.congested_links}\n")
                f.write(f"Average Utilization: {results.average_utilization:.1f}%\n\n")
                
                f.write("LINK UTILIZATIONS:\n")
                f.write("-" * 30 + "\n")
                for util in sorted(results.link_utilizations, 
                                 key=lambda x: x.utilization_percentage, reverse=True):
                    status = "CONGESTED" if util.is_congested else "OK"
                    f.write(f"{util.source} <--> {util.target}: "
                           f"{util.utilization_percentage:.1f}% [{status}]\n")
                    f.write(f"  Capacity: {util.total_capacity//1000} Mbps, "
                           f"Interface: {util.interface}\n\n")
                
                f.write("RECOMMENDATIONS:\n")
                f.write("-" * 30 + "\n")
                for i, rec in enumerate(results.recommendations, 1):
                    f.write(f"{i}. [{rec.priority.upper()}] {rec.recommendation_type.replace('_', ' ').title()}\n")
                    f.write(f"   Description: {rec.description}\n")
                    if rec.affected_links:
                        f.write(f"   Affected Links: {', '.join(rec.affected_links)}\n")
                    f.write(f"   Estimated Benefit: {rec.estimated_benefit}\n")
                    f.write(f"   Implementation: {rec.implementation_notes}\n\n")
                
                if results.alternative_paths:
                    f.write("ALTERNATIVE PATHS:\n")
                    f.write("-" * 30 + "\n")
                    for path_name, paths in results.alternative_paths.items():
                        if paths:
                            f.write(f"{path_name}:\n")
                            for i, path in enumerate(paths[:3], 1):
                                f.write(f"  Path {i}: {' -> '.join(path)}\n")
                            f.write("\n")
        
        self.logger.info(f"Load balancing recommendations saved to {output_file}")