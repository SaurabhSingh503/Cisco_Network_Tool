#!/usr/bin/env python3
"""
Cisco Network Topology Generation and Simulation Tool
Main Entry Point

This tool provides comprehensive network topology generation, validation,
and simulation capabilities as specified in the Cisco VIP 2025 Problem Statement.

Author: Generated for Cisco VIP 2025 Networking Stream
Date: August 2025
"""

import sys
import os
import argparse
import logging
from pathlib import Path
from typing import Dict, List, Optional

# Add src directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from config_parser import ConfigParser
from topology_generator import TopologyGenerator
from network_validator import NetworkValidator
from network_simulator import NetworkSimulator
from load_balancer import LoadBalancer
from utils import setup_logging, print_banner

def main():
    """Main application entry point"""
    
    # Setup command line arguments
    parser = argparse.ArgumentParser(
        description="Cisco Network Topology Generation and Simulation Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -c /path/to/configs --generate-topology
  %(prog)s -c /path/to/configs --validate --simulate
  %(prog)s -c /path/to/configs --load-balance --day1-sim
        """
    )
    
    # Configuration directory
    parser.add_argument('-c', '--config-dir', 
                       required=True,
                       help='Directory containing router configuration files')
    
    # Operation modes
    parser.add_argument('--generate-topology', 
                       action='store_true',
                       help='Generate hierarchical network topology')
    
    parser.add_argument('--validate', 
                       action='store_true',
                       help='Validate network configurations')
    
    parser.add_argument('--simulate', 
                       action='store_true',
                       help='Run network simulation')
    
    parser.add_argument('--day1-sim', 
                       action='store_true',
                       help='Run Day-1 simulation (ARP, neighbor discovery, OSPF)')
    
    parser.add_argument('--load-balance', 
                       action='store_true',
                       help='Generate load balancing recommendations')
    
    parser.add_argument('--fault-inject', 
                       action='store_true',
                       help='Inject faults and test network resilience')
    
    # Output options
    parser.add_argument('-o', '--output-dir', 
                       default='output',
                       help='Output directory for results (default: output)')
    
    parser.add_argument('--output-format', 
                       choices=['json', 'yaml', 'text'],
                       default='json',
                       help='Output format (default: json)')
    
    # Simulation options
    parser.add_argument('--threads', 
                       type=int, 
                       default=10,
                       help='Number of threads for simulation (default: 10)')
    
    parser.add_argument('--verbose', '-v', 
                       action='count', 
                       default=0,
                       help='Increase verbosity (use -v, -vv, or -vvv)')
    
    args = parser.parse_args()
    
    # Setup logging
    log_level = logging.WARNING
    if args.verbose == 1:
        log_level = logging.INFO
    elif args.verbose >= 2:
        log_level = logging.DEBUG
        
    setup_logging(log_level)
    logger = logging.getLogger(__name__)
    
    # Print banner
    print_banner()
    
    # Validate config directory
    config_dir = Path(args.config_dir)
    if not config_dir.exists():
        logger.error(f"Configuration directory does not exist: {config_dir}")
        sys.exit(1)
    
    # Create output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(exist_ok=True)
    
    try:
        # Initialize components
        logger.info("Initializing network analysis tool...")
        
        config_parser = ConfigParser(config_dir)
        topology_generator = TopologyGenerator()
        validator = NetworkValidator()
        simulator = NetworkSimulator(num_threads=args.threads)
        load_balancer = LoadBalancer()
        
        # Parse configuration files
        logger.info("Parsing configuration files...")
        configs = config_parser.parse_all_configs()
        
        if not configs:
            logger.error("No valid configuration files found")
            sys.exit(1)
            
        logger.info(f"Successfully parsed {len(configs)} configuration files")
        
        # Generate topology if requested
        if args.generate_topology:
            logger.info("Generating network topology...")
            topology = topology_generator.generate_topology(configs)
            
            # Save topology
            topology_file = output_dir / f"topology.{args.output_format}"
            topology_generator.save_topology(topology, topology_file, args.output_format)
            logger.info(f"Topology saved to {topology_file}")
        
        # Validate configurations if requested
        if args.validate:
            logger.info("Validating network configurations...")
            validation_results = validator.validate_all(configs)
            
            # Save validation results
            validation_file = output_dir / f"validation_results.{args.output_format}"
            validator.save_results(validation_results, validation_file, args.output_format)
            logger.info(f"Validation results saved to {validation_file}")
        
        # Generate load balancing recommendations if requested
        if args.load_balance:
            logger.info("Generating load balancing recommendations...")
            recommendations = load_balancer.analyze_and_recommend(configs)
            
            # Save recommendations
            lb_file = output_dir / f"load_balancing_recommendations.{args.output_format}"
            load_balancer.save_recommendations(recommendations, lb_file, args.output_format)
            logger.info(f"Load balancing recommendations saved to {lb_file}")
        
        # Run simulation if requested
        if args.simulate or args.day1_sim:
            logger.info("Starting network simulation...")
            
            # Initialize simulation
            if args.generate_topology:
                sim_results = simulator.run_simulation(topology, day1=args.day1_sim)
            else:
                # Generate topology for simulation
                topology = topology_generator.generate_topology(configs)
                sim_results = simulator.run_simulation(topology, day1=args.day1_sim)
            
            # Save simulation results
            sim_file = output_dir / f"simulation_results.{args.output_format}"
            simulator.save_results(sim_results, sim_file, args.output_format)
            logger.info(f"Simulation results saved to {sim_file}")
        
        # Run fault injection if requested
        if args.fault_inject:
            logger.info("Running fault injection tests...")
            fault_results = simulator.inject_faults(configs)
            
            # Save fault injection results
            fault_file = output_dir / f"fault_injection_results.{args.output_format}"
            simulator.save_results(fault_results, fault_file, args.output_format)
            logger.info(f"Fault injection results saved to {fault_file}")
        
        logger.info("Network analysis completed successfully!")
        print(f"\nResults saved in: {output_dir.absolute()}")
        
    except KeyboardInterrupt:
        logger.info("Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"An error occurred: {str(e)}")
        if args.verbose >= 2:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()