"""
Examples for using the Advanced OS Toolkit
"""

from advanced_os_toolkit import AdvancedOSToolkit
import json

def example_basic_usage():
    """Basic usage examples"""
    toolkit = AdvancedOSToolkit()
    
    print("=" * 50)
    print("ADVANCED OS TOOLKIT - BASIC USAGE")
    print("=" * 50)
    
    # 1. Get system report
    print("\n1. System Report:")
    report = toolkit.generate_report('system')
    print(f"System: {report['system_info']['platform']['system']}")
    print(f"Release: {report['system_info']['platform']['release']}")
    print(f"Uptime: {report['uptime']}")
    
    # 2. Monitor system resources
    print("\n2. System Resources:")
    cpu_info = toolkit.monitor.get_cpu_info()
    print(f"CPU Cores: {cpu_info['physical_cores']} physical, {cpu_info['logical_cores']} logical")
    print(f"CPU Usage: {cpu_info['avg_usage']}%")
    
    mem_info = toolkit.monitor.get_memory_info()
    print(f"Memory Usage: {mem_info['virtual']['percent']}%")
    print(f"Memory Used: {mem_info['virtual']['used']}")
    
    # 3. List processes
    print("\n3. Top 5 Processes by CPU:")
    processes = toolkit.process_manager.list_processes(detailed=True)[:5]
    for proc in processes:
        print(f"  {proc['name']:20} - CPU: {proc.get('cpu_percent', 0):5.1f}% | "
              f"Memory: {proc.get('memory_percent', 0):5.1f}%")
    
    # 4. File operations
    print("\n4. File Operations Example:")
    # This is just a demonstration - you'd use actual file paths
    print("  Use toolkit.file_manager.secure_copy() for secure file copying")
    print("  Use toolkit.file_manager.find_files() for advanced file searching")
    
    # 5. Network information
    print("\n5. Network Information:")
    net_info = toolkit.monitor.get_network_info()
    print(f"Bytes Sent: {net_info['bytes_sent']}")
    print(f"Bytes Received: {net_info['bytes_recv']}")
    
    interfaces = toolkit.network_tools.get_network_interfaces()
    print(f"Active Interfaces: {len([i for i in interfaces.values() if i['is_up']])}")

def example_monitoring():
    """Real-time monitoring example"""
    toolkit = AdvancedOSToolkit()
    
    print("\n" + "=" * 50)
    print("REAL-TIME MONITORING EXAMPLE")
    print("=" * 50)
    
    # Start monitoring
    toolkit.monitor.start_monitoring()
    
    print("Monitoring started. Collecting data for 10 seconds...")
    
    monitoring_data = []
    import time
    for i in range(5):  # Collect 5 samples
        time.sleep(2)  # Wait for monitoring interval
        
        data = toolkit.monitor.get_monitoring_data()
        if data:
            monitoring_data.append(data)
            print(f"\nSample {i + 1}:")
            print(f"  CPU: {data['cpu']['avg_usage']:.1f}%")
            print(f"  Memory: {data['memory']['virtual']['percent']:.1f}%")
            print(f"  Network Sent: {data['network']['bytes_sent']}")
    
    # Stop monitoring
    toolkit.monitor.stop_monitoring()
    
    print("\nMonitoring complete!")
    
    # Save monitoring data to file
    if monitoring_data:
        with open('monitoring_data.json', 'w') as f:
            json.dump(monitoring_data, f, indent=2)
        print("Data saved to monitoring_data.json")

def example_process_management():
    """Process management examples"""
    toolkit = AdvancedOSToolkit()
    
    print("\n" + "=" * 50)
    print("PROCESS MANAGEMENT EXAMPLES")
    print("=" * 50)
    
    # Find processes by name
    print("\nSearching for Python processes:")
    python_procs = toolkit.process_manager.find_process_by_name('python')
    
    if python_procs:
        for proc in python_procs[:3]:  # Show first 3
            print(f"  PID: {proc['pid']}, Name: {proc['name']}")
            
            # Get detailed information
            details = toolkit.process_manager.get_process_details(proc['pid'])
            if details:
                print(f"    Memory: {details['memory_percent']:.1f}%")
                print(f"    CPU: {details['cpu_percent']:.1f}%")
                print(f"    Threads: {details['threads']}")
    else:
        print("  No Python processes found")

def example_file_operations():
    """File operations examples"""
    toolkit = AdvancedOSToolkit()
    
    print("\n" + "=" * 50)
    print("FILE OPERATIONS EXAMPLES")
    print("=" * 50)
    
    # Calculate hash of this file
    print("\n1. File Hash Calculation:")
    try:
        file_hash = toolkit.file_manager.calculate_hash(__file__)
        print(f"  {__file__}")
        print(f"  SHA256: {file_hash}")
    except:
        print("  Could not calculate hash (file might not exist in this context)")
    
    # Find large files (example)
    print("\n2. Finding Large Files:")
    # This would search in current directory for files > 1MB
    # large_files = toolkit.file_manager.find_files('.', min_size=1024*1024)
    # print(f"  Found {len(large_files)} files larger than 1MB")
    
    print("  (Note: File operations require actual file paths)")

def example_network_tools():
    """Network tools examples"""
    toolkit = AdvancedOSToolkit()
    
    print("\n" + "=" * 50)
    print("NETWORK TOOLS EXAMPLES")
    print("=" * 50)
    
    # Get network interfaces
    print("\n1. Network Interfaces:")
    interfaces = toolkit.network_tools.get_network_interfaces()
    
    for name, info in interfaces.items():
        if info['is_up']:
            print(f"  {name}:")
            for addr in info['addresses']:
                if addr['family'] == 'AddressFamily.AF_INET':
                    print(f"    IPv4: {addr['address']}")
    
    # Ping localhost
    print("\n2. Ping Test:")
    result = toolkit.network_tools.ping_host('127.0.0.1', count=2)
    if result['success']:
        print("  Localhost is reachable")
    else:
        print(f"  Ping failed: {result['error']}")
    
    # DNS lookup
    print("\n3. DNS Lookup:")
    dns_info = toolkit.network_tools.get_dns_info('example.com')
    if 'ipv4_addresses' in dns_info:
        print(f"  example.com resolves to: {', '.join(dns_info['ipv4_addresses'])}")

def example_generate_reports():
    """Generate different types of reports"""
    toolkit = AdvancedOSToolkit()
    
    print("\n" + "=" * 50)
    print("REPORT GENERATION EXAMPLES")
    print("=" * 50)
    
    # Generate different report types
    report_types = ['system', 'hardware', 'network', 'processes']
    
    for report_type in report_types:
        print(f"\nGenerating {report_type} report...")
        report = toolkit.generate_report(report_type)
        
        print(f"  Report contains {len(report)} sections")
        
        # Save each report
        filename = f"{report_type}_report.json"
        toolkit.save_report(filename, report_type)
        print(f"  Saved to {filename}")

def main():
    """Run all examples"""
    print("ADVANCED OS TOOLKIT - EXAMPLES")
    print("=" * 60)
    
    # Run examples
    example_basic_usage()
    example_monitoring()
    example_process_management()
    example_file_operations()
    example_network_tools()
    example_generate_reports()
    
    print("\n" + "=" * 60)
    print("All examples completed!")
    print("\nFor more information, see the documentation in README.md")

if __name__ == "__main__":
    main()
