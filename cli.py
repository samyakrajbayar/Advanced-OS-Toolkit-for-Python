#!/usr/bin/env python3
"""
Command Line Interface for Advanced OS Toolkit
"""

import argparse
import json
from advanced_os_toolkit import AdvancedOSToolkit

def main():
    toolkit = AdvancedOSToolkit()
    
    parser = argparse.ArgumentParser(
        description="Advanced OS Toolkit - System Management Utility",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ostool monitor                   # Start real-time monitoring
  ostool processes --detailed      # List all processes with details
  ostool report --type full        # Generate full system report
  ostool kill --pid 1234           # Kill process with PID 1234
  ostool find --name chrome        # Find processes by name
  ostool scan --target localhost   # Scan ports on localhost
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # Monitor command
    monitor_parser = subparsers.add_parser("monitor", help="Real-time system monitoring")
    monitor_parser.add_argument("--interval", type=int, default=2, help="Update interval in seconds")
    
    # Report command
    report_parser = subparsers.add_parser("report", help="Generate system report")
    report_parser.add_argument("--type", choices=["full", "system", "hardware", "network", "processes"], 
                              default="full", help="Report type")
    report_parser.add_argument("--output", help="Output file name")
    
    # Processes command
    proc_parser = subparsers.add_parser("processes", help="Process management")
    proc_parser.add_argument("--detailed", action="store_true", help="Show detailed information")
    proc_parser.add_argument("--kill", type=int, help="Kill process by PID")
    proc_parser.add_argument("--kill-tree", type=int, help="Kill process tree by PID")
    
    # Find processes
    find_parser = subparsers.add_parser("find", help="Find processes")
    find_parser.add_argument("--name", required=True, help="Process name to search for")
    
    # File operations
    file_parser = subparsers.add_parser("file", help="File operations")
    file_parser.add_argument("--copy", nargs=2, metavar=("SOURCE", "DEST"), help="Copy file")
    file_parser.add_argument("--find", help="Find files in directory")
    file_parser.add_argument("--hash", help="Calculate file hash")
    
    # Network operations
    net_parser = subparsers.add_parser("network", help="Network operations")
    net_parser.add_argument("--interfaces", action="store_true", help="Show network interfaces")
    net_parser.add_argument("--scan", metavar="TARGET", help="Scan ports on target")
    net_parser.add_argument("--ping", metavar="HOST", help="Ping host")
    net_parser.add_argument("--dns", metavar="DOMAIN", help="Get DNS information")
    
    # System info
    sys_parser = subparsers.add_parser("system", help="System information")
    sys_parser.add_argument("--uptime", action="store_true", help="Show system uptime")
    sys_parser.add_argument("--users", action="store_true", help="Show logged in users")
    sys_parser.add_argument("--sensors", action="store_true", help="Show sensor information")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    try:
        if args.command == "monitor":
            print("Starting real-time monitoring... Press Ctrl+C to stop.")
            toolkit.monitor.start_monitoring()
            try:
                while True:
                    data = toolkit.monitor.get_monitoring_data()
                    if data:
                        print(f"\n{'='*50}")
                        print(f"Time: {data['timestamp']}")
                        print(f"CPU Usage: {data['cpu']['avg_usage']:.1f}%")
                        print(f"Memory Usage: {data['memory']['virtual']['percent']:.1f}%")
                        print(f"Network Sent: {data['network']['bytes_sent']}")
                        print(f"Network Received: {data['network']['bytes_recv']}")
            except KeyboardInterrupt:
                toolkit.monitor.stop_monitoring()
                print("\nMonitoring stopped.")
                
        elif args.command == "report":
            report = toolkit.generate_report(args.type)
            if args.output:
                toolkit.save_report(args.output, args.type)
                print(f"Report saved to {args.output}")
            else:
                print(json.dumps(report, indent=2, default=str))
                
        elif args.command == "processes":
            if args.kill:
                success, message = toolkit.process_manager.kill_process(args.kill)
                print(message)
            elif args.kill_tree:
                success, message = toolkit.process_manager.kill_process_tree(args.kill_tree)
                print(message)
            else:
                processes = toolkit.process_manager.list_processes(args.detailed)
                for proc in processes[:20]:  # Show top 20
                    print(f"PID: {proc['pid']:6} | Name: {proc['name'][:20]:20} | "
                          f"User: {proc['username'][:10]:10} | Status: {proc['status']}")
                    
        elif args.command == "find":
            processes = toolkit.process_manager.find_process_by_name(args.name)
            if processes:
                for proc in processes:
                    print(f"PID: {proc['pid']} | Name: {proc['name']}")
                    if proc['cmdline']:
                        print(f"  Command: {' '.join(proc['cmdline'])[:80]}")
                    print()
            else:
                print(f"No processes found with name containing '{args.name}'")
                
        elif args.command == "file":
            if args.copy:
                success, message = toolkit.file_manager.secure_copy(args.copy[0], args.copy[1])
                print(message)
            elif args.find:
                files = toolkit.file_manager.find_files(args.find)
                for file in files[:10]:  # Show first 10
                    print(f"{file['path']} ({file['size_human']})")
            elif args.hash:
                file_hash = toolkit.file_manager.calculate_hash(args.hash)
                print(f"SHA256: {file_hash}")
                
        elif args.command == "network":
            if args.interfaces:
                interfaces = toolkit.network_tools.get_network_interfaces()
                for name, info in interfaces.items():
                    print(f"\nInterface: {name}")
                    print(f"  Status: {'UP' if info['is_up'] else 'DOWN'}")
                    for addr in info['addresses']:
                        print(f"  {addr['family']}: {addr['address']}")
            elif args.scan:
                print(f"Scanning {args.scan}...")
                results = toolkit.network_tools.port_scan(args.scan, ports=list(range(1, 100)))
                open_ports = [r for r in results if r['status'] == 'OPEN']
                if open_ports:
                    print("Open ports:")
                    for port in open_ports:
                        print(f"  {port['port']:5} - {port['service']}")
                else:
                    print("No open ports found")
            elif args.ping:
                result = toolkit.network_tools.ping_host(args.ping)
                print(result['output'])
            elif args.dns:
                info = toolkit.network_tools.get_dns_info(args.dns)
                print(json.dumps(info, indent=2))
                
        elif args.command == "system":
            if args.uptime:
                print(f"Uptime: {toolkit.utils.get_system_uptime()}")
            elif args.users:
                users = toolkit.utils.get_logged_in_users()
                for user in users:
                    print(f"User: {user['name']} on {user['terminal']} from {user['host']}")
            elif args.sensors:
                sensors = toolkit.utils.get_sensors_info()
                if sensors.get('temperatures'):
                    print("Temperatures:")
                    for name, entries in sensors['temperatures'].items():
                        for entry in entries:
                            print(f"  {name}: {entry['label']} = {entry['current']}°C")
                if sensors.get('fans'):
                    print("\nFans:")
                    for name, entries in sensors['fans'].items():
                        for entry in entries:
                            print(f"  {name}: {entry['label']} = {entry['current']} RPM")
                            
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()
