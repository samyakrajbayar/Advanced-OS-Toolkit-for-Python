from advanced_os_toolkit import AdvancedOSToolkit

# Initialize toolkit
toolkit = AdvancedOSToolkit()

# Generate system report
report = toolkit.generate_report('full')
print(f"System: {report['system_info']['platform']['system']}")
print(f"CPU Usage: {report['cpu']['avg_usage']}%")

# Monitor system resources
cpu_info = toolkit.monitor.get_cpu_info()
mem_info = toolkit.monitor.get_memory_info()

# Manage processes
processes = toolkit.process_manager.list_processes(detailed=True)
