from advanced_os_toolkit import SystemMonitor

monitor = SystemMonitor(update_interval=2)
monitor.start_monitoring()

try:
    while True:
        data = monitor.get_monitoring_data()
        if data:
            print(f"CPU: {data['cpu']['avg_usage']}%")
            print(f"Memory: {data['memory']['virtual']['percent']}%")
except KeyboardInterrupt:
    monitor.stop_monitoring()
