"""
Advanced OS Toolkit for Python
A comprehensive toolkit for system operations, monitoring, and management.
"""

import os
import sys
import platform
import psutil
import shutil
import socket
import hashlib
import json
import time
import subprocess
import threading
import queue
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Union, Any
import warnings
import signal

# Suppress psutil warnings
warnings.filterwarnings('ignore')

class SystemMonitor:
    """Real-time system monitoring class"""
    
    def __init__(self, update_interval: int = 2):
        self.update_interval = update_interval
        self.running = False
        self.monitor_thread = None
        self.data_queue = queue.Queue()
        
    def get_cpu_info(self) -> Dict:
        """Get detailed CPU information"""
        cpu_info = {
            'physical_cores': psutil.cpu_count(logical=False),
            'logical_cores': psutil.cpu_count(logical=True),
            'usage_percent': psutil.cpu_percent(interval=1, percpu=True),
            'avg_usage': psutil.cpu_percent(interval=1),
            'frequency': psutil.cpu_freq()._asdict() if psutil.cpu_freq() else None,
            'stats': psutil.cpu_stats()._asdict(),
            'times': psutil.cpu_times()._asdict()
        }
        return cpu_info
    
    def get_memory_info(self) -> Dict:
        """Get detailed memory information"""
        virtual_mem = psutil.virtual_memory()
        swap_mem = psutil.swap_memory()
        
        memory_info = {
            'virtual': {
                'total': self._format_bytes(virtual_mem.total),
                'available': self._format_bytes(virtual_mem.available),
                'used': self._format_bytes(virtual_mem.used),
                'percent': virtual_mem.percent,
                'free': self._format_bytes(virtual_mem.free)
            },
            'swap': {
                'total': self._format_bytes(swap_mem.total),
                'used': self._format_bytes(swap_mem.used),
                'free': self._format_bytes(swap_mem.free),
                'percent': swap_mem.percent
            }
        }
        return memory_info
    
    def get_disk_info(self) -> Dict:
        """Get detailed disk information"""
        partitions = psutil.disk_partitions()
        disk_info = {}
        
        for partition in partitions:
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                disk_info[partition.device] = {
                    'mountpoint': partition.mountpoint,
                    'fstype': partition.fstype,
                    'total': self._format_bytes(usage.total),
                    'used': self._format_bytes(usage.used),
                    'free': self._format_bytes(usage.free),
                    'percent': usage.percent
                }
            except:
                continue
                
        return disk_info
    
    def get_network_info(self) -> Dict:
        """Get network information"""
        net_io = psutil.net_io_counters()
        net_if_addrs = psutil.net_if_addrs()
        net_if_stats = psutil.net_if_stats()
        
        network_info = {
            'bytes_sent': self._format_bytes(net_io.bytes_sent),
            'bytes_recv': self._format_bytes(net_io.bytes_recv),
            'packets_sent': net_io.packets_sent,
            'packets_recv': net_io.packets_recv,
            'interfaces': {}
        }
        
        for interface, addrs in net_if_addrs.items():
            network_info['interfaces'][interface] = {
                'addresses': [str(addr.address) for addr in addrs],
                'is_up': net_if_stats[interface].isup if interface in net_if_stats else False
            }
            
        return network_info
    
    def get_process_info(self, pid: Optional[int] = None) -> Union[Dict, List]:
        """Get process information"""
        if pid:
            try:
                proc = psutil.Process(pid)
                return self._process_to_dict(proc)
            except psutil.NoSuchProcess:
                return {'error': f'Process {pid} not found'}
        
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                processes.append(self._process_to_dict(proc))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
                
        return sorted(processes, key=lambda x: x.get('cpu_percent', 0), reverse=True)[:20]
    
    def get_system_info(self) -> Dict:
        """Get comprehensive system information"""
        return {
            'platform': {
                'system': platform.system(),
                'release': platform.release(),
                'version': platform.version(),
                'machine': platform.machine(),
                'processor': platform.processor(),
                'python_version': platform.python_version()
            },
            'boot_time': datetime.fromtimestamp(psutil.boot_time()).strftime('%Y-%m-%d %H:%M:%S'),
            'users': [user._asdict() for user in psutil.users()]
        }
    
    def start_monitoring(self):
        """Start real-time monitoring"""
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop real-time monitoring"""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=1)
    
    def get_monitoring_data(self) -> Optional[Dict]:
        """Get latest monitoring data"""
        try:
            return self.data_queue.get_nowait()
        except queue.Empty:
            return None
    
    def _monitor_loop(self):
        """Monitoring loop for real-time data"""
        while self.running:
            data = {
                'timestamp': datetime.now().isoformat(),
                'cpu': self.get_cpu_info(),
                'memory': self.get_memory_info(),
                'disk': self.get_disk_info(),
                'network': self.get_network_info()
            }
            self.data_queue.put(data)
            time.sleep(self.update_interval)
    
    def _process_to_dict(self, proc) -> Dict:
        """Convert process object to dictionary"""
        try:
            cpu_percent = proc.cpu_percent(interval=0.1)
            memory_info = proc.memory_info()
            
            return {
                'pid': proc.pid,
                'name': proc.name(),
                'status': proc.status(),
                'cpu_percent': cpu_percent,
                'memory_percent': proc.memory_percent(),
                'memory_rss': self._format_bytes(memory_info.rss),
                'memory_vms': self._format_bytes(memory_info.vms),
                'create_time': datetime.fromtimestamp(proc.create_time()).strftime('%Y-%m-%d %H:%M:%S'),
                'username': proc.username(),
                'exe': proc.exe() if proc.exe() else 'N/A',
                'cmdline': ' '.join(proc.cmdline()) if proc.cmdline() else 'N/A'
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return {'pid': proc.pid, 'name': 'Access Denied'}
    
    @staticmethod
    def _format_bytes(bytes_num: int) -> str:
        """Format bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_num < 1024.0:
                return f"{bytes_num:.2f} {unit}"
            bytes_num /= 1024.0
        return f"{bytes_num:.2f} PB"


class FileManager:
    """Advanced file management operations"""
    
    def __init__(self):
        self.operations_log = []
    
    def secure_copy(self, src: str, dst: str, buffer_size: int = 65536) -> Tuple[bool, str]:
        """Copy file with verification and progress tracking"""
        try:
            src_path = Path(src)
            dst_path = Path(dst)
            
            if not src_path.exists():
                return False, f"Source file not found: {src}"
            
            # Create destination directory if it doesn't exist
            dst_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Calculate file size for progress
            total_size = src_path.stat().st_size
            copied = 0
            
            # Get source file hash
            src_hash = self.calculate_hash(src)
            
            # Copy with progress
            with open(src, 'rb') as f_src, open(dst, 'wb') as f_dst:
                while True:
                    buffer = f_src.read(buffer_size)
                    if not buffer:
                        break
                    f_dst.write(buffer)
                    copied += len(buffer)
            
            # Verify copy with hash
            dst_hash = self.calculate_hash(dst)
            
            if src_hash == dst_hash:
                self._log_operation('COPY', src, dst, 'SUCCESS')
                return True, f"File copied successfully. Verified with hash: {src_hash}"
            else:
                dst_path.unlink()  # Delete corrupted copy
                return False, "Copy verification failed - hash mismatch"
                
        except Exception as e:
            return False, f"Copy failed: {str(e)}"
    
    def recursive_copy(self, src_dir: str, dst_dir: str, pattern: str = "*") -> Dict:
        """Recursively copy files matching pattern"""
        src_path = Path(src_dir)
        dst_path = Path(dst_dir)
        
        if not src_path.exists():
            return {'success': False, 'message': f"Source directory not found: {src_dir}"}
        
        results = {
            'total_files': 0,
            'copied_files': 0,
            'failed_files': 0,
            'failures': []
        }
        
        for file_path in src_path.rglob(pattern):
            if file_path.is_file():
                results['total_files'] += 1
                rel_path = file_path.relative_to(src_path)
                dst_file = dst_path / rel_path
                
                success, message = self.secure_copy(str(file_path), str(dst_file))
                if success:
                    results['copied_files'] += 1
                else:
                    results['failed_files'] += 1
                    results['failures'].append({
                        'file': str(file_path),
                        'error': message
                    })
        
        self._log_operation('RECURSIVE_COPY', src_dir, dst_dir, 
                           f"Copied {results['copied_files']} of {results['total_files']} files")
        return results
    
    def find_files(self, directory: str, pattern: str = "*", 
                   min_size: Optional[int] = None, 
                   max_size: Optional[int] = None,
                   modified_after: Optional[datetime] = None,
                   modified_before: Optional[datetime] = None) -> List[Dict]:
        """Find files with advanced filtering"""
        dir_path = Path(directory)
        
        if not dir_path.exists():
            return []
        
        files = []
        for file_path in dir_path.rglob(pattern):
            if file_path.is_file():
                file_stat = file_path.stat()
                
                # Apply filters
                if min_size and file_stat.st_size < min_size:
                    continue
                if max_size and file_stat.st_size > max_size:
                    continue
                if modified_after and datetime.fromtimestamp(file_stat.st_mtime) < modified_after:
                    continue
                if modified_before and datetime.fromtimestamp(file_stat.st_mtime) > modified_before:
                    continue
                
                files.append({
                    'path': str(file_path),
                    'size': file_stat.st_size,
                    'size_human': SystemMonitor._format_bytes(file_stat.st_size),
                    'modified': datetime.fromtimestamp(file_stat.st_mtime).isoformat(),
                    'created': datetime.fromtimestamp(file_stat.st_ctime).isoformat()
                })
        
        return files
    
    def calculate_hash(self, filepath: str, algorithm: str = 'sha256') -> str:
        """Calculate file hash"""
        hash_func = hashlib.new(algorithm)
        
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_func.update(chunk)
        
        return hash_func.hexdigest()
    
    def compare_directories(self, dir1: str, dir2: str) -> Dict:
        """Compare two directories"""
        dir1_path = Path(dir1)
        dir2_path = Path(dir2)
        
        if not dir1_path.exists() or not dir2_path.exists():
            return {'error': 'One or both directories do not exist'}
        
        dir1_files = {f.relative_to(dir1_path): f for f in dir1_path.rglob('*') if f.is_file()}
        dir2_files = {f.relative_to(dir2_path): f for f in dir2_path.rglob('*') if f.is_file()}
        
        comparison = {
            'only_in_dir1': [],
            'only_in_dir2': [],
            'different_files': [],
            'identical_files': []
        }
        
        all_files = set(dir1_files.keys()) | set(dir2_files.keys())
        
        for rel_path in all_files:
            if rel_path not in dir1_files:
                comparison['only_in_dir2'].append(str(rel_path))
            elif rel_path not in dir2_files:
                comparison['only_in_dir1'].append(str(rel_path))
            else:
                hash1 = self.calculate_hash(str(dir1_files[rel_path]))
                hash2 = self.calculate_hash(str(dir2_files[rel_path]))
                
                if hash1 == hash2:
                    comparison['identical_files'].append(str(rel_path))
                else:
                    comparison['different_files'].append(str(rel_path))
        
        return comparison
    
    def _log_operation(self, operation: str, source: str, destination: str, status: str):
        """Log file operations"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'operation': operation,
            'source': source,
            'destination': destination,
            'status': status
        }
        self.operations_log.append(log_entry)
    
    def get_operations_log(self) -> List[Dict]:
        """Get operations log"""
        return self.operations_log.copy()


class ProcessManager:
    """Advanced process management"""
    
    def __init__(self):
        self.process_history = []
    
    def list_processes(self, detailed: bool = False) -> List[Dict]:
        """List all processes"""
        processes = []
        
        for proc in psutil.process_iter(['pid', 'name', 'username', 'status']):
            try:
                proc_info = {
                    'pid': proc.pid,
                    'name': proc.name(),
                    'username': proc.username(),
                    'status': proc.status()
                }
                
                if detailed:
                    with proc.oneshot():
                        proc_info.update({
                            'cpu_percent': proc.cpu_percent(interval=0.1),
                            'memory_percent': proc.memory_percent(),
                            'memory_info': proc.memory_info()._asdict(),
                            'create_time': datetime.fromtimestamp(proc.create_time()).isoformat(),
                            'exe': proc.exe() if proc.exe() else None,
                            'cmdline': proc.cmdline(),
                            'connections': len(proc.connections()) if hasattr(proc, 'connections') else 0
                        })
                
                processes.append(proc_info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        return sorted(processes, key=lambda x: x['pid'])
    
    def get_process_details(self, pid: int) -> Optional[Dict]:
        """Get detailed information about a process"""
        try:
            proc = psutil.Process(pid)
            
            with proc.oneshot():
                details = {
                    'pid': proc.pid,
                    'name': proc.name(),
                    'status': proc.status(),
                    'username': proc.username(),
                    'create_time': datetime.fromtimestamp(proc.create_time()).isoformat(),
                    'cpu_percent': proc.cpu_percent(interval=0.1),
                    'memory_percent': proc.memory_percent(),
                    'memory_info': proc.memory_info()._asdict(),
                    'exe': proc.exe(),
                    'cmdline': proc.cmdline(),
                    'cwd': proc.cwd(),
                    'environ': dict(proc.environ()),
                    'threads': proc.num_threads(),
                    'open_files': [f._asdict() for f in proc.open_files()] if proc.open_files() else [],
                    'connections': [c._asdict() for c in proc.connections()] if hasattr(proc, 'connections') else []
                }
            
            return details
        except psutil.NoSuchProcess:
            return None
    
    def kill_process(self, pid: int, force: bool = False) -> Tuple[bool, str]:
        """Kill a process"""
        try:
            proc = psutil.Process(pid)
            
            if force:
                proc.kill()
                action = 'forcefully killed'
            else:
                proc.terminate()
                action = 'terminated'
            
            self._log_process_action(pid, action, 'SUCCESS')
            return True, f"Process {pid} {action} successfully"
            
        except psutil.NoSuchProcess:
            return False, f"Process {pid} does not exist"
        except psutil.AccessDenied:
            return False, f"Access denied to process {pid}"
        except Exception as e:
            return False, f"Failed to kill process {pid}: {str(e)}"
    
    def kill_process_tree(self, pid: int) -> Tuple[bool, str]:
        """Kill a process and all its children"""
        try:
            parent = psutil.Process(pid)
            children = parent.children(recursive=True)
            
            # Kill children first
            for child in children:
                try:
                    child.kill()
                except:
                    pass
            
            # Kill parent
            parent.kill()
            
            self._log_process_action(pid, 'killed with children', 'SUCCESS')
            return True, f"Process tree for {pid} killed successfully"
            
        except psutil.NoSuchProcess:
            return False, f"Process {pid} does not exist"
        except Exception as e:
            return False, f"Failed to kill process tree: {str(e)}"
    
    def start_process(self, command: List[str], 
                      cwd: Optional[str] = None,
                      env: Optional[Dict] = None,
                      capture_output: bool = False) -> Dict:
        """Start a new process"""
        try:
            if capture_output:
                result = subprocess.run(
                    command,
                    cwd=cwd,
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                output = {
                    'returncode': result.returncode,
                    'stdout': result.stdout,
                    'stderr': result.stderr
                }
            else:
                # Start detached process
                proc = subprocess.Popen(
                    command,
                    cwd=cwd,
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    start_new_session=True
                )
                
                output = {
                    'pid': proc.pid,
                    'returncode': None,
                    'stdout': 'Process started in background',
                    'stderr': ''
                }
            
            self._log_process_action(
                output.get('pid', 'N/A'), 
                'started', 
                'SUCCESS',
                command=' '.join(command)
            )
            
            return {'success': True, 'output': output}
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def monitor_process(self, pid: int, interval: int = 1, duration: int = 60) -> List[Dict]:
        """Monitor a process over time"""
        monitoring_data = []
        end_time = time.time() + duration
        
        while time.time() < end_time:
            try:
                proc = psutil.Process(pid)
                
                with proc.oneshot():
                    data = {
                        'timestamp': datetime.now().isoformat(),
                        'cpu_percent': proc.cpu_percent(interval=0.1),
                        'memory_percent': proc.memory_percent(),
                        'memory_rss': proc.memory_info().rss,
                        'threads': proc.num_threads(),
                        'status': proc.status()
                    }
                    monitoring_data.append(data)
                
                time.sleep(interval)
                
            except psutil.NoSuchProcess:
                break
            except Exception:
                continue
        
        return monitoring_data
    
    def find_process_by_name(self, name: str) -> List[Dict]:
        """Find processes by name (partial match)"""
        matching_processes = []
        
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                if (name.lower() in proc.info['name'].lower() or
                    (proc.info['cmdline'] and 
                     any(name.lower() in cmd.lower() for cmd in proc.info['cmdline']))):
                    
                    matching_processes.append({
                        'pid': proc.info['pid'],
                        'name': proc.info['name'],
                        'cmdline': proc.info['cmdline']
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        return matching_processes
    
    def _log_process_action(self, pid: int, action: str, status: str, command: str = ''):
        """Log process actions"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'pid': pid,
            'action': action,
            'status': status,
            'command': command
        }
        self.process_history.append(log_entry)
    
    def get_process_history(self) -> List[Dict]:
        """Get process action history"""
        return self.process_history.copy()


class NetworkTools:
    """Network utilities and tools"""
    
    def __init__(self):
        self.scan_results = []
    
    def get_network_interfaces(self) -> Dict:
        """Get all network interfaces"""
        interfaces = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        
        result = {}
        for interface, addrs in interfaces.items():
            result[interface] = {
                'addresses': [
                    {
                        'family': str(addr.family),
                        'address': addr.address,
                        'netmask': addr.netmask if addr.netmask else None,
                        'broadcast': addr.broadcast if addr.broadcast else None
                    }
                    for addr in addrs
                ],
                'is_up': stats[interface].isup if interface in stats else False,
                'speed': stats[interface].speed if interface in stats else 0,
                'mtu': stats[interface].mtu if interface in stats else 0
            }
        
        return result
    
    def port_scan(self, target: str, ports: List[int] = None, 
                  timeout: float = 1.0) -> List[Dict]:
        """Scan ports on target host"""
        if ports is None:
            ports = list(range(1, 1025))  # Scan common ports
        
        results = []
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                
                result = sock.connect_ex((target, port))
                
                if result == 0:
                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = 'unknown'
                    
                    results.append({
                        'port': port,
                        'status': 'OPEN',
                        'service': service
                    })
                else:
                    results.append({
                        'port': port,
                        'status': 'CLOSED',
                        'service': None
                    })
                
                sock.close()
                
            except socket.error:
                results.append({
                    'port': port,
                    'status': 'ERROR',
                    'service': None
                })
        
        self.scan_results.append({
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'results': results
        })
        
        return results
    
    def get_connections(self) -> List[Dict]:
        """Get all network connections"""
        connections = []
        
        for conn in psutil.net_connections():
            try:
                conn_info = {
                    'fd': conn.fd,
                    'family': str(conn.family),
                    'type': str(conn.type),
                    'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                    'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    'status': conn.status,
                    'pid': conn.pid
                }
                connections.append(conn_info)
            except (psutil.NoSuchProcess, AttributeError):
                continue
        
        return connections
    
    def get_bandwidth_usage(self) -> Dict:
        """Get network bandwidth usage"""
        net_io = psutil.net_io_counters()
        
        return {
            'bytes_sent': net_io.bytes_sent,
            'bytes_recv': net_io.bytes_recv,
            'packets_sent': net_io.packets_sent,
            'packets_recv': net_io.packets_recv,
            'errin': net_io.errin,
            'errout': net_io.errout,
            'dropin': net_io.dropin,
            'dropout': net_io.dropout
        }
    
    def ping_host(self, host: str, count: int = 4, timeout: int = 2) -> Dict:
        """Ping a host"""
        try:
            # Platform-specific ping command
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            
            command = ['ping', param, str(count), '-W', str(timeout), host]
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=count * timeout + 5
            )
            
            return {
                'success': result.returncode == 0,
                'output': result.stdout,
                'error': result.stderr,
                'returncode': result.returncode
            }
            
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'output': '',
                'error': 'Ping timeout',
                'returncode': -1
            }
        except Exception as e:
            return {
                'success': False,
                'output': '',
                'error': str(e),
                'returncode': -1
            }
    
    def get_dns_info(self, domain: str) -> Dict:
        """Get DNS information for domain"""
        try:
            # Get A records (IPv4)
            ipv4_addresses = []
            try:
                ipv4_info = socket.getaddrinfo(domain, None, socket.AF_INET)
                ipv4_addresses = [info[4][0] for info in ipv4_info]
            except:
                pass
            
            # Get AAAA records (IPv6)
            ipv6_addresses = []
            try:
                ipv6_info = socket.getaddrinfo(domain, None, socket.AF_INET6)
                ipv6_addresses = [info[4][0] for info in ipv6_info]
            except:
                pass
            
            return {
                'domain': domain,
                'ipv4_addresses': ipv4_addresses,
                'ipv6_addresses': ipv6_addresses,
                'canonical_name': socket.getfqdn(domain)
            }
            
        except socket.gaierror as e:
            return {
                'domain': domain,
                'error': str(e)
            }


class SystemUtils:
    """System utility functions"""
    
    @staticmethod
    def get_system_uptime() -> str:
        """Get system uptime"""
        uptime_seconds = time.time() - psutil.boot_time()
        
        days = uptime_seconds // 86400
        hours = (uptime_seconds % 86400) // 3600
        minutes = (uptime_seconds % 3600) // 60
        seconds = uptime_seconds % 60
        
        return f"{int(days)}d {int(hours)}h {int(minutes)}m {int(seconds)}s"
    
    @staticmethod
    def get_logged_in_users() -> List[Dict]:
        """Get logged in users"""
        users = []
        for user in psutil.users():
            users.append({
                'name': user.name,
                'terminal': user.terminal,
                'host': user.host,
                'started': datetime.fromtimestamp(user.started).isoformat(),
                'pid': user.pid
            })
        return users
    
    @staticmethod
    def get_battery_info() -> Optional[Dict]:
        """Get battery information"""
        try:
            battery = psutil.sensors_battery()
            if battery:
                return {
                    'percent': battery.percent,
                    'power_plugged': battery.power_plugged,
                    'secsleft': battery.secsleft if battery.secsleft != psutil.POWER_TIME_UNLIMITED else 'Unlimited',
                    'time_left': f"{battery.secsleft // 3600}h {(battery.secsleft % 3600) // 60}m" if battery.secsleft != psutil.POWER_TIME_UNLIMITED else 'Unlimited'
                }
        except AttributeError:
            pass
        return None
    
    @staticmethod
    def get_sensors_info() -> Dict:
        """Get sensor information"""
        sensors = {}
        
        try:
            # Temperature sensors
            temps = psutil.sensors_temperatures()
            if temps:
                sensors['temperatures'] = {}
                for name, entries in temps.items():
                    sensors['temperatures'][name] = [
                        {'label': entry.label or f'Sensor {i}', 
                         'current': entry.current, 
                         'high': entry.high, 
                         'critical': entry.critical}
                        for i, entry in enumerate(entries)
                    ]
        except AttributeError:
            pass
        
        try:
            # Fan sensors
            fans = psutil.sensors_fans()
            if fans:
                sensors['fans'] = {}
                for name, entries in fans.items():
                    sensors['fans'][name] = [
                        {'label': entry.label or f'Fan {i}', 'current': entry.current}
                        for i, entry in enumerate(entries)
                    ]
        except AttributeError:
            pass
        
        return sensors
    
    @staticmethod
    def run_command(command: str, timeout: int = 30) -> Dict:
        """Run a shell command"""
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            return {
                'success': result.returncode == 0,
                'returncode': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'command': command
            }
            
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'returncode': -1,
                'stdout': '',
                'stderr': 'Command timeout',
                'command': command
            }
        except Exception as e:
            return {
                'success': False,
                'returncode': -1,
                'stdout': '',
                'stderr': str(e),
                'command': command
            }
    
    @staticmethod
    def get_system_load() -> Dict:
        """Get system load averages"""
        load_avg = os.getloadavg() if hasattr(os, 'getloadavg') else (0, 0, 0)
        
        return {
            '1min': load_avg[0],
            '5min': load_avg[1],
            '15min': load_avg[2],
            'cpu_count': psutil.cpu_count()
        }


class AdvancedOSToolkit:
    """Main class combining all toolkit functionality"""
    
    def __init__(self):
        self.monitor = SystemMonitor()
        self.file_manager = FileManager()
        self.process_manager = ProcessManager()
        self.network_tools = NetworkTools()
        self.utils = SystemUtils()
        
    def generate_report(self, report_type: str = 'full') -> Dict:
        """Generate system report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'system': platform.system(),
            'report_type': report_type
        }
        
        if report_type in ['full', 'system']:
            report['system_info'] = self.monitor.get_system_info()
            report['uptime'] = self.utils.get_system_uptime()
            report['load'] = self.utils.get_system_load()
        
        if report_type in ['full', 'hardware']:
            report['cpu'] = self.monitor.get_cpu_info()
            report['memory'] = self.monitor.get_memory_info()
            report['disk'] = self.monitor.get_disk_info()
            report['battery'] = self.utils.get_battery_info()
            report['sensors'] = self.utils.get_sensors_info()
        
        if report_type in ['full', 'network']:
            report['network'] = self.monitor.get_network_info()
            report['connections'] = self.network_tools.get_connections()
        
        if report_type in ['full', 'processes']:
            report['processes'] = self.process_manager.list_processes(detailed=True)[:50]  # Top 50
        
        if report_type in ['full', 'users']:
            report['users'] = self.utils.get_logged_in_users()
        
        return report
    
    def save_report(self, filename: str = None, report_type: str = 'full') -> str:
        """Save report to file"""
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f'system_report_{timestamp}.json'
        
        report = self.generate_report(report_type)
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        return filename


# Export main classes
__all__ = [
    'AdvancedOSToolkit',
    'SystemMonitor',
    'FileManager',
    'ProcessManager',
    'NetworkTools',
    'SystemUtils'
]
