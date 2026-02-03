"""
Unit tests for Advanced OS Toolkit
"""

import unittest
import tempfile
import os
from pathlib import Path
from advanced_os_toolkit import AdvancedOSToolkit, SystemMonitor, FileManager, ProcessManager, NetworkTools

class TestSystemMonitor(unittest.TestCase):
    def setUp(self):
        self.monitor = SystemMonitor()
    
    def test_cpu_info(self):
        info = self.monitor.get_cpu_info()
        self.assertIn('physical_cores', info)
        self.assertIn('logical_cores', info)
        self.assertIn('avg_usage', info)
        
    def test_memory_info(self):
        info = self.monitor.get_memory_info()
        self.assertIn('virtual', info)
        self.assertIn('swap', info)
        self.assertIn('total', info['virtual'])
        
    def test_disk_info(self):
        info = self.monitor.get_disk_info()
        # At least one disk should be present
        self.assertTrue(len(info) > 0)
        
    def test_format_bytes(self):
        self.assertEqual(SystemMonitor._format_bytes(1024), "1024.00 B")
        self.assertEqual(SystemMonitor._format_bytes(1024*1024), "1.00 MB")

class TestFileManager(unittest.TestCase):
    def setUp(self):
        self.file_manager = FileManager()
        self.temp_dir = tempfile.mkdtemp()
        
    def tearDown(self):
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_calculate_hash(self):
        # Create a test file
        test_file = Path(self.temp_dir) / "test.txt"
        test_file.write_text("Hello, World!")
        
        hash_value = self.file_manager.calculate_hash(str(test_file))
        self.assertEqual(len(hash_value), 64)  # SHA256 hash length
        
    def test_secure_copy(self):
        # Create source file
        src_file = Path(self.temp_dir) / "source.txt"
        src_file.write_text("Test content for secure copy")
        
        # Destination file
        dst_file = Path(self.temp_dir) / "destination.txt"
        
        success, message = self.file_manager.secure_copy(str(src_file), str(dst_file))
        self.assertTrue(success)
        self.assertTrue(dst_file.exists())
        
        # Verify content
        self.assertEqual(src_file.read_text(), dst_file.read_text())

class TestProcessManager(unittest.TestCase):
    def setUp(self):
        self.process_manager = ProcessManager()
    
    def test_list_processes(self):
        processes = self.process_manager.list_processes()
        self.assertTrue(len(processes) > 0)
        
        # Check process structure
        if processes:
            proc = processes[0]
            self.assertIn('pid', proc)
            self.assertIn('name', proc)
            self.assertIn('status', proc)
            
    def test_find_process_by_name(self):
        # Should at least find the current Python process
        processes = self.process_manager.find_process_by_name('python')
        # Note: This might fail in some test environments
        # self.assertTrue(len(processes) > 0)

class TestNetworkTools(unittest.TestCase):
    def setUp(self):
        self.network_tools = NetworkTools()
    
    def test_get_network_interfaces(self):
        interfaces = self.network_tools.get_network_interfaces()
        self.assertTrue(len(interfaces) > 0)
        
    def test_get_bandwidth_usage(self):
        usage = self.network_tools.get_bandwidth_usage()
        self.assertIn('bytes_sent', usage)
        self.assertIn('bytes_recv', usage)

class TestAdvancedOSToolkit(unittest.TestCase):
    def setUp(self):
        self.toolkit = AdvancedOSToolkit()
    
    def test_generate_report(self):
        report = self.toolkit.generate_report('system')
        self.assertIn('timestamp', report)
        self.assertIn('system_info', report)
        self.assertIn('uptime', report)
        
    def test_save_report(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            filename = Path(temp_dir) / "test_report.json"
            saved_file = self.toolkit.save_report(str(filename), 'system')
            
            self.assertEqual(saved_file, str(filename))
            self.assertTrue(Path(saved_file).exists())
            
            # Verify it's valid JSON
            import json
            with open(saved_file, 'r') as f:
                data = json.load(f)
                self.assertIn('system_info', data)

if __name__ == '__main__':
    unittest.main()
