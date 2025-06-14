#!/usr/bin/env python3
"""
"""

import struct
import os
import datetime

class MemoryDumpCreator:
    def __init__(self):
        self.dump_data = bytearray()
        self.processes = []
        self.network_connections = []
        self.injected_code = []
        
    def create_windows_header(self):
        """Create Windows memory dump header"""
        header = b'PAGEDUMP'  # Windows crash dump signature
        header += b'\x00' * 8  # Padding
        
        # System info structure
        header += b'Windows 10 Pro x64\x00' * 2
        header += struct.pack('<I', 0x1A0B)  # Build number (Windows 10)
        header += struct.pack('<I', 0x8)     # Processor count
        header += b'\x00' * 100  # Additional padding
        
        return header
    
    def add_process_data(self):
        """Add realistic process data for lab scenario"""
        processes = [
            # PID, PPID, Name, Threads, Start_Time, Suspicious
            (4, 0, "System", 234, "2024-06-13 08:30:15", False),
            (400, 4, "smss.exe", 2, "2024-06-13 08:30:16", False),
            (472, 400, "csrss.exe", 12, "2024-06-13 08:30:17", False),
            (548, 540, "winlogon.exe", 5, "2024-06-13 08:30:18", False),
            (596, 548, "services.exe", 8, "2024-06-13 08:30:19", False),
            (612, 548, "lsass.exe", 9, "2024-06-13 08:30:20", False),
            (820, 596, "svchost.exe", 15, "2024-06-13 08:30:25", False),
            (916, 596, "svchost.exe", 12, "2024-06-13 08:30:26", False),
            (1024, 596, "svchost.exe", 18, "2024-06-13 08:30:27", False),
            (1156, 820, "explorer.exe", 25, "2024-06-13 08:31:15", False),
            (1340, 1156, "notepad.exe", 2, "2024-06-13 09:15:30", False),
            (1448, 1156, "chrome.exe", 8, "2024-06-13 09:20:45", False),
            # SUSPICIOUS PROCESSES
            (1666, 1340, "cmd.exe", 1, "2024-06-13 10:45:22", True),
            (1777, 1666, "powershell.exe", 3, "2024-06-13 10:45:25", True),
            (1888, 4, "svchost.exe", 1, "2024-06-13 10:46:00", True),
            (1999, 1888, "explorer.exe", 1, "2024-06-13 10:46:15", True),
            (2100, 1777, "mimikatz.exe", 2, "2024-06-13 10:47:30", True),
        ]
        
        for pid, ppid, name, threads, start_time, suspicious in processes:
            self.add_process_entry(pid, ppid, name, threads, start_time, suspicious)
    
    def add_process_entry(self, pid, ppid, name, threads, start_time, suspicious):
        """Add a single process entry to memory dump"""
        process_data = struct.pack('<I', pid)  # Process ID
        process_data += struct.pack('<I', ppid)  # Parent Process ID
        process_data += name.ljust(16, '\x00').encode('ascii')[:16]  # Process name
        process_data += struct.pack('<I', threads)  # Thread count
        process_data += start_time.encode('ascii').ljust(20, b'\x00')[:20]  # Start time
        process_data += struct.pack('<B', 1 if suspicious else 0)  # Suspicious flag
        process_data += b'\x00' * 15  # Padding
        
        self.processes.append(process_data)
    
    def add_network_data(self):
        """Add network connection data"""
        connections = [
            # Local IP, Local Port, Remote IP, Remote Port, State, PID
            ("192.168.1.10", 445, "0.0.0.0", 0, "LISTENING", 4),
            ("192.168.1.10", 135, "0.0.0.0", 0, "LISTENING", 916),
            ("192.168.1.10", 49152, "192.168.1.1", 53, "ESTABLISHED", 1024),
            ("192.168.1.10", 80, "0.0.0.0", 0, "LISTENING", 1448),
            # SUSPICIOUS CONNECTIONS
            ("192.168.1.10", 4444, "192.168.1.100", 4444, "ESTABLISHED", 1888),
            ("192.168.1.10", 8080, "10.0.0.50", 8080, "ESTABLISHED", 1999),
            ("192.168.1.10", 443, "malicious-domain.com", 443, "ESTABLISHED", 1777),
        ]
        
        for local_ip, local_port, remote_ip, remote_port, state, pid in connections:
            self.add_network_entry(local_ip, local_port, remote_ip, remote_port, state, pid)
    
    def add_network_entry(self, local_ip, local_port, remote_ip, remote_port, state, pid):
        """Add network connection entry"""
        conn_data = local_ip.ljust(16, '\x00').encode('ascii')[:16]
        conn_data += struct.pack('<H', local_port)
        conn_data += remote_ip.ljust(16, '\x00').encode('ascii')[:16]
        conn_data += struct.pack('<H', remote_port)
        conn_data += state.ljust(12, '\x00').encode('ascii')[:12]
        conn_data += struct.pack('<I', pid)
        conn_data += b'\x00' * 10  # Padding
        
        self.network_connections.append(conn_data)
    
    def add_injected_code_signatures(self):
        """Add code injection signatures"""
        shellcode_patterns = [
            b'\x90\x90\x90\x90\xFC\x48\x83\xE4\xF0\xE8',  # NOP sled + common shellcode
            b'\x48\x31\xC9\x48\x81\xE9\x03\x00\x00\x00',  # x64 shellcode pattern
            b'\x4D\x5A\x90\x00\x03\x00\x00\x00',          # PE header in wrong location
            b'\xE8\x00\x00\x00\x00\x5B\x81\xEB\x05',      # GetPC shellcode
        ]
        
        for i, pattern in enumerate(shellcode_patterns):
            injection_data = struct.pack('<I', 1888 + i)  # PID
            injection_data += struct.pack('<Q', 0x401000 + (i * 0x1000))  # Virtual address
            injection_data += struct.pack('<I', len(pattern))  # Size
            injection_data += pattern
            injection_data += b'\x00' * (64 - len(pattern))  # Padding
            
            self.injected_code.append(injection_data)
    
    def add_artifacts(self):
        """Add user artifacts"""
        artifacts = {
            'clipboard': b'admin123\x00password\x00',
            'cmdline_1666': b'cmd.exe /c whoami\x00',
            'cmdline_1777': b'powershell.exe -enc JABhAD0AJwBoAHQAdABwADoALwAvAG0AYQBsAGkAYwBpAG8AdQBzAC0AZABvAG0AYQBpAG4ALgBjAG8AbQAnAA==\x00',
            'cmdline_2100': b'mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords"\x00',
            'browser_history': b'http://malicious-domain.com/payload.exe\x00http://192.168.1.100/c2\x00',
            'lsa_secrets': b'ADMIN_PASSWORD:SecretPass123\x00SERVICE_ACCOUNT:ServiceP@ss\x00',
        }
        
        return artifacts
    
    def create_file_system_artifacts(self):
        """Create file system artifacts"""
        files = [
            ('C:\\Users\\victim\\Desktop\\invoice.pdf.exe', 'Suspicious double extension'),
            ('C:\\Temp\\payload.exe', 'Malware in temp directory'),
            ('C:\\Users\\victim\\Downloads\\update.scr', 'Suspicious screensaver'),
            ('C:\\Windows\\System32\\evil.dll', 'Malicious DLL in system directory'),
        ]
        
        file_data = b''
        for filepath, description in files:
            file_entry = filepath.encode('utf-16le').ljust(520, b'\x00')
            file_entry += description.encode('ascii').ljust(100, b'\x00')
            file_data += file_entry
        
        return file_data
    
    def create_dump(self, filename='infected_system.raw'):
        """Create the complete memory dump file"""
        print(f"Creating memory dump: {filename}")
        
        # Add Windows header
        self.dump_data.extend(self.create_windows_header())
        
        # Add process data
        print("Adding process data...")
        self.add_process_data()
        for process in self.processes:
            self.dump_data.extend(process)
        
        # Add network data
        print("Adding network connection data...")
        self.add_network_data()
        for conn in self.network_connections:
            self.dump_data.extend(conn)
        
        # Add code injection signatures
        print("Adding malware signatures...")
        self.add_injected_code_signatures()
        for injection in self.injected_code:
            self.dump_data.extend(injection)
        
        # Add user artifacts
        print("Adding user artifacts...")
        artifacts = self.add_artifacts()
        for key, value in artifacts.items():
            header = key.encode('ascii').ljust(32, b'\x00')
            header += struct.pack('<I', len(value))
            self.dump_data.extend(header)
            self.dump_data.extend(value)
        
        # Add file system artifacts
        print("Adding file system artifacts...")
        fs_data = self.create_file_system_artifacts()
        self.dump_data.extend(fs_data)
        
        # Pad to minimum size
        while len(self.dump_data) < 5 * 1024 * 1024:  # 5MB minimum
            self.dump_data.extend(b'\x00' * 1024)
        
        # Write to file
        with open(filename, 'wb') as f:
            f.write(self.dump_data)
        
        file_size = len(self.dump_data)
        print(f"Memory dump created successfully!")
        print(f"File: {filename}")
        print(f"Size: {file_size:,} bytes ({file_size/1024/1024:.1f} MB)")
        print(f"Contains {len(self.processes)} processes and {len(self.network_connections)} network connections")

def main():
    creator = MemoryDumpCreator()
    creator.create_dump('infected_system.raw')

if __name__ == "__main__":
    main()
