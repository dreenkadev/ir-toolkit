#!/usr/bin/env python3
"""
Incident Response Toolkit - Automated forensic data collection

Features:
- System info collection
- Process listing
- Network connections
- User accounts
- Scheduled tasks
- Auto-start entries
- Recent files
- Event logs
"""

import argparse
import json
import os
import platform
import socket
import subprocess
import sys
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any

VERSION = "1.0.0"

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'


class IRCollector:
    def __init__(self, output_dir: str = "./ir_collection"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.data: Dict[str, Any] = {
            'collection_time': datetime.now().isoformat(),
            'hostname': socket.gethostname(),
            'platform': platform.system()
        }
        
    def run_command(self, cmd: str) -> str:
        """Run a command and return output"""
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, 
                text=True, timeout=30
            )
            return result.stdout
        except:
            return ""
    
    def collect_system_info(self):
        """Collect system information"""
        print(f"{Colors.CYAN}[1/8]{Colors.RESET} Collecting system info...")
        
        info = {
            'os': platform.system(),
            'os_release': platform.release(),
            'os_version': platform.version(),
            'machine': platform.machine(),
            'processor': platform.processor(),
            'hostname': socket.gethostname(),
            'python_version': platform.python_version(),
        }
        
        # Get uptime
        if platform.system() == 'Linux':
            uptime = self.run_command("uptime -p")
            info['uptime'] = uptime.strip()
            
            # Get kernel
            info['kernel'] = self.run_command("uname -r").strip()
        
        self.data['system_info'] = info
        
    def collect_processes(self):
        """Collect running processes"""
        print(f"{Colors.CYAN}[2/8]{Colors.RESET} Collecting processes...")
        
        processes = []
        
        if platform.system() == 'Linux':
            output = self.run_command("ps aux --no-headers")
            for line in output.strip().split('\n'):
                if line:
                    parts = line.split(None, 10)
                    if len(parts) >= 11:
                        processes.append({
                            'user': parts[0],
                            'pid': parts[1],
                            'cpu': parts[2],
                            'mem': parts[3],
                            'command': parts[10][:100]
                        })
        
        self.data['processes'] = processes[:100]  # Limit
        print(f"    Found {len(processes)} processes")
        
    def collect_network(self):
        """Collect network connections"""
        print(f"{Colors.CYAN}[3/8]{Colors.RESET} Collecting network connections...")
        
        connections = []
        
        if platform.system() == 'Linux':
            output = self.run_command("ss -tunapl 2>/dev/null | head -100")
            for line in output.strip().split('\n')[1:]:
                if line:
                    parts = line.split()
                    if len(parts) >= 5:
                        connections.append({
                            'proto': parts[0],
                            'local': parts[4],
                            'remote': parts[5] if len(parts) > 5 else '',
                            'state': parts[1] if len(parts) > 1 else ''
                        })
        
        # Get listening ports
        listening = self.run_command("ss -tlnp 2>/dev/null")
        
        self.data['network'] = {
            'connections': connections,
            'interfaces': self.get_interfaces()
        }
        print(f"    Found {len(connections)} connections")
        
    def get_interfaces(self) -> List[Dict]:
        """Get network interfaces"""
        interfaces = []
        
        if platform.system() == 'Linux':
            output = self.run_command("ip addr show")
            current = {}
            for line in output.split('\n'):
                if line and not line.startswith(' '):
                    if current:
                        interfaces.append(current)
                    parts = line.split(':')
                    current = {'name': parts[1].strip() if len(parts) > 1 else ''}
                elif 'inet ' in line:
                    parts = line.strip().split()
                    current['ipv4'] = parts[1] if len(parts) > 1 else ''
            if current:
                interfaces.append(current)
        
        return interfaces
        
    def collect_users(self):
        """Collect user accounts"""
        print(f"{Colors.CYAN}[4/8]{Colors.RESET} Collecting user accounts...")
        
        users = []
        
        if platform.system() == 'Linux':
            # Get users from passwd
            try:
                with open('/etc/passwd', 'r') as f:
                    for line in f:
                        parts = line.strip().split(':')
                        if len(parts) >= 7:
                            uid = int(parts[2])
                            # Only include real users
                            if uid >= 1000 or uid == 0:
                                users.append({
                                    'username': parts[0],
                                    'uid': parts[2],
                                    'gid': parts[3],
                                    'home': parts[5],
                                    'shell': parts[6]
                                })
            except:
                pass
            
            # Get logged in users
            logged_in = self.run_command("who")
            
        self.data['users'] = {
            'accounts': users,
            'logged_in': self.run_command("who").strip().split('\n') if platform.system() == 'Linux' else []
        }
        print(f"    Found {len(users)} user accounts")
        
    def collect_scheduled_tasks(self):
        """Collect scheduled tasks/cron jobs"""
        print(f"{Colors.CYAN}[5/8]{Colors.RESET} Collecting scheduled tasks...")
        
        tasks = []
        
        if platform.system() == 'Linux':
            # System crontab
            crontab = self.run_command("cat /etc/crontab 2>/dev/null")
            if crontab:
                tasks.append({'type': 'system_crontab', 'content': crontab[:1000]})
            
            # User crontabs
            user_cron = self.run_command("crontab -l 2>/dev/null")
            if user_cron:
                tasks.append({'type': 'user_crontab', 'content': user_cron[:1000]})
            
            # Cron directories
            for cron_dir in ['/etc/cron.d', '/etc/cron.daily', '/etc/cron.hourly']:
                if os.path.exists(cron_dir):
                    files = os.listdir(cron_dir)
                    tasks.append({'type': cron_dir, 'files': files})
            
            # Systemd timers
            timers = self.run_command("systemctl list-timers --no-pager 2>/dev/null | head -20")
            if timers:
                tasks.append({'type': 'systemd_timers', 'content': timers})
        
        self.data['scheduled_tasks'] = tasks
        
    def collect_autostart(self):
        """Collect auto-start entries"""
        print(f"{Colors.CYAN}[6/8]{Colors.RESET} Collecting autostart entries...")
        
        autostart = []
        
        if platform.system() == 'Linux':
            # Systemd services
            services = self.run_command("systemctl list-unit-files --type=service --state=enabled --no-pager 2>/dev/null | head -50")
            if services:
                autostart.append({'type': 'systemd_enabled', 'content': services})
            
            # Init.d
            if os.path.exists('/etc/init.d'):
                autostart.append({'type': 'initd', 'files': os.listdir('/etc/init.d')})
            
            # rc.local
            rclocal = self.run_command("cat /etc/rc.local 2>/dev/null")
            if rclocal:
                autostart.append({'type': 'rc.local', 'content': rclocal[:500]})
        
        self.data['autostart'] = autostart
        
    def collect_recent_files(self):
        """Collect recently modified files"""
        print(f"{Colors.CYAN}[7/8]{Colors.RESET} Collecting recent files...")
        
        recent = []
        
        if platform.system() == 'Linux':
            # Files modified in last 24 hours
            output = self.run_command("find /home /tmp /var/log -mtime -1 -type f 2>/dev/null | head -100")
            for line in output.strip().split('\n'):
                if line:
                    try:
                        stat = os.stat(line)
                        recent.append({
                            'path': line,
                            'mtime': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                            'size': stat.st_size
                        })
                    except:
                        pass
        
        self.data['recent_files'] = recent[:50]
        print(f"    Found {len(recent)} recent files")
        
    def collect_logs(self):
        """Collect relevant log entries"""
        print(f"{Colors.CYAN}[8/8]{Colors.RESET} Collecting log snippets...")
        
        logs = {}
        
        if platform.system() == 'Linux':
            log_files = [
                '/var/log/auth.log',
                '/var/log/syslog',
                '/var/log/secure',
                '/var/log/messages'
            ]
            
            for log_file in log_files:
                if os.path.exists(log_file):
                    # Get last 50 lines
                    output = self.run_command(f"tail -50 {log_file} 2>/dev/null")
                    if output:
                        logs[log_file] = output
        
        self.data['logs'] = logs
        
    def save_results(self):
        """Save collected data"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"ir_collection_{timestamp}.json"
        filepath = self.output_dir / filename
        
        with open(filepath, 'w') as f:
            json.dump(self.data, f, indent=2, default=str)
        
        return filepath
    
    def run_collection(self) -> str:
        """Run full collection"""
        print(f"\n{Colors.BOLD}Starting Incident Response Collection{Colors.RESET}")
        print(f"Hostname: {self.data['hostname']}")
        print(f"Platform: {self.data['platform']}")
        print(f"{Colors.CYAN}{'─' * 50}{Colors.RESET}\n")
        
        self.collect_system_info()
        self.collect_processes()
        self.collect_network()
        self.collect_users()
        self.collect_scheduled_tasks()
        self.collect_autostart()
        self.collect_recent_files()
        self.collect_logs()
        
        filepath = self.save_results()
        
        print(f"\n{Colors.CYAN}{'─' * 50}{Colors.RESET}")
        print(f"{Colors.GREEN}✓ Collection complete!{Colors.RESET}")
        print(f"  Output: {filepath}")
        
        return str(filepath)


def print_banner():
    print(f"""{Colors.CYAN}
  ___ ____    _____           _ _    _ _   
 |_ _|  _ \  |_   _|__   ___ | | | _(_) |_ 
  | || |_) |   | |/ _ \ / _ \| | |/ / | __|
  | ||  _ <    | | (_) | (_) | |   <| | |_ 
 |___|_| \_\   |_|\___/ \___/|_|_|\_\_|\__|
{Colors.RESET}                                  v{VERSION}
""")


def demo_mode():
    """Run demo"""
    print(f"{Colors.CYAN}Running demo...{Colors.RESET}\n")
    
    print(f"{Colors.BOLD}Starting Incident Response Collection{Colors.RESET}")
    print(f"Hostname: demo-server")
    print(f"Platform: Linux")
    print(f"{Colors.CYAN}{'─' * 50}{Colors.RESET}\n")
    
    steps = [
        ("[1/8]", "Collecting system info...", ""),
        ("[2/8]", "Collecting processes...", "    Found 156 processes"),
        ("[3/8]", "Collecting network connections...", "    Found 23 connections"),
        ("[4/8]", "Collecting user accounts...", "    Found 5 user accounts"),
        ("[5/8]", "Collecting scheduled tasks...", ""),
        ("[6/8]", "Collecting autostart entries...", ""),
        ("[7/8]", "Collecting recent files...", "    Found 47 recent files"),
        ("[8/8]", "Collecting log snippets...", ""),
    ]
    
    import time
    for step, desc, extra in steps:
        print(f"{Colors.CYAN}{step}{Colors.RESET} {desc}")
        if extra:
            print(extra)
        time.sleep(0.3)
    
    print(f"\n{Colors.CYAN}{'─' * 50}{Colors.RESET}")
    print(f"{Colors.GREEN}✓ Collection complete!{Colors.RESET}")
    print(f"  Output: ./ir_collection/ir_collection_20240115_103045.json")


def main():
    parser = argparse.ArgumentParser(description="Incident Response Toolkit")
    parser.add_argument("-o", "--output", default="./ir_collection", help="Output directory")
    parser.add_argument("--demo", action="store_true", help="Run demo")
    
    args = parser.parse_args()
    
    print_banner()
    
    if args.demo:
        demo_mode()
        return
    
    if os.geteuid() != 0:
        print(f"{Colors.YELLOW}Warning: Running as non-root may limit data collection{Colors.RESET}\n")
    
    collector = IRCollector(output_dir=args.output)
    collector.run_collection()


if __name__ == "__main__":
    main()
