#!/usr/bin/env python3
"""
eVPM - eBPF VM Performance Monitor
Main entry point
"""

import sys
import argparse
import signal
import time
from typing import Optional

from evpm.core.bpf_loader import BPFLoader
from evpm.collector.event_collector import EventCollector
from evpm.storage.metrics_store import MetricsStore
from evpm.cli.tui import EVPMTUI


def signal_handler(sig, frame):
    print("\n🛑 Stopping eVPM...")
    sys.exit(0)


def main():
    parser = argparse.ArgumentParser(
        description='eBPF VM Performance Monitor',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  sudo evpm start              # Start monitoring all VMs
  sudo evpm start --pid 12345  # Monitor specific VM
  sudo evpm cli                # Interactive CLI mode
  sudo evpm web --port 8080    # Start web UI
  sudo evpm export             # Export Prometheus metrics
        '''
    )
    
    parser.add_argument('command', choices=['start', 'cli', 'web', 'export'],
                       help='Command to run')
    parser.add_argument('--pid', type=int, help='Target QEMU process PID')
    parser.add_argument('--vm-name', type=str, help='VM name for labeling')
    parser.add_argument('--port', type=int, default=8080, help='Web UI port')
    parser.add_argument('--db', type=str, default='/var/lib/evpm/metrics.db',
                       help='SQLite database path')
    parser.add_argument('--interval', type=int, default=1,
                       help='Sampling interval in seconds')
    
    args = parser.parse_args()
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    if args.command == 'start':
        run_monitor(args)
    elif args.command == 'cli':
        run_cli(args)
    elif args.command == 'web':
        run_web(args)
    elif args.command == 'export':
        run_exporter(args)


def run_monitor(args):
    """Run monitoring daemon"""
    print("🚀 Starting eVPM monitor...")
    
    # Initialize components
    store = MetricsStore(args.db)
    loader = BPFLoader()
    collector = EventCollector(loader, store)
    
    try:
        # Load eBPF programs
        print("📦 Loading eBPF programs...")
        loader.load_program('vcpu_sched', 'vcpu_sched_monitor.bpf.c')
        loader.load_program('vmexit', 'vmexit_monitor.bpf.c')
        
        # Start collection
        print("📊 Starting event collection...")
        collector.start()
        
        print(f"✅ eVPM is running. Press Ctrl+C to stop.")
        print(f"   Target: {'PID ' + str(args.pid) if args.pid else 'All VMs'}")
        print(f"   Database: {args.db}")
        
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n🛑 Stopping...")
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)
    finally:
        collector.stop()
        loader.cleanup()
        store.close()


def run_cli(args):
    """Run interactive CLI"""
    print("🖥️  Starting CLI mode...")
    
    store = MetricsStore(args.db)
    tui = EVPMTUI(store)
    
    try:
        tui.run()
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")


def run_web(args):
    """Run web UI"""
    print(f"🌐 Starting web UI on port {args.port}...")
    
    from evpm.web.server import start_server
    start_server(port=args.port, db_path=args.db)


def run_exporter(args):
    """Run Prometheus exporter"""
    print("📈 Starting Prometheus exporter...")
    
    from evpm.exporter.prometheus_exporter import PrometheusExporter
    exporter = PrometheusExporter(db_path=args.db)
    exporter.start()


if __name__ == '__main__':
    main()
