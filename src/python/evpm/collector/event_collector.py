"""
Event Collector
Collects events from BPF ring buffers and processes them
"""

import threading
import time
from queue import Queue, Empty
from typing import Callable, Dict, Optional
from bcc import BPF

from evpm.core.bpf_loader import BPFLoader
from evpm.storage.metrics_store import MetricsStore


class EventCollector:
    """Collect and process events from BPF programs"""
    
    def __init__(self, bpf_loader: BPFLoader, store: MetricsStore):
        self.bpf_loader = bpf_loader
        self.store = store
        self.running = False
        self.threads: Dict[str, threading.Thread] = {}
        self.event_queue = Queue(maxsize=10000)
        self.callbacks: Dict[str, Callable] = {}
        
        # Register event handlers
        self._register_handlers()
    
    def _register_handlers(self):
        """Register event type handlers"""
        self.callbacks['vcpu_sched'] = self._handle_vcpu_sched
        self.callbacks['vmexit'] = self._handle_vmexit
    
    def start(self):
        """Start collecting events"""
        self.running = True
        
        # Start consumer thread
        consumer = threading.Thread(target=self._process_events)
        consumer.daemon = True
        consumer.start()
        self.threads['consumer'] = consumer
        
        # Start producer threads for each BPF program
        for name in self.bpf_loader.programs.keys():
            t = threading.Thread(target=self._consume_ring_buffer, args=(name,))
            t.daemon = True
            t.start()
            self.threads[f'producer_{name}'] = t
        
        print(f"  Started {len(self.threads)} threads")
    
    def stop(self):
        """Stop collecting events"""
        self.running = False
        
        for name, t in self.threads.items():
            t.join(timeout=2.0)
            if t.is_alive():
                print(f"  Warning: Thread {name} did not stop gracefully")
    
    def _consume_ring_buffer(self, program_name: str):
        """Consume events from a BPF ring buffer"""
        bpf = self.bpf_loader.get_program(program_name)
        if not bpf:
            return
        
        # Get ring buffer (default name: events)
        ring_buf = None
        for map_name, map_obj in bpf.get_tables().items():
            if hasattr(map_obj, 'open_ring_buffer'):
                ring_buf = map_obj
                break
        
        if not ring_buf:
            print(f"  Warning: No ring buffer found in {program_name}")
            return
        
        def callback(ctx, data, size):
            event = bpf.bpf_get_table('events').event(data)
            self.event_queue.put((program_name, event))
        
        ring_buf.open_ring_buffer(callback)
        
        while self.running:
            try:
                ring_buf.poll(timeout=100)
            except Exception as e:
                print(f"  Ring buffer error in {program_name}: {e}")
                time.sleep(1)
    
    def _process_events(self):
        """Process events from queue"""
        while self.running:
            try:
                program_name, event = self.event_queue.get(timeout=1.0)
                handler = self.callbacks.get(program_name)
                if handler:
                    handler(event)
            except Empty:
                continue
            except Exception as e:
                print(f"  Event processing error: {e}")
    
    def _handle_vcpu_sched(self, event):
        """Handle vCPU scheduling event"""
        # Convert to metrics and store
        from dataclasses import dataclass
        
        @dataclass
        class vCPUMetrics:
            timestamp: int
            vcpu_id: int
            pid: int
            event_type: int
            duration_ns: int
        
        metrics = vCPUMetrics(
            timestamp=event.timestamp,
            vcpu_id=event.vcpu_id,
            pid=event.pid,
            event_type=event.event_type,
            duration_ns=event.duration_ns
        )
        
        self.store.insert_vcpu_metrics(metrics)
    
    def _handle_vmexit(self, event):
        """Handle VM Exit event"""
        self.store.insert_vmexit_event(
            timestamp=event.timestamp,
            vcpu_id=event.vcpu_id,
            exit_reason=event.exit_reason,
            duration_ns=event.duration_ns
        )
