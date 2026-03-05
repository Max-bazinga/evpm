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
        """Consume events from a BPF Hash table (poll-based for BCC 0.26.0 compatibility)"""
        print(f"  DEBUG: Starting consumer thread for {program_name}")
        print(f"  DEBUG: Available programs: {list(self.bpf_loader.programs.keys())}")
        
        bpf = self.bpf_loader.get_program(program_name)
        print(f"  DEBUG: bpf type = {type(bpf)}, value = {bpf}")
        if bpf is None:
            print(f"  DEBUG: No BPF program for {program_name}")
            return
        
        print(f"  DEBUG: Got BPF program for {program_name}")
        
        # Get events hash table
        try:
            events_table = bpf.get_table('events')
            counter_table = bpf.get_table('event_counter')
            print(f"  DEBUG: Got tables - events: {type(events_table)}, counter: {type(counter_table)}")
        except Exception as e:
            print(f"  Warning: Cannot get tables from {program_name}: {e}")
            return
        
        last_event_id = 0
        print(f"  Polling hash table for {program_name}")
        
        while self.running:
            try:
                # Get current counter
                counter_key = 0
                try:
                    counter_val = counter_table[counter_key]
                    current_max = counter_val.value if hasattr(counter_val, 'value') else int(counter_val)
                except (KeyError, Exception) as e:
                    print(f"  DEBUG: Counter read error: {e}")
                    current_max = 0
                
                # Debug: print counter value periodically
                if last_event_id == 0 or current_max % 100 == 0:
                    print(f"  DEBUG: Counter = {current_max}, last_id = {last_event_id}")
                
                # Read new events
                events_read = 0
                while last_event_id < current_max:
                    try:
                        # Create proper key for hash lookup
                        from ctypes import c_uint
                        key = c_uint(last_event_id)
                        event = events_table[key]
                        print(f"  DEBUG: Read event {last_event_id}: vcpu_id={getattr(event, 'vcpu_id', 'N/A')}")
                        self.event_queue.put((program_name, event))
                        last_event_id += 1
                        events_read += 1
                    except KeyError:
                        # Event not yet available, skip
                        last_event_id += 1
                        break
                    except Exception as e:
                        print(f"  Error reading event {last_event_id}: {e}")
                        break
                
                if events_read > 0:
                    print(f"  DEBUG: Read {events_read} events this cycle")
                
                time.sleep(0.1)  # Poll every 100ms
                
            except Exception as e:
                if self.running:
                    print(f"  Hash table poll error: {e}")
                time.sleep(0.5)
    
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
