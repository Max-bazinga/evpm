"""
Prometheus Exporter for eVPM
Exports VM performance metrics in Prometheus format
"""

import time
import threading
from typing import Dict, Optional

from prometheus_client import start_http_server, Gauge, Counter, Histogram, Info

from evpm.storage.metrics_store import MetricsStore


class PrometheusExporter:
    """Export eVPM metrics to Prometheus"""
    
    def __init__(self, store: MetricsStore, port: int = 9090):
        self.store = store
        self.port = port
        self.running = False
        self.thread: Optional[threading.Thread] = None
        
        # Define metrics
        self._init_metrics()
    
    def _init_metrics(self):
        """Initialize Prometheus metrics"""
        
        # Info
        self.evpm_info = Info('evpm', 'eVPM version information')
        self.evpm_info.info({'version': '1.0.0', 'build_date': '2026-03-04'})
        
        # vCPU metrics
        self.vcpu_usage = Gauge(
            'evpm_vcpu_usage_percent',
            'vCPU usage percentage',
            ['vm_name', 'vcpu_id']
        )
        
        self.vcpu_run_time = Gauge(
            'evpm_vcpu_run_time_ns',
            'Total vCPU run time in nanoseconds',
            ['vm_name', 'vcpu_id']
        )
        
        self.vcpu_halt_time = Gauge(
            'evpm_vcpu_halt_time_ns',
            'Total vCPU halt time in nanoseconds',
            ['vm_name', 'vcpu_id']
        )
        
        self.vcpu_schedule_count = Counter(
            'evpm_vcpu_schedule_count_total',
            'Total vCPU schedule count',
            ['vm_name', 'vcpu_id']
        )
        
        # Scheduling latency
        self.sched_latency = Gauge(
            'evpm_sched_latency_ns',
            'Scheduling latency in nanoseconds',
            ['vm_name', 'vcpu_id']
        )
        
        self.sched_latency_hist = Histogram(
            'evpm_sched_latency_histogram_ns',
            'Scheduling latency histogram',
            ['vm_name'],
            buckets=[1000, 5000, 10000, 50000, 100000, 500000, 1000000, 
                    5000000, 10000000, 50000000]
        )
        
        # VM Exit metrics
        self.vmexit_total = Counter(
            'evpm_vmexit_total',
            'Total VM exits',
            ['vm_name', 'exit_reason', 'exit_name']
        )
        
        self.vmexit_duration = Histogram(
            'evpm_vmexit_duration_ns',
            'VM exit handling duration',
            ['vm_name', 'exit_reason'],
            buckets=[100, 500, 1000, 5000, 10000, 50000, 100000, 500000, 1000000]
        )
        
        self.vmexit_avg_duration = Gauge(
            'evpm_vmexit_avg_duration_ns',
            'Average VM exit handling duration',
            ['vm_name', 'exit_reason']
        )
        
        self.vmexit_max_duration = Gauge(
            'evpm_vmexit_max_duration_ns',
            'Maximum VM exit handling duration',
            ['vm_name', 'exit_reason']
        )
        
        # Memory metrics
        self.mm_page_faults = Counter(
            'evpm_mm_page_faults_total',
            'Total page faults',
            ['vm_name', 'vcpu_id']
        )
        
        self.mm_ept_violations = Counter(
            'evpm_mm_ept_violations_total',
            'Total EPT violations',
            ['vm_name', 'vcpu_id']
        )
        
        self.mm_page_fault_duration = Histogram(
            'evpm_mm_page_fault_duration_ns',
            'Page fault handling duration',
            ['vm_name'],
            buckets=[1000, 5000, 10000, 50000, 100000, 500000, 1000000]
        )
        
        # I/O metrics
        self.io_virtio_notifies = Counter(
            'evpm_io_virtio_notifies_total',
            'Total Virtqueue notifications',
            ['vm_name', 'device_id']
        )
        
        self.io_irq_injections = Counter(
            'evpm_io_irq_injections_total',
            'Total IRQ injections',
            ['vm_name', 'irq']
        )
    
    def start(self):
        """Start Prometheus HTTP server"""
        start_http_server(self.port)
        print(f"📈 Prometheus exporter started on port {self.port}")
        
        self.running = True
        self.thread = threading.Thread(target=self._update_metrics)
        self.thread.daemon = True
        self.thread.start()
    
    def stop(self):
        """Stop the exporter"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5.0)
    
    def _update_metrics(self):
        """Periodically update metrics from database"""
        while self.running:
            try:
                self._update_vcpu_metrics()
                self._update_vmexit_metrics()
                self._update_mm_metrics()
                time.sleep(5)  # Update every 5 seconds
            except Exception as e:
                print(f"Error updating metrics: {e}")
                time.sleep(10)
    
    def _update_vcpu_metrics(self):
        """Update vCPU metrics"""
        now = int(time.time())
        start_time = now - 60  # Last 60 seconds
        
        stats = self.store.get_vcpu_stats(start_time * 1e9, now * 1e9)
        for row in stats:
            vcpu_id, count, avg_dur, max_dur = row
            vm_name = f"vm-{row[1]}"  # Use PID as VM identifier
            
            self.vcpu_schedule_count.labels(
                vm_name=vm_name, 
                vcpu_id=str(vcpu_id)
            ).inc(count)
            
            self.sched_latency.labels(
                vm_name=vm_name,
                vcpu_id=str(vcpu_id)
            ).set(avg_dur)
    
    def _update_vmexit_metrics(self):
        """Update VM Exit metrics"""
        now = int(time.time())
        start_time = now - 60
        
        stats = self.store.get_vmexit_stats(start_time * 1e9, now * 1e9)
        for row in stats:
            exit_reason, count, avg_dur, max_dur = row
            vm_name = "vm-default"
            exit_name = self._get_exit_reason_name(exit_reason)
            
            self.vmexit_total.labels(
                vm_name=vm_name,
                exit_reason=str(exit_reason),
                exit_name=exit_name
            ).inc(count)
            
            self.vmexit_avg_duration.labels(
                vm_name=vm_name,
                exit_reason=str(exit_reason)
            ).set(avg_dur)
            
            self.vmexit_max_duration.labels(
                vm_name=vm_name,
                exit_reason=str(exit_reason)
            ).set(max_dur)
    
    def _update_mm_metrics(self):
        """Update memory metrics"""
        # Placeholder - implement when mm monitoring is active
        pass
    
    def _get_exit_reason_name(self, reason: int) -> str:
        """Get human-readable exit reason name"""
        names = {
            0: "EXCEPTION_NMI",
            1: "EXTERNAL_INTERRUPT",
            2: "TRIPLE_FAULT",
            7: "PENDING_INTERRUPT",
            10: "CPUID",
            12: "HLT",
            28: "CR_ACCESS",
            29: "DR_ACCESS",
            30: "IO_INSTRUCTION",
            31: "MSR_READ",
            32: "MSR_WRITE",
            48: "EPT_VIOLATION",
            49: "EPT_MISCONFIG",
        }
        return names.get(reason, f"EXIT_{reason}")


def start_exporter(store: MetricsStore, port: int = 9090):
    """Convenience function to start exporter"""
    exporter = PrometheusExporter(store, port)
    exporter.start()
    return exporter
