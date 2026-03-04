"""
CLI TUI (Terminal User Interface)
Simple text-based interface for real-time monitoring
"""

import sys
import time
import signal
from typing import Optional

from evpm.storage.metrics_store import MetricsStore


class EVPMTUI:
    """Simple terminal UI for eVPM"""
    
    def __init__(self, store: MetricsStore):
        self.store = store
        self.running = False
        self.refresh_interval = 1.0
        
        # Setup signal handler
        signal.signal(signal.SIGINT, self._signal_handler)
    
    def _signal_handler(self, sig, frame):
        self.running = False
        print("\n👋 Goodbye!")
        sys.exit(0)
    
    def run(self):
        """Run the TUI"""
        self.running = True
        self._clear_screen()
        
        print("🖥️  eVPM - VM Performance Monitor")
        print("=" * 60)
        print("Press Ctrl+C to exit\n")
        
        try:
            while self.running:
                self._draw_dashboard()
                time.sleep(self.refresh_interval)
        except KeyboardInterrupt:
            pass
    
    def _clear_screen(self):
        """Clear terminal screen"""
        print('\033[2J\033[H', end='')
    
    def _draw_dashboard(self):
        """Draw the main dashboard"""
        self._clear_screen()
        
        now = int(time.time())
        start_time = now - 60  # Last 60 seconds
        
        print("🖥️  eVPM - VM Performance Monitor")
        print("=" * 60)
        print(f"Time: {time.strftime('%H:%M:%S')}")
        print()
        
        # vCPU Statistics
        print("📊 vCPU Statistics (last 60s)")
        print("-" * 60)
        vcpu_stats = self.store.get_vcpu_stats(start_time * 1e9, now * 1e9)
        
        if vcpu_stats:
            print(f"{'vCPU':<8} {'Events':<10} {'Avg Latency':<15} {'Max Latency':<15}")
            print("-" * 60)
            for row in vcpu_stats:
                vcpu_id, count, avg_dur, max_dur = row
                print(f"{vcpu_id:<8} {count:<10} {avg_dur/1000:>10.1f} μs {max_dur/1000:>10.1f} μs")
        else:
            print("No data available")
        
        print()
        
        # VM Exit Statistics
        print("🔄 Top VM Exit Reasons (last 60s)")
        print("-" * 60)
        vmexit_stats = self.store.get_vmexit_stats(start_time * 1e9, now * 1e9)
        
        if vmexit_stats:
            print(f"{'Reason':<25} {'Count':<10} {'Avg Duration':<15}")
            print("-" * 60)
            for row in vmexit_stats[:5]:
                reason, count, avg_dur, max_dur = row
                reason_name = self._get_exit_reason_name(reason)
                print(f"{reason_name:<25} {count:<10} {avg_dur/1000:>10.1f} μs")
        else:
            print("No VM Exit data available")
        
        print()
        print("=" * 60)
        print("Press Ctrl+C to exit")
    
    def _get_exit_reason_name(self, reason: int) -> str:
        """Get human-readable exit reason name"""
        exit_reasons = {
            0: "EXCEPTION_NMI",
            1: "EXTERNAL_INTERRUPT",
            2: "TRIPLE_FAULT",
            3: "INIT",
            7: "PENDING_INTERRUPT",
            8: "NMI_WINDOW",
            9: "TASK_SWITCH",
            10: "CPUID",
            12: "HLT",
            13: "INVD",
            14: "INVLPG",
            15: "RDPMC",
            16: "RDTSC",
            18: "VMCALL",
            19: "VMCLEAR",
            20: "VMLAUNCH",
            21: "VMPTRLD",
            22: "VMPTRST",
            23: "VMREAD",
            24: "VMRESUME",
            25: "VMWRITE",
            26: "VMOFF",
            27: "VMON",
            28: "CR_ACCESS",
            29: "DR_ACCESS",
            30: "IO_INSTRUCTION",
            31: "MSR_READ",
            32: "MSR_WRITE",
            33: "INVALID_STATE",
            34: "MSR_LOAD_FAIL",
            36: "MWAIT_INSTRUCTION",
            37: "MONITOR_TRAP_FLAG",
            39: "MONITOR_INSTRUCTION",
            40: "PAUSE_INSTRUCTION",
            41: "MCE_DURING_VMENTRY",
            43: "TPR_BELOW_THRESHOLD",
            44: "APIC_ACCESS",
            45: "EOI_INDUCED",
            46: "GDTR_IDTR",
            47: "LDTR_TR",
            48: "EPT_VIOLATION",
            49: "EPT_MISCONFIG",
            50: "INVEPT",
            51: "RDTSCP",
            52: "PREEMPTION_TIMER",
            53: "INVVPID",
            54: "WBINVD",
            55: "XSETBV",
            56: "APIC_WRITE",
            57: "RDRAND",
            58: "INVPCID",
            59: "VMFUNC",
            60: "ENCLS",
            61: "RDSEED",
            62: "PML_FULL",
            63: "XSAVES",
            64: "XRSTORS",
            67: "BUS_LOCK",
        }
        return exit_reasons.get(reason, f"EXIT_REASON_{reason}")
