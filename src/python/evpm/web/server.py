"""
Web UI for eVPM
Flask-based REST API and WebSocket for real-time monitoring
"""

import json
import time
from datetime import datetime, timedelta
from typing import Dict, List

from flask import Flask, jsonify, render_template, request
from flask_cors import CORS

from evpm.storage.metrics_store import MetricsStore


def create_app(store: MetricsStore):
    """Create Flask application"""
    app = Flask(__name__, 
                template_folder='templates',
                static_folder='static')
    CORS(app)
    
    @app.route('/')
    def index():
        """Main dashboard page"""
        return render_template('index.html')
    
    @app.route('/api/health')
    def health():
        """Health check endpoint"""
        return jsonify({'status': 'ok', 'timestamp': time.time()})
    
    @app.route('/api/vcpu/stats')
    def vcpu_stats():
        """Get vCPU statistics"""
        duration = request.args.get('duration', 60, type=int)
        
        now = int(time.time())
        start_time = now - duration
        
        stats = store.get_vcpu_stats(start_time * 1e9, now * 1e9)
        
        result = []
        for row in stats:
            result.append({
                'vcpu_id': row[0],
                'event_count': row[1],
                'avg_duration_ns': row[2],
                'max_duration_ns': row[3],
                'avg_duration_us': row[2] / 1000 if row[2] else 0,
            })
        
        return jsonify({
            'timestamp': now,
            'duration': duration,
            'vcpus': result
        })
    
    @app.route('/api/vmexit/stats')
    def vmexit_stats():
        """Get VM Exit statistics"""
        duration = request.args.get('duration', 60, type=int)
        
        now = int(time.time())
        start_time = now - duration
        
        stats = store.get_vmexit_stats(start_time * 1e9, now * 1e9)
        
        result = []
        for row in stats:
            result.append({
                'exit_reason': row[0],
                'exit_name': get_exit_reason_name(row[0]),
                'count': row[1],
                'avg_duration_ns': row[2],
                'max_duration_ns': row[3],
                'avg_duration_us': row[2] / 1000 if row[2] else 0,
            })
        
        return jsonify({
            'timestamp': now,
            'duration': duration,
            'exits': result
        })
    
    @app.route('/api/events/recent')
    def recent_events():
        """Get recent events"""
        limit = request.args.get('limit', 100, type=int)
        
        events = store.get_recent_events(limit)
        
        result = []
        for row in events:
            result.append({
                'timestamp': row[0],
                'vcpu_id': row[1],
                'pid': row[2],
                'event_type': row[3],
                'duration_ns': row[4],
                'duration_us': row[4] / 1000 if row[4] else 0,
            })
        
        return jsonify({
            'count': len(result),
            'events': result
        })
    
    @app.route('/api/dashboard')
    def dashboard():
        """Get dashboard summary"""
        now = int(time.time())
        start_time = now - 300  # Last 5 minutes
        
        vcpu_stats = store.get_vcpu_stats(start_time * 1e9, now * 1e9)
        vmexit_stats = store.get_vmexit_stats(start_time * 1e9, now * 1e9)
        
        total_exits = sum(row[1] for row in vmexit_stats)
        
        return jsonify({
            'timestamp': now,
            'summary': {
                'active_vcpus': len(vcpu_stats),
                'total_vmexits_5m': total_exits,
                'top_exit_reasons': [
                    {
                        'reason': row[0],
                        'name': get_exit_reason_name(row[0]),
                        'count': row[1]
                    }
                    for row in vmexit_stats[:5]
                ]
            }
        })
    
    return app


def get_exit_reason_name(reason: int) -> str:
    """Get human-readable exit reason name"""
    names = {
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
    return names.get(reason, f"EXIT_{reason}")


def start_server(store: MetricsStore, port: int = 8080, debug: bool = False):
    """Start Flask web server"""
    app = create_app(store)
    app.run(host='0.0.0.0', port=port, debug=debug)
