"""
Metrics Storage
Stores and retrieves metrics data
"""

import sqlite3
import time
from dataclasses import dataclass
from typing import List, Optional, Tuple


@dataclass
class vCPUMetrics:
    timestamp: int
    vcpu_id: int
    pid: int
    event_type: int
    duration_ns: int


@dataclass
class VMExitMetrics:
    timestamp: int
    vcpu_id: int
    exit_reason: int
    duration_ns: int


class MetricsStore:
    """SQLite-based metrics storage"""
    
    def __init__(self, db_path: str = '/var/lib/evpm/metrics.db'):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self._init_tables()
        self._init_indexes()
    
    def _init_tables(self):
        """Initialize database tables"""
        cursor = self.conn.cursor()
        
        # vCPU metrics table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vcpu_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL,
                vcpu_id INTEGER NOT NULL,
                pid INTEGER NOT NULL,
                event_type INTEGER NOT NULL,
                duration_ns INTEGER NOT NULL
            )
        ''')
        
        # VM Exit events table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vmexit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL,
                vcpu_id INTEGER NOT NULL,
                exit_reason INTEGER NOT NULL,
                duration_ns INTEGER NOT NULL
            )
        ''')
        
        # VM Exit statistics (aggregated)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vmexit_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL,
                exit_reason INTEGER NOT NULL,
                count INTEGER NOT NULL,
                avg_duration_ns INTEGER NOT NULL,
                max_duration_ns INTEGER NOT NULL,
                min_duration_ns INTEGER NOT NULL
            )
        ''')
        
        # Scheduling latency histogram
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sched_latency_hist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL,
                bucket_us INTEGER NOT NULL,
                count INTEGER NOT NULL
            )
        ''')
        
        self.conn.commit()
    
    def _init_indexes(self):
        """Create indexes for better query performance"""
        cursor = self.conn.cursor()
        
        indexes = [
            'CREATE INDEX IF NOT EXISTS idx_vcpu_ts ON vcpu_metrics(timestamp)',
            'CREATE INDEX IF NOT EXISTS idx_vcpu_id ON vcpu_metrics(vcpu_id)',
            'CREATE INDEX IF NOT EXISTS idx_vmexit_ts ON vmexit_events(timestamp)',
            'CREATE INDEX IF NOT EXISTS idx_vmexit_reason ON vmexit_events(exit_reason)',
        ]
        
        for idx in indexes:
            cursor.execute(idx)
        
        self.conn.commit()
    
    def insert_vcpu_metrics(self, metrics: vCPUMetrics):
        """Insert vCPU metrics"""
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO vcpu_metrics (timestamp, vcpu_id, pid, event_type, duration_ns)
            VALUES (?, ?, ?, ?, ?)
        ''', (metrics.timestamp, metrics.vcpu_id, metrics.pid, 
              metrics.event_type, metrics.duration_ns))
        self.conn.commit()
    
    def insert_vmexit_event(self, timestamp: int, vcpu_id: int, 
                           exit_reason: int, duration_ns: int):
        """Insert VM Exit event"""
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO vmexit_events (timestamp, vcpu_id, exit_reason, duration_ns)
            VALUES (?, ?, ?, ?)
        ''', (timestamp, vcpu_id, exit_reason, duration_ns))
        self.conn.commit()
    
    def get_vcpu_stats(self, start_time: int, end_time: int) -> List[Tuple]:
        """Get vCPU statistics for time range"""
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT vcpu_id, 
                   COUNT(*) as event_count,
                   AVG(duration_ns) as avg_duration,
                   MAX(duration_ns) as max_duration
            FROM vcpu_metrics
            WHERE timestamp BETWEEN ? AND ?
            GROUP BY vcpu_id
        ''', (start_time, end_time))
        return cursor.fetchall()
    
    def get_vmexit_stats(self, start_time: int, end_time: int) -> List[Tuple]:
        """Get VM Exit statistics"""
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT exit_reason,
                   COUNT(*) as count,
                   AVG(duration_ns) as avg_duration,
                   MAX(duration_ns) as max_duration
            FROM vmexit_events
            WHERE timestamp BETWEEN ? AND ?
            GROUP BY exit_reason
            ORDER BY count DESC
        ''', (start_time, end_time))
        return cursor.fetchall()
    
    def get_recent_events(self, limit: int = 100) -> List[Tuple]:
        """Get recent vCPU events"""
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT timestamp, vcpu_id, pid, event_type, duration_ns
            FROM vcpu_metrics
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (limit,))
        return cursor.fetchall()
    
    def cleanup_old_data(self, retention_days: int = 7):
        """Clean up data older than retention_days"""
        cutoff = int(time.time() - retention_days * 24 * 3600) * 1e9
        cursor = self.conn.cursor()
        
        tables = ['vcpu_metrics', 'vmexit_events', 'vmexit_stats', 'sched_latency_hist']
        for table in tables:
            cursor.execute(f'DELETE FROM {table} WHERE timestamp < ?', (cutoff,))
        
        self.conn.commit()
        print(f"🧹 Cleaned up data older than {retention_days} days")
    
    def close(self):
        """Close database connection"""
        self.conn.close()
