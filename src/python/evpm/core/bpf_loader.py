"""
eBPF Program Loader
Handles loading and attaching BPF programs
"""

import os
import sys
import subprocess
import tempfile
from typing import Dict, Optional
from bcc import BPF


class BPFLoader:
    """Load and manage eBPF programs"""
    
    def __init__(self):
        self.programs: Dict[str, BPF] = {}
        # 尝试多种方式找到内核源码目录
        possible_paths = [
            # 开发模式 (从 git clone 运行)
            os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'src', 'kernels'),
            # 安装后模式
            os.path.join(os.path.dirname(__file__), '..', '..', 'kernels'),
            # 当前目录模式
            os.path.join(os.getcwd(), 'src', 'kernels'),
            # 绝对路径
            '/home/zh/evpm/src/kernels',
            '/usr/local/share/evpm/kernels',
            '/opt/evpm/kernels',
        ]
        
        self.kernel_src_dir = None
        for path in possible_paths:
            if os.path.exists(path) and os.path.isdir(path):
                self.kernel_src_dir = os.path.abspath(path)
                print(f"  Found BPF kernels at: {self.kernel_src_dir}")
                break
        
        if not self.kernel_src_dir:
            raise RuntimeError(f"BPF kernel directory not found. Searched: {possible_paths}")
        
        # 如果没有 vmlinux.h，生成
        vmlinux_h = os.path.join(self.kernel_src_dir, 'vmlinux.h')
        if not os.path.exists(vmlinux_h):
            print(f"  Generating vmlinux.h...")
            self._generate_vmlinux_h(vmlinux_h)
    
    def _generate_vmlinux_h(self, output_path: str):
        """Generate vmlinux.h from system BTF"""
        import subprocess
        try:
            result = subprocess.run(
                ['bpftool', 'btf', 'dump', 'file', '/sys/kernel/btf/vmlinux', 
                 'format', 'c'],
                capture_output=True,
                text=True,
                check=True
            )
            with open(output_path, 'w') as f:
                f.write(result.stdout)
            print(f"    ✓ Generated vmlinux.h")
        except Exception as e:
            print(f"    ⚠ Could not generate vmlinux.h: {e}")
            # Create minimal placeholder
            with open(output_path, 'w') as f:
                f.write('/* Minimal vmlinux.h placeholder */\n')
                f.write('/* Install bpftool and run: bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h */\n')
            print(f"    ⚠ Created placeholder vmlinux.h")
        
    def load_program(self, name: str, src_file: str) -> BPF:
        """Load a BPF program from source file"""
        src_path = os.path.join(self.kernel_src_dir, src_file)
        
        if not os.path.exists(src_path):
            raise FileNotFoundError(f"BPF source not found: {src_path}")
        
        with open(src_path, 'r') as f:
            src = f.read()
        
        # Compile and load BPF program with include paths
        try:
            # 添加系统 BPF 头文件路径（多架构支持）
            cflags = [
                '-I/usr/include',
                f'-I{self.kernel_src_dir}',
                '-I/usr/include/bpf',
                '-I/usr/include/x86_64-linux-gnu',  # Debian/Ubuntu x86_64
                '-I/usr/include/aarch64-linux-gnu',  # ARM64
                '-I/usr/include/i386-linux-gnu',     # x86
            ]
            # BCC 自动附加 tracepoints 和 kprobes（不需要手动遍历）
            print(f"  Debug: Loading BPF from {src_path}")
            bpf = BPF(text=src, cflags=cflags, debug=0)
            print(f"  Debug: BPF loaded, tables: {list(bpf.tables.keys()) if hasattr(bpf, 'tables') else 'N/A'}")
            self.programs[name] = bpf
            
            # TRACEPOINT_PROBE macros auto-attach, no manual attachment needed
            print(f"  ✓ Loaded: {name}")
            
            return bpf
            
        except Exception as e:
            print(f"  ✗ Failed to load {name}: {e}")
            raise
    
    def _auto_attach(self, bpf: BPF, name: str):
        """Automatically attach tracepoints and kprobes"""
        attached = []
        
        # Get tracepoints using BCC API
        try:
            # Try different BCC versions API
            tracepoints = getattr(bpf, 'tracepoints', None) or bpf.get_tracepoints()
            if tracepoints:
                for tp_name, tp_fn in tracepoints.items() if isinstance(tracepoints, dict) else [(t, None) for t in tracepoints]:
                    try:
                        # tp_name is like "kvm:kvm_vcpu_run_begin"
                        parts = tp_name.split(':')
                        if len(parts) == 2:
                            category, event = parts
                            fn_name = tp_fn.name if tp_fn else f"trace_{event}"
                            bpf.attach_tracepoint(event=f"{category}:{event}", fn_name=fn_name)
                            attached.append(f"tp:{tp_name}")
                    except Exception as e:
                        print(f"    Warning: Failed to attach tracepoint {tp_name}: {e}")
        except Exception as e:
            print(f"    Info: No tracepoints found or attach failed: {e}")
        
        # Get kprobes
        try:
            kprobes = getattr(bpf, 'kprobes', None) or []
            for kprobe_name in kprobes if isinstance(kprobes, list) else kprobes.keys() if isinstance(kprobes, dict) else []:
                try:
                    bpf.attach_kprobe(event=kprobe_name, fn_name=kprobe_name)
                    attached.append(f"kp:{kprobe_name}")
                except Exception as e:
                    print(f"    Warning: Failed to attach kprobe {kprobe_name}: {e}")
        except Exception as e:
            print(f"    Info: No kprobes found or attach failed: {e}")
        
        if attached:
            print(f"    Attached: {', '.join(attached)}")
    
    def get_program(self, name: str) -> Optional[BPF]:
        """Get loaded BPF program by name"""
        return self.programs.get(name)
    
    def get_ring_buffer(self, name: str, map_name: str = 'events'):
        """Get ring buffer from a BPF program"""
        bpf = self.programs.get(name)
        if not bpf:
            return None
        return bpf.get_table(map_name)
    
    def get_map(self, name: str, map_name: str):
        """Get a BPF map"""
        bpf = self.programs.get(name)
        if not bpf:
            return None
        return bpf.get_table(map_name)
    
    def cleanup(self):
        """Cleanup all loaded BPF programs"""
        print("🧹 Cleaning up BPF programs...")
        for name, bpf in self.programs.items():
            try:
                bpf.cleanup()
                print(f"  ✓ Unloaded: {name}")
            except Exception as e:
                print(f"  ✗ Error unloading {name}: {e}")
        self.programs.clear()


class BTFLoader:
    """Load BTF (BPF Type Format) information for CO-RE"""
    
    def __init__(self):
        self.btf_path = '/sys/kernel/btf/vmlinux'
        
    def check_btf_support(self) -> bool:
        """Check if kernel supports BTF"""
        return os.path.exists(self.btf_path)
    
    def get_header(self) -> str:
        """Get vmlinux.h header for CO-RE"""
        if not self.check_btf_support():
            raise RuntimeError("BTF not supported on this kernel")
        
        # Use bpftool to generate vmlinux.h
        try:
            result = subprocess.run(
                ['bpftool', 'btf', 'dump', 'file', self.btf_path, 'format', 'c'],
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            print(f"Warning: Could not generate vmlinux.h: {e}")
            return ""
