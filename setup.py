#!/usr/bin/env python3
"""
Setup script for eVPM (eBPF VM Performance Monitor)
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="evpm",
    version="1.0.0",
    author="eVPM Team",
    description="eBPF-based Virtual Machine Performance Monitor",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourname/evpm",
    packages=find_packages(where="src/python"),
    package_dir={"": "src/python"},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Topic :: System :: Monitoring",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
    python_requires=">=3.8",
    install_requires=[
        # Note: bcc must be installed via system package manager
        # Ubuntu/Debian: sudo apt install bpfcc-tools libbpfcc-dev
        # macOS: brew install bcc
        # See: https://github.com/iovisor/bcc/blob/master/INSTALL.md
        "rich>=10.0.0",
        "prometheus-client>=0.11.0",
        "flask>=2.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=6.0",
            "black>=21.0",
            "flake8>=3.9",
        ],
    },
    entry_points={
        "console_scripts": [
            "evpm=evpm.__main__:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
