#!/usr/bin/env python3
"""
Setup script for HomeScan - Home Network Security Audit Tool
"""

from setuptools import setup, find_packages
import os

# Read README file for long description
def read_readme():
    readme_path = os.path.join(os.path.dirname(__file__), 'README.md')
    if os.path.exists(readme_path):
        with open(readme_path, 'r', encoding='utf-8') as f:
            return f.read()
    return "HomeScan - Home Network Security Audit Tool"

# Read requirements from requirements.txt
def read_requirements():
    requirements_path = os.path.join(os.path.dirname(__file__), 'requirements.txt')
    if os.path.exists(requirements_path):
        with open(requirements_path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    return []

setup(
    name="homescan",
    version="1.0.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="Home Network Security Audit Tool",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/homescan",
    project_urls={
        "Bug Reports": "https://github.com/yourusername/homescan/issues",
        "Source": "https://github.com/yourusername/homescan",
        "Documentation": "https://github.com/yourusername/homescan#readme"
    },
    
    # Package configuration
    py_modules=["homescan"],
    include_package_data=True,
    
    # Dependencies
    install_requires=read_requirements(),
    python_requires=">=3.6",
    
    # Entry points for command line
    entry_points={
        "console_scripts": [
            "homescan=homescan:main",
        ],
    },
    
    # Package metadata
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: System Administrators",
        "Intended Audience :: End Users/Desktop",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS",
        "Operating System :: Microsoft :: Windows",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
        "Topic :: Utilities"
    ],
    
    # Keywords for PyPI search
    keywords=[
        "network", "security", "audit", "scanner", "home", "wifi", 
        "vulnerability", "port-scanner", "network-monitoring", "cybersecurity"
    ],
    
    # Additional metadata
    license="MIT",
    platforms=["any"],
    
    # Optional dependencies
    extras_require={
        "dev": [
            "pytest>=6.0",
            "black>=21.0",
            "flake8>=3.8",
            "mypy>=0.800"
        ],
        "docs": [
            "sphinx>=3.0",
            "sphinx-rtd-theme>=0.5"
        ]
    },
    
    # Data files
    package_data={
        "": ["*.md", "*.txt", "*.rst"],
    },
    
    # Zip safe
    zip_safe=False,
)