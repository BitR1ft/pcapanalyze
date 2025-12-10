from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="pcapanalyze",
    version="1.0.0",
    author="Final Year Project Team",
    description="A comprehensive PCAP/PCAPNG file analyzer with GUI",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Security",
    ],
    python_requires=">=3.8",
    install_requires=[
        "PyQt5>=5.15.0",
        "scapy>=2.5.0",
        "matplotlib>=3.5.0",
        "pandas>=1.3.0",
        "dpkt>=1.9.8",
        "plotly>=5.0.0",
        "reportlab>=3.6.0",
        "python-magic>=0.4.27",
        "netifaces>=0.11.0",
        "psutil>=5.9.0",
    ],
    entry_points={
        "console_scripts": [
            "pcapanalyze=pcap_analyzer:main",
        ],
    },
)
