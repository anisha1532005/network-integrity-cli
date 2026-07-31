from setuptools import setup, find_packages

setup(
    name="network-integrity-cli",
    version="1.0.0",
    description="Real-Time MITM & Network Path Integrity Analyzer",
    packages=find_packages(),
    py_modules=["cli"],
    install_requires=[
        "scapy",
        "requests",
        "python-whois",
        "rich",
    ],
    entry_points={
        "console_scripts": [
            "network-integrity=cli:main",
        ],
    },
    python_requires=">=3.8",
)
