"""
Setup script for PacketMimic VPN Protocol
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="packetmimic",
    version="1.0.0",
    author="PacketMimic Team",
    description="VPN Protocol for secure IP packet tunneling",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/packetmimic/packetmimic",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: System :: Networking",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=[
        "cryptography>=41.0.0",
    ],
    entry_points={
        "console_scripts": [
            "packetmimic-server=packetmimic.server:main",
            "packetmimic-client=packetmimic.client:main",
        ],
    },
)


