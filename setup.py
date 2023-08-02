#!/usr/bin/env python

from setuptools import find_packages, setup

from protonvpn_nm_lib.constants import APP_VERSION

long_description = """
Proton VPN NetworkManager library for Linux clients.
"""

setup(
    name="protonvpn-nm-lib",
    version=APP_VERSION,
    packages=find_packages(exclude=["tests", "tests.*"]),
    description="Proton VPN NetworkManager Linux library",
    author="Proton Technologies AG",
    author_email="contact@protonvpn.com",
    long_description=long_description,
    install_requires=[
        "proton-client", "pyxdg", "keyring",
        "PyGObject", "Jinja2", "distro", "systemd-python"
    ],
    include_package_data=True,
    license="GPLv3",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Topic :: Security",
        "Operating System :: POSIX :: Linux",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
    ],
)
