#!/usr/bin/env python

from setuptools import find_packages, setup

from protonvpn_nm_lib.constants import APP_VERSION

long_description = """
ProtonVPN NetworkManager library for Linux clients.
"""

setup(
    name="protonvpn-nm-lib",
    version=APP_VERSION,
    packages=find_packages(),
    description="ProtonVPN NetworkManager Linux library",
    author="Proton Technologies AG",
    author_email="contact@protonvpn.com",
    long_description=long_description,
    install_requires=[
        "proton-client", "keyring", "PyGObject", "Jinja2", "distro",
        "systemd-python"
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
