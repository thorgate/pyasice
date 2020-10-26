#!/usr/bin/env python

from setuptools import setup


with open("pyasice/__init__.py") as f:
    version_line = next(line for line in f if line.startswith("__version__"))

version = version_line.split("=")[-1].strip().strip('"' + "'")

readme = open("README.md").read()

requirements = [line for line in open("requirements.txt").readlines() if line and not line.startswith("#")]

setup(
    name="pyasice",
    version=version,
    description="""Manipulate ASiC-E containers and XAdES/eIDAS signatures for Estonian e-identity services""",
    long_description=readme,
    long_description_content_type="text/markdown",
    author="Thorgate",
    author_email="yuriy@thorgate.eu",
    url="https://github.com/thorgate/pyasice",
    packages=[
        "pyasice",
    ],
    include_package_data=True,
    install_requires=requirements,
    license="ISC",
    keywords="esteid asice xades smartid smart-id mobiilid mobile-id idcard",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: ISC License (ISCL)",
        "Natural Language :: English",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
    ],
)
