"""
Setup configuration for Odoo 19 Prompts SDK.

Installation:
    pip install -e .

Or from PyPI (once published):
    pip install odoo19-prompts-sdk
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text(encoding="utf-8") if readme_file.exists() else ""

setup(
    name="odoo19-prompts-sdk",
    version="1.0.0",
    author="Pedro Troncoso",
    author_email="pwills85@example.com",
    description="Python SDK for automated Odoo 19 prompt system management and multi-agent audits",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/your-org/odoo19-prompts-sdk",
    packages=find_packages(include=["prompts_sdk", "prompts_sdk.*"]),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Quality Assurance",
        "Topic :: Software Development :: Testing",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.8",
    install_requires=[
        "click>=8.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "mypy>=1.0.0",
            "flake8>=6.0.0",
        ],
        "integrations": [
            "requests>=2.28.0",  # For Slack, GitHub integrations
        ],
        "docs": [
            "sphinx>=5.0.0",
            "sphinx-rtd-theme>=1.2.0",
            "sphinx-autodoc-typehints>=1.20.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "prompts-sdk=prompts_sdk.cli:cli",
        ],
    },
    include_package_data=True,
    zip_safe=False,
    keywords="odoo audit testing compliance ci-cd automation multi-agent",
    project_urls={
        "Documentation": "https://your-org.github.io/odoo19-prompts-sdk/",
        "Source": "https://github.com/your-org/odoo19-prompts-sdk",
        "Tracker": "https://github.com/your-org/odoo19-prompts-sdk/issues",
    },
)
