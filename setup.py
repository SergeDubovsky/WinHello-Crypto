"""
Setup script for WinHello-Crypto
"""

from setuptools import setup, find_packages
from pathlib import Path
import re

# Load version from pyproject.toml so that it remains the single source of truth
pyproject_file = Path(__file__).parent / "pyproject.toml"
version_match = re.search(
    r'^version\s*=\s*"([^"\n]+)"',
    pyproject_file.read_text(encoding="utf-8"),
    re.MULTILINE,
)
project_version = version_match.group(1) if version_match else "0.0.0"

# Read README for long description
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text(encoding='utf-8') if readme_file.exists() else ""

# Read requirements
requirements_file = Path(__file__).parent / "requirements.txt"
if requirements_file.exists():
    with open(requirements_file, 'r', encoding='utf-8') as f:
        requirements = [
            line.strip() for line in f.readlines()
            if line.strip() and not line.startswith('#')
        ]
else:
    requirements = [
        'cryptography>=41.0.0,<42.0.0',
        'pywinrt>=2.0.0,<3.0.0'
    ]

setup(
    name="winhello-crypto",
    version=project_version,
    author="Serge Dubovsky",
    author_email="",
    description="Enterprise-Grade AWS Credential Security with Windows Hello Biometric Authentication",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/SergeDubovsky/WinHello-Crypto",
    packages=find_packages(),
    py_modules=[
        "hello_crypto",
        "aws_hello_creds", 
        "security_utils",
        "security_config"
    ],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: Microsoft :: Windows :: Windows 10",
        "Operating System :: Microsoft :: Windows :: Windows 11",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security :: Cryptography",
        "Topic :: System :: Systems Administration :: Authentication/Directory",
        "Topic :: Utilities"
    ],
    python_requires=">=3.7",
    install_requires=[req.split(';')[0].split('>=')[0].split('==')[0] for req in requirements if not req.strip().startswith('#')],
    extras_require={
        'dev': [
            'pytest>=7.4.0',
            'pytest-asyncio>=0.21.0',
            'pytest-cov>=4.1.0',
            'black>=23.7.0',
            'flake8>=6.0.0',
            'mypy>=1.5.0'
        ],
        'security': [
            'bandit>=1.7.5',
            'safety>=2.3.0'
        ],
        'docs': [
            'sphinx>=7.1.0',
            'sphinx-rtd-theme>=1.3.0'
        ]
    },
    entry_points={
        'console_scripts': [
            'winhello-crypto=hello_crypto:main',
            'aws-hello-creds=aws_hello_creds:main',
        ],
    },
    include_package_data=True,
    package_data={
        '': ['*.md', '*.txt', '*.bat'],
    },
    zip_safe=False,
    platforms=['Windows'],
    keywords=[
        'windows-hello', 'biometric', 'authentication', 'encryption', 
        'aws', 'credentials', 'security', 'cryptography'
    ],
    project_urls={
        'Bug Reports': 'https://github.com/SergeDubovsky/WinHello-Crypto/issues',
        'Source': 'https://github.com/SergeDubovsky/WinHello-Crypto',
        'Documentation': 'https://github.com/SergeDubovsky/WinHello-Crypto/blob/main/README.md',
    },
)
