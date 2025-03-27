from setuptools import setup, find_packages

setup(
    name="autorecon",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        'shodan',
        'requests',
        'beautifulsoup4',
        'python-nmap',
        'PyYAML'
    ],
    entry_points={
        'console_scripts': [
            'autorecon=src.main:main',
        ],
    },
)
