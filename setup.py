from setuptools import setup, find_packages

setup(
    name='VulnEagle',
    version='0.1',
    packages=find_packages(),
    install_requires=[
        'requests',
        'beautifulsoup4',
        'selenium',
        'playwright',
        'rich',
        'Jinja2'
    ],
    entry_points={
        'console_scripts': [
            'vulneagle = vulneagle:main'
        ]
    }
)