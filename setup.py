from setuptools import setup

setup(
    name="vulneagle",
    version="0.4.0",  # synced with __version__ in vulneagle.py
    description="Lightweight recon tool (passive subdomain enum, DNS brute, status probe, directory brute)",
    long_description="See project README for details.",
    long_description_content_type="text/markdown",
    author="Parvesh",
    url="https://github.com/Parvesh776/VulnEagle",
    license="MIT",
    py_modules=["vulneagle"],  # single-file module
    python_requires=">=3.10",
    install_requires=[
        "requests"
    ],
    extras_require={
        "dns": ["dnspython"],
        "providers": ["PyYAML"],
    },
    entry_points={
        "console_scripts": [
            "vulneagle = vulneagle:main"
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
    ],
)