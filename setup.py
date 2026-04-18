from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="secure-req-check",
    version="0.1.1",
    author="Your Name",
    description="CLI tool to check requirements.txt for vulnerabilities using NVD API",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/secure-req-check",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=[
        "click>=8.0.0",
        "requests>=2.25.0",
        "tabulate>=0.8.9",
        "colorama>=0.4.4",
    ],
    entry_points={
        "console_scripts": [
            "secure-req-check=secure_req_check.cli:main",
        ],
    },
)