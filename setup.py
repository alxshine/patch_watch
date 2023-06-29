from setuptools import setup, find_packages

setup(
    name="patch_watch",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        "pandas",
        "requests",
        "plotille",
    ],
    entry_points={
        "console_scripts": [
            "patch_watch = patch_watch:main",
        ],
    },
)