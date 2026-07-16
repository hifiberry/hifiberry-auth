from setuptools import setup, find_packages

setup(
    name="hifiberry-auth",
    version="0.1.0",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    entry_points={"console_scripts": ["hifiberry-auth=hifiberry_auth.__main__:main"]},
)
