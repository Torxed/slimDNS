import setuptools, glob, shutil

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="slimDNS",
    version="1.0.0rc2",
    author="Anton Hvornum",
    author_email="anton@hvornum.se",
    description="A simple DNS server written in vanilla Python.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Torxed/slimDNS",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3.8",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: POSIX :: Linux",
    ],
    python_requires='>=3.8',
    package_data={'slimDNS': glob.glob('examples/*.py') + glob.glob('profiles/*.py')},
)