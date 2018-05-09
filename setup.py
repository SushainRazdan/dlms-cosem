from setuptools import find_packages, setup

with open('README.rst') as readme_file:
    readme = readme_file.read()

with open('HISTORY.rst') as history_file:
    history = history_file.read()

setup(
    name='dlms-cosem',
    version='0.0.1.dev1',
    description='A Python library for DLMS/COSEM',
    long_description=readme + '\n\n' + history,
    url='https://github.com/pwitab/dlms-cosem',
    author='Henrik Palmlund Wahlgren , '
           '@ Palmlund Wahlgren Innovative Technology AB',
    author_email='henrik@pwit.se',
    license='BSD 3-Clause License',
    packages=['dlms_cosem'],
    install_requires=[],
    zip_safe=False,
    keywords=[],
    classifiers=[

    ],

)
