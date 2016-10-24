"""
    Domain fuzzer
    ~~~~~~~~~~~~~

    Fuzz domains to detect possible typosquatters, phishing attacks, etc.

"""
import os
import re
from setuptools import setup, find_packages


def fpath(name):
    return os.path.join(os.path.dirname(__file__), name)


def read(fname):
    return open(fpath(fname)).read()

init_str = read(fpath('domainfuzzer/__init__.py'))


def grep(attr, file=None):
    if file is None:
        file = init_str
    pattern = r"{0}\W*=\W*'([^']+)'".format(attr)
    strval, = re.findall(pattern, file)
    return strval


setup(
    name='domainfuzzer',
    version=grep('__version__'),
    url='https://github.com/ics/domainfuzzer/',
    license='BSD',
    author='Alexandru Ciobanu',
    author_email='iscandr@gmail.com',
    description='Fuzz domains to detect possible typosquatters, '
                'phishing attacks, etc.',
    long_description=__doc__,
    packages=find_packages(exclude=['tests']),
    platforms='any',
    package_data={
        'domainfuzzer.data': ['*.dat']
    },
    entry_points={
        'console_scripts': [
            'domainfuzzer=domainfuzzer.fuzz:main'
        ]
    },
    install_requires=['GeoIP', 'dnspython', 'ssdeep', 'whois', 'tqdm'],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3'
        'Topic :: Internet :: Name Service (DNS)',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ]
)
