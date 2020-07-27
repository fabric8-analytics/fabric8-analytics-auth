"""Project setup file."""

from setuptools import setup


def get_requirements():
    """Parse all packages mentioned in the 'requirements.in' file."""
    with open('requirements.in') as fd:
        return fd.read().splitlines()


setup(
    name='fabric8a_auth',
    version='0.0.1',
    description='a pip-installable package example',
    license='Apache License 2.0',
    packages=['fabric8a_auth'],
    author='Tomas Hrcka',
    author_email='thrcka@redhat.com',
    keywords=['fabric8-analytics'],
    url='https://github.com/fabric8-analytics/fabric8-analytics-auth',
    install_requires=get_requirements(),
)
