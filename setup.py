
import os
from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(here, 'README.rst')) as f:
    README = f.read()

with open(os.path.join(here, 'CHANGES.txt')) as f:
    CHANGES = f.read()

requires = ['repoze.who', 'unittest2']

setup(name='repoze.who.plugins.digestauth',
      version='0.1.1',
      description='repoze.who.plugins.digestauth',
      long_description=README + '\n\n' + CHANGES,
      classifiers=[
        "Programming Language :: Python",
        ],
      author='Mozilla Services',
      author_email='services-dev@mozilla.org',
      url='https://github.com/mozilla-services/repoze.who.plugins.digestauth',
      keywords='authentication repoze http digest',
      packages=find_packages(),
      include_package_data=True,
      zip_safe=False,
      install_requires=requires,
      tests_require=requires,
      namespace_packages=['repoze', 'repoze.who', 'repoze.who.plugins'],
      test_suite="repoze.who.plugins.digestauth")
