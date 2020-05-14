#!/usr/bin/env python
from setuptools import setup, find_packages
import os

setup(name='bridge',
      version='0.1',
      description='Ocean Ethereum Bridge',
      author='CommerceBlock',
      author_email='nikolaos@commerceblock.com',
      url='http://github.com/commerceblock/ethbridge',
      packages=find_packages(),
      scripts=[],
      include_package_data=True,
      data_files=[],
)
