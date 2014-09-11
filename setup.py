#!/usr/bin/env python
# -*- coding: utf-8 -*-

try:
    from setuptools import setup, find_packages
except ImportError:
    from distutils.core import setup, find_packages

setup(
    name='ec2_launch_more_like_this',
    version='0.1.0',
    author='ARASHI, Jumpei',
    author_email='jumpei.arashi@arashike.com',
    url='https://github.com/JumpeiArashi/creat-ec2-more-like-this',
    license='MIT',
    install_requires=[
        'boto'
    ],
    test_suite='test',
    test_requires=[
        'nose',
        'moto'
    ]
)
