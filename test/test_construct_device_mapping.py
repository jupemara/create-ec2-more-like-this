#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging

import boto.ec2
import boto.ec2.blockdevicemapping
import moto
import nose.tools

import more_like_this


class TestRootDeviceOnly(object):

    pass


class TestOptionalDevice(object):

    pass


class TestDeprecatedRootDevice(object):

    @moto.mock_ec2
    def setup(self):
        self.conn = boto.ec2.connect_to_region(
            region_name='us-east-1',
            aws_access_key_id='HOGEHOGE',
            aws_secret_access_key='FUGAFUGA'
        )
        self.more_like_this = more_like_this.MoreLikeThisEC2Instance(
            conn=self.conn
        )

    @moto.mock_ec2
    def test_deprecated_root_device(self):
        root_volume = self.conn.create_volume(
            size=8,
            zone=self.conn.region.name
        )
        deprecated_root_volume = self.conn.create_volume(
            size=8,
            zone=self.conn.region.name
        )
        root_device = boto.ec2.blockdevicemapping.BlockDeviceType(
            volume_id=root_volume.id
        )
        deprecated_root_device = boto.ec2.blockdevicemapping.BlockDeviceType(
            volume_id=deprecated_root_volume.id
        )
        block_device_mapping = boto.ec2.blockdevicemapping.BlockDeviceMapping()
        block_device_mapping['/dev/xvda'] = root_device
        block_device_mapping['/dev/sda1'] = deprecated_root_device

        self.more_like_this.set_base_block_device_mapping(
            block_device_mapping
        )
        constructed_device_options = self.more_like_this._construct_device_mapping(
            raw_options=self.more_like_this.device_mapping
        )
        logging.debug(
            'current constructed options is {0}'.format(constructed_device_options)
        )
        nose.tools.ok_(
            len(constructed_device_options.keys()) == 1 and
            constructed_device_options.keys()[0] == '/dev/sda1'
        )
