#!/usr/bin/env python
# -*- coding: utf-8 -*-

import boto.ec2
import boto.ec2.blockdevicemapping
import moto
import moto.ec2.models
import nose.tools

import more_like_this


class TestRootDeviceOnly(object):

    @moto.mock_ec2
    def create_block_device_mapping(self):
        volume = self.conn.create_volume(
            size=8,
            zone=self.conn.region.name
        )
        root_device = boto.ec2.blockdevicemapping.BlockDeviceType(
            volume_id=volume.id
        )
        block_device_map = boto.ec2.blockdevicemapping.BlockDeviceMapping()
        block_device_map['/dev/sda1'] = root_device
        return block_device_map

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
        block_device_map = self.create_block_device_mapping()
        self.more_like_this.set_base_block_device_mapping(
            block_device_mapping=block_device_map
        )

    @moto.mock_ec2
    def teardown(self):
        self.conn.close()
        del(self.more_like_this)

    def apply_value(self, name, value):
        self.more_like_this.apply_root_ebs_option(
            name=name,
            value=value
        )
        nose.tools.eq_(
            value,
            self.more_like_this.device_mapping['/dev/sda1'].get(name)
        )

    @moto.mock_ec2
    def test_override_root_ebs_size(self):
        """
        test --override-root-ebs-size
        """
        self.apply_value(
            name='size',
            value=200
        )

    @moto.mock_ec2
    def test_override_root_ebs_type(self):
        """
        test --override-root-ebs-type
        """
        self.apply_value(
            name='type',
            value='consistent-iops'
        )

    @moto.mock_ec2
    def test_override_root_ebs_iops(self):
        """
        test --override-root-ebs-iops
        """
        self.apply_value(
            name='iops',
            value=100
        )


class TestOptionalDevice(object):

    optional_device = '/dev/sdh'

    @moto.mock_ec2
    def create_block_device_mapping(self):
        root_device = self.conn.create_volume(
            size=8,
            zone=self.conn.region.name
        )
        optional_device = self.conn.create_volume(
            size=100,
            zone=self.conn.region.name
        )
        block_device_map = boto.ec2.blockdevicemapping.BlockDeviceMapping()
        block_device_map['/dev/sda1'] = (
            boto.ec2.blockdevicemapping.BlockDeviceType(
                volume_id=root_device.id
            )
        )
        block_device_map[self.optional_device] = (
            boto.ec2.blockdevicemapping.BlockDeviceType(
                volume_id=optional_device.id
            )
        )
        return block_device_map

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
        block_device_map = self.create_block_device_mapping()
        self.more_like_this.set_base_block_device_mapping(
            block_device_mapping=block_device_map
        )

    @moto.mock_ec2
    def teardown(self):
        self.conn.close()
        del(self.more_like_this)

    def apply_value(self, name, value, device=None):
        self.more_like_this.apply_optional_ebs_option(
            name=name,
            value=value,
            device=device
        )
        if device is None:
            optional_device = self.optional_device
        else:
            optional_device = device
        nose.tools.eq_(
            value,
            self.more_like_this.device_mapping[optional_device].get(name)
        )

    @moto.mock_ec2
    def test_override_optional_ebs_size_with_same_device_name(self):
        """
        test --override-optional-ebs-size
        """
        self.apply_value(
            name='size',
            value=200
        )

    @moto.mock_ec2
    def test_override_optional_ebs_type_with_same_device_name(self):
        """
        test --override-optional-ebs-type
        """
        self.apply_value(
            name='type',
            value='standard'
        )

    @moto.mock_ec2
    def test_override_optional_ebs_iops_with_same_device_name(self):
        """
        test --override-optional-ebs-iops
        """
        self.apply_value(
            name='iops',
            value=200
        )
