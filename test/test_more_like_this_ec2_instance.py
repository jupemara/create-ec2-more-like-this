#!/usr/bin/env python
# -*- coding: utf-8 -*-

import boto.ec2.blockdevicemapping
import boto.ec2.instance
import boto.ec2.image
import moto
import nose.tools

import test.base


class TestMoreLikeThisEC2InstanceWithoutEBS(
    test.base.BaseMoreLikeThisEC2Instance
):

    @moto.mock_ec2
    def test_set_base_image(self):
        self.more_like_this.set_base_image(base_image=self.image)

        nose.tools.ok_(
            isinstance(
                self.more_like_this.base_image,
                boto.ec2.image.Image
            )
        )

    @moto.mock_ec2
    def test_set_base_ec2_instance(self):
        instance = self.create_instance()
        self.more_like_this.set_base_ec2_instance(instance)

    @moto.mock_ec2
    def test_run_without_ebs(self):
        self.more_like_this.set_base_image(base_image=self.image)
        instance = self.create_instance()
        self.more_like_this.set_base_ec2_instance(ec2_instance=instance)

        result = self.more_like_this.run(
            wait_until_running=False,
            checking_state_term=0.001
        )

        nose.tools.ok_(
            isinstance(result, boto.ec2.instance.Instance)
        )


class TestSetBaseBlockDeviceMapping(
    test.base.BaseMoreLikeThisEC2Instance
):

    @moto.mock_ec2
    def create_instance(self):
        volume = self.conn.create_volume(
            size=100,
            zone=self.conn.region.name
        )
        block_device_map = boto.ec2.blockdevicemapping.BlockDeviceMapping(
            connection=self.conn
        )
        block_device_type = boto.ec2.blockdevicemapping.BlockDeviceType(
            connection=self.conn,
            size=100,
            volume_id=volume.id
        )
        block_device_map['/dev/sdh'] = block_device_type
        self.conn.run_instances(
            image_id='ami-HOGEHOGE',
            block_device_map=block_device_map
        )
        reservations = self.conn.get_all_instances()
        instance = reservations[0].instances[0]
        return instance

    @moto.mock_ec2
    def test_set_base_block_device_mapping(self):
        instance = self.create_instance()
        self.more_like_this.set_base_block_device_mapping(
            block_device_mapping=instance.block_device_mapping
        )
