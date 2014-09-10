#!/usr/bin/env python
# -*- coding: utf-8 -*-

import boto.ec2
import boto.ec2.instance
import boto.ec2.image
import moto
import nose.tools

import more_like_this


class TestMoreLikeThisEC2InstanceWithoutEBS(object):

    @moto.mock_ec2
    def create_instance(self):
        self.conn.run_instances(
            image_id='ami-HOGEHOGE'
        )
        reservations = self.conn.get_all_instances()
        return reservations[0].instances[0]

    @moto.mock_ec2
    def setup(self):
        self.conn = boto.ec2.connect_to_region(
            region_name='us-east-1',
            aws_access_key_id='HOGEHOGE',
            aws_secret_access_key='FUGAFUGA'
        )
        instance = self.create_instance()
        self.conn.create_image(
            instance_id=instance.id,
            name='TESTING_IMAGE'
        )
        self.image = self.conn.get_all_images()[0]
        self.more_like_this = more_like_this.MoreLikeThisEC2Instance()

    @moto.mock_ec2
    def teardown(self):
        self.conn.close()

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
            checking_state_term=0.00001,
            checking_count_threshold=1
        )

        nose.tools.ok_(
            isinstance(result, boto.ec2.instance.Instance)
        )
