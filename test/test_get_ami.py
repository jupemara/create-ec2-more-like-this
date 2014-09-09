#!/usr/bin/env python
# -*- coding: utf-8 -*-

import boto.ec2.image
import moto
import nose.tools

import more_like_this


class TestGetAMI(object):

    def setup(self):
        self.conn = more_like_this.create_conn(
            region_name='us-east-1',
            aws_access_key_id='HOGEHOGE',
            aws_secret_access_key='FUGAFUGA'
        )

    def teardown(self):
        self.conn.close()

    @nose.tools.raises(more_like_this.EC2MoreLikeThisException)
    @moto.mock_ec2
    def test_does_not_exist_specified_ami(self):
        more_like_this.get_ami(
            conn=self.conn,
            ami_id='ami-HOGEHOGE'
        )

    @moto.mock_ec2
    def test_success(self):
        # create instance and image for test
        self.conn.run_instances(
            image_id='ami-TESTING'
        )
        reservations = self.conn.get_all_instances()
        instance_id = reservations[0].instances[0].id
        image_id = self.conn.create_image(
            instance_id,
            name='TEST_IMAGE'
        )

        images = more_like_this.get_ami(
            conn=self.conn,
            ami_id=image_id
        )

        nose.tools.ok_(
            isinstance(images[0], boto.ec2.image.Image)
        )




