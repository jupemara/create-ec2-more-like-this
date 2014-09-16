#!/usr/bin/env python
# -*- coding: utf-8 -*-

import boto.ec2
import moto

import more_like_this

class BaseMoreLikeThisEC2Instance(object):

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
        self.more_like_this = more_like_this.MoreLikeThisEC2Instance(
            conn=self.conn
        )

    @moto.mock_ec2
    def teardown(self):
        self.conn.close()
        del(self.more_like_this)
