#!/usr/bin/env python
# -*- coding: utf-8 -*-

import boto.ec2
import moto

import more_like_this


class TestAddNameTagToVolume(object):

    @moto.mock_ec2
    def setup(self):
        self.conn = boto.ec2.connect_to_region(
            region_name='us-east-1',
            aws_access_key_id='HOGEHOGE',
            aws_secret_access_key='FUGAFUGA',
        )
        self.more_like_this = more_like_this.MoreLikeThisEC2Instance(
            conn=self.conn
        )

    @moto.mock_ec2
    def test_root_device_only(self):
        """
        This is not implemented, because moto doesn't implemented Volume.tags
        """

    @moto.mock_ec2
    def test_root_device_plus_optional_device(self):
        """
        This is not implemented, because moto doesn't implemented Volume.tags
        """

    @moto.mock_ec2
    def test_no_device(self):
        """
        This is not implemented, because moto doesn't implemented Volume.tags
        """
