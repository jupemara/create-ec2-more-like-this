#!/usr/bin/env python
# -*- coding: utf-8 -*-

import boto.ec2.instance
import moto
import nose.tools

import more_like_this


class TestFailGetBaseEC2Instance(object):

    @moto.mock_ec2
    def setup(self):
        self.conn = more_like_this.create_conn(
            region_name='us-east-1',
            aws_access_key_id='hogehoge',
            aws_secret_access_key='fugafuga'
        )

    @moto.mock_ec2
    @nose.tools.raises(more_like_this.EC2MoreLikeThisException)
    def test_no_both_hostname_and_id(self):
        more_like_this.get_base_ec2_instance(
            conn=self.conn,
            base_ec2_hostname='',
            base_ec2_id=''
        )

    @moto.mock_ec2
    @nose.tools.raises(more_like_this.EC2MoreLikeThisException)
    def test_both_hostname_and_id(self):
        more_like_this.get_base_ec2_instance(
            conn=self.conn,
            base_ec2_hostname='HOGEHOGE',
            base_ec2_id='HOGEHOGE'
        )


class TestGetBaseEC2InstanceById(object):

    @moto.mock_ec2
    def setup(self):
        self.conn = more_like_this.create_conn(
            region_name='us-east-1',
            aws_access_key_id='hogehoge',
            aws_secret_access_key='fugafuga'
        )

    @moto.mock_ec2
    def teardown(self):
        self.conn.close()

    @moto.mock_ec2
    def test_success_get_base_ec2_instance(self):
        # create ec2 instance
        self.conn.run_instances(
            image_id='ami-hogehoge'
        )
        # get created instance id
        instance_id = self.conn.get_all_instances()[0].instances[0].id

        result = more_like_this.get_base_ec2_instance(
            conn=self.conn,
            base_ec2_id=instance_id
        )
        nose.tools.ok_(
            isinstance(result[0], boto.ec2.instance.Reservation)
        )

    @moto.mock_ec2
    @nose.tools.raises(more_like_this.EC2MoreLikeThisException)
    def test_no_instance_get_base_ec2_instance(self):

        more_like_this.get_base_ec2_instance(
            conn=self.conn,
            base_ec2_id='HOGEHOGE'
        )
