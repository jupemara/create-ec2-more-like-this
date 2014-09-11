#!/usr/bin/env python
# -*- coding: utf-8 -*-

import boto.ec2
import moto
import nose.tools

import more_like_this
import test.base


class TestApplyEC2OverrideOptions(test.base.BaseMoreLikeThisEC2Instance):

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
        self.more_like_this.set_base_image(
            base_image=self.image
        )

    @moto.mock_ec2
    def apply_value(self, name, value):
        instance = self.create_instance()
        self.more_like_this.set_base_ec2_instance(
            ec2_instance=instance
        )
        self.more_like_this.apply_ec2_option(
            name=name,
            value=value
        )
        self.more_like_this.set_ec2_connection(self.conn)
        result = self.more_like_this.run(
            wait_until_running=False
        )
        nose.tools.ok_(
            (self.more_like_this.ec2_attributes.get(name) == value) and
            (getattr(result, name, 'CannotGet{0}'.format(name)) == value)
        )

    @moto.mock_ec2
    def test_override_subnet_id(self):
        """
        test --override-subnet-id option
        """
        self.apply_value(
            name='subnet_id',
            value='subnet-HOGEHOGE'
        )

    @moto.mock_ec2
    @nose.tools.raises(more_like_this.EC2MoreLikeThisException)
    def test_apply_no_exist_attribute(self):
        self.apply_value(
            name='HOGEHOGE',
            value='FUGAFUGA'
        )

    @moto.mock_ec2
    def test_override_instance_type(self):
        """
        test --override-ami-id option
        """
        self.apply_value(
            name='instance_type',
            value='c3.xlarge'
        )

    @moto.mock_ec2
    def test_override_private_ip_address(self):
        """
        test --override-private-ip-address option
        """
        self.apply_value(
            name='private_ip_address',
            value='10.100.100.1'
        )

    @moto.mock_ec2
    def test_override_terminate_protection(self):
        """
        test --override-terminate-protection option
        This test may be failed,
        because "disable_api_termination" option is not implemented
        in moto.mock_ec2.
        """
        self.apply_value(
            name='disable_api_termination',
            value=True
        )

    @moto.mock_ec2
    def test_override_instance_initiated_shutdown_behavior(self):
        """
        test --override-shutdown-behavior option
        This test may be failed,
        because "instance_initiated_shutdown_behavior" option
        is not implemented in moto.mock_ec2.
        """
        self.apply_value(
            name='instance_initiated_shutdown_behavior',
            value='shutdown'
        )

    @moto.mock_ec2
    def test_override_sg_ids(self):
        """
        test --override-security group option
        """
        based_sg_name = 'BASED_SG_NAME'
        instance_security_group = self.conn.create_security_group(
            name=based_sg_name,
            description='based ec2 instance security group'
        )
        override_security_group = 'OVERRIDE_SG_NAME'
        override_security_group = self.conn.create_security_group(
            override_security_group,
            description='override security group'
        )
        based_instance = self.conn.run_instances(
            image_id='ami-HOGEHOGE',
            security_group_ids=[instance_security_group.id]
        ).instances[0]
        self.more_like_this.set_base_ec2_instance(
            ec2_instance=based_instance
        )
        image_id = self.conn.create_image(
            instance_id=based_instance.id,
            name='TESTING_IMAGE'
        )
        image = self.conn.get_all_images(image_ids=[image_id])[0]
        self.more_like_this.set_base_image(image)
        self.more_like_this.apply_ec2_option(
            name='security_group_ids',
            value=[override_security_group.id]
        )
        result = self.more_like_this.run(wait_until_running=False)

        nose.tools.eq_(
            self.more_like_this.ec2_attributes['security_group_ids'],
            [ entry.id for entry in result.groups]
        )
