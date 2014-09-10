#!/usr/bin/env python
# -*- coding: utf-8 -*-

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
            checking_state_term=0.00001,
            checking_count_threshold=1
        )

        nose.tools.ok_(
            isinstance(result, boto.ec2.instance.Instance)
        )
