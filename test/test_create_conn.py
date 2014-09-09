#!/usr/bin/env python
# -*- coding: utf-8 -*-

import boto.ec2
import moto
import nose.tools

import more_like_this


@moto.mock_ec2
def test_success_authentication():
    conn = more_like_this.create_conn(
        region_name='us-east-1',
        aws_access_key_id='HOGEHOGE',
        aws_secret_access_key='FUGAFUGA'
    )
    nose.tools.ok_(
        isinstance(conn, boto.ec2.EC2Connection)
    )

@nose.tools.raises(more_like_this.EC2MoreLikeThisException)
def test_fail_authentication():
    conn = more_like_this.create_conn(
        region_name='us-east-1',
        aws_access_key_id=None,
        aws_secret_access_key=None
    )
    print conn.ResponseError
