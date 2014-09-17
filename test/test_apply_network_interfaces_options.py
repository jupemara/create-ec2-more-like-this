#!/usr/bin/env python
# -*- coding: utf-8 -*-

import boto.ec2.networkinterface
import nose.tools

import more_like_this


class TestApplyNetworkInterfacesOptions(object):

    def setup(self):
        """
        Set MoreLikeThisEC2Instance.interface_collection_attributes.
        """
        interface_attributes_mock = dict(
            NO_PRIMARY_PRIVATE_IP=
            boto.ec2.networkinterface.NetworkInterfaceSpecification(
                device_index=0,
                subnet_id='subnet-HOGEHOGE',
                groups=[],
                private_ip_addresses=[
                    boto.ec2.networkinterface.PrivateIPAddress(
                        private_ip_address='10.0.100.100',
                        primary=False
                    )
                ]
            ),
            PRIMARY_PRIVATE_IP=
            boto.ec2.networkinterface.NetworkInterfaceSpecification(
                device_index=0,
                subnet_id='subnet-HOGEHOGE',
                groups=[],
                private_ip_addresses=[
                    boto.ec2.networkinterface.PrivateIPAddress(
                        private_ip_address='10.0.101.100',
                        primary=True
                    )
                ]
            ),
            NO_ASSOCIATE_PUBLIC_IP_ADDRESS=
            boto.ec2.networkinterface.NetworkInterfaceSpecification(
                device_index=0,
                subnet_id='subnet-HOGEHOGE',
                groups=[],
                private_ip_addresses=[
                    boto.ec2.networkinterface.PrivateIPAddress()
                ],
                associate_public_ip_address=None
            )
        )

        self.more_like_this = more_like_this.MoreLikeThisEC2Instance()
        self.more_like_this.interface_collection_attributes = (
            interface_attributes_mock
        )

    def teardown(self):
        del(self.more_like_this)

    def test_apply_private_ip_for_no_primary(self):
        private_ip_address = '10.0.200.100'
        self.more_like_this.apply_nic_private_ip(
            key='NO_PRIMARY_PRIVATE_IP',
            private_ip=private_ip_address
        )

        nose.tools.assert_not_equal(
            private_ip_address,
            (
                self.more_like_this
                .interface_collection_attributes['NO_PRIMARY_PRIVATE_IP']
                .private_ip_addresses[0]
                .private_ip_address
            )
        )

    def test_apply_private_ip_for_primary(self):
        private_ip_address = '10.0.200.100'
        self.more_like_this.apply_nic_private_ip(
            key='PRIMARY_PRIVATE_IP',
            private_ip=private_ip_address
        )
        nose.tools.eq_(
            private_ip_address,
            (
                self.more_like_this
                .interface_collection_attributes['PRIMARY_PRIVATE_IP']
                .private_ip_addresses[0]
                .private_ip_address
            )
        )

    def test_apply_associate_public_ip(self):
        is_associate_public_ip_address = True
        self.more_like_this.apply_nic_associate_public_ip(
            key='NO_ASSOCIATE_PUBLIC_IP_ADDRESS',
            associate_public_ip_address=is_associate_public_ip_address
        )
        nose.tools.ok_(
            (
                self.more_like_this
                .interface_collection_attributes[
                    'NO_ASSOCIATE_PUBLIC_IP_ADDRESS'
                ]
                .associate_public_ip_address
            )
        )

    def test_apply_subnet_id(self):
        subnet_id = 'subnet-FUGAFUGA'
        self.more_like_this.apply_subnet_id(
            subnet_id=subnet_id
        )
        nose.tools.eq_(
            self.more_like_this.interface_collection_attributes[
                'PRIMARY_PRIVATE_IP'
            ].subnet_id,
            subnet_id
        )

    def test_apply_security_group_ids(self):
        security_group_ids = [
            'sg-HOGEHOGE',
            'sg-FUGAFUGA'
        ]
        self.more_like_this.apply_security_group_ids(
            security_group_ids=security_group_ids
        )
        nose.tools.eq_(
            self.more_like_this.interface_collection_attributes[
                'PRIMARY_PRIVATE_IP'
            ].groups,
            security_group_ids
        )
