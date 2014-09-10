#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import optparse
import time

import boto.ec2
import boto.ec2.image
import boto.exception


DEFAULT = {
    'region_name': 'us-east-1',
    'aws_access_key_id': None,
    'aws_secret_access_key': None,
    'base_ec2_hostname': None,
    'base_ec2_id': None,
    'hostname': None,
    'override_ami_id': None,
    'override_sg_ids': None,
    'override_subnet_id': None,
    'override_instance_type': None,
    'override_private_ip': None,
    'override_terminate_protection': None,
    'override_shutdown_behavior': None,
    'override_ebs_size': None,
    'override_ebs_device': None,
    'override_ebs_type': None,
    'override_ebs_iops': None,
    'userdata': None,
    'log_level': 'INFO',
    'dry_run': False,
}


def get_args():

    usage = (
        'Create EC2 instance like "AWS Launch more like this".'
    )
    parser = optparse.OptionParser(usage=usage)

    aws_credential_option_group = optparse.OptionGroup(
        parser,
        'AWS credential parameters'
    )

    aws_credential_option_group.add_option(
        '--region-name', '-r',
        type='string', default=DEFAULT['region_name'],
        dest='region_name',
        help='AWS Region Name.'
    )
    aws_credential_option_group.add_option(
        '--aws-access-key-id', '-i',
        type='string', default=DEFAULT['aws_access_key_id'],
        dest='aws_access_key_id',
        help='AWS Access Key Id'
    )
    aws_credential_option_group.add_option(
        '--aws-secret-access-key', '-k',
        type='string', default=DEFAULT['aws_secret_access_key'],
        dest='aws_secret_access_key',
        help='AWS Secret Access Key'
    )
    parser.add_option_group(aws_credential_option_group)

    override_ec2_option_group = optparse.OptionGroup(
        parser,
        'Override Instance Options'
    )

    override_ec2_option_group.add_option(
        '--override-ami-id', '-a',
        type='string', default=DEFAULT['override_ami_id'],
        dest='override_ami_id',
        help='When you want to override new instance AMI, use this option.'
    )
    override_ec2_option_group.add_option(
        '--override-sg-ids', '-s',
        type='string', default=DEFAULT['override_sg_ids'],
        dest='override_sg_ids',
        help=(
            'When you want to override new instance security groups, '
            'use this option. '
            'Use comma as delimiter.'
        )
    )
    override_ec2_option_group.add_option(
        '--override-subnet-id', '-c',
        type='string', default=DEFAULT['override_subnet_id'],
        dest='override_subnet_id',
        help='when you want to override new instance subnet, use this option.'
    )
    override_ec2_option_group.add_option(
        '--override-instance-type', '-t',
        type='string', default=DEFAULT['override_instance_type'],
        dest='override_instance_type',
        help=(
            'when you want to override new instance instance type, '
            'use this option.'
        )
    )
    override_ec2_option_group.add_option(
        '--override-private-ip', '-x',
        type='string', default=DEFAULT['override_private_ip'],
        dest='override_private_ip',
        help=(
            'when you want to override new instance private IP address, '
            'use this option.'
        )
    )
    override_ec2_option_group.add_option(
        '--override-terminate-protection', '-d',
        type='string', default=DEFAULT['override_terminate_protection'],
        dest='override_terminate_protection',
        help=(
            'When you want to '
            'override new instance terminate protection option, '
            'use this option.'
        )
    )
    override_ec2_option_group.add_option(
        '--override-shutdown-behavior', '-b',
        type='choice', default=DEFAULT['override_shutdown_behavior'],
        choices=[
            'stop',
            'terminate'
        ],
        dest='override_shutdown_behavior',
        help=(
            'When you want to override new instance shutdown behavior, '
            'use this option.'
        )
    )
    parser.add_option_group(override_ec2_option_group)

    override_ebs_option_group = optparse.OptionGroup(
        parser,
        'Override EBS Options'
    )
    override_ebs_option_group.add_option(
        '--override-ebs-size', '-v',
        type='int', default=DEFAULT['override_ebs_size'],
        dest='override_ebs_size',
        help=(
            'When you want to override EBS size, '
            'use this option. Unit of this option is GB.'
        )
    )
    override_ebs_option_group.add_option(
        '--override-ebs-device', '-g',
        type='string', default=DEFAULT['override_ebs_device'],
        dest='override_ebs_device',
        help=(
            'When you want to override EBS attached device, '
            'use this option. e.x: /dev/xvdb1'
        )
    )
    override_ebs_option_group.add_option(
        '--override-ebs-type', '-f',
        type='choice', default=DEFAULT['override_ebs_device'],
        choices=[
            'standard',
            'consistent-iops'
        ],
        dest='override_ebs_type',
        help=(
            'When you want to override EBS type, '
            'use this option.'
        )
    )
    override_ebs_option_group.add_option(
        '--override-ebs-iops', '-o',
        type='int', default=DEFAULT['override_ebs_iops'],
        dest='override_ebs_iops',
        help=(
            'When you want to override EBS type, '
            'use this option.'
        )
    )
    parser.add_option_group(override_ebs_option_group)

    parser.add_option(
        '--base-ec2-name', '-N',
        type='string', default=DEFAULT['base_ec2_hostname'],
        dest='base_ec2_name',
        help='Based EC2 instance hostname.'
    )
    parser.add_option(
        '--base-ec2-id', '-I',
        type='string', default=DEFAULT['base_ec2_id'],
        dest='base_ec2_id',
        help='Based EC2 instance id.'
    )
    parser.add_option(
        '--hostname', '-H',
        type='string', default=DEFAULT['hostname'],
        help='New EC2 instance hostname(Name Tag).'
    )
    parser.add_option(
        '--userdata', '-U',
        type='string', default=DEFAULT['userdata'],
        help='Injected AWS "Userdata".'
    )
    parser.add_option(
        '--dry-run', '-D',
        action='store_true', default=DEFAULT['dry_run'],
        dest='dry_run',
        help='Dry run flag.'
    )
    parser.add_option(
        '--log-level', '-L',
        type='choice', default=DEFAULT['log_level'],
        choices=[
            'DEBUG',
            'INFO',
            'WARNING',
            'ERROR',
            'CRITICAL'
        ],
        help=(
            'Injected AWS "Userdata".'
        )
    )

    return parser.parse_args()[0]


class EC2MoreLikeThisException(BaseException):

    def __init__(self, message):
        super(EC2MoreLikeThisException, self).__init__(message)


def set_log_level(log_level='DEBUG'):
    logging.basicConfig(
        format='[%(levelname)s] %(message)s',
        level=getattr(logging, log_level)
    )


def validate_options(options):

    if not options.aws_access_key_id:
        raise EC2MoreLikeThisException(
            '"--aws-access-key-id" option is required.'
        )

    if not options.aws_secret_access_key:
        raise EC2MoreLikeThisException(
            '"--aws-secret-access-key" option is required.'
        )

    if (
        not options.base_ec2_hostname and
        not options.base_ec2_id
    ):
        raise EC2MoreLikeThisException(
            '"--base-ec2-hostname" or "--base-ec2-id"'
            'specify any.'
        )


def convert_options(options):

    if options.override_terminate_protection:
        if options.override_terminate_protection.lower() == 'true':
            options.override_terminate_protection = True
        elif options.override_terminate_protection.lower() == 'false':
            options.override_terminate_protection = False
        else:
            raise EC2MoreLikeThisException(
                (
                    '"--override-terminate-protection" option must be '
                    '"true" or "false"'
                )
            )

    if options.override_sg_ids:
        try:
            options.override_sg_ids = [
                entry.strip() for entry in options.override_sg_ids.split(',')
            ]
        except:
            raise EC2MoreLikeThisException(
                '--override-sg-ids option must be separated by comma.'
            )


def create_conn(region_name, aws_access_key_id, aws_secret_access_key):

    try:
        conn = boto.ec2.connect_to_region(
            region_name=region_name,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key
        )
    except Exception as exception:
        raise EC2MoreLikeThisException(
            exception.__str__()
        )

    if conn is None:
        raise EC2MoreLikeThisException(
            'Maybe failed to AWS authentication.'
        )

    return conn


def get_base_ec2_instance(conn,
                          base_ec2_hostname=None,
                          base_ec2_id=None):
    """
    Get EC2 instance by Name tag or instance id.
    :param conn: EC2 connection
    :type conn: boto.ec2.EC2Connection
    :param base_ec2_hostname: Name tag of based ec2 instance
    :type base_ec2_hostname: str
    :param base_ec2_id: Instance id of based ec2 instance
    :type base_ec2_id: str
    :rtype: list
    :return: EC2 Reservation
    """

    if not base_ec2_hostname and not base_ec2_id:
        raise EC2MoreLikeThisException(
            '"base_ec2_hostname" or "base_ec2_id" argument is required.'
        )
    elif base_ec2_hostname and base_ec2_id:
        raise EC2MoreLikeThisException(
            '"base_ec2_hostname" and "base_ec2_id" arguments are exclusive.'
        )
    elif base_ec2_hostname:
        try:
            result = conn.get_all_instances(
                filters={
                    'tag:Name': base_ec2_hostname
                }
            )
            logging.debug(
                'Base instance is {0}.'.format(result)
            )
            return result
        except boto.exception.EC2ResponseError as exception:
            raise EC2MoreLikeThisException(
                exception.__str__()
            )
    elif base_ec2_id:
        try:
            result = conn.get_all_instances(instance_ids=[base_ec2_id])
            logging.debug(
                'Base instance is {0}.'.format(result)
            )
            return result
        except boto.exception.EC2ResponseError as exception:
            raise EC2MoreLikeThisException(
                exception.__str__()
            )


def get_ami(conn, ami_id):

    try:
        result = conn.get_all_images(image_ids=[ami_id])
        return result
    except boto.exception.EC2ResponseError as exception:
        raise EC2MoreLikeThisException(
            exception.__str__()
        )


class MoreLikeThisEC2Instance(object):

    def __init__(self):
        self.conn = None
        self.base_ec2_instance = None
        self.base_block_device_mapping = None
        self.ec2_attributes = dict()
        self.ec2_tags = dict()
        self.device_mapping = dict()
        self.base_image = None

    def set_base_ec2_instance(self, ec2_instance):
        self.base_ec2_instance = ec2_instance

        self.ec2_attributes['key_name'] = self.base_ec2_instance.key_name
        self.ec2_attributes['security_group_ids'] = (
            self.base_ec2_instance.groups
        )
        self.ec2_attributes['subnet_id'] = self.base_ec2_instance.subnet_id
        self.ec2_attributes['instance_type'] = (
            self.base_ec2_instance.instance_type
        )
        try:
            self.ec2_attributes['disable_api_termination'] = (
                self.base_ec2_instance.get_attribute(
                    'disableApiTermination'
                ).get('disableApiTermination', False)
            )
        except AttributeError:
            logging.warn(
                'Instance doesn\'t have "disableApiTermination" attribute.'
            )
        try:
            self.ec2_attributes['instance_initiated_shutdown_behavior'] = (
                self.base_ec2_instance.get_attribute(
                    'instanceInitiatedShutdownBehavior'
                ).get('instanceInitiatedShutdownBehavior', 'stop')
            )
        except AttributeError:
            logging.warn(
                'Instance doesn\'t have '
                '"instanceInitiatedShutdownBehavior" attribute.'
            )
        self.ec2_tags = self.base_ec2_instance.tags

    def set_base_block_device_mapping(self, block_device_mapping):
        self.base_block_device_mapping = block_device_mapping

    def set_ec2_connection(self, conn):
        self.conn = conn

    def set_base_image(self, base_image):
        self.base_image = base_image

    def apply_ec2_option(self, name, value):
        if value and name in self.ec2_attributes.keys():
            self.ec2_attributes[name] = value
        else:
            raise EC2MoreLikeThisException(
                'EC2 instance has no attributes {0}'.format(name)
            )

        if len(self.base_block_device_mapping.keys()) > 2:
            raise NotImplementedError(
                (
                    'Sorry!! We haven\'t implement "Launch more like this" '
                    'to ec2 instance that has EBSs more than two.'
                )
            )

    def apply_ec2_hostname(self, hostname):
        self.ec2_tags['Name'] = hostname

    def verify_ec2_instance_by_name(self, name):
        reservations = self.conn.get_all_instances(
            filters={'tag:Name': name}
        )
        if len(reservations[0].instances) > 0:
            raise EC2MoreLikeThisException(
                'Specified instance name {0} is already used.'.format(name)
            )
        return True

    def verify_ec2_instance_by_private_ip(self, private_ip_address):
        all_nics = self.conn.get_all_network_interfaces()
        all_private_ips = [
            entry.private_ip_address for entry in all_nics
        ]
        if private_ip_address in all_private_ips:
            raise EC2MoreLikeThisException(
                'Specified private IP {0} is already used.'
                ''.format(private_ip_address)
            )
        return True

    def run(self,
            wait_until_running=True,
            checking_state_term=5,
            checking_count_threshold=60,
            dry_run=False):
        run_params = self.ec2_attributes.copy()
        run_params['dry_run'] = dry_run
        reservation = self.base_image.run(
            **run_params
        )
        instance = reservation.instances[0]
        if self.ec2_tags:
            instance.add_tags(self.ec2_tags)
        else:
            logging.info(
                'You specify no tags for new EC2 instance.'
            )

        #attach_ebs


        if wait_until_running:
            pending_count = 0
            while instance.state.lower() == 'pending':
                logging.info(
                    'Created instance state is "pending"'
                )
                time.sleep(checking_state_term)
                pending_count += 1

                if pending_count > checking_count_threshold:
                    logging.warn(
                        'Checking instance state timeout.'
                    )
                    break
            return instance

        else:
            return instance


if __name__ == '__main__':
    get_args()
