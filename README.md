create-ec2-more-like-this
=========================

![Circle CI build status](https://circleci.com/gh/JumpeiArashi/create-ec2-more-like-this.svg?style=shield&circle-token=:73be2d63d115ec3560d8efb69139562d482197bd)


What is this script??
---------------------

This script create your new EC2 instance such as "Launch more like this".

Normally you manipulate from GUI(called GAMEN_POCHIPOCHI in japanese) when creating new EC2 Instance.

1. Choice Based EC2 Instance
2. Click *Launch More Like This* button
3. Update New Instance Parameters
    + Private IP
    + Brock Device Mapping(EBS Mapping)
    + Security Groups ...etc
4. Launch your New EC2 Instance

But we (at least I) think it's very boring to repeat above workflow...
So I implement AWS console *Launch more like this* button on our terminal.


Conduct to "Launch more like this" on command line
--------------------------------------------------

### 1. Install me.

```bash
git clone https://github.com/JumpeiArashi/create-ec2-more-like-this.git
```

### 2. Install python module requires.

```bash
python setup.py develop
```

OR

```bash
pip install boto
```

note:

Required module is only `boto`.
We use no third party python module for compatible python 2.6.X.

### 3. Launch More Like This!!

```bash
./more_like_this.py \
--base-ec2-name=YOUR_BASE_EC2_NAME_TAG \
--hostname=NEW_EC2_INSTANCE_NAME_TAG \
--aws-access-key-id=YOUR_AWS_ACCESS_KEY_ID \
--aws-secret-access-key=YOUR_AWS_ACCESS_ACCESS_KEY
```

Specifying only 4 options, you can launch new EC2 instance.


Command Line Options
--------------------

And we implemented following command line options.
You can override various EC2 instance parameters such as AMI ID, Security Groups, EBS mapping and private IP address.

### General

| long option name     | short hand | description                                                                 | default | require?                                           |
|----------------------|------------|-----------------------------------------------------------------------------|---------|----------------------------------------------------|
| --base-ec2-name      | -N         | **Name** tag of based EC2 instance                                          | -       | Either --base-ec2-id option and this are require   |
| --base-ec2-id        | -I         | Based EC2 instance id like i-XXXXXXX                                        | -       | Either --base-ec2-name option and this are require |
| --hostname           | -H         | New EC2 instance hostname(Name Tag).                                        | -       | :x:                                                |
| --dry-run            | -D         | Dry run flag. This option must be "true" or "false" as str type.            | true    | :x:                                                |
| --wait-until-running | -W         | Whether wait to change instance status is running.                          | false   | :x:                                                |
| --log-level          | -L         | Console output log level. Must be DEBUG, INFO, WARNING, ERROR and CRITICAL. | INFO    | :x:                                                |

note:

If you specify `--log-level=DEBUG`, you can see boto's debug logging.

### AWS Credential

| long option name        | short hand | description              | default   | require? |
|-------------------------|------------|--------------------------|-----------|----------|
| --region-name           | -r         | AWS Region Name          | us-east-1 | :x:      |
| --aws-access-key-id     | -i         | AWS Access Key ID        | -         | :o:      |
| --aws-secret-access-key | -k         | AWS Secret Access Key ID | -         | :o:      |

note:

We will implement to get credential by IAM role of EC2 instance in the future.
So you will not need to use "--aws-access-key-id" and "--aws-secret-access-key" options.

### Override EC2 Option

You can apply following parameter new EC2 instance.
All parameters in this section are not optional.

| long option name                                     | short hand | description                                                                                 |
|------------------------------------------------------|------------|---------------------------------------------------------------------------------------------|
| --orverride-ami-id                                   | -a         | Override AMI id(Base Image)                                                                 |
| --ovreride-security-groups                           | -s         | Override security groups                                                                    |
| --override-subnet-id                                 | -c         | Override Subnet ID                                                                          |
| --override-instance-type                             | -t         | Override EC2 Instance Type                                                                  |
| --override-primary-nic-private-ip-address            | -x         | Override Primary Private Address                                                            |
| --override-primary-nic-associate-public-ip-address   | -y         | Override Whether Associate Public IP                                                        |
| --override-secondary-nic-private-ip-address          | -X         | Override Private Address                                                                    |
| --override-secondary-nic-associate-public-ip-address | -Y         | Override Whether Associate Public IP                                                        |
| --override-terminate-protection                      | -d         | Override Whether Protect Termination.                                                       |
| --override-shutdown-behavior                         | -b         | Override shutdown behavior. You can specify either "stop" or "terminate"                    |
| --override-root-ebs-size                             | -v         | Override root volume size                                                                   |
| --override-root-ebs-type                             | -f         | Override root volume type. You can specify either "standard"(Magnetic) or "consistent-iops" |
| --override-root-ebs-iops                             | -o         | Override root volume IOPS                                                                   |
| --override-optional-ebs-size                         | -V         | Override optional volume size                                                               |
| --override-optional-ebs-device                       | -G         | Override optional EBS device name. e.g: /dev/dbh                                            |
| --override-optional-ebs-type                         | -F         | Override optional volume type                                                               |
| --override-optional-ebs-iops                         | -O         | Override optional volume IOPS                                                               |

### Especially

You can use *cloud-init* with `--userdata` option.
But we don't support base64 encoded string and script file.
You need to write directly script to your terminal.

e.g: `--userdata='echo "hogehogehogehoge"'`

Set your mind at ease.
We will support base64 encoded string in the future.

### warning

##### --override-security-groups

When you want to apply multiple security groups,
you need to use comma as delimiter.

e.g: `--override-security-groups='sg-XXXXXXX,sg-YYYYYYYY''`

#### Overriding Elastic NIC parameters

Sorry, we support up to 2 Elastic NIC.
And if you not specify private IP address, your new instance has automatically private IP address by DHCP.

#### Overriding EBS parameters

Sorry, we support up to 2 EBS volumes.

Future
------

* Support temporary credential by IAM role of EC2 instance.
* Support base64 encoded string as `--userdata` option.


Licence
-------

create-ec2-more-like is released under the [WTFPL license](http://www.wtfpl.net/). ![WTFPL license logo](http://www.wtfpl.net/wp-content/uploads/2012/12/wtfpl-badge-4.png)
