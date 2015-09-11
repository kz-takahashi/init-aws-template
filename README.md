init-aws-template
=================

About
-----

This CloudFormation template provides functions to configure initial AWS account to keep audit log and use more secure.
It update account password policy, enable CloudTrail, and create CloudWatch alarm to notify root account login.

Getting Started
---------------

### Compress lambda function code in zip format and upload to your S3 bucket

```
git clone https://github.com/kz-takahashi/init-aws-template
cd init-aws-template
npm install
zip -r initAWS.zip ./index.js ./node_modules
aws s3 cp ./initAWS.zip s3://<your-bucket-name>/<path-to-store-file> # (or upload manually from Management Console)
```

### Create CloudFormation stack

Access your management console and create stack using template.json as CloudFormation Template.

### Delete CloudFormation stack after creation completed successfully

Delete Stack in order to delete Lambda function and IAM role.

Contact
-------

GitHub Issues: https://github.com/kz-takahashi/init-aws-template/issues
