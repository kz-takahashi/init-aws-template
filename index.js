var aws = require('aws-sdk');
var async = require('async');

var s3BucketRegion = 'ap-northeast-1';
var globalLogRegion = 'us-east-1';
var REGIONS = [
    'ap-northeast-1',
    'ap-southeast-1',
    'ap-southeast-2',
    'eu-central-1',
    'eu-west-1',
    'sa-east-1',
    'us-east-1',
    'us-west-1',
    'us-west-2'
];

exports.handler = function(event, context) {
    console.log("REQUEST RECEIVED:\n", JSON.stringify(event));

    // For Delete requests, immediately send a SUCCESS response.
    if (event.RequestType === "Delete") {
        sendResponse(event, context, "SUCCESS");
        return;
    }

    var responseData = {};
    var params = {
        enableAccountPasswordPolicy: event.ResourceProperties.EnableAccountPasswordPolicy,
        enableCloudTrail: event.ResourceProperties.EnableCloudTrail,
        enableRootLoginAlarm: event.ResourceProperties.EnableRootLoginAlarm,
        cloudTrailBucketName: event.ResourceProperties.CloudTrailBucketName,
        passwordPolicyJson: event.ResourceProperties.PasswordPolicyJson,
        notificationEmailAddress: event.ResourceProperties.NotificationEmailAddress
    };

    async.auto({
        enableAccountPasswordPolicy: function(callback) {
            if (params.enableAccountPasswordPolicy) {
                console.log("[PasswordPolicy] EnableAccountPasswordPolicy: true. Start process.");
                updateAccountPasswordPolicy(params.passwordPolicyJson, callback);
            } else {
                console.log("[PasswordPolicy] EnableAccountPasswordPolicy: false. Skipped.");
                callback(null);
            }
        },
        enableCloudTrail: function(callback) {
            if (params.enableCloudTrail) {
                console.log("[CloudTrail] EnableCloudTrail: true. Start process.");
                enableCloudTrail(params.cloudTrailBucketName, callback);
            } else {
                console.log("[CloudTrail] EnableCloudTrail: false. Skipped.");
                callback(null);
            }
        },
        enableRootLoginAlarm: ['enableCloudTrail', function(callback) {
            if (params.enableCloudTrail && params.enableRootLoginAlarm) {
                console.log("[RootLoginAlarm] EnableRootLoginAlarm: true. Start process.");
                createRootLoginAlarm(params.notificationEmailAddress, callback);
            } else {
                console.log("[RootLoginAlarm] EnableRootLoginAlarm: false. Skipped.");
                callback(null);
            }
        }]
    }, function(err, results) {
        if (err) {
            console.log("Lambda function failed. " + err.message);
            responseData.Error = err.message;
            sendResponse(event, context, "FAILED", responseData);
        } else {
            console.log("Lambda function completed successfully.");
            sendResponse(event, context, "SUCCESS", responseData);
        }
    });
};

//Sends response to the pre-signed S3 URL
function sendResponse(event, context, responseStatus, responseData) {
   var responseBody = JSON.stringify({
        Status: responseStatus,
        Reason: "See the details in CloudWatch Log Stream: " + context.logStreamName,
        PhysicalResourceId: context.logStreamName,
        StackId: event.StackId,
        RequestId: event.RequestId,
        LogicalResourceId: event.LogicalResourceId,
        Data: responseData
    });
    
    console.log("RESPONSE BODY:\n", responseBody);

    var https = require("https");
    var url = require("url");

    var parsedUrl = url.parse(event.ResponseURL);
    var options = {
        hostname: parsedUrl.hostname,
        port: 443,
        path: parsedUrl.path,
        method: "PUT",
        headers: {
            "content-type": "",
            "content-length": responseBody.length
        }
    };

    var request = https.request(options, function(response) {
        console.log("STATUS: " + response.statusCode);
        console.log("HEADERS: " + JSON.stringify(response.headers));
        // Tell AWS Lambda that the function execution is done  
        context.done();
    });

    request.on("error", function(error) {
        console.log("sendResponse Error:\n", error);
        // Tell AWS Lambda that the function execution is done  
        context.done();
    });

    // write data to request body
    request.write(responseBody);
    request.end();
}

function updateAccountPasswordPolicy(policyJson, callback){
    var iam = new aws.IAM();
    var params = JSON.parse(policyJson);
    if (params.MaxPasswordAge === 0) { delete params.MaxPasswordAge; }
    if (params.PasswordReusePrevention === 0) { delete params.PasswordReusePrevention; }

    iam.updateAccountPasswordPolicy(params, function(err, data) {
        if (err) {
            console.log("[PasswordPolicy] Failed to update account password policy.");
            console.log(err, err.stack);
            callback(err);
        } else {
            console.log("[PasswordPolicy] Success to update account password policy.");
            callback(null);
        }
    });
}

function enableCloudTrail(s3BucketName, callback){
    async.auto({
        createS3Bucket: function(cb) {
            createS3BucketForCloudTrail(s3BucketName, cb);
        },
        createRole: function(cb) {
            createIAMRoleForCloudTrail(cb);
        },
        createTrail: ['createS3Bucket', 'createRole', function(cb, results) {
            createCloudTrailOnAllRegions(s3BucketName, results.createRole, cb);
        }]
    }, function(err, results) {
        if (err) {
            console.log("[CloudTrail] Failed to enable CloudTrail.");
            console.log(err, err.stack);
            callback(err);
        } else {
            console.log("[CloudTrail] Success to enable CloudTrail.");
            callback(null);
        }
    });
}

function createS3BucketForCloudTrail(s3BucketName, callback) {
    var s3 = new aws.S3();
    var bucketPolicy = (function(){/*
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AWSCloudTrailAclCheck20131101",
            "Effect": "Allow",
            "Principal": {
                "AWS": [
                    "arn:aws:iam::903692715234:root",
                    "arn:aws:iam::035351147821:root",
                    "arn:aws:iam::859597730677:root",
                    "arn:aws:iam::814480443879:root",
                    "arn:aws:iam::216624486486:root",
                    "arn:aws:iam::086441151436:root",
                    "arn:aws:iam::388731089494:root",
                    "arn:aws:iam::284668455005:root",
                    "arn:aws:iam::113285607260:root"
                ]
            },
            "Action": "s3:GetBucketAcl",
            "Resource": "replaceS3BucketArn"
        },
        {
            "Sid": "AWSCloudTrailWrite20131101",
            "Effect": "Allow",
            "Principal": {
                "AWS": [
                    "arn:aws:iam::903692715234:root",
                    "arn:aws:iam::035351147821:root",
                    "arn:aws:iam::859597730677:root",
                    "arn:aws:iam::814480443879:root",
                    "arn:aws:iam::216624486486:root",
                    "arn:aws:iam::086441151436:root",
                    "arn:aws:iam::388731089494:root",
                    "arn:aws:iam::284668455005:root",
                    "arn:aws:iam::113285607260:root"
                ]
            },
            "Action": "s3:PutObject",
            "Resource": "replaceS3BucketDirectoryArn",
            "Condition": {
                "StringEquals": {
                    "s3:x-amz-acl": "bucket-owner-full-control"
                }
            }
        }
    ]
}
    */}).toString().match(/\n([\s\S]*)\n/)[1];
    bucketPolicy = bucketPolicy.replace("replaceS3BucketArn", "arn:aws:s3:::" + s3BucketName);
    bucketPolicy = bucketPolicy.replace("replaceS3BucketDirectoryArn", "arn:aws:s3:::" + s3BucketName + "/*");

    async.auto({
        getBucket: function(cb) {
            s3.getBucketPolicy({
                Bucket: s3BucketName
            }, function(err, data) {
                var isExist = (err ? false : true);
                cb(null, isExist);
            });
        },
        createBucket: ['getBucket', function(cb, results) {
            if(results.getBucket) {
                console.log("[CloudTrail] S3 bucket '" + s3BucketName + "' already exists. Skipped.");
                cb(null);
            } else {
                var params = {
                    Bucket: s3BucketName,
                    ACL: "private",
                    CreateBucketConfiguration: {
                        LocationConstraint: s3BucketRegion
                    }
                };
                s3.createBucket(params, cb);
            }
        }],
        putBucketPolicy: ['createBucket', function(cb, results){
            if(results.getBucket) {
                console.log("[CloudTrail] S3 bucket '" + s3BucketName + "' already exists. putBucketPolicy Skipped.");
                cb(null);
            } else {
                var params = {
                    Bucket: s3BucketName,
                    Policy: bucketPolicy
                };
                s3.putBucketPolicy(params, function(err, data) {
                    if (err) {
                        console.log("[CloudTrail] Failed to put bucket policy.");
                        cb(err);
                    } else {
                        cb(null, data);
                    }
                });
            }
        }]
    }, function(err, results) {
        if (err) {
            console.log("[CloudTrail] Failed to create S3 bucket.");
            callback(err);
        } else {
            callback(null);
        }
    });
}

function createCloudTrailOnAllRegions(s3BucketName, roleArn, callback){
    async.each(REGIONS, function(region, cb) {
        createCloudTrail(region, s3BucketName, roleArn, cb);
    }, function(err, results) {
        if (err) {
            console.log("[CloudTrail] Failed to enable CloudTrail. " + err.message);
            callback(err);
        } else {
            console.log("[CloudTrail] Success to enable CloudTrail at all regions.");
            callback(null);
        }
    });
}

function createCloudTrail(region, s3BucketName, roleArn, callback){
    var cloudtrail = new aws.CloudTrail({region: region});
    var trailName = 'Default';

    async.auto({
        getTrail: function(cb) {
            cloudtrail.getTrailStatus({
                Name: trailName
            }, function(err, data) {
                var trail = (err ? null : data);
                cb(null, trail);
            });
        },
        createCloudWatchLogsLogGroup: ['getTrail', function(cb, results) {
            if (results.getTrail) {
                cb(null);
            }
            // CloudTrail does not support integration with CloudWatch Logs at sa-east-1.
            if(region !== "sa-east-1") {
                createCloudWatchLogsLogGroup(region, cb);
            } else {
                cb(null);
            }
        }],
        createTrail: ['getTrail', 'createCloudWatchLogsLogGroup', function(cb, results) {
            if (results.getTrail) {
                console.log("[CloudTrail] CloudTrail is already configured at", region, ". Skipped.");
                cb(null, results.getTrail);
            } else {
                console.log("[CloudTrail] CloudTrail is not configured at", region, ". Create new trail.");
                var params = {
                    Name: trailName,
                    S3BucketName: s3BucketName,
                    IncludeGlobalServiceEvents: (region === globalLogRegion ? true : false)
                };
                // CloudTrail does not support integration with CloudWatch Logs at sa-east-1.
                if(region !== "sa-east-1") {
                    params.CloudWatchLogsLogGroupArn = results.createCloudWatchLogsLogGroup;
                    params.CloudWatchLogsRoleArn = roleArn;
                }
                cloudtrail.createTrail(params, cb);
            }
        }],
        startLogging: ['createTrail', function(cb, results) {
            if ('IsLogging' in results.createTrail && results.createTrail.IsLogging) {
                cb(null);
            } else {
                cloudtrail.startLogging({Name: trailName}, cb);
            }
        }]
    }, function(err, results) {
        if (err) {
            console.log("[CloudTrail] Failed to enable CloudTrail at " + region + ".");
            callback(err);
        } else {
            callback(null);
        }
    });
}

function createCloudWatchLogsLogGroup(region, callback){
    var cloudwatchlogs = new aws.CloudWatchLogs({region: region});
    var logGroupName = "CloudTrail/DefaultLogGroup";

    async.auto({
        getLogGroup: function(cb){
            cloudwatchlogs.describeLogGroups({
                logGroupNamePrefix: logGroupName
            }, function(err, data) {
                if (err) {
                    cb(err);
                } else {
                    var logGroupArn = (data.logGroups.length > 0 ? data.logGroups[0].arn : null);
                    cb(null, logGroupArn);
                }
            });
        },
        createLogGroup: ['getLogGroup', function(cb, results){
            if(results.getLogGroup) {
                cb(null, results.getLogGroup);
            } else {
                cloudwatchlogs.createLogGroup({logGroupName: logGroupName}, cb);
            }
        }],
        getNewLogGroup: ['createLogGroup', function(cb, results){
            if(results.getLogGroup) {
                cb(null, results.getLogGroup);
            } else {
                cloudwatchlogs.describeLogGroups({
                    logGroupNamePrefix: logGroupName
                }, function(err, data) {
                    if (err) {
                        cb(err);
                    } else {
                        var logGroupArn = (data.logGroups.length > 0 ? data.logGroups[0].arn : null);
                        cb(null, logGroupArn);
                    }
                });
            }
        }]
    }, function(err, results) {
        if (err) {
            console.log("[CloudTrail] Failed to create CloudWatch Logs log group.");
            callback(err);
        } else {
            var logGroupArn = results.getNewLogGroup;
            callback(null, logGroupArn);
        }
    });
}

function createIAMRoleForCloudTrail(callback){
    var iam = new aws.IAM();
    var roleName = "CloudTrail_CloudWatchLogs";
    var instanceProfileName = roleName;
    var iamAssumeRolePolicy = (function(){/*
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
              "Service": [ "cloudtrail.amazonaws.com" ]
            },
            "Action": [ "sts:AssumeRole" ]
        }
    ]
}
    */}).toString().match(/\n([\s\S]*)\n/)[1];

    var iamPolicy = (function(){/*
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AWSCloudTrailCreateLogStream",
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogStream"
            ],
            "Resource": [
                "arn:aws:logs:*:*:log-group:CloudTrail/DefaultLogGroup:log-stream:*_CloudTrail_*"
            ]
        },
        {
            "Sid": "AWSCloudTrailPutLogEvents",
            "Effect": "Allow",
            "Action": [
                "logs:PutLogEvents"
            ],
            "Resource": [
                "arn:aws:logs:*:*:log-group:CloudTrail/DefaultLogGroup:log-stream:*_CloudTrail_*"
            ]
        }
    ]
}
    */}).toString().match(/\n([\s\S]*)\n/)[1];

    async.auto({
        getRole: function(cb) {
            iam.getRole({
                RoleName: roleName
            }, function(err, data) {
                var roleArn = (err ? null : data.Role.Arn);
                cb(null, roleArn);
            });
        },
        createRole: ['getRole', function(cb, results) {
            if(results.getRole){
                console.log("[CloudTrail] IAM Role '" + roleName + "' already exists. Skipped.");
                cb(null, results.getRole);
            } else {
                iam.createRole({
                    AssumeRolePolicyDocument: iamAssumeRolePolicy,
                    RoleName: roleName
                }, function(err, data){
                    if (err) {
                        console.log("[CloudTrail] Failed to create IAM role.");
                        cb(err);
                    } else {
                        cb(null, data.Role.Arn);
                    }
                });
            }
        }],
        putRolePolicy: ['createRole', function(cb, results) {
            iam.putRolePolicy({
                PolicyDocument: iamPolicy,
                PolicyName: roleName,
                RoleName: roleName
            }, cb);
        }],
        createInstanceProfile: ['getRole', function(cb, results) {
            if(results.getRole){
                cb(null);
            } else {
                iam.createInstanceProfile({
                    InstanceProfileName: instanceProfileName
                }, function(err, data){
                    if (err) {
                        console.log("[CloudTrail] Failed to create instance profile.");
                        cb(err);
                    } else {
                        cb(null, data.InstanceProfile.Arn);
                    }
                });
            }
        }],
        addRoleToInstanceProfile: ['putRolePolicy', 'createInstanceProfile', function(cb, results) {
            if(results.getRole) {
                cb(null);
            } else {
                iam.addRoleToInstanceProfile({
                    InstanceProfileName: instanceProfileName,
                    RoleName: roleName
                }, function(err, data){
                    if (err) {
                        console.log("[CloudTrail] Failed to add role to instance profile.");
                        cb(err);
                    } else {
                        cb(null);
                    }
                });
            }
        }]
    }, function(err, results) {
        if (err) {
            console.log("[CloudTrail] Failed to create IAM Role for CloudTrail.");
            callback(err);
        } else {
            console.log("[CloudTrail] Success to create IAM Role for CloudTrail.");
            var roleArn = results.createRole;
            callback(null, roleArn);
        }
    });
}

function createRootLoginAlarm(notificationEmailAddress, callback) {
    var cloudwatchlogs = new aws.CloudWatchLogs({region: globalLogRegion});
    var cloudwatch = new aws.CloudWatch({region: globalLogRegion});

    var logGroupName = "CloudTrail/DefaultLogGroup";
    var metricFilterName = "RootLoginEvent";
    var metricFilterPattern = '{ $.eventName = "ConsoleLogin" && $.userIdentity.type = "Root" && $.responseElements.ConsoleLogin = "Success" }';
    var metricName = "RootLoginEvent";
    var metricNamespace = "CloudTrailMetrics";
    var alarmName = "RootLoginAlarm";

    async.auto({
        createSNSTopic: function(cb) {
            createSNSTopic(notificationEmailAddress, cb);
        },
        describeMetricFilters: function(cb) {
            cloudwatchlogs.describeMetricFilters({
                logGroupName: logGroupName,
                filterNamePrefix: metricFilterName
            }, function(err, data) {
                if (err) {
                    cb(err);
                } else {
                    var filterArn = (data.metricFilters.length > 0 ? data.metricFilters[0] : null);
                    cb(null, filterArn);
                }
            });
        },
        putMetricFilter: ['describeMetricFilters', function(cb, results) {
            if(results.getMetricFilters){
                console.log("[RootLoginAlarm] MetricFilter '" + metricFilterName + "' already exists. Skipped.");
                cb(null, results.getMetricFilters);
            } else {
                var params = {
                    logGroupName: logGroupName,
                    filterName: metricFilterName,
                    filterPattern: metricFilterPattern,
                    metricTransformations: [{
                        metricName: metricName,
                        metricNamespace: metricNamespace,
                        metricValue: "$.sourceIPAddress"
                    }]
                };
                cloudwatchlogs.putMetricFilter(params, cb);
            }
        }],
        describeAlarms: ['putMetricFilter', function(cb, results) {
            cloudwatch.describeAlarms({
                AlarmNames: [alarmName]
            }, function(err, data) {
                if (err) {
                    cb(err);
                } else {
                    var isExist = (data.MetricAlarms.length > 0 ? true : false);
                    cb(null, isExist);
                }
            });
        }],
        putMetricAlarm: ['createSNSTopic', 'describeAlarms', function(cb, results) {
            if (results.describeAlarms) {
                console.log("[RootLoginAlarm] MetricAlarm '" + alarmName + "' already exists. Skipped.");
                cb(null);
            } else {
                var params = {
                    AlarmName: alarmName,
                    AlarmDescription: 'Alarm when detect root account login.',
                    ActionsEnabled: true,
                    MetricName: metricName,
                    Namespace: metricNamespace,
                    EvaluationPeriods: 1,
                    Period: 300,
                    Statistic: 'SampleCount',
                    Unit: 'Count',
                    ComparisonOperator: 'GreaterThanThreshold',
                    Threshold: 0,
                    Dimensions: [],
                    AlarmActions: [results.createSNSTopic]
                };
                cloudwatch.putMetricAlarm(params, cb);
            }
        }]
    }, function(err, results) {
        if (err) {
            console.log("[RootLoginAlarm] Failed to create RootLoginAlarm. " + err.message);
            callback(err);
        } else {
            console.log("[RootLoginAlarm] Success to create RootLoginAlarm.");
            callback(null);
        }
    });
}

function createSNSTopic(notificationEmailAddress, callback) {
    var sns = new aws.SNS({region: globalLogRegion});
    var topicName = "CloudTrailAlarms";

    async.auto({
        listTopics: function(cb){
            sns.listTopics({}, function(err, data) {
                if (err) {
                    console.log("[RootLoginAlarm] Failed to list SNS topics.");
                    cb(err);
                } else {
                    var topicArn = null;
                    for (var topic in data.Topics) {
                        if (topic.indexOf(topicName) > -1) {
                            topicArn = topic;
                        }
                    }
                    cb(null, topicArn);
                }
            });
        },
        createTopic: ['listTopics', function(cb, results) {
            if(results.listTopics) {
                console.log("[RootLoginAlarm] SNS Topic already exists. Skipped.");
                cb(null, results.listTopics);
            } else {
                sns.createTopic({
                    Name: topicName
                }, function(err, data) {
                    if (err) {
                        console.log("[RootLoginAlarm] Failed to create SNS topic.");
                        cb(err);
                    } else {
                        cb(null, data.TopicArn);
                    }
                });
            }
        }],
        subscribe: ['createTopic', function(cb, results) {
            if(results.listTopics) {
                cb(null);
            } else {
                var topicArn = results.createTopic;
                sns.subscribe({
                    TopicArn: topicArn,
                    Protocol: 'email',
                    Endpoint: notificationEmailAddress
                }, function(err, data) {
                    if (err) {
                        console.log("[RootLoginAlarm] Failed to subscribe topic.");
                        cb(err);
                    } else {
                        cb(null);
                    }
                });
            }
        }]
    }, function(err, results) {
        if (err) {
            console.log("[RootLoginAlarm] Failed to subscribe SNS topic for RootLogin alarm.");
            callback(err);
        } else {
            console.log("[RootLoginAlarm] Success to subscribe SNS topic for RootLogin alarm.");
            var topicArn = results.createTopic;
            callback(null, topicArn);
        }
    });
}
