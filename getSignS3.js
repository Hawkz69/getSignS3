CineUser.getSignS3 = function(obj) {
        var config = {
            bucket: 'myBucket',
            access_key: 'myAccessKEY',
            secret_key: 'mySecretKEY',
            region: 'region',
            acl: 'acl',                                                 
            "x-amz-algorithm": 'x-amz-algorithm',                         
            "success_action_status": 'success_action_status'                                
        };

        var upload_url = "https://" + config.bucket + ".s3.amazonaws.com";
        var date = new Date().toISOString();
        var dateString = date.substr(0, 4) + date.substr(5, 2) + date.substr(8, 2);
        var credential = config.access_key + "/" + dateString + "/" + config.region + "/s3/aws4_request";

        function hmac(key, string) {
            var hmac = require('crypto').createHmac('sha256', key);
            hmac.end(string);
            return hmac.read();
        }

        var policy = {
            expiration: new Date((new Date).getTime() + (5 * 60 * 1000)).toISOString(),
            conditions: [
                { bucket: config.bucket },
                { key: "img/users/" + obj.id + "/" + obj.filename},                            
                { acl: config.acl },
                { success_action_status: config.success_action_status },
                ["content-length-range", 0, 5000000],
                { "x-amz-algorithm": config["x-amz-algorithm"] },
                { "x-amz-credential": credential },
                { "x-amz-date": dateString + "T000000Z" }
            ]
        };

        var policyBase64 = new Buffer(JSON.stringify(policy)).toString('base64');
        var dateKey = hmac("AWS4" + config.secret_key, dateString);
        var dateRegionKey = hmac(dateKey, config.region);
        var dateRegionServiceKey = hmac(dateRegionKey, 's3');
        var signingKey = hmac(dateRegionServiceKey, 'aws4_request');

        // sign policy
        var xAmzSignature = hmac(signingKey, policyBase64).toString('hex');


        var returns = {
            key: "img/users/" + obj.id + "/" + obj.filename,
            acl: config.acl,
            success_action_status: config.success_action_status,
            policy: policyBase64,
            "x-amz-algorithm": config["x-amz-algorithm"],
            "x-amz-credential": credential,
            "x-amz-date": dateString + "T000000Z",
            "x-amz-signature": xAmzSignature
        }

        return returns;
    }