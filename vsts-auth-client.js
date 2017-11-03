const config = require('./config.js');
const request = require('request');
const RCH = require('request-capture-har');
const requestCaptureHar = new RCH(request);

const k_REFRESH_TOKEN = 'refresh_token';

class AuthorizationError extends Error {
    constructor(...a) {
        super(...a);
    }
}

exports.AuthorizationError = AuthorizationError;
exports.setRefreshToken = t => config.set(k_REFRESH_TOKEN, t);
exports.getAuthToken = captureHar => {
    // we can short-circuit in a lab environment where SYSTEM_ACCESSTOKEN is available
    // this avoids the instability of making unnecessary network requests
    // docs: https://docs.microsoft.com/en-us/vsts/build-release/concepts/definitions/build/variables?tabs=batch#predefined-variables
    let lab_token = process.env['SYSTEM_ACCESSTOKEN'];
    if (lab_token) {
        console.log('using SYSTEM_ACCESSTOKEN provided.');
        consig.set(k_REFRESH_TOKEN, lab_token);
        return Promise.resolve(lab_token);
    }

    let configObj = config.get();
    // validate config
    if (!configObj || !configObj.tokenEndpoint) {
        return Promise.reject(new Error('invalid config, missing tokenEndpoint'));
    } else if (!configObj[k_REFRESH_TOKEN]) {
        return Promise.reject(new AuthorizationError('missing ' + k_REFRESH_TOKEN));
    }

    return new Promise((resolve, reject) => {
        let requestId = Date.now();
        let options = {
            uri: configObj.tokenEndpoint,
            method: 'POST',
            json: true,
            qs: {
                code: configObj[k_REFRESH_TOKEN]
            },
            callback: (err, res, body) => {
                console.log(`[${requestId} complete.]`);
                if (err) {
                    return reject(err);
                } else if (!body || !body[k_REFRESH_TOKEN] || !body.access_token) {
                    return reject('malformed response body:\n' + body);
                } else {
                    // stash the refresh_token
                    config.set(k_REFRESH_TOKEN, body[k_REFRESH_TOKEN]);
                    return resolve(body.access_token);
                }
            }
        };

        console.log(`[${requestId}] ${options.method}: ${options.uri}`);
        return requestCaptureHar.request(options);
    }).then(result => {
        // if the har flag is set, stash the result
        if (captureHar) {
            requestCaptureHar.saveHar(`better-vsts-npm-auth_${Date.now()}.har`);
        }
        return Promise.resolve(result);
    });
};