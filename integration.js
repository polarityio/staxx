'use strict';

let request = require('request');
let _ = require('lodash');
let util = require('util');
let net = require('net');
let config = require('./config/config');
let async = require('async');
let fs = require('fs');
let SessionManager = require('./lib/session-manager');
let Logger;

let requestOptions = {};
let sessionManager;

const IGNORED_IPS = new Set([
    '127.0.0.1',
    '255.255.255.255',
    '0.0.0.0'
]);

const SEVERITY_LEVELS = ['low', 'medium', 'high', 'very-high'];
const SEVERITY_LEVELS_QUERY_FORMAT = ['severity = low', 'severity = medium', 'severity = high', 'severity = very-high'];
const ERROR_EXPIRED_SESSION = 'expired_session_error';
const MAX_ENTITIES_PER_LOOKUP = 10;

function createEntityGroups(entities, options, cb) {
    let entityLookup = {};
    let entityGroups = [];
    let entityGroup = [];

    Logger.trace({entities:entities, options:options}, 'Entities and Options');

    entities.forEach(function (entity) {
        if (entityGroup.length >= MAX_ENTITIES_PER_LOOKUP) {
            entityGroups.push(entityGroup);
            entityGroup = [];
        }

        if((entity.isPrivateIP || IGNORED_IPS.has(entity.value)) && options.ignorePrivateIps){
            return;
        }else{
            entityGroup.push("value='" + entity.value + "'");
            entityLookup[entity.value.toLowerCase()] = entity;
        }
    });

    // grab any "trailing" entities
    if (entityGroup.length > 0) {
        entityGroups.push(entityGroup);
    }

    _doLookup(entityGroups, entityLookup, options, cb);
}

/**
 *
 * @param entities
 * @param options
 * @param cb
 */
function _doLookup(entityGroups, entityLookup, options, cb) {
    if (entityGroups.length > 0) {
        Logger.debug({entityGroups: entityGroups}, 'Looking up Entity Groups');

        let sessionToken = sessionManager.getSession(options.username, options.password);

        if(sessionToken){
            // we are already authenticated.
            Logger.trace({numSession: sessionManager.getNumSessions()}, 'Session Already Exists');

            options.severityQueryString = SEVERITY_LEVELS_QUERY_FORMAT.slice(SEVERITY_LEVELS.indexOf(options.minimumSeverity))
                .join(" OR " );

            _lookupWithSessionToken(entityGroups, entityLookup, options, sessionToken, function(err, results){
                if(err && err === ERROR_EXPIRED_SESSION){
                    // the session was expired so we need to retry
                    // remove the session and try again
                    Logger.debug({err:err}, "Clearing Session");
                    sessionManager.clearSession(options.username, options.password);
                    _doLookup(entityGroups, entityLookup, options, cb);
                }else if(err){
                    Logger.error({err:err}, 'Error doing lookup');
                    cb(err);
                }else{
                    cb(null, results);
                }
            });
        }else{
            // we are not authenticated so we need to login and get a sessionToken
            Logger.trace('Session does not exist. Creating Session');
            _login(options, function(err, sessionToken){
                Logger.trace({sessionToken:sessionToken}, 'Created new session');
                if(err){
                    Logger.error({err:err}, 'Error logging in');
                    // Cover the case where an error is returned but the session was still created.
                    if(err === ERROR_EXPIRED_SESSION){
                        cb('Invalid Username or Password');
                    }else{
                        cb(err);
                    }

                    return;
                }

                sessionManager.setSession(options.username, options.password, sessionToken);
                _doLookup(entityGroups, entityLookup, options, cb);
            });
        }
    }else{
        cb(null, []);
    }
}



function _lookupWithSessionToken(entityGroups, entityLookup, options, sessionToken, cb){
    let lookupResults = [];

    async.map(entityGroups, function (entityGroup, next) {
        _lookupEntity(entityGroup, entityLookup, sessionToken, options, next);
    }, function (err, results) {
        if (err) {
            cb(err);
            return;
        }

        results.forEach(entityGroup => {
            entityGroup.forEach(staxxResult => {
                lookupResults.push({
                    entity: entityLookup[staxxResult.indicator.toLowerCase()],
                    data:{
                        summary: [staxxResult.itype, staxxResult.severity, staxxResult.confidence],
                        details: staxxResult
                    }
                });
            });
        });

        Logger.trace({lookupResults:lookupResults}, 'Lookup Results');

        cb(null, lookupResults);
    });
}

function _handleRequestError(err, response, body, options, cb) {
    if (err) {
        cb(_createJsonErrorPayload("Unable to connect to STAXX server", null, '500', '2A', 'STAXX HTTP Request Failed', {
            err: err,
            response: response,
            body: body
        }));
        return;
    }

    // Sessions will expire after a set period of time which means we need to login again if we
    // receive this error.
    // 403 is returned if the session is invalid but also if you try to login with invalid creds.
    if (response.statusCode === 403) {
        cb(ERROR_EXPIRED_SESSION);
        return;
    }

    if (response.statusCode !== 200) {
        if (body) {
            cb(body);
        } else {
            cb(_createJsonErrorPayload(response.statusMessage, null, response.statusCode, '2A', 'STAXX HTTP Request Failed', {
                response: response,
                body: body
            }));
        }
        return;
    }

    cb(null, body);
}


function _login(options, done){
    //do the lookup
    requestOptions.uri = options.url + '/api/v1/login';
    requestOptions.method = 'POST';
    requestOptions.body = {
        username: options.username,
        password: options.password
    };
    requestOptions.json = true;

    request(requestOptions, function(err, response, body){
        _handleRequestError(err, response, body, options, function (err, body) {
            if (err) {
                Logger.error({err: err}, 'Error Authenticating with STAXX');
                done(err);
                return;
            }

            done(null, body.token_id);
        });
    });
}

function _lookupEntity(entitiesArray, entityLookup, apiToken, options, done) {
    //do the lookup
    requestOptions.uri = options.url + '/api/v1/intelligence';
    requestOptions.method = 'POST';
    requestOptions.body = {
        token: apiToken,
        query: "(" + entitiesArray.join(" OR ") + ") AND confidence >= " +
            options.minimumConfidence + " AND (" + options.severityQueryString + ")",
        type: "json",
        size: MAX_ENTITIES_PER_LOOKUP
    };
    requestOptions.json = true;

    Logger.debug({requestOptions: requestOptions}, 'Request Options for Lookup');

    request(requestOptions, function (err, response, body) {
        _handleRequestError(err, response, body, options, function (err, body) {
            if (err) {
                if(err === ERROR_EXPIRED_SESSION){
                    Logger.debug({err:err}, 'Session Expired');
                }else{
                    Logger.error({err: err}, 'Error Looking up Entity');
                }

                done(err);
                return;
            }

            done(null, body);
        });
    });
}

/**
 * Helper method that creates a fully formed JSON payload for a single error
 * @param msg
 * @param pointer
 * @param httpCode
 * @param code
 * @param title
 * @returns {{errors: *[]}}
 * @private
 */
function _createJsonErrorPayload(msg, pointer, httpCode, code, title, meta) {
    return {
        errors: [
            _createJsonErrorObject(msg, pointer, httpCode, code, title, meta)
        ]
    }
}

function _createJsonErrorObject(msg, pointer, httpCode, code, title, meta) {
    let error = {
        detail: msg,
        status: httpCode.toString(),
        title: title,
        code: 'STAXX_' + code.toString()
    };

    if (pointer) {
        error.source = {
            pointer: pointer
        };
    }

    if (meta) {
        error.meta = meta;
    }

    return error;
}

function startup(logger) {
    Logger = logger;

    if (typeof config.request.cert === 'string' && config.request.cert.length > 0) {
        requestOptions.cert = fs.readFileSync(config.request.cert);
    }

    if (typeof config.request.key === 'string' && config.request.key.length > 0) {
        requestOptions.key = fs.readFileSync(config.request.key);
    }

    if (typeof config.request.passphrase === 'string' && config.request.passphrase.length > 0) {
        requestOptions.passphrase = config.request.passphrase;
    }

    if (typeof config.request.ca === 'string' && config.request.ca.length > 0) {
        requestOptions.ca = fs.readFileSync(config.request.ca);
    }

    if (typeof config.request.proxy === 'string' && config.request.proxy.length > 0) {
        requestOptions.proxy = config.request.proxy;
    }


    if (typeof config.request.rejectUnauthorized === 'boolean') {
        requestOptions.rejectUnauthorized = config.request.rejectUnauthorized;
    }

    sessionManager = new SessionManager(Logger);

    // Logger.info({requestOptionsIp: requestOptionsIp}, 'requestOptionsIp after load');
    // Logger.info({requestOptionsHash: requestOptionsHash}, 'requestOptionsHash after load');
}


function validateOptions(userOptions, cb) {
    let errors = [];
    if (typeof userOptions.url.value !== 'string' ||
        (typeof userOptions.url.value === 'string' && userOptions.url.value.length === 0)) {
        errors.push({
            key: 'url',
            message: 'You must provide your STAXX server URL'
        })
    }

    if (typeof userOptions.username.value !== 'string' ||
        (typeof userOptions.username.value === 'string' && userOptions.username.value.length === 0)) {
        errors.push({
            key: 'username',
            message: 'You must provide your STAXX username'
        })
    }

    if (typeof userOptions.password.value !== 'string' ||
        (typeof userOptions.password.value === 'string' && userOptions.password.value.length === 0)) {
        errors.push({
            key: 'password',
            message: 'You must provide your STAXX username\'s password'
        })
    }

    if (typeof userOptions.minimumSeverity.value !== 'string' ||
        (typeof userOptions.minimumSeverity.value === 'string' && userOptions.minimumSeverity.value.length === 0)) {
        errors.push({
            key: 'minimumSeverity',
            message: 'You must provide a minimum severity level'
        });
    }else if(SEVERITY_LEVELS.indexOf(userOptions.minimumSeverity.value) < 0){
        errors.push({
            key: 'minimumSeverity',
            message: 'The minimum severity level must be "low", "medium", "high", or "very-high"'
        });
    }

    let minConfidence = Number(userOptions.minimumConfidence.value);
    if (userOptions.minimumConfidence.value.length === 0 || !_.isInteger(minConfidence)){
        errors.push({
            key: 'minimumConfidence',
            message: 'The Minimum Confidence value must be an integer'
        })
    }else if(minConfidence < 0 || minConfidence > 100){
        errors.push({
            key: 'minimumConfidence',
            message: 'The Minimum Confidence value must be between 0 and 100'
        })
    }

    cb(null, errors);
}

module.exports = {
    doLookup: createEntityGroups,
    startup: startup,
    validateOptions: validateOptions
};