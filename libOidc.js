/**
 * Copyright 2013 Nomura Research Institute, Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * The following software is included for convenience: JSJWS, JSRSASIGN, CryptoJS;
 * Use of any of these software may be governed by their respective licenses.
 */

/**
 * The 'jsjws'(JSON Web Signature JavaScript Library) License
 *
 * Copyright (c) 2012 Kenji Urushima
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/**
 * The 'jsrsasign'(RSA-Sign JavaScript Library) License
 *
 * Copyright (c) 2010-2013 Kenji Urushima
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 *  THE SOFTWARE.
 */

/**
 * The Crypto-JS  license
 *
 * (c) 2009-2013 by Jeff Mott. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice, this list
 * of conditions, and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice, this
 * list of conditions, and the following disclaimer in the documentation or other
 * materials provided with the distribution.
 *
 * Neither the name CryptoJS nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior written
 * permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS," AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ARE DISCLAIMED.
 * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
 * OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */



/**
 * OIDC namespace
 * @namespace OIDC
 */
var OIDC = namespace('OIDC');

/**
 * @property {array} OIDC.supportedProviderOptions                                 - List of the Identity Provider's configuration parameters
 * @property {string} OIDC.supportedProviderOptions.issuer                         - Issuer ID
 * @property {string} OIDC.supportedProviderOptions.authorization_endpoint         - Authorization Endpoint URL
 * @property {string} OIDC.supportedProviderOptions.jwks_uri                       - JWKS URL
 * @property {boolean} OIDC.supportedProviderOptions.claims_parameter_supported    - Claims parameter support
 * @property {boolean} OIDC.supportedProviderOptions.request_parameter_supported   - Request parameter support
 * @property {object} OIDC.supportedProviderOptions.jwks                           - Identity Provider's JWK Set
 * @readonly
 * @memberof OIDC
 */
OIDC.supportedProviderOptions = [
    'issuer',
    'authorization_endpoint',
    'jwks_uri',
    'claims_parameter_supported',
    'request_parameter_supported',
    'jwks'

    /*
     / Reserve for future use
     'token_endpoint',
     'userinfo_endpoint',
     'check_session_iframe',
     'end_session_endpoint',
     'registration_endpoint',
     'scopes_supported',
     'response_types_supported',
     'grant_types_supported',
     'acr_values_supported',
     'subject_types_supported',
     'userinfo_signing_alg_values_supported',
     'userinfo_encryption_alg_values_supported',
     'id_token_signing_alg_values_supported',
     'id_token_encryption_alg_values_supported',
     'id_token_encryption_enc_values_supported',
     'request_object_signing_alg_values_supported',
     'request_object_encryption_alg_values_supported',
     'request_object_encryption_enc_values_supported',
     'token_endpoint_auth_methods_supported',
     'token_endpoint_auth_signing_alg_values_supported',
     'display_values_supported',
     'claim_types_supported',
     'claims_supported',
     'service_documentation',
     'ui_locales_supported',
     'require_request_uri_registration',
     'op_policy_uri',
     'op_tos_uri',
     'claims_locales_supported',
     'request_uri_parameter_supported',
     */
];

/**
 * @property {array} OIDC.supportedRequestOptions             - Supported Login Request parameters
 * @property {string} OIDC.supportedRequestOptions.scope      - space separated scope values
 * @property {string} OIDC.supportedRequestOptions.response_type  - space separated response_type values
 * @property {string} OIDC.supportedRequestOptions.display    - display
 * @property {string} OIDC.supportedRequestOptions.max_age    - max_age
 * @property {object} OIDC.supportedRequestOptions.claims    - claims object containing what information to return in the UserInfo endpoint and ID Token
 * @property {array} OIDC.supportedRequestOptions.claims.id_token    - list of claims to return in the ID Token
 * @property {array} OIDC.supportedRequestOptions.claims.userinfo    - list of claims to return in the UserInfo endpoint
 * @property {boolean} OIDC.supportedRequestOptions.request   - signed request object JWS. Not supported yet.
 * @readonly
 * @memberof OIDC
 *
 */
OIDC.supportedRequestOptions = [
    'scope',
    'response_type',
    'display',
    'max_age',
    'claims',
    'request'
];

/**
 * @property {array} OIDC.supportedClientOptions                 - List of supported Client configuration parameters
 * @property {string} OIDC.supportedClientOptions.client_id      - The client's client_id
 * @property {string} OIDC.supportedClientOptions.redirect_uri   - The client's redirect_uri
 * @readonly
 * @memberof OIDC
 *
 */
OIDC.supportedClientOptions = [
    'client_id',
    'redirect_uri'
//    'client_secret',
];


/**
 * Sets the Identity Provider's configuration parameters
 * @function setProviderInfo
 * @memberof OIDC
 * @param {object} p      - The Identity Provider's configuration options described in {@link OIDC.supportedProviderOptions}
 * @returns {boolean}     - Indicates status of
 * @example
 * // set Identity Provider configuration
 * OIDC.setProviderInfo( {
 *                          issuer: 'https:/op.example.com',
 *                          authorization_endpoint: 'http://op.example.com/auth.html',
 *                          jwks_uri: 'https://op.example.com/jwks'
 *                       }
 *                     );
 *
 * // set Identity Provider configuration using discovery information
 * var discovery = OIDC.discover('https://op.example.com');
 * if(var)
 *     OIDC.setProviderInfo(discovery);
 */
OIDC.setProviderInfo = function (p) {
    var params = this.supportedProviderOptions;

    if (p !== 'undefined') {
        for (var i = 0; i < params.length; i++) {
            if (p[params[i]] !== 'undefined') {
                this[params[i]] = p[params[i]];
            }
        }
    }
    return true;
};


/**
 * Sets the Client's configuration parameters
 * @function setClientInfo
 * @memberof OIDC
 * @param {object} p      - The Client's configuration options described in {@link OIDC.supportedClientOptions}
 * @returns {boolean}       Indicates status of call
 * @example
 * // set client_id and redirect_uri
 * OIDC.setClientInfo( {
 *                          client_id: 'myclientID',
 *                          redirect_uri: 'https://rp.example.com/callback.html'
 *                     }
 *                   );
 */
OIDC.setClientInfo = function(p)
{
    var params = this.supportedClientOptions;

    if(typeof p !== 'undefined') {
        for(var i = 0; i < params.length; i++) {
            if(typeof p[params[i]] !== 'undefined') {
                this[params[i]] = p[params[i]];
            }
        }
    }
    return true;
};


/**
 * Stores the Identity Provider and Client configuration options in the browser session storage for reuse later
 * @function storeInfo
 * @memberof OIDC
 * @param {object} providerInfo    - The Identity Provider's configuration options described in {@link OIDC.supportedProviderOptions}
 * @param {object} clientInfo      - The Client's configuration options described in {@link OIDC.supportedClientOptions}
 */
OIDC.storeInfo = function (providerInfo, clientInfo)
{
    var pOptions = this.supportedProviderOptions;
    var cOptions = this.supportedClientOptions;
    var pInfo = {};
    var cInfo = {};

    if(providerInfo) {
        for(var i = 0; i < pOptions.length; i++) {
            if(typeof providerInfo[pOptions[i]] != 'undefined')
                pInfo[pOptions[i]] = providerInfo[pOptions[i]];
        }
        sessionStorage['providerInfo'] = JSON.stringify(pInfo);
    } else {
        if(sessionStorage['providerInfo'])
            sessionStorage.removeItem('providerInfo');
    }

    if(clientInfo) {
        for(i = 0; i < cOptions.length; i++) {
            if(typeof clientInfo[cOptions[i]] != 'undefined')
                cInfo[cOptions[i]] = clientInfo[cOptions[i]];
        }
        sessionStorage['clientInfo'] = JSON.stringify(cInfo);
    } else {
        if(sessionStorage['clientInfo'])
            sessionStorage.removeItem('clientInfo');
    }
};


/**
 * Load and restore the Identity Provider and Client configuration options from the browser session storage
 * @function restoreInfo
 * @memberof OIDC
 */
OIDC.restoreInfo = function()
{
    var providerInfo = sessionStorage['providerInfo'];
    var clientInfo = sessionStorage['clientInfo'];
    if(providerInfo) {
        this.setProviderInfo(JSON.parse(providerInfo));
    }
    if(clientInfo) {
        this.setClientInfo(JSON.parse(clientInfo));
    }
};

/**
 * Check whether the required configuration parameters are set
 * @function checkRequiredInfo
 * @param {array} params    - List of Identity Provider and client configuration parameters
 * @memberof OIDC
 * @private
 * @return {boolean}        - Indicates whether the options have been set
 *
 */
OIDC.checkRequiredInfo = function(params)
{
    if(params) {
        for(var i = 0; i < params.length; i++) {
            if(!this[params[i]]) {
                throw new OidcException('Required parameter not set - ' + params[i]);
            }
        }
    }
    return true;
};

/**
 * Clears the Identity Provider configuration parameters
 * @function clearProviderInfo
 * @memberof OIDC
 * @private
 */
OIDC.clearProviderInfo = function()
{
    for(var i = 0; i < this.supportedProviderOptions.length; i++) {
        this[this.supportedProviderOptions[i]] = null;
    }
};


/**
 * Redirect to the Identity Provider for authenticaton
 * @param {object} reqOptions    - Optional authentication request options. See {@link OIDC.supportedRequestOptions}
 * @throws {OidcException}
 * @example
 *
 * // login with options
 * OIDC.login( {
 *               scope : 'openid profile',
 *               response_type : 'token id_token',
 *               max_age : 60,
 *               claims : {
 *                          id_token : ['email', 'phone_number'],
 *                          userinfo : ['given_name', 'family_name']
 *                        }
 *              }
 *            );
 *
 * // login with default scope=openid, response_type=id_token
 * OIDC.login();
 */
OIDC.login = function(reqOptions) {
    // verify required parameters
    this.checkRequiredInfo(new Array('client_id', 'redirect_uri', 'authorization_endpoint'));

    var state = null;
    var nonce = null;

    // Replace state and nonce with secure ones if
    var crypto = window.crypto || window.msCrypto;
    if(crypto && crypto.getRandomValues) {
        var D = new Uint32Array(2);
        crypto.getRandomValues(D);
        state = D[0].toString(36);
        nonce = D[1].toString(36);
    } else {
        var byteArrayToLong = function(/*byte[]*/byteArray) {
            var value = 0;
            for ( var i = byteArray.length - 1; i >= 0; i--) {
                value = (value * 256) + byteArray[i];
            }
            return value;
        };

        rng_seed_time();
        var sRandom = new SecureRandom();
        var randState= new Array(4);
        sRandom.nextBytes(randState);
        state = byteArrayToLong(randState).toString(36);

        rng_seed_time();
        var randNonce= new Array(4);
        sRandom.nextBytes(randNonce);
        nonce = byteArrayToLong(randNonce).toString(36);
    }


    // Store the them in session storage
    sessionStorage['state'] = state;
    sessionStorage['nonce'] = nonce;

    var response_type = 'id_token';
    var scope = 'openid';
    var display = null;
    var max_age = null;
    var claims = null;
    var idTokenClaims = {};
    var userInfoClaims = {};

    if(reqOptions) {
        if(reqOptions['response_type']) {
            var parts = reqOptions['response_type'].split(' ');
            var temp = [];
            if(parts) {
                for(var i = 0; i < parts.length; i++) {
                    if(parts[i] == 'code' || parts[i] == 'token' || parts[i] == 'id_token')
                        temp.push(parts[i]);
                }
            }
            if(temp)
                response_type = temp.join(' ');
        }

        if(reqOptions['scope'])
            scope = reqOptions['scope'];
        if(reqOptions['display'])
            display = reqOptions['display'];
        if(reqOptions['max_age'])
            max_age = reqOptions['max_age'];


        if(reqOptions['claims']) {

            if(this['claims_parameter_supported']) {

                if(reqOptions['claims']['id_token']) {
                    for(var j = 0; j < reqOptions['claims']['id_token'].length; j++) {
                        idTokenClaims[reqOptions['claims']['id_token'][j]] = null
                    }
                    if(!claims)
                        claims = {};
                    claims['id_token'] = idTokenClaims;
                }
                if(reqOptions['claims']['userinfo']) {
                    for(var k = 0; k < reqOptions['claims']['userinfo'].length; k++) {
                        userInfoClaims[reqOptions['claims']['userinfo'][k]] = null;
                    }
                    if(!claims)
                        claims = {};
                    claims['userinfo'] = userInfoClaims;
                }

            } else
                throw new OidcException('Provider does not support claims request parameter')

        }
    }

    // Construct the redirect URL
    // For getting an id token, response_type of
    // "token id_token" (note the space), scope of
    // "openid", and some value for nonce is required.
    // client_id must be the consumer key of the connected app.
    // redirect_uri must match the callback URL configured for
    // the connected app.

    var optParams = '';
    if(display)
        optParams += '&display='  + display;
    if(max_age)
        optParams += '&max_age=' + max_age;
    if(claims)
        optParams += '&claims=' + JSON.stringify(claims);

    var url =
        this['authorization_endpoint']
            + '?response_type=' + response_type
            + '&scope=' + scope
            + '&nonce=' + nonce
            + '&client_id=' + this['client_id']
            + '&redirect_uri=' + this['redirect_uri']
            + '&state=' + state
            + optParams;


    window.location.replace(url);
};


/**
 * Verifies the ID Token signature using the JWK Keyset from jwks or jwks_uri of the
 * Identity Provider Configuration options set via {@link OIDC.setProviderInfo}.
 * Supports only RSA signatures
 * @param {string }idtoken      - The ID Token string
 * @returns {boolean}           Indicates whether the signature is valid or not
 * @see OIDC.setProviderInfo
 * @throws {OidcException}
 */
OIDC.verifyIdTokenSig = function (idtoken)
{
    var verified = false;
    var requiredParam = this['jwks_uri'] || this['jwks'];
    if(!requiredParam) {
        throw new OidcException('jwks_uri or jwks parameter not set');
    } else  if(idtoken) {
        var idtParts = this.getIdTokenParts(idtoken);
        var header = this.getJsonObject(idtParts[0])
        var jwks = this['jwks'] || this.fetchJSON(this['jwks_uri']);
        if(!jwks)
            throw new OidcException('No JWK keyset');
        else {
            if(header['alg'] && header['alg'].substr(0, 2) == 'RS') {
                var jwk = this.jwk_get_key(jwks, 'RSA', 'sig', header['kid']);
                if(!jwk)
                    new OidcException('No matching JWK found');
                else {
                    verified = this.rsaVerifyJWS(idtoken, jwk[0]);
                }
            } else
                throw new OidcException('Unsupported JWS signature algorithm ' + header['alg']);
        }
    }
    return verified;
}


/**
 * Validates the information in the ID Token against configuration data in the Identity Provider
 * and Client configuration set via {@link OIDC.setProviderInfo} and set via {@link OIDC.setClientInfo}
 * @param {string} idtoken      - The ID Token string
 * @returns {boolean}           Validity of the ID Token
 * @throws {OidcException}
 */
OIDC.isValidIdToken = function(idtoken) {

    var idt = null;
    var valid = false;
    this.checkRequiredInfo(['issuer', 'client_id']);

    if(idtoken) {
        var idtParts = this.getIdTokenParts(idtoken);
        var payload = this.getJsonObject(idtParts[1])
        if(payload) {
            var now =  new Date() / 1000;
            if( payload['iat'] >  now + (5 * 60))
                throw new OidcException('ID Token issued time is later than current time');
            if(payload['exp'] < now - (5*60))
                throw new OidcException('ID Token expired');
            var audience = null;
            if(payload['aud']) {
                if(payload['aud'] instanceof Array) {
                    audience = payload['aud'][0];
                } else
                    audience = payload['aud'];
            }
            if(audience != this['client_id'])
                throw new OidcException('invalid audience');
            if(payload['iss'] != this['issuer'])
                throw new OidcException('invalid issuer ' + payload['iss'] + ' != ' + this['issuer']);
            if(payload['nonce'] != sessionStorage['nonce'])
                throw new OidcException('invalid nonce');
            valid = true;
        } else
            throw new OidcException('Unable to parse JWS payload');
    }
    return valid;
}

/**
 * Verifies the JWS string using the JWK
 * @param {string} jws      - The JWS string
 * @param {object} jwk      - The JWK Key that will be used to verify the signature
 * @returns {boolean}       Validity of the JWS signature
 * @throws {OidcException}
 */
OIDC.rsaVerifyJWS = function (jws, jwk)
{
    if(jws && typeof jwk === 'object') {
        if(jwk['kty'] == 'RSA') {
            var verifier = new KJUR.jws.JWS();
            if(jwk['n'] && jwk['e']) {
                var keyN = b64utohex(jwk['n']);
                var keyE = b64utohex(jwk['e']);
                return verifier.verifyJWSByNE(jws, keyN, keyE);
            } else if (jwk['x5c']) {
                return verifier.verifyJWSByPemX509Cert(jws, "-----BEGIN CERTIFICATE-----\n" + jwk['x5c'][0] + "\n-----END CERTIFICATE-----\n");
            }
        } else {
            throw new OidcException('No RSA kty in JWK');
        }
    }
    return false;
}

/**
 * Get the ID Token from the current page URL whose signature is verified and contents validated
 * against the configuration data set via {@link OIDC.setProviderInfo} and {@link OIDC.setClientInfo}
 * @returns {string|null}
 * @throws {OidcException}
 */
OIDC.getValidIdToken = function()
{
    var url = window.location.href;

    // Check if there was an error parameter
    var error = url.match('error=([^&]*)')
    if (error) {
        // If so, extract the error description and display it
        var description = url.match('error_description=([^&]*)');
        throw new OidcException(error[1] + ' Description: ' + description[1]);
    }
    // Exract state from the state parameter
    var smatch = url.match('state=([^&]*)');
    if (smatch) {
        var state = smatch[1] ;
        var sstate = sessionStorage['state'];
        var badstate = (state != sstate);
    }

    // Extract id token from the id_token parameter
    var match = url.match('id_token=([^&]*)');
    if (badstate) {
        throw new OidcException("State mismatch");
    } else if (match) {
        var id_token = match[1]; // String captured by ([^&]*)

        if (id_token) {
            var sigVerified = this.verifyIdTokenSig(id_token);
            var valid = this.isValidIdToken(id_token);
            if(sigVerified && valid)
                return id_token;
        } else {
            throw new OidcException('Could not retrieve ID Token from the URL');
        }
    } else {
        throw new OidcException('No ID Token returned');
    }
    return null;
};


/**
 * Get Access Token from the current page URL
 *
 * @returns {string|null}  Access Token
 */
OIDC.getAccessToken = function()
{
    var url = window.location.href;

    // Check for token
    var token = url.match('access_token=([^&]*)');
    if (token)
        return token[1];
    else
        return null;
}


/**
 * Get Authorization Code from the current page URL
 *
 * @returns {string|null}  Authorization Code
 */
OIDC.getCode = function()
{
    var url = window.location.href;

    // Check for code
    var code = url.match('code=([^(&)]*)');
    if (code) {
        return code[1];
    }
}


/**
 * Splits the ID Token string into the individual JWS parts
 * @param  {string} id_token    - ID Token
 * @returns {Array} An array of the JWS compact serialization components (header, payload, signature)
 */
OIDC.getIdTokenParts = function (id_token) {
    var jws = new KJUR.jws.JWS();
    jws.parseJWS(id_token);
    return new Array(jws.parsedJWS.headS, jws.parsedJWS.payloadS, jws.parsedJWS.si);
};

/**
 * Get the contents of the ID Token payload as an JSON object
 * @param {string} id_token     - ID Token
 * @returns {object}            - The ID Token payload JSON object
 */
OIDC.getIdTokenPayload = function (id_token) {
    var parts = this.getIdTokenParts(id_token);
    if(parts)
        return this.getJsonObject(parts[1]);
}

/**
 * Get the JSON object from the JSON string
 * @param {string} jsonS    - JSON string
 * @returns {object|null}   JSON object or null
 */
OIDC.getJsonObject = function (jsonS) {
    var jws = KJUR.jws.JWS;
    if(jws.isSafeJSONString(jsonS)) {
        return jws.readSafeJSONString(jsonS);
    }
    return null;
//    return JSON.parse(jsonS);
};


/**
 * Retrieves the JSON file at the specified URL. The URL must have CORS enabled for this function to work.
 * @param {string} url      - URL to fetch the JSON file
 * @returns {string|null}    contents of the URL or null
 * @throws {OidcException}
 */
OIDC.fetchJSON = function(url) {
    try {
        var request = new XMLHttpRequest();
        request.open('GET', url, false);
        request.send(null);

        if (request.status === 200) {
            return request.responseText;
        } else
            throw new OidcException("fetchJSON - " + request.status + ' ' + request.statusText);

    }
    catch(e) {
        throw new OidcException('Unable to retrieve JSON file at ' + url + ' : ' + e.toString());
    }
    return null;
};

/**
 * Retrieve the JWK key that matches the input criteria
 * @param {string|object} jwkIn     - JWK Keyset string or object
 * @param {string} kty              - The 'kty' to match (RSA|EC). Only RSA is supported.
 * @param {string}use               - The 'use' to match (sig|enc).
 * @param {string}kid               - The 'kid' to match
 * @returns {array}                 Array of JWK keys that match the specified criteria                                                                     itera
 */
OIDC.jwk_get_key = function(jwkIn, kty, use, kid )
{
    var jwk = null;
    var foundKeys = [];

    if(jwkIn) {
        if(typeof jwkIn === 'string')
            jwk = this.getJsonObject(jwkIn);
        else if(typeof jwkIn === 'object')
            jwk = jwkIn;

        if(jwk != null) {
            if(typeof jwk['keys'] === 'object') {
                if(jwk.keys.length == 0)
                    return null;

                for(var i = 0; i < jwk.keys.length; i++) {
                    if(jwk['keys'][i]['kty'] == kty)
                        foundKeys.push(jwk.keys[i]);
                }

                if(foundKeys.length == 0)
                    return null;

                if(use) {
                    var temp = [];
                    for(var j = 0; j < foundKeys.length; j++) {
                        if(!foundKeys[j]['use'])
                            temp.push(foundKeys[j]);
                        else if(foundKeys[j]['use'] == use)
                            temp.push(foundKeys[j]);
                    }
                    foundKeys = temp;
                }
                if(foundKeys.length == 0)
                    return null;

                if(kid) {
                    temp = [];
                    for(var k = 0; k < foundKeys.length; k++) {
                        if(foundKeys[k]['kid'] == kid)
                            temp.push(foundKeys[k]);
                    }
                    foundKeys = temp;
                }
                if(foundKeys.length == 0)
                    return null;
                else
                    return foundKeys;
            }
        }

    }

};

/**
 * Performs discovery on the IdP issuer_id (OIDC.discover)
 * @function discover
 * @memberof OIDC
 * @param {string} issuer     - The Identity Provider's issuer_id
 * @returns {object|null}     - The JSON object of the discovery document or null
 * @throws {OidcException}
 */
OIDC.discover = function(issuer)
{
    var discovery = null;
    if(issuer) {
        var openidConfig = issuer + '/.well-known/openid-configuration';
        var discoveryDoc = this.fetchJSON(openidConfig);
        if(discoveryDoc)
            discovery = this.getJsonObject(discoveryDoc)
    }
    return discovery;
};


/**
 * OidcException
 * @param {string } message  - The exception error message
 * @constructor
 */
function OidcException(message) {
    this.name = 'OidcException';
    this.message = message;
}
OidcException.prototype = new Error();
OidcException.prototype.constructor = OidcException;



function namespace(namespaceString) {
    var parts = namespaceString.split('.'),
        parent = window,
        currentPart = '';

    for(var i = 0, length = parts.length; i < length; i++) {
        currentPart = parts[i];
        parent[currentPart] = parent[currentPart] || {};
        parent = parent[currentPart];
    }
    return parent;
}