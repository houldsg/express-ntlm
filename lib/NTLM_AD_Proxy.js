/* jshint node:true */

var util = require('util');

var ASN1 = require('./ASN1'),
    NTLM_Proxy = require('./NTLM_Proxy'),
    utils = require('./utils');


function LDAP_Context() {
    this.messageID = 0;

    this.LDAP_Result_success = 0;
    this.LDAP_Result_saslBindInProgress = 14;




    this.result_description = {
        "0" : 'success',
        "1" : 'operationsError',
        "2" : 'protocolError',
        "3" : 'timeLimitExceeded',
        "4" : 'sizeLimitExceeded',
        "5" : 'compareFalse',
        "6" : 'compareTrue',
        "7" : 'authMethodNotSupported',
        "8" : 'strongerAuthRequired',
        "10" : 'referral - wrong base DN?',
        "11" : 'adminLimitExceeded',
        "12" : 'unavailableCriticalExtension',
        "13" : 'confidentialityRequired',
        "14" : 'saslBindInProgress',
        "16" : 'noSuchAttribute',
        "17" : 'undefinedAttributeType',
        "18" : 'inappropriateMatching',
        "19" : 'constraintViolation',
        "20" : 'attributeOrValueExists',
        "21" : 'invalidAttributeSyntax',
        "32" : 'noSuchObject',
        "33" : 'aliasProblem',
        "34" : 'invalidDNSSyntax',
        "36" : 'aliasDereferencingProblem',
        "48" : 'inappropriateAuthentication',
        "49" : 'invalidCredentials',
        "50" : 'insufficientAccessRights',
        "51" : 'busy',
        "52" : 'unavailable',
        "53" : 'unwillingToPerform',
        "54" : 'loopDetect',
        "64" : 'namingViolation',
        "65" : 'objectClassViolation',
        "66" : 'notAllowedOnNonLeaf',
        "67" : 'notAllowedOnRDN',
        "68" : 'entryAlreadyExists',
        "69" : 'objectClassProhibited',
        "71" : 'affectsMultipleDSAs',
        "80" : 'other',
    };

    //# scope in SearchRequest
    this.LDAP_Scope_baseObject = 0;
    this.LDAP_Scope_singleLevel = 1;
    this.LDAP_Scope_wholeSubtree = 2;
}

LDAP_Context.prototype.make_session_setup_req = function(ntlm_token, type1) {

    var authentication = ASN1.maketlv(0xA3, utils.concatBuffer(ASN1.makeoctstr('GSS-SPNEGO'), ASN1.makeoctstr(ntlm_token))),
        bindRequest = ASN1.maketlv(0x60, utils.concatBuffer(ASN1.makeint(3), ASN1.makeoctstr(''), authentication));

    this.messageID++;

    return ASN1.makeseq(utils.concatBuffer(ASN1.makeint(this.messageID), bindRequest));
};

LDAP_Context.prototype.make_negotiate_protocol_req = function() {
    return;
};

LDAP_Context.prototype.parse_session_setup_resp = function(response, callback) {
    try {
        var data = ASN1.parseseq(response);

        var messageID = ASN1.parseint(data, true);
        data = messageID[1];
        messageID = messageID[0];


        if (messageID != this.messageID) {
            throw new Error('Unexpected MessageID: ' + messageID + ' instead of ' + this.messageID);
        }

        var controls = ASN1.parsetlv(0x61, data, true);
        data = controls[0];
        controls = controls[1];

        var resultCode = ASN1.parseenum(data, true);
        data = resultCode[1];
        resultCode = resultCode[0];

        var matchedDN = ASN1.parseoctstr(data, true);
        data = matchedDN[1];
        matchedDN = matchedDN[0];

        var diagnosticMessage = ASN1.parseoctstr(data, true);
        data = diagnosticMessage[1];
        diagnosticMessage = diagnosticMessage[0];

        if (resultCode == this.LDAP_Result_success) {
            return callback(null, true, '');
        }

        if (resultCode != this.LDAP_Result_saslBindInProgress) {
            return callback(null, false, '');
        }

        var serverSaslCreds = ASN1.parsetlv(0x87, data);
        return callback(null, true, serverSaslCreds);
    }
    catch (error) {
        return callback(error);
    }
};


/*
 Create an LDAP search request that can be sent to the AD server.
 
 @base          The DN to start the search from.
 @criteria      A dictionary with the attributes to look for (zero or one object for now)
 @attributes    A list of attributes to return.
 @return        The LDAP request to send to the AD server.
*/
LDAP_Context.prototype.make_search_req = function(base, criteria, attributes) {
        //assert(len(criteria)<=1)

        //# AttributeSelection
        //ldapattributes = makeseq(''.join([makeoctstr(x) for x in attributes]))

        var ldapattributes = ASN1.makeseq(attributes.map(function(str){ ASN1.makeoctstr(str); }).join(''));
        var ldapfilter;

        //# Filter is a choice with CONTEXT IMPLICIT tags
        if(criteria){
            //# equalityMatch has tag [3] for constructured type (SEQUENCE)
            //ldapfilter = maketlv('\xA3', makeoctstr(criteria.keys()[0]) + makeoctstr(criteria.values()[0]))
            ldapfilter = ASN1.maketlv('\xA3', ASN1.makeoctstr(criteria[0]) + ASN1.makeoctstr(criteria[1]));
        }
        else{
            //# present has tag [7] for primitive type (OCTET STRING)
            ldapfilter = ASN1.maketlv('\x87', 'objectClass');
        }
        //# SearchRequest has APPLICATION IMPLICIT tag [3] for constructed type (SEQUENCE)
        var searchRequest = ASN1.maketlv('\x63', ASN1.makeoctstr(base) + ASN1.makeenum(this.LDAP_Scope_wholeSubtree) +
            ASN1.makeenum(3) + ASN1.makeint(0) + ASN1.makeint(0) + ASN1.makebool(false) + ldapfilter + ldapattributes);
        //# LDAPMessage
        this.messageID++;
        console.log(this.messageID);

        return ASN1.makeseq(ASN1.makeint(this.messageID) + searchRequest);
};




/*
        """Parse an LDAP search response received from the AD server.
        
        @return         A tuple (True, string) if the search is complete.
                        A tuple (False, objectName, attributes) where objectName is a DN, and
                        attributes is a dictionary of lists. In attributes, the key is the
                        attribute name; the list contain all the values for such attribute.
        """
*/
LDAP_Context.prototype.parse_search_resp = function(response) {

        //# LDAPMessage
        var data = ASN1.parseseq(response);
        var t = ASN1.parseint(data, true);
        var messageID = t[0];
        data = t[1];
        var controls, resultCode, matchedDN, diagnosticMessage;

        if(messageID != this.messageID){
            console.log('LDAP_Parse_Exception Unexpected MessageID: ' + messageID + ' instead of ' + this.messageID);
            //throw LDAP_Parse_Exception("Unexpected MessageID: %d instead of %d" % (messageID, this.messageID));
        }
        //# SearchResultDone has APPLICATION IMPLICIT tag [5] for primitive type (OCTET STRING)
        if(data[0] == '\x65'){
            t = ASN1.parsetlv('\x65', data, true);
            data = t[0];
            controls = t[1];
            t = ASN1.parseenum(data, true);
            resultCode = t[0];
            data = t[1];
            t = ASN1.parseoctstr(data, true);
            matchedDN = t[0];
            data = t[1];
            t = ASN1.parseoctstr(data, true);
            diagnosticMessage = t[0];
            data = t[1];
            if(resultCode){
                //import re
                var rd = this.result_description[resultCode] || "unknown";
                console.log('NTLM_Proxy_Exception. Failed search. Code ' + resultCode + '(' + rd + ')' + 'Message: ' + diagnosticMessage);
                /*
                raise NTLM_Proxy_Exception("Failed search. Code %d (%s). Message: %s." % (resultCode, rd, re.sub(r'[\x00-\x1F]','',diagnosticMessage)))
                */
            }
            return [true, diagnosticMessage];
        }
        //# SearchResultReference has APPLICATION IMPLICIT tag [19] for constructed type (SEQUENCE)
        if(data[0] == '\x73'){
            return [false, null, {}];
        }

        //# SearchResultEntry has APPLICATION IMPLICIT tag [4] for constructed type (SEQUENCE)
        t = ASN1.parsetlv('\x64', data, true);
        data = t[0];
        controls = t[1];

        var attributes = {};
        t = ASN1.parseoctstr(data, true);
        var objectName = t[0];
        data = t[1];
        var attributelist = ASN1.parseseq(data);

        var partattr, attrtype, attrvalues, value;

        while(attributelist){
            //# Payload of a PartialAttribute
            t = ASN1.parseseq(attributelist, true);
            partattr = t[0];
            attributelist = t[1];
            //# Attribute name
            t = ASN1.parseoctstr(partattr, true);
            attrtype = t[0];
            attributesdata = t[1];
            attributes[attrtype] = [];
            //# Attribute values
            attrvalues = ASN1.parseset(attributesdata);

            while(attrvalues){
                t = parseoctstr(attrvalues, true);
                value = t[0];
                attrvalues = t[1];
                attributes[attrtype].push(value);
            }
        }
        return [false, objectName, attributes];

};



function NTLM_AD_Proxy(ipad, port, domain, base, use_tls, tlsOptions) {
    this._ipad = ipad;
    this._portad = port || (use_tls ? 636 : 398);

    NTLM_Proxy.call(this, this._ipad, this._portad, domain, LDAP_Context, use_tls, tlsOptions);
    this.base = base;
}

util.inherits(NTLM_AD_Proxy, NTLM_Proxy);

module.exports = NTLM_AD_Proxy;
