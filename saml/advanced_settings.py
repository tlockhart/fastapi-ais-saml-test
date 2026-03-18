ADVANCED_CONFIG={
    "security": {
        "nameIdEncrypted": False,
        "authnRequestsSigned": False,
        "logoutRequestSigned": False,
        "logoutResponseSigned": False,
        "signMetadata": False,
        "wantMessagesSigned": False,
        "wantAssertionsSigned": False,
        "wantNameId" : True,
        "wantNameIdEncrypted": False,
        "wantAssertionsEncrypted": False,
        "allowSingleLabelDomains": False,
        "signatureAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        "digestAlgorithm": "http://www.w3.org/2001/04/xmlenc#sha256",
        "rejectDeprecatedAlgorithm": True
    },
    "contactPerson": {
        "technical": {
            "givenName": "technical_name",
            "emailAddress": "technical@example.com"
        },
        "support": {
            "givenName": "support_name",
            "emailAddress": "support@example.com"
        }
    },
    "organization": {
        "en-US": {
            "name": "sp_test",
            "displayname": "SP test",
            "url": "http://sp.example.com"
        }
    },
    "lowercase_urlencoding": True
}
