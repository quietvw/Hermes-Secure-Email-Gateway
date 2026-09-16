<!---
Hermes Secure Email Gateway Copyright Dionyssios Edwards 2011-2026. All Rights Reserved.

This file is part of Hermes Secure Email Gateway Community Edition.
--->

<cfscript>
function googleSsoEnabled() {
    if (NOT StructKeyExists(request, "googleSsoEnabled")) {
        var enabledQuery = queryExecute(
            "SELECT value2
             FROM parameters2
             WHERE module = 'google_provisioning'
               AND parameter = 'enabled'
             LIMIT 1",
            {},
            { datasource = "hermes" }
        );
        request.googleSsoEnabled = enabledQuery.recordCount GTE 1 AND Trim(enabledQuery.value2) EQ "1";
    }

    return request.googleSsoEnabled;
}

function googleSsoCookieName() {
    return "hermes_google_sso";
}

function googleSsoCurrentEpoch() {
    return DateDiff("s", CreateDateTime(1970, 1, 1, 0, 0, 0), Now());
}

function googleSsoSanitizeHeaderValue(rawValue) {
    var cleanValue = ToString(arguments.rawValue);
    cleanValue = Replace(cleanValue, Chr(13), " ", "all");
    cleanValue = Replace(cleanValue, Chr(10), " ", "all");
    return Trim(cleanValue);
}

function googleSsoSignValue(rawValue) {
    return LCase(HMAC(arguments.rawValue, googleSsoReadKey(), "HmacSHA256", "UTF-8"));
}

function googleSsoGenerateIvHex() {
    var secureRandom = CreateObject("java", "java.security.SecureRandom");
    var byteArrayClass = CreateObject("java", "java.lang.Byte").TYPE;
    var ivBytes = CreateObject("java", "java.lang.reflect.Array").newInstance(byteArrayClass, 16);
    secureRandom.nextBytes(ivBytes);
    return LCase(BinaryEncode(ivBytes, "Hex"));
}

function googleSsoReadKey() {
    if (NOT StructKeyExists(request, "googleSsoKey")) {
        request.googleSsoKey = Trim(FileRead("/opt/hermes/keys/hermes.key", "utf-8"));
    }

    return request.googleSsoKey;
}

function googleSsoReadCookieValue() {
    var cookieName = googleSsoCookieName();
    var cookieValue = "";
    var reqData = GetHttpRequestData();
    var rawCookieHeader = "";

    if (StructKeyExists(cookie, cookieName) AND Len(Trim(cookie[cookieName])) GT 0) {
        return Trim(cookie[cookieName]);
    }

    if (IsStruct(reqData) AND StructKeyExists(reqData, "Headers") AND IsStruct(reqData.Headers) AND StructKeyExists(reqData.Headers, "cookie")) {
        rawCookieHeader = reqData.Headers["cookie"];
        for (var cookiePair in ListToArray(rawCookieHeader, ";", false)) {
            var pair = ListToArray(cookiePair, "=", true);
            if (ArrayLen(pair) GTE 2 AND Trim(pair[1]) EQ cookieName) {
                cookieValue = Mid(cookiePair, Find("=", cookiePair) + 1, Len(cookiePair));
                return Trim(cookieValue);
            }
        }
    }

    return "";
}

function googleSsoReadSession() {
    var result = {
        valid: false,
        email: "",
        name: "",
        expires_at: 0
    };
    var rawCookieValue = googleSsoReadCookieValue();

    if (Len(rawCookieValue) EQ 0) {
        return result;
    }

    try {
        var firstSeparator = Find(":", rawCookieValue);
        var secondSeparator = firstSeparator GT 0 ? Find(":", rawCookieValue, firstSeparator + 1) : 0;
        var cookieSignature = "";
        var ivHex = "";
        var encryptedPayload = "";
        var decryptedPayload = "";
        var payload = "";

        if (firstSeparator LTE 1 OR secondSeparator LTE firstSeparator) {
            return result;
        }

        cookieSignature = LCase(Left(rawCookieValue, firstSeparator - 1));
        ivHex = Mid(rawCookieValue, firstSeparator + 1, secondSeparator - firstSeparator - 1);
        encryptedPayload = Mid(rawCookieValue, secondSeparator + 1, Len(rawCookieValue) - secondSeparator);

        if (Len(ivHex) NEQ 32 OR cookieSignature NEQ googleSsoSignValue(ivHex & ":" & encryptedPayload)) {
            return result;
        }

        decryptedPayload = Decrypt(encryptedPayload, googleSsoReadKey(), "AES/CBC/PKCS5Padding", "Hex", BinaryDecode(ivHex, "Hex"));
        payload = DeserializeJSON(decryptedPayload);

        if (NOT StructKeyExists(payload, "email") OR NOT IsValid("email", payload.email)) {
            return result;
        }

        if (NOT StructKeyExists(payload, "expires_at") OR Val(payload.expires_at) LTE googleSsoCurrentEpoch()) {
            return result;
        }

        result.valid = true;
        result.email = LCase(Trim(payload.email));
        result.name = StructKeyExists(payload, "name") ? googleSsoSanitizeHeaderValue(payload.name) : result.email;
        result.expires_at = Val(payload.expires_at);
    } catch (any ignoreInvalidCookie) {
        return result;
    }

    return result;
}

function googleSsoIssueSession(required string email, string name = "", numeric ttlSeconds = 43200) {
    var payload = {
        email: LCase(Trim(arguments.email)),
        name: googleSsoSanitizeHeaderValue(Len(Trim(arguments.name)) GT 0 ? arguments.name : arguments.email),
        issued_at: googleSsoCurrentEpoch(),
        expires_at: googleSsoCurrentEpoch() + Int(arguments.ttlSeconds)
    };
    var ivHex = googleSsoGenerateIvHex();
    var encryptedPayload = Encrypt(SerializeJSON(payload), googleSsoReadKey(), "AES/CBC/PKCS5Padding", "Hex", BinaryDecode(ivHex, "Hex"));
    var signedPayload = googleSsoSignValue(ivHex & ":" & encryptedPayload) & ":" & ivHex & ":" & encryptedPayload;

    cfcookie(
        name = googleSsoCookieName(),
        value = signedPayload,
        httponly = true,
        secure = true,
        path = "/",
        samesite = "Lax"
    );
}

function googleSsoClearSession() {
    cfcookie(
        name = googleSsoCookieName(),
        value = "",
        expires = "now",
        httponly = true,
        secure = true,
        path = "/",
        samesite = "Lax"
    );
}

function googleSsoBuildAuthContext(required string target) {
    var sessionData = googleSsoReadSession();
    var result = {
        valid: sessionData.valid,
        authorized: false,
        email: sessionData.email,
        name: sessionData.name,
        username: "",
        groups: "",
        target: LCase(Trim(arguments.target)),
        portalPath: "/users/"
    };
    var recipientQuery = "";
    var adminQuery = "";
    var authGroups = [];
    var accessGroup = "one_factor";
    var recipientGroup = "";

    if (NOT googleSsoEnabled() OR NOT sessionData.valid) {
        return result;
    }

    recipientQuery = queryExecute(
        "SELECT r.recipient, COALESCE(r.recipient_type, 'relay') AS recipient_type, COALESCE(us.ldap_username, '') AS ldap_username
               , r.status
         FROM recipients r
         LEFT JOIN user_settings us ON us.email = r.recipient
         WHERE r.recipient = :email
          AND r.status = 'OK'
         LIMIT 1",
        { email = { value = sessionData.email, cfsqltype = "cf_sql_varchar" } },
        { datasource = "hermes" }
    );

    adminQuery = queryExecute(
        "SELECT username, email, first_name, last_name, access_control
         FROM system_users
         WHERE email = :email
           AND applied = '1'
         LIMIT 1",
        { email = { value = sessionData.email, cfsqltype = "cf_sql_varchar" } },
        { datasource = "hermes" }
    );

    if (recipientQuery.recordCount GTE 1) {
        recipientGroup = recipientQuery.recipient_type EQ "mailbox" ? "mailboxes" : "relays";
        ArrayAppend(authGroups, recipientGroup);
        result.username = Len(Trim(recipientQuery.ldap_username)) GT 0 ? LCase(Trim(recipientQuery.ldap_username)) : sessionData.email;
        result.portalPath = "/users/";
    }

    if (adminQuery.recordCount GTE 1) {
        accessGroup = ListFindNoCase("one_factor,two_factor", adminQuery.access_control) ? adminQuery.access_control : accessGroup;
        if (ArrayFindNoCase(authGroups, "admins") EQ 0) {
            ArrayAppend(authGroups, "admins");
        }
        result.portalPath = "/admin/";
        if (Len(Trim(result.username)) EQ 0) {
            result.username = adminQuery.username;
        }
        if (result.target EQ "admin") {
            result.username = adminQuery.username;
        }
        if (Len(Trim(sessionData.name)) EQ 0 AND (Len(Trim(adminQuery.first_name)) GT 0 OR Len(Trim(adminQuery.last_name)) GT 0)) {
            result.name = googleSsoSanitizeHeaderValue(Trim(adminQuery.first_name & " " & adminQuery.last_name));
        }
    }

    if (ArrayFindNoCase(authGroups, accessGroup) EQ 0) {
        ArrayAppend(authGroups, accessGroup);
    }

    if (result.target EQ "admin") {
        result.authorized = ArrayFindNoCase(authGroups, "admins") GT 0;
    } else if (result.target EQ "users") {
        result.authorized = ArrayFindNoCase(authGroups, "relays") GT 0 OR ArrayFindNoCase(authGroups, "mailboxes") GT 0;
    }

    if (Len(Trim(result.username)) EQ 0) {
        result.username = sessionData.email;
    }

    result.groups = ArrayToList(authGroups, ",");
    return result;
}
</cfscript>
