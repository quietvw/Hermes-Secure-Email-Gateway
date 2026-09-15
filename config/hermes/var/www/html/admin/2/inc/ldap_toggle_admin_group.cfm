<!---
Hermes Secure Email Gateway Copyright Dionyssios Edwards 2011-2026. All Rights Reserved.

This file is part of Hermes Secure Email Gateway Community Edition.

    Hermes Secure Email Gateway Community Edition is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Hermes Secure Email Gateway Community Edition is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with Hermes Secure Email Gateway Community Edition.  If not, see <https://www.gnu.org/licenses/agpl.html>.
--->

<!---
TOGGLE ADMIN GROUP MEMBERSHIP FOR AN EXISTING LDAP USER.
Requires:
- ldapUsername: LDAP cn / uid
- adminGroupAction: "add" or "remove"

Benign states are treated as success:
- add when already in cn=admins
- remove when not currently in cn=admins
--->

<cfparam name="ldapUsername" default="">
<cfparam name="adminGroupAction" default="add">

<cfscript>
function escapeLdapRdnValue(rawValue) {
    var value = ToString(arguments.rawValue);
    var escaped = "";
    var i = 1;
    var ch = "";

    for (i = 1; i <= Len(value); i++) {
        ch = Mid(value, i, 1);

        if ((i EQ 1 AND (ch EQ " " OR ch EQ Chr(35)))
            OR (i EQ Len(value) AND ch EQ " ")
            OR ch EQ "\"
            OR ch EQ ","
            OR ch EQ "+"
            OR ch EQ Chr(34)
            OR ch EQ "<"
            OR ch EQ ">"
            OR ch EQ ";"
            OR ch EQ "=") {
            escaped &= "\" & ch;
        } else {
            escaped &= ch;
        }
    }

    return escaped;
}

function escapeCommandArgument(rawValue) {
    return Chr(34) & Replace(ToString(arguments.rawValue), Chr(34), "\" & Chr(34), "all") & Chr(34);
}

function isBenignAdminGroupMessage(rawMessage, groupAction) {
    var message = ToString(arguments.rawMessage);

    if (arguments.groupAction EQ "add") {
        return message CONTAINS "already exists" OR message CONTAINS "Type or value exists";
    }

    return message CONTAINS "No such attribute" OR message CONTAINS "no such value";
}

function hasLdapFailure(rawMessage) {
    var message = ToString(arguments.rawMessage);
    return message CONTAINS "ldap_modify:" OR message CONTAINS "ldapmodify:";
}
</cfscript>

<cfif Len(Trim(ldapUsername)) GT 0 AND ListFindNoCase("add,remove", adminGroupAction)>
    <cfinclude template="generate_customtrans.cfm">

    <cfset ldapModifyResult = "">
    <cfset ldapModifyError = "">
    <cfset safeFileSuffix = REReplace(customtrans3, "[^A-Za-z0-9_-]", "", "all")>
    <cfif safeFileSuffix EQ "">
        <cfset safeFileSuffix = Hash(customtrans3)>
    </cfif>
    <cfset fileToDelete = "/opt/hermes/tmp/#safeFileSuffix#_toggle_admin_group.ldif">
    <cfset ldapEscapedUsername = escapeLdapRdnValue(ldapUsername)>

    <cfif adminGroupAction EQ "add">
        <cfset ldapGroupActionLdif = "dn: cn=admins,ou=groups,dc=hermes,dc=local#Chr(10)#changetype: modify#Chr(10)#add: member#Chr(10)#member: cn=#ldapEscapedUsername#,ou=users,dc=hermes,dc=local#Chr(10)#">
    <cfelse>
        <cfset ldapGroupActionLdif = "dn: cn=admins,ou=groups,dc=hermes,dc=local#Chr(10)#changetype: modify#Chr(10)#delete: member#Chr(10)#member: cn=#ldapEscapedUsername#,ou=users,dc=hermes,dc=local#Chr(10)#">
    </cfif>

    <cftry>
        <cffile action="write"
            file="#fileToDelete#"
            output="#ldapGroupActionLdif#"
            addNewLine="no">

        <cfexecute name="/usr/local/bin/docker"
            arguments='exec hermes_ldap ldapmodify -Y EXTERNAL -H ldapi://%2Fvar%2Frun%2Fslapd%2Fldapi -f #escapeCommandArgument(fileToDelete)#'
            variable="ldapModifyResult"
            errorVariable="ldapModifyError"
            timeout="60">
        </cfexecute>

        <cfif Len(Trim(ldapModifyError)) GT 0>
            <cfset benignErrors = ldapModifyError>
            <cfif isBenignAdminGroupMessage(benignErrors, adminGroupAction)>
                <!--- Desired end-state already achieved. --->
            <cfelseif hasLdapFailure(benignErrors)>
                <cfif FileExists(fileToDelete)>
                    <cffile action="delete" file="#fileToDelete#">
                </cfif>
                <cfset m="LDAP Toggle Admin Group: #ldapModifyError#">
                <cfinclude template="error.cfm">
                <cfabort>
            </cfif>
        </cfif>

    <cfcatch type="any">
        <cfset benignErrors = (isDefined("ldapModifyError") ? ldapModifyError : "") & " " & cfcatch.detail>
        <cfif isBenignAdminGroupMessage(benignErrors, adminGroupAction)>
            <!--- Desired end-state already achieved. --->
        <cfelse>
            <cfif FileExists(fileToDelete)>
                <cffile action="delete" file="#fileToDelete#">
            </cfif>
            <cfset m="LDAP Toggle Admin Group: #cfcatch.message# | Detail: #cfcatch.detail# | LDAP Error: #ldapModifyError#">
            <cfinclude template="error.cfm">
            <cfabort>
        </cfif>
    </cfcatch>
    </cftry>

    <cfif FileExists(fileToDelete)>
        <cffile action="delete" file="#fileToDelete#">
    </cfif>
</cfif>
