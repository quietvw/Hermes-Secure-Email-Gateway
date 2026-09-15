
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

<cfinclude template="generate_customtrans.cfm">

<!--- EDIT RECIPIENTS STARTS HERE.
     enforce_mfa is the admin policy bit only — no LDAP cascade fires here.
     The user must click Enable in their Account Settings (user_settings.cfm)
     to actually move into cn=two_factor. Same pattern as the mailbox flow
     (Phase 1.5) so the two pages share one mental model. (#225 Phase 2) --->
<cfquery name="editrecipients" datasource="hermes">
    UPDATE recipients
    SET policy_id    = <cfqueryparam value="#form.policy#"      cfsqltype="cf_sql_integer">,
        enforce_mfa  = <cfqueryparam value="#form.enforce_mfa#" cfsqltype="cf_sql_tinyint">
    WHERE recipient  = <cfqueryparam value="#recipient#"        cfsqltype="cf_sql_varchar">
</cfquery>
<!--- EDIT RECIPIENT ENDS HERE --->

<!--- EDIT USER_SETTINGS STARTS HERE --->
<cfquery name="editusersettings" datasource="hermes">
    UPDATE user_settings
    SET report_enabled = <cfqueryparam value="#form.reports#"      cfsqltype="cf_sql_varchar">,
        train_bayes    = <cfqueryparam value="#form.train_bayes#"  cfsqltype="cf_sql_tinyint">,
        download_msg   = <cfqueryparam value="#form.download_msg#" cfsqltype="cf_sql_tinyint">
    WHERE email        = <cfqueryparam value="#recipient#"         cfsqltype="cf_sql_varchar">
</cfquery>
<!--- EDIT USER_SETTINGS ENDS HERE --->

<!--- RELAY RECIPIENT SYSTEM ADMIN SYNC --->
<cfquery name="getRecipientAdminContext" datasource="hermes">
    SELECT r.recipient, r.auth_type, r.remoteauth_domain, COALESCE(us.ldap_username, '') AS ldap_username
    FROM recipients r
    LEFT JOIN user_settings us ON us.email = r.recipient
    WHERE r.id = <cfqueryparam value="#edit_id#" cfsqltype="cf_sql_integer">
    LIMIT 1
</cfquery>

<cfif getRecipientAdminContext.recordcount GTE 1>
    <cfset relayAdminUsername = Len(Trim(getRecipientAdminContext.ldap_username)) GT 0 ? LCase(Trim(getRecipientAdminContext.ldap_username)) : LCase(getRecipientAdminContext.recipient)>

    <cfquery name="getSystemUserByUsername" datasource="hermes">
        SELECT id, username, email, system
        FROM system_users
        WHERE username = <cfqueryparam value="#relayAdminUsername#" cfsqltype="cf_sql_varchar">
          AND system = '3'
        LIMIT 1
    </cfquery>

    <cfquery name="getSystemUserByEmail" datasource="hermes">
        SELECT id, username, email, system
        FROM system_users
        WHERE email = <cfqueryparam value="#getRecipientAdminContext.recipient#" cfsqltype="cf_sql_varchar">
          AND system = '3'
        LIMIT 1
    </cfquery>

    <cfquery name="getConflictingSystemUserByUsername" datasource="hermes">
        SELECT id
        FROM system_users
        WHERE username = <cfqueryparam value="#relayAdminUsername#" cfsqltype="cf_sql_varchar">
          AND (system IS NULL OR system <> '3')
        LIMIT 1
    </cfquery>

    <cfquery name="getConflictingSystemUserByEmail" datasource="hermes">
        SELECT id
        FROM system_users
        WHERE email = <cfqueryparam value="#getRecipientAdminContext.recipient#" cfsqltype="cf_sql_varchar">
          AND (system IS NULL OR system <> '3')
        LIMIT 1
    </cfquery>

    <cfset targetSystemUserId = 0>
    <cfset targetSystemUserUsername = "">
    <cfset targetSystemUserEmail = "">

    <cfif getSystemUserByUsername.recordcount GTE 1 AND getSystemUserByEmail.recordcount GTE 1 AND getSystemUserByUsername.id NEQ getSystemUserByEmail.id>
        <cfset m="Edit Relay Recipients: conflicting system user records matched by username/email">
        <cfinclude template="error.cfm">
        <cfabort>
    <cfelseif getConflictingSystemUserByUsername.recordcount GTE 1 OR getConflictingSystemUserByEmail.recordcount GTE 1>
        <cfset m="Edit Relay Recipients: relay admin toggle conflicts with an existing dedicated system user">
        <cfinclude template="error.cfm">
        <cfabort>
    <cfelseif getSystemUserByUsername.recordcount GTE 1>
        <cfset targetSystemUserId = getSystemUserByUsername.id>
        <cfset targetSystemUserUsername = getSystemUserByUsername.username>
        <cfset targetSystemUserEmail = getSystemUserByUsername.email>
    <cfelseif getSystemUserByEmail.recordcount GTE 1>
        <cfset targetSystemUserId = getSystemUserByEmail.id>
        <cfset targetSystemUserUsername = getSystemUserByEmail.username>
        <cfset targetSystemUserEmail = getSystemUserByEmail.email>
    </cfif>

    <cfif form.system_admin EQ "1">
        <cfif targetSystemUserId GT 0>
            <cfquery datasource="hermes">
                UPDATE system_users
                SET username = <cfqueryparam value="#relayAdminUsername#" cfsqltype="cf_sql_varchar">,
                    email = <cfqueryparam value="#getRecipientAdminContext.recipient#" cfsqltype="cf_sql_varchar">,
                    auth_type = <cfqueryparam value="#getRecipientAdminContext.auth_type#" cfsqltype="cf_sql_varchar">,
                    remoteauth_domain = <cfqueryparam value="#getRecipientAdminContext.remoteauth_domain#" cfsqltype="cf_sql_varchar" null="#(getRecipientAdminContext.remoteauth_domain EQ '')#">,
                    ldap_synced = 1,
                    applied = '1'
                WHERE id = <cfqueryparam value="#targetSystemUserId#" cfsqltype="cf_sql_integer">
            </cfquery>

            <cfset relayAdminSessionTargets = "">
            <cfloop list="#targetSystemUserUsername#,#targetSystemUserEmail#" index="candidateSessionUser">
                <cfset candidateSessionUser = Trim(candidateSessionUser)>
                <cfif Len(candidateSessionUser) GT 0
                    AND candidateSessionUser NEQ relayAdminUsername
                    AND candidateSessionUser NEQ getRecipientAdminContext.recipient
                    AND NOT ListFindNoCase(relayAdminSessionTargets, candidateSessionUser)>
                    <cfset relayAdminSessionTargets = ListAppend(relayAdminSessionTargets, candidateSessionUser)>
                </cfif>
            </cfloop>

            <cfloop list="#relayAdminSessionTargets#" index="targetSessionUser">
                <cfinclude template="invalidate_user_sessions.cfm">
            </cfloop>
        <cfelse>
            <cfquery datasource="hermes">
                INSERT INTO system_users
                (username, email, first_name, last_name, system, access_control, applied, ldap_synced, auth_type, remoteauth_domain, password)
                VALUES
                (
                    <cfqueryparam value="#relayAdminUsername#" cfsqltype="cf_sql_varchar">,
                    <cfqueryparam value="#getRecipientAdminContext.recipient#" cfsqltype="cf_sql_varchar">,
                    <cfqueryparam value="#ListFirst(getRecipientAdminContext.recipient, '@')#" cfsqltype="cf_sql_varchar">,
                    <cfqueryparam value="User" cfsqltype="cf_sql_varchar">,
                    '3',
                    'one_factor',
                    '1',
                    1,
                    <cfqueryparam value="#getRecipientAdminContext.auth_type#" cfsqltype="cf_sql_varchar">,
                    <cfqueryparam value="#getRecipientAdminContext.remoteauth_domain#" cfsqltype="cf_sql_varchar" null="#(getRecipientAdminContext.remoteauth_domain EQ '')#">,
                    ''
                )
            </cfquery>
        </cfif>

        <cfif targetSystemUserId GT 0 OR (getConflictingSystemUserByUsername.recordcount EQ 0 AND getConflictingSystemUserByEmail.recordcount EQ 0)>
            <cfset ldapUsername = relayAdminUsername>
            <cfset adminGroupAction = "add">
            <cfinclude template="ldap_toggle_admin_group.cfm">
        </cfif>
    <cfelse>
        <cfif targetSystemUserId GT 0>
            <cfquery datasource="hermes">
                UPDATE system_users
                SET applied = '0'
                WHERE id = <cfqueryparam value="#targetSystemUserId#" cfsqltype="cf_sql_integer">
            </cfquery>
            <cfset ldapUsername = relayAdminUsername>
            <cfset adminGroupAction = "remove">
            <cfinclude template="ldap_toggle_admin_group.cfm">

            <cfset relayAdminSessionTargets = "">
            <cfloop list="#targetSystemUserUsername#,#targetSystemUserEmail#,#relayAdminUsername#,#getRecipientAdminContext.recipient#" index="candidateSessionUser">
                <cfset candidateSessionUser = Trim(candidateSessionUser)>
                <cfif Len(candidateSessionUser) GT 0 AND NOT ListFindNoCase(relayAdminSessionTargets, candidateSessionUser)>
                    <cfset relayAdminSessionTargets = ListAppend(relayAdminSessionTargets, candidateSessionUser)>
                </cfif>
            </cfloop>

            <cfloop list="#relayAdminSessionTargets#" index="targetSessionUser">
                <cfinclude template="invalidate_user_sessions.cfm">
            </cfloop>
        </cfif>
    </cfif>
</cfif>
