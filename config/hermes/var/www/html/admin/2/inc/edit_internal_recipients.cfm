
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
    <cfset relayAdminUsername = getRecipientAdminContext.ldap_username NEQ "" ? LCase(getRecipientAdminContext.ldap_username) : LCase(getRecipientAdminContext.recipient)>

    <cfquery name="getExistingSystemUser" datasource="hermes">
        SELECT id, username, email
        FROM system_users
        WHERE username = <cfqueryparam value="#relayAdminUsername#" cfsqltype="cf_sql_varchar">
           OR email = <cfqueryparam value="#getRecipientAdminContext.recipient#" cfsqltype="cf_sql_varchar">
        LIMIT 1
    </cfquery>

    <cfif form.system_admin EQ "1">
        <cfif getExistingSystemUser.recordcount GTE 1>
            <cfquery datasource="hermes">
                UPDATE system_users
                SET username = <cfqueryparam value="#relayAdminUsername#" cfsqltype="cf_sql_varchar">,
                    email = <cfqueryparam value="#getRecipientAdminContext.recipient#" cfsqltype="cf_sql_varchar">,
                    auth_type = <cfqueryparam value="#getRecipientAdminContext.auth_type#" cfsqltype="cf_sql_varchar">,
                    remoteauth_domain = <cfqueryparam value="#getRecipientAdminContext.remoteauth_domain#" cfsqltype="cf_sql_varchar" null="#(getRecipientAdminContext.remoteauth_domain EQ '')#">,
                    ldap_synced = 1,
                    applied = '1'
                WHERE id = <cfqueryparam value="#getExistingSystemUser.id#" cfsqltype="cf_sql_integer">
            </cfquery>
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
                    '2',
                    'one_factor',
                    '1',
                    1,
                    <cfqueryparam value="#getRecipientAdminContext.auth_type#" cfsqltype="cf_sql_varchar">,
                    <cfqueryparam value="#getRecipientAdminContext.remoteauth_domain#" cfsqltype="cf_sql_varchar" null="#(getRecipientAdminContext.remoteauth_domain EQ '')#">,
                    ''
                )
            </cfquery>
        </cfif>

        <cfset ldapUsername = relayAdminUsername>
        <cfset adminGroupAction = "add">
        <cfinclude template="ldap_toggle_admin_group.cfm">
    <cfelse>
        <cfif getExistingSystemUser.recordcount GTE 1>
            <cfquery datasource="hermes">
                UPDATE system_users
                SET username = <cfqueryparam value="#relayAdminUsername#" cfsqltype="cf_sql_varchar">,
                    email = <cfqueryparam value="#getRecipientAdminContext.recipient#" cfsqltype="cf_sql_varchar">,
                    auth_type = <cfqueryparam value="#getRecipientAdminContext.auth_type#" cfsqltype="cf_sql_varchar">,
                    remoteauth_domain = <cfqueryparam value="#getRecipientAdminContext.remoteauth_domain#" cfsqltype="cf_sql_varchar" null="#(getRecipientAdminContext.remoteauth_domain EQ '')#">,
                    applied = '0'
                WHERE id = <cfqueryparam value="#getExistingSystemUser.id#" cfsqltype="cf_sql_integer">
            </cfquery>
        </cfif>

        <cfset ldapUsername = relayAdminUsername>
        <cfset adminGroupAction = "remove">
        <cfinclude template="ldap_toggle_admin_group.cfm">

        <cfif getExistingSystemUser.recordcount GTE 1 AND Len(Trim(getExistingSystemUser.username)) GT 0>
            <cfset targetSessionUser = getExistingSystemUser.username>
            <cfinclude template="invalidate_user_sessions.cfm">
        </cfif>
        <cfif getExistingSystemUser.recordcount GTE 1 AND Len(Trim(getExistingSystemUser.email)) GT 0 AND getExistingSystemUser.email NEQ getExistingSystemUser.username>
            <cfset targetSessionUser = getExistingSystemUser.email>
            <cfinclude template="invalidate_user_sessions.cfm">
        </cfif>
        <cfif relayAdminUsername NEQ "" AND (getExistingSystemUser.recordcount LT 1 OR relayAdminUsername NEQ getExistingSystemUser.username)>
            <cfset targetSessionUser = relayAdminUsername>
            <cfinclude template="invalidate_user_sessions.cfm">
        </cfif>
        <cfif getRecipientAdminContext.recipient NEQ "" AND (getExistingSystemUser.recordcount LT 1 OR getRecipientAdminContext.recipient NEQ getExistingSystemUser.email)>
            <cfset targetSessionUser = getRecipientAdminContext.recipient>
            <cfinclude template="invalidate_user_sessions.cfm">
        </cfif>
    </cfif>
</cfif>
