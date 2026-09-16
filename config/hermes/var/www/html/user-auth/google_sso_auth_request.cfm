<cfinclude template="./inc/google_sso_session.cfm">
<cfparam name="url.target" default="users">

<cfset googleAuthContext = googleSsoBuildAuthContext(url.target)>

<cfif googleAuthContext.valid AND googleAuthContext.authorized>
    <cfheader name="Remote-User" value="#googleAuthContext.username#">
    <cfheader name="Remote-Email" value="#googleAuthContext.email#">
    <cfheader name="Remote-Name" value="#googleAuthContext.name#">
    <cfheader name="Remote-Groups" value="#googleAuthContext.groups#">
    <cfheader name="X-Hermes-Auth-Source" value="google_sso">
    <cfheader statuscode="200" statustext="Authorized">
    <cfoutput>Authorized</cfoutput>
<cfelse>
    <cfheader statuscode="401" statustext="Unauthorized">
    <cfoutput>Unauthorized</cfoutput>
</cfif>
<cfabort>
