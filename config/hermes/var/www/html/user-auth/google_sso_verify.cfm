<cfinclude template="./inc/google_sso_session.cfm">
<cfparam name="url.target" default="users">

<cfset googleAuthContext = googleSsoBuildAuthContext(url.target)>

<cfif googleAuthContext.valid AND googleAuthContext.authorized>
    <cfoutput>Authorized</cfoutput>
    <cfabort>
</cfif>

<cfquery name="getConsoleHost" datasource="hermes">
    SELECT value2
    FROM parameters2
    WHERE module = 'console' AND parameter = 'console.host'
</cfquery>

<cfif getConsoleHost.recordcount LT 1 OR Len(Trim(getConsoleHost.value2)) EQ 0>
    <cfoutput>Unauthorized</cfoutput>
    <cfabort>
</cfif>

<cfset authTargetPath = LCase(url.target) EQ "admin" ? "/admin/" : "/users/">
<cfset requestCookies = "">
<cfset reqData = GetHttpRequestData()>
<cfif IsStruct(reqData) AND StructKeyExists(reqData, "Headers") AND IsStruct(reqData.Headers) AND StructKeyExists(reqData.Headers, "cookie")>
    <cfset requestCookies = reqData.Headers["cookie"]>
</cfif>

<cfif Len(Trim(requestCookies)) EQ 0>
    <cfoutput>Unauthorized</cfoutput>
    <cfabort>
</cfif>

<cftry>
    <cfexecute name="/usr/bin/curl"
        arguments="-X 'GET' -k 'https://#getConsoleHost.value2#/api/verify' -H 'accept: */*' -H 'X-Original-URL: https://#getConsoleHost.value2##authTargetPath#' -H 'Cookie: #requestCookies#'"
        variable="curlresult"
        timeout="10" />
    <cfoutput>#Trim(curlresult)#</cfoutput>
    <cfcatch type="any">
        <cfoutput>Unauthorized</cfoutput>
    </cfcatch>
</cftry>
<cfabort>
