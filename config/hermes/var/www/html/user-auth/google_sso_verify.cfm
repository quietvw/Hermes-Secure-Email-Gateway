<cfinclude template="./inc/google_sso_session.cfm">
<cfparam name="url.target" default="users">

<cfset googleAuthContext = googleSsoBuildAuthContext(url.target)>

<cfif googleAuthContext.valid AND googleAuthContext.authorized>
    <cfoutput>Authorized</cfoutput>
    <cfabort>
</cfif>

<cfset authTargetPath = LCase(url.target) EQ "admin" ? "/admin/" : "/users/">
<cfset requestCookies = "">
<cfset verifyHost = StructKeyExists(cgi, "server_name") ? Trim(cgi.server_name) : "">
<cfset reqData = GetHttpRequestData()>

<cfif verifyHost EQ "" AND StructKeyExists(cgi, "http_host")>
    <cfset verifyHost = REReplace(Trim(cgi.http_host), ":\d+$", "", "all")>
</cfif>

<cfif verifyHost EQ "" OR NOT REFind("^[A-Za-z0-9.-]+$", verifyHost)>
    <cfoutput>Unauthorized</cfoutput>
    <cfabort>
</cfif>

<cfif IsStruct(reqData) AND StructKeyExists(reqData, "Headers") AND IsStruct(reqData.Headers) AND StructKeyExists(reqData.Headers, "cookie")>
    <cfset requestCookies = reqData.Headers["cookie"]>
</cfif>

<cfif Len(Trim(requestCookies)) EQ 0>
    <cfoutput>Unauthorized</cfoutput>
    <cfabort>
</cfif>

<cftry>
    <cfhttp url="https://#verifyHost#/api/verify" method="GET" result="verifyResult" timeout="10" throwOnError="no">
        <cfhttpparam type="header" name="accept" value="*/*">
        <cfhttpparam type="header" name="X-Original-URL" value="https://#verifyHost##authTargetPath#">
        <cfhttpparam type="header" name="Cookie" value="#requestCookies#">
    </cfhttp>
    <cfoutput>#Trim(verifyResult.fileContent)#</cfoutput>
    <cfcatch type="any">
        <cfoutput>Unauthorized</cfoutput>
    </cfcatch>
</cftry>
<cfabort>
