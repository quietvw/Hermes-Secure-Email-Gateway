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
<cfset verifyHostPattern = "">
<cfset originalUrl = "">
<cfset reqData = GetHttpRequestData()>

<cfif verifyHost EQ "" AND StructKeyExists(cgi, "http_host")>
    <cfset verifyHost = REReplace(Trim(cgi.http_host), ":\d+$", "", "all")>
</cfif>

<cfif verifyHost EQ "" OR NOT REFind("^[A-Za-z0-9.-]+$", verifyHost)>
    <cfoutput>Unauthorized</cfoutput>
    <cfabort>
</cfif>

<cfset verifyHostPattern = Replace(verifyHost, ".", "\.", "all")>

<cfif IsStruct(reqData) AND StructKeyExists(reqData, "Headers") AND IsStruct(reqData.Headers) AND StructKeyExists(reqData.Headers, "x-original-url")>
    <cfset originalUrl = Trim(reqData.Headers["x-original-url"])>
</cfif>

<cfif originalUrl EQ "" OR NOT ReFindNoCase("^https://#verifyHostPattern##authTargetPath#(?:$|[?#/])", originalUrl)>
    <cfset originalUrl = "https://#verifyHost##authTargetPath#">
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
        <cfhttpparam type="header" name="X-Original-URL" value="#originalUrl#">
        <cfhttpparam type="header" name="Cookie" value="#requestCookies#">
    </cfhttp>
    <cfif StructKeyExists(verifyResult, "statusCode")
        AND Left(verifyResult.statusCode, 3) EQ "200"
        AND StructKeyExists(verifyResult, "responseHeader")
        AND IsStruct(verifyResult.responseHeader)
        AND StructKeyExists(verifyResult.responseHeader, "Remote-User")
        AND Len(Trim(verifyResult.responseHeader["Remote-User"])) GT 0>
        <cfoutput>Authorized</cfoutput>
    <cfelse>
        <cfoutput>Unauthorized</cfoutput>
    </cfif>
    <cfcatch type="any">
        <cfoutput>Unauthorized</cfoutput>
    </cfcatch>
</cftry>
<cfabort>
