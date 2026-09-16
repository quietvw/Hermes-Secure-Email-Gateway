<cfcomponent displayname="HermesSEGUser" output="false" hint="Handle the applications">

  <cffile action="read" file="/opt/hermes/creds/hermes_username" variable="HERMES_DATASOURCE_USERNAME">
  <cffile action="read" file="/opt/hermes/creds/hermes_password" variable="HERMES_DATASOURCE_PASSWORD">

//Define Datasource
      <cfscript>
                this.datasources["hermes"] = {
                class: 'com.mysql.jdbc.Driver'
                , bundleName: 'com.mysql.jdbc'
                , bundleVersion: '5.1.40'
                , connectionString: 'jdbc:mysql://hermes_db_server:3306/hermes?useUnicode=true&characterEncoding=UTF-8&useLegacyDatetimeCode=true&autoReconnect=true&useSSL=false&verifyServerCertificate=false&enabledTLSProtocols=TLSv1.2&requireSSL=false'
                , username: '#HERMES_DATASOURCE_USERNAME#'
                , password: "#HERMES_DATASOURCE_PASSWORD#"
                // optional settings
                , blob:true // default: false
                , clob:true // default: false
                , connectionLimit:100 // default:-1
                };
        </cfscript>


        <cfset This.name="UserGUI" />
        <cfset This.Sessionmanagement="True" />
       <cfset This.loginstorage="session" />
       <cfset This.requestTimeout=createTimeSpan(0,1,0,0) />

       //Define POP4 Component
        <cfset This.componentpaths["/pop"]= "/var/www/html/cfc/pop4" />

        <cffunction name="onRequest">
       <cfargument name="targetPage" type="String" required=true />

       <!--- Set default session.LoggedIn parameter as false --->
       <cfparam name="session.Loggedin" default=false />

       <!--- Set default datasource name --->
       <cfset datasource="hermes" />

       <!--- Authentication Session --->

<!--- GET CONSOLE HOST --->
<cfset consoleHost = StructKeyExists(cgi, "server_name") ? Trim(cgi.server_name) : "">
<cfif consoleHost EQ "" AND StructKeyExists(cgi, "http_host")>
<cfset consoleHost = REReplace(Trim(cgi.http_host), ":\d+$", "", "all")>
</cfif>
<cfif consoleHost EQ "" OR NOT REFind("^[A-Za-z0-9.-]+$", consoleHost)>
<cfset m="User Application.cfc: unable to determine a safe console host">
<cfinclude template="/user-auth/error.cfm">
<cfabort>
</cfif>


      <cfset reqData = GetHttpRequestData() />



       <cfset session.theUser = getHttpRequestData().headers["remote-user"]>

      <!--- CHECK FOR REMOTE-USER HEADER --->
      <cfif IsStruct( reqData ) AND StructKeyExists( reqData, "Headers" ) AND IsStruct( reqData.Headers ) AND StructKeyExists( reqData.Headers , "remote-user" ) AND StructKeyExists( reqData.Headers , "remote-email" ) AND StructKeyExists( reqData.Headers , "remote-name") AND StructKeyExists( reqData.Headers , "remote-groups" )>


       <cfset session.theUser = getHttpRequestData().headers["remote-user"]>
       <cfset session.email = getHttpRequestData().headers["remote-email"]>
        <cfset session.theName = getHttpRequestData().headers["remote-name"]>
        <cfset session.theGroups = getHttpRequestData().headers["remote-groups"]>

      <cfelse>

     <cfset m="User Application.cfc: remote-user and/or remote-email, remote-name heeaders do NOT exist">
     <cfinclude template="/user-auth/error.cfm">
     <cfabort>


     <!--- IsStruct( reqData ) AND StructKeyExists( reqData, "Headers" ) AND IsStruct( reqData.Headers ) AND StructKeyExists( reqData.Headers , "remote-user" ) --->
     </cfif>

     <!--- CHECK FOR COOKIE HEADER --->

     <cfif IsStruct( reqData ) AND StructKeyExists( reqData, "Headers" ) AND IsStruct( reqData.Headers ) AND StructKeyExists( reqData.Headers , "cookie" )>

     <cfset theCookie = getHttpRequestData().headers["cookie"]>

     <!--- DEBUG BELOW --->

     <!---
    <cfoutput>the cookie: #theCookie#<br>
the url: https://#ConsoleHost#</cfoutput>
    --->


         <cfhttp url="https://#ConsoleHost#/user-auth/google_sso_verify.cfm?target=users" method="GET" result="verifyResult" timeout="10" throwOnError="no">
         <cfhttpparam type="header" name="accept" value="*/*">
         <cfhttpparam type="header" name="Cookie" value="#theCookie#">
         </cfhttp>
         <cfset curlresult = Trim(verifyResult.fileContent)>

       <cfif #curlresult# is "Unauthorized">

       <cfset m="User Application.cfc: session is unauthorized">
       <cfinclude template="/user-auth/error.cfm">
       <cfabort>


<cfelse>

       <cfset session.loggedin = "true">

<cfif session.theGroups CONTAINS "admins" AND NOT (session.theGroups CONTAINS "relays" OR session.theGroups CONTAINS "mailboxes")>
  <cflocation url="/admin/" addtoken="no">
</cfif>


  <cfquery name="getid" datasource="hermes">
  select id from maddr where email='#session.email#'
  </cfquery>

<cfif #getid.recordcount# LT 1>
  <!--- No maddr entry yet (new mailbox user, no mail processed by Amavis).
       Set owner to 0 so portal loads with empty message history/filters. --->
  <cfset session.owner = 0>
<cfelse>
  <cfset session.owner = #getid.id#>
<!--- /CFIF #getid.recordcount# --->
</cfif>

  <cfquery name="getusersettings" datasource="hermes">
  select train_bayes, download_msg, secondary_email, secondary_email_verified
  from user_settings where email='#session.email#'
  </cfquery>

<cfif #getusersettings.recordcount# LT 1>

       <cfset m="User Application.cfc: Unable to get user settings ">
       <cfinclude template="/user-auth/error.cfm">
       <cfabort>
<cfelse>

 <cfset session.train_bayes = #getusersettings.train_bayes#>
  <cfset session.download_msg = #getusersettings.download_msg#>
  <cfset session.secondary_email = getusersettings.secondary_email>
  <cfset session.secondary_email_verified = getusersettings.secondary_email_verified>

  <!--- Auth type (local vs remote/SSO). Used to suppress the
       password-recovery-email nag for remote-auth users — their
       password lives in an external IdP, so a recovery email here
       would do nothing. Defaults to empty if no recipients row. --->
  <cfquery name="getauthtype" datasource="hermes">
  select auth_type from recipients where recipient = <cfqueryparam value="#session.email#" cfsqltype="cf_sql_varchar">
  </cfquery>
  <cfif IsStruct( reqData ) AND StructKeyExists( reqData, "Headers" ) AND IsStruct( reqData.Headers ) AND StructKeyExists( reqData.Headers , "x-hermes-auth-source" ) AND reqData.Headers["x-hermes-auth-source"] EQ "google_sso">
    <cfset session.auth_type = "remote">
  <cfelseif getauthtype.recordcount GTE 1>
    <cfset session.auth_type = getauthtype.auth_type>
  <cfelse>
    <cfset session.auth_type = "">
  </cfif>

<!--- /CFIF #getusersettings.recordcount# --->
</cfif>



     <!---
      <cfset session.theGroups = getHttpRequestData().headers["remote-groups"]>
      --->



       <!--- /CFIF  #curlresult# is "Unauthorized"  --->
       </cfif>


     <cfelse>

       <cfset m="User Application.cfc: cookie header does NOT exist">
       <cfinclude template="/user-auth/error.cfm">
       <cfabort>

    <!--- IsStruct( reqData ) AND StructKeyExists( reqData, "Headers" ) AND IsStruct( reqData.Headers ) AND StructKeyExists( reqData.Headers , "cookie" ) --->
        </cfif>





      <!--- Record login (first request of new session only; flag-gated inside) --->
      <cfinclude template="/admin/2/inc/record_login.cfm" />

      <cfinclude template="#Arguments.targetPage#" />
      <cfreturn />



       </cffunction>
</cfcomponent>
