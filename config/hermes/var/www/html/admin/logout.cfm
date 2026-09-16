<CFHEADER NAME="Expires" VALUE="Mon, 06 Jan 1990 00:00:01 GMT"> 
<CFHEADER NAME="Pragma" VALUE="no-cache"> 
<CFHEADER NAME="cache-control" VALUE="no-cache"> 
<!-- meta anti cache--> 
<META HTTP-EQUIV="Expires" CONTENT="Mon, 06 Jan 1990 00:00:01 GMT"> 
<META HTTP-EQUIV="Pragma" CONTENT="no-cache"> 
<META HTTP-EQUIV="Cache-Control" CONTENT="no-cache"> 
<!-- Kills the login session Variable --> 
<CFSET Session.Loggedin = FALSE> 
<!-- Kills the license session Variable --> 
<CFSET session.license = ""> 
<!-- Kills the edition session Variable --> 
<CFSET session.edition = ""> 
<cfinclude template="/user-auth/inc/google_sso_session.cfm">
<cfset googleSsoClearSession()>
<!--- Redirect to Authelia Logout --->

<!--- DETERMINE CONSOLE MODE --->
<cfquery name = "getconsolemode" datasource="hermes">
select parameter, value2 from parameters2 where parameter='console.mode'
</cfquery>
    
<cfif #getconsolemode.value2# is "ip">

<cfoutput>
<cflocation url="/logout?rd=https://#cgi.local_addr#/admin/" addtoken="no">
</cfoutput>

<cfelse>

<!--- DETERMINE CONSOLE HOST --->
<cfquery name = "getconsolehost" datasource="hermes">
select parameter, value2 from parameters2 where parameter='console.host'
</cfquery>

<cfoutput>
<cflocation url="/logout?rd=https://#getconsolehost.value2#/admin/" addtoken="no">
</cfoutput>

<!--- /CFIF GETSONSOLEMODE.VALUE --->
</cfif>
