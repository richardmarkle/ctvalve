<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
<%@page import="java.security.*" %>
<%@page import="javax.security.auth.*" %>

<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<title>ClearTrust Authentication</title>
</head>
<body>
<h1>ClearTrust Authentication!</h1>

<pre>
<% Subject subject = Subject.getSubject(AccessController.getContext()); %> 


<b>Subject</b> = <%= subject %>

<b>RemoteUser</b> = <%= request.getRemoteUser() %>


<%
	out.print("Is user in role \"OffSite & Advisor\"?: ");
	if (request.isUserInRole("OffSite & Advisor")) {
		out.println("yes");
	} else {
		out.println("no");
	}
%> 

<b>Session Contents</b>
<% 
	java.util.Enumeration<String> atts = session.getAttributeNames();
	while (atts.hasMoreElements()) {
		String elem = (String)atts.nextElement();
		out.println(elem + " -> " + session.getAttribute(elem));
		out.println( );
	}
%>


</pre>

</body>
</html>