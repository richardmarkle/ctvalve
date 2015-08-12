package com.centurylink.fsr.security.valve;

import java.io.IOException;
import java.net.URL;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.StringTokenizer;

import javax.security.auth.Subject;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.RequestDispatcher;

import org.apache.catalina.Realm;
import org.apache.catalina.Session;
import org.apache.catalina.Context;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.realm.GenericPrincipal;
import org.apache.catalina.valves.ValveBase;

public class ClearTrustCustomValve extends ValveBase {
	public Subject subject = new Subject();
	public Context context;
	public Session session;

	public void invoke(Request request, Response response) throws IOException,
			ServletException {
		System.out.println("Security Valve: invoke");

		session = request.getSessionInternal();
		String pathString = request.getRequestURI();
		if (!pathString.equals(null)) {
			StringTokenizer st = new StringTokenizer(pathString, "/");
			while (st.hasMoreElements()) {
				if (st.nextToken().equals("uf_logout")) {
					sendToLogoutPage(request, response);
					return;
				}
			}
		}

		Realm realm = request.getContext().getRealm();
		System.out.println("Realm: " + realm.toString());

		// Check if the user is currently logged in
		Principal p1 = request.getUserPrincipal();

		// If the user is not already logged in
		if (p1 == null) {

			// Get user and roles and set Principal
			String username = this.getUserName(request);
			List<String> groups = this.getRoles(request);

			if ((groups.contains("Rx_Flow_AuthorUsers"))
					|| ((groups.contains("Rxflow_AnalystUsers")))) {
				GenericPrincipal p = new GenericPrincipal(username,
						realm.toString(), groups);

				request.setUserPrincipal(p);

				subject.getPrincipals().add(p);

			} else {
				this.sendToNotAuthPage(request, response, session);
			}

		} else {
			// Just log and invoke next Valve
			System.out.println("Principal: " + p1);
			System.out.println("Security Valve: exit invoke");
		}
		// Invoke next valve
		//getNext().invoke(request, response);
	}

	public String getUserName(Request request) {
		System.out.println("Getting user name.");

		// Provide fake name so username will never be null
		// This should never show up in the output

		String name = "ct-remote-user-NOT_FOUND";

		String username = (String) request.getHeader("ct-remote-user");
		if (username != null) {
			name = username;
		}
		System.out.println(" returning username: " + name);
		return name;
	}

	public List<String> getRoles(Request request) {
		System.out.println("Getting Roles.");

		List<String> groups = new ArrayList<String>();
		String currentGroup;

		String groupString = (String) request.getHeader("x-ctallgroups");
		if (groupString != null) {

			StringTokenizer st = new StringTokenizer(groupString, ",");
			while (st.hasMoreElements()) {
				currentGroup = st.nextToken();
				System.out.println("Adding group: " + currentGroup);
				groups.add(currentGroup);
			}
		} else {
			groups.add("x-ctallgroups-NOTFOUND");
			System.out
					.println("Adding non-existent group x-ctallgroups-NOTFOUND");
		}
		System.out.println("Returning Groups");
		return groups;

	}

	/*
	 * private List<String> addFakeGroupNames() { ArrayList<String> fakeRoles =
	 * new ArrayList<String>(); String[] hardCodedRoles = { "RXFlow_admin",
	 * "RXFlow_developer", "RXFlow_analyst", "RXFlow_manager", "RXFlow_user" };
	 * int index = new Random().nextInt(5);
	 * fakeRoles.add(hardCodedRoles[index]); return fakeRoles; }
	 */

	protected void sendToNotAuthPage(Request request, Response response,
			Session session) throws IOException, ServletException {
		RequestDispatcher dispatch = request.getServletContext()
				.getRequestDispatcher("/not_authorized.jsp");
		if (dispatch == null)
			System.out.println("");
		else {
			System.out.println("Forwarding request to Not Authorized Page.");
			session.expire();
			try {
				dispatch.forward(request, response);
			} catch (Exception e) {
				dispatch.forward(request.getRequest(), response);
			}
		}
	}

	protected void sendToLogoutPage(
			org.apache.catalina.connector.Request request,
			org.apache.catalina.connector.Response response)
			throws IOException, ServletException {
		RequestDispatcher dispatch = request.getServletContext()
				.getRequestDispatcher("/logout.jsp");
		if (dispatch == null)
			System.out.println("Dispatch was null");
		else {
			System.out.println("Forwarding request to Logout Page.");
			//session.expire();
			try {
				dispatch.forward(request, response);
			} catch (Exception e) {
				dispatch.forward(request.getRequest(), response);
			}
		}
	}
}
