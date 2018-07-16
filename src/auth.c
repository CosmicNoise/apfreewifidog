/* vim: set et sw=4 ts=4 sts=4 : */
/********************************************************************\
 * This program is free software; you can redistribute it and/or    *
 * modify it under the terms of the GNU General Public License as   *
 * published by the Free Software Foundation; either version 2 of   *
 * the License, or (at your option) any later version.              *
 *                                                                  *
 * This program is distributed in the hope that it will be useful,  *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of   *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the    *
 * GNU General Public License for more details.                     *
 *                                                                  *
 * You should have received a copy of the GNU General Public License*
 * along with this program; if not, contact:                        *
 *                                                                  *
 * Free Software Foundation           Voice:  +1-617-542-5942       *
 * 59 Temple Place - Suite 330        Fax:    +1-617-542-2652       *
 * Boston, MA  02111-1307,  USA       gnu@gnu.org                   *
 *                                                                  *
\********************************************************************/

/* $Id$ */
/** @file auth.c
    @brief Authentication handling thread
    @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@miniguru.ca>
	@author Copyright (C) 2016 Dengfeng Liu <liudengfeng@kunteng.org>
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <syslog.h>

#include "httpd.h"

#include <json-c/json.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubus.h>

#include "http.h"
#include "safe.h"
#include "conf.h"
#include "debug.h"
#include "auth.h"
#include "centralserver.h"
#include "fw_iptables.h"
#include "firewall.h"
#include "client_list.h"
#include "util.h"
#include "wd_util.h"

/** Launches a thread that periodically checks if any of the connections has timed out
@param arg Must contain a pointer to a string containing the IP adress of the client to check to check
@todo Also pass MAC adress? 
@todo This thread loops infinitely, need a watchdog to verify that it is still running?
*/
void
thread_client_timeout_check(const void *arg)
{
    pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
    pthread_mutex_t cond_mutex = PTHREAD_MUTEX_INITIALIZER;
    struct timespec timeout;
    t_auth_serv *auth_server = get_auth_server();
    struct evhttps_request_context *context = NULL;

    if (auth_server->authserv_use_ssl) {
        context = evhttps_context_init();
        if (!context) {
            debug(LOG_ERR, "evhttps_context_init failed, process exit()");
            exit(0);
        }
    }

    while (1) {
        /* Sleep for config.checkinterval seconds... */
        timeout.tv_sec = time(NULL) + config_get_config()->checkinterval;
        timeout.tv_nsec = 0;

        /* Mutex must be locked for pthread_cond_timedwait... */
        pthread_mutex_lock(&cond_mutex);

        /* Thread safe "sleep" */
        pthread_cond_timedwait(&cond, &cond_mutex, &timeout);

        /* No longer needs to be locked */
        pthread_mutex_unlock(&cond_mutex);

        debug(LOG_DEBUG, "Running fw_counter()");

        if (auth_server->authserv_use_ssl) {
            evhttps_fw_sync_with_authserver(context);
            evhttps_update_trusted_mac_list_status(context);
        } else {
            fw_sync_with_authserver(); 
            update_trusted_mac_list_status();
        }  
    }

    if (auth_server->authserv_use_ssl) {
        evhttps_context_exit(context);
    }
}

void
evhttps_logout_client(void *ctx, t_client *client)
{
    struct evhttps_request_context *context = (struct evhttps_request_context *)ctx;
    const s_config *config = config_get_config();

    fw_deny(client);
    client_list_remove(client);

    if (config->auth_servers != NULL) {
        UNLOCK_CLIENT_LIST();
        char *uri = get_auth_uri(REQUEST_TYPE_LOGOUT, online_client, client);
        if (uri) {
            struct auth_response_client authresponse_client;
            memset(&authresponse_client, 0, sizeof(authresponse_client));
            authresponse_client.type = request_type_logout;
            evhttps_request(context, uri, 2, process_auth_server_response, &authresponse_client);
            free(uri);
        }
        LOCK_CLIENT_LIST();
    }

    client_free_node(client);
}

/**
 * @brief Logout a client and report to auth server.
 *
 * This function assumes it is being called with the client lock held! This
 * function remove the client from the client list and free its memory, so
 * client is no langer valid when this method returns.
 *
 * @param client Points to the client to be logged out
 */
void
logout_client(t_client * client)
{
    t_authresponse authresponse;
    const s_config *config = config_get_config();
    fw_deny(client);
	debug(LOG_DEBUG, "logout client");
    client_list_remove(client);

    /* Advertise the logout if we have an auth server */
    if (config->auth_servers != NULL) {
        UNLOCK_CLIENT_LIST();
        auth_server_request(&authresponse, REQUEST_TYPE_LOGOUT,
                            client->ip, client->mac, client->token,
                            client->counters.incoming, client->counters.outgoing, 
							client->counters.incoming_delta, client->counters.outgoing_delta,
							//>>> liudf added 20160112
							client->first_login, (client->counters.last_updated - client->first_login),
							client->name?client->name:"null", client->wired);
		close_auth_server();
        if (authresponse.authcode == AUTH_ERROR)
            debug(LOG_WARNING, "Auth server error when reporting logout");
        LOCK_CLIENT_LIST();
    }

    client_free_node(client);
}

/** Authenticates a single client against the central server and returns when done
 * Alters the firewall rules depending on what the auth server says
@param r httpd request struct
*/
void
authenticate_client(request * r)
{
    t_client *client, *tmp;
    t_authresponse auth_response; 
    char *urlFragment = NULL;

    LOCK_CLIENT_LIST();
    client = client_dup(client_list_find_by_ip(r->clientAddr));
    UNLOCK_CLIENT_LIST();

    if (client == NULL) {
        debug(LOG_ERR, "authenticate_client(): Could not find client for %s", r->clientAddr);
        return;
    }

    s_config    *config = config_get_config();
    t_auth_serv *auth_server = get_auth_server();

    if (auth_server->authserv_use_ssl) {
        struct evhttps_request_context *context = evhttps_context_init();
        if (!context) {
            client_list_destroy(client);
            return;
        }

        char *uri = get_auth_uri(REQUEST_TYPE_LOGIN, online_client, client);
        if (uri) {
            struct auth_response_client authresponse_client;
            memset(&authresponse_client, 0, sizeof(authresponse_client));
            authresponse_client.type    = request_type_login;
            authresponse_client.client  = client;
            authresponse_client.req     = r;
            evhttps_request(context, uri, 2, process_auth_server_response, &authresponse_client);
            free(uri);
        }

        evhttps_context_exit(context);
        return;
    }

    char *token = NULL;
    httpVar *var = NULL;
    /* Users could try to log in(so there is a valid token in
     * request) even after they have logged in, try to deal with
     * this */
    if ((var = httpdGetVariableByName(r, "token")) != NULL) {
        token = safe_strdup(var->value);
    } else {
        token = safe_strdup(client->token);
    }

	//<<<
    /* 
     * At this point we've released the lock while we do an HTTP request since it could
     * take multiple seconds to do and the gateway would effectively be frozen if we
     * kept the lock.
     */
    auth_server_request(&auth_response, REQUEST_TYPE_LOGIN, client->ip, client->mac, token, 0, 0, 0, 0, 0, 0, "null", client->wired);
	close_auth_server(); 
	
    /* Prepare some variables we'll need below */
    
    
    LOCK_CLIENT_LIST();
    /* can't trust the client to still exist after n seconds have passed */
    tmp = client_list_find_by_client(client);
    if (NULL == tmp) {
        debug(LOG_ERR, "authenticate_client(): Could not find client node for %s (%s)", client->ip, client->mac);
        UNLOCK_CLIENT_LIST();
        client_list_destroy(client);    /* Free the cloned client */
        free(token);
        return;
    }

    client_list_destroy(client);        /* Free the cloned client */
    client = tmp;
    if (strcmp(token, client->token) != 0) {
        /* If token changed, save it. */
        free(client->token);
        client->token = token;
    } else {
        free(token);
    }
    
	
    switch (auth_response.authcode) {

    case AUTH_ERROR:
		/* Error talking to central server */
        debug(LOG_ERR, "Got ERROR from central server authenticating token %s from %s at %s", client->token, client->ip,
              client->mac);
		client_list_delete(client);	
    	UNLOCK_CLIENT_LIST();
        
        send_http_page(r, "Error!", "Error: We did not get a valid answer from the central server");
        break;

    case AUTH_DENIED:
        /* Central server said invalid token */
        debug(LOG_INFO,
              "Got DENIED from central server authenticating token %s from %s at %s - deleting from firewall and redirecting them to denied message",
              client->token, client->ip, client->mac);
        fw_deny(client);
		client_list_delete(client);
    	UNLOCK_CLIENT_LIST();
        safe_asprintf(&urlFragment, "%smessage=%s",
                      auth_server->authserv_msg_script_path_fragment, GATEWAY_MESSAGE_DENIED);
        http_send_redirect_to_auth(r, urlFragment, "Redirect to denied message");
        free(urlFragment);
        break;

    case AUTH_VALIDATION:
        fw_allow(client, FW_MARK_PROBATION);
    	UNLOCK_CLIENT_LIST();
        /* They just got validated for X minutes to check their email */
        debug(LOG_INFO, "Got VALIDATION from central server authenticating token %s from %s at %s"
              "- adding to firewall and redirecting them to activate message", client->token, client->ip, client->mac);
        safe_asprintf(&urlFragment, "%smessage=%s",
                      auth_server->authserv_msg_script_path_fragment, GATEWAY_MESSAGE_ACTIVATE_ACCOUNT);
        http_send_redirect_to_auth(r, urlFragment, "Redirect to activate message");
        free(urlFragment);
        break;

    case AUTH_ALLOWED:
        fw_allow(client, FW_MARK_KNOWN);
        UNLOCK_CLIENT_LIST();
        /* Logged in successfully as a regular account */
        debug(LOG_INFO, "Got ALLOWED from central server authenticating token %s from %s at %s - "
              "adding to firewall and redirecting them to portal", client->token, client->ip, client->mac);
    	
		//>>> liudf added 20160112
		client->first_login = time(NULL);
		client->is_online = 1;
        {
            LOCK_OFFLINE_CLIENT_LIST();
            t_offline_client *o_client = offline_client_list_find_by_mac(client->mac);    
            if(o_client) {
				debug(LOG_DEBUG, "delete client(%s) from offline client list", client->mac);
                offline_client_list_delete(o_client);
			}
            UNLOCK_OFFLINE_CLIENT_LIST();
        }
		
		//<<< liudf added end
        served_this_session++;
		if(httpdGetVariableByName(r, "type")) {
        	send_http_page_direct(r, "<htm><body>weixin auth success!</body><html>");
		} else {
			if(config->origin) {
				safe_asprintf(&urlFragment, "%sgw_id=%s&channel_path=%s&mac=%s&name=%s", 
					auth_server->authserv_portal_script_path_fragment, 
					config->gw_id,
					g_channel_path?g_channel_path:"null",
					client->mac?client->mac:"null",
					client->name?client->name:"null");
        		http_send_redirect_to_auth(r, urlFragment, "Redirect to portal");
        		free(urlFragment);
			}
			else {
				send_http_page_direct(r, "<htm><body>Auth success!</body><html>");
			}
		}
        break;

    case AUTH_VALIDATION_FAILED:
		/* Client had X minutes to validate account by email and didn't = too late */
        debug(LOG_INFO, "Got VALIDATION_FAILED from central server authenticating token %s from %s at %s "
              "- redirecting them to failed_validation message", client->token, client->ip, client->mac);
		client_list_delete(client);
    	UNLOCK_CLIENT_LIST();
        
        safe_asprintf(&urlFragment, "%smessage=%s",
                      auth_server->authserv_msg_script_path_fragment, GATEWAY_MESSAGE_ACCOUNT_VALIDATION_FAILED);
        http_send_redirect_to_auth(r, urlFragment, "Redirect to failed validation message");
        free(urlFragment);
        break;

    default:
		debug(LOG_WARNING,
              "I don't know what the validation code %d means for token %s from %s at %s - sending error message",
              auth_response.authcode, client->token, client->ip, client->mac);
		client_list_delete(client);	
    	UNLOCK_CLIENT_LIST();
        
        send_http_page_direct(r, "<htm><body>Internal Error, We can not validate your request at this time</body></html>");
        break;

    }

    return;
}
char *sitelist;

size_t auth_request_frame(char **buf, const char *ip, const char *mac)
{
	json_object *jso;
	json_object *get;
	json_object *ret;

	jso = json_object_new_object();
	get = json_object_new_object();
	ret = json_object_new_object();
	if (!jso || !get || !ret){
		debug(LOG_ERR, "alloc json object failed");
		*buf = NULL;
		return 0;
	}

	json_object_object_add(jso, "devmac", json_object_new_string(mac));
//	json_object_object_add(jso, "lasttime", json_object_new_int64(time(NULL)));
	json_object_object_add(get, "getqiyedevwl", jso);
	json_object_object_add(ret, "get", get);

	*buf = safe_strdup(json_object_to_json_string(ret));

	json_object_put(jso);
	json_object_put(get);
	json_object_put(ret);
	
	debug(LOG_DEBUG, "auth:%s", *buf);

	return strlen(*buf);
}

size_t ac_request_frame(char **buf)
{
	json_object *jso;
	json_object *get;
	json_object *content;

	jso = json_object_new_object();
	get = json_object_new_object();
	content = json_object_new_object();
	if(!jso || !get || !content){
		debug(LOG_ERR, "alloc json object failed");
		*buf = NULL;
		return 0;
	}
	json_object_object_add(content, "lasttime", json_object_new_int64(time(NULL)));
	json_object_object_add(get, "getqiyesitewbl", content);
	json_object_object_add(jso, "get", get);
	
	*buf = safe_strdup(json_object_to_json_string(jso));

	debug(LOG_DEBUG, "access control request:%s", *buf);
	json_object_put(get);
	json_object_put(jso);
	json_object_put(content);

	return strlen(*buf);
}

size_t sync_request_frame(char **buf)
{	
	json_object *jso = NULL;
	json_object *devlist = NULL;
	json_object *submit = NULL;
	json_object *iface = NULL;
	char *ifn = config_get_config()->external_interface;
	char *path;
	
	if (!client_get_first_client())	{
		debug(LOG_DEBUG, "No client");
		*buf = NULL;
		return 0;
	}
	jso = json_object_new_object();
	submit = json_object_new_object();
	devlist = json_object_new_array();
	if(ifn){
		iface = json_object_new_object();
	}
	if (!jso || !submit || !devlist){
		debug(LOG_ERR, "alloc json object failed");
		*buf = NULL;
		return 0;
	}
	LOCK_CLIENT_LIST();
	client_for_each(c){
		if(!c->ip || (!c->counters.outgoing && !c->counters.incoming)){
			continue;
		}
		json_object *a = json_object_new_object();
		json_object_object_add(a, "clientmac", json_object_new_string(c->mac));
		json_object_object_add(a, "up", json_object_new_int64(c->counters.outgoing));
		json_object_object_add(a, "down", json_object_new_int64(c->counters.incoming));
		json_object_array_add(devlist, a);
	}
	UNLOCK_CLIENT_LIST();
	if(ifn){
		debug(LOG_DEBUG, "add extern interface %s flow", ifn);
		safe_asprintf(&path, "/sys/class/net/%s/statistics/tx_bytes", ifn);
		debug(LOG_ERR, "path:%s", path);
		if(!access(path, R_OK)){
			FILE *fp;
			unsigned long long tx;
			fp = fopen(path, "r");
			if (fp){
				if(fscanf(fp, "%llu", &tx) == 1){
					json_object_object_add(iface, "up", json_object_new_int64(tx));
				}
				fclose(fp);
			}
		}
		free(path);
		safe_asprintf(&path, "/sys/class/net/%s/statistics/rx_bytes", ifn);
		debug(LOG_ERR, "path:%s", path);
		if(!access(path, R_OK)){
			FILE *fp;
			unsigned long long rx;
			fp = fopen(path, "r");
			if (fp){
				if(fscanf(fp, "%llu", &rx) == 1){
					json_object_object_add(iface, "down", json_object_new_int64(rx));
				}
				fclose(fp);
			}
		}
		free(path);
		json_object_object_add(jso, "setrouterdf", iface);
	}

	json_object_object_add(jso, "setdevdf", devlist);
	json_object_object_add(submit, "submit", jso);

	*buf = safe_strdup(json_object_to_json_string(submit));	
	
	json_object_put(jso);
	json_object_put(devlist);
	json_object_put(submit);
	if(iface){
		json_object_put(iface);
	}

	debug(LOG_DEBUG, "SYNC:%s", *buf);

	return strlen(*buf);
}

static void tc_data_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	debug(LOG_DEBUG, "tc rules callback function");
}

static int _ubus_tc(const char *format, ...)
{
	va_list vlist;
	char *cmd;
	int rc;

	va_start(vlist, format);
	safe_vasprintf(&cmd, format, vlist);
	va_end(vlist);

	debug(LOG_DEBUG, "execute:%s", cmd);

	rc = execute(cmd, 1);
	if (rc!=0) {
		debug(LOG_ERR, "tc command failed(%d): %s", rc, cmd); 
	}

	free(cmd);

	return rc; 
}


static void _blob_buf_free(struct blob_buf *buf)
{
	free(buf->buf);
	buf->buf = NULL;
	buf->buflen = 0;
}


void ubus_tc(const char *ip, const char *mac, const char *tx, const char *rx, int flag)
{
	/* must initial buf */
	struct blob_buf buf = {};
	int ret;
	int count;

	/*
	struct ubus_context *ctx;
	uint32_t id;
	ctx = ubus_connect(NULL);
	debug(LOG_DEBUG, "invoke ubus to add tc rule");
	if (!ctx){
		debug(LOG_ERR, "connect to ubus error");
		return;
	}
	else {
		debug(LOG_DEBUG, "connect to ubus success");
	}

	ubus_add_uloop(ctx);
	ret = ubus_lookup_id(ctx, "tc", &id);
	debug(LOG_DEBUG, "ubus lookup id");
	if(ret){
		debug(LOG_ERR, "tc maybe disable");
		ubus_free(ctx);
		return;
	}
	else {
		debug(LOG_DEBUG, "ubus lookup id return :%d", ret);
	}
	*/

	blobmsg_buf_init(&buf);
	if(mac){
		blobmsg_add_string(&buf, "name", mac);
	}
	else {
		debug(LOG_ERR, "tc parameter invalid");
		return;
	}
	if(!ip){
		blobmsg_add_string(&buf, "mac", mac);
	}
	else {
		blobmsg_add_string(&buf, "ip", ip);
	}
	if(tx){
		blobmsg_add_string(&buf, "upload", tx);
	}
	if(rx){
		blobmsg_add_string(&buf, "download", rx);
	}
	debug(LOG_DEBUG, "tc parameter:%s", blobmsg_format_json(buf.head, true));

	/*
	debug(LOG_DEBUG, "ubus_invoke");	
	if(flag) {
		ret = ubus_invoke(ctx, id, "tc_add", buf.head, tc_data_cb, NULL, 3000);
	}
	else {
		ret = ubus_invoke(ctx, id, "tc_del", buf.head, tc_data_cb, NULL, 3000);
	}
	debug(LOG_DEBUG, "invoke ubus done return :%d", ret);
	*/

	/* olny reinvoked tc when add user rule failed */
	/* make sure not to be dead lock */
	ret = _ubus_tc("ubus call tc %s '%s'", flag ? "tc_add" : "tc_del", blobmsg_format_json(buf.head, true));
	count = 10;
	while(flag && count && ret == 1){
		ret = _ubus_tc("ubus call tc %s '%s'", flag ? "tc_add" : "tc_del", blobmsg_format_json(buf.head, true));
		sleep(5);	
		count--;
	}
	debug(LOG_DEBUG, "invoke ubus done return :%d", ret);
	_blob_buf_free(&buf);
	//ubus_free(ctx);	
	debug(LOG_DEBUG, "add tc fule done");
}

t_authcode _authenticate(json_object *obj, const char *ip, const char *mac)
{
	t_authcode ret = AUTH_DENIED;
	t_client *client;
	int tc_flag = 0;
	char tx[1024];
	char rx[1024];

	if (!mac){
		debug(LOG_INFO, "Invalid client MAC");	
		return AUTH_ERROR;
	}


	json_object_object_foreach(obj, key, val){
		debug(LOG_DEBUG, "value:%s, mac:%s strcmp:%d", json_object_get_string(val), mac, strcmp(json_object_get_string(val), mac));
		if(!strcmp(key, "devmac") && !strcmp(json_object_get_string(val), mac)){
			debug(LOG_DEBUG, "allow client(%s)", mac);
			/* auth allowed */		
			ret = AUTH_ALLOWED;
		}
		if(!strcmp(key, "uplimit")){
			/* tx */	
			strcpy(tx, json_object_get_string(val));
			strcat(tx, "bit");
			tc_flag = 1;
		}
		if(!strcmp(key, "downlimit")){
			/* rx */
			strcpy(rx, json_object_get_string(val));
			strcat(rx, "bit");
			tc_flag = 1;
		}
		if(!strcmp(key, "devtype")){
			/* device type */
			debug(LOG_DEBUG, "Client using %s", json_object_get_int(val) ? "phone" : "computer");
		}
	}
	
	if(AUTH_ALLOWED == ret && tc_flag){
		LOCK_CLIENT_LIST();
		client = client_list_find_by_mac(mac);
		if(client){
			client->rx = safe_strdup(rx);
			client->tx = safe_strdup(tx);
			debug(LOG_DEBUG, "Add Client(%s): tx:%s rx:%s", mac, client->tx, client->rx);
		}
		UNLOCK_CLIENT_LIST();
		ubus_tc(ip, mac, tx, rx, 1);
	}
	/*
	else if (AUTH_DUPLICATE == ret && tc_flag){
		LOCK_CLIENT_LIST();
		client = client_list_find_by_mac(mac);
		if(client && client->tx && client->rx){
			if(strcmp(client->rx, rx) && strcmp(client->tx, tx)){
				free(client->rx);
				free(client->tx);
				client->rx = safe_strdup(rx);
				client->tx = safe_strdup(tx);
				debug(LOG_DEBUG, "Update Client(%s): tx:%s rx:%s", client->mac, client->tx, client->rx);
			}	
			else {
				tc_flag = 0;
			}
		}
		UNLOCK_CLIENT_LIST();
		if(tc_flag){
			ubus_tc(ip, mac, tx, rx, 1);
		}
	}
	*/
	else if(AUTH_DENIED == ret) {
		LOCK_CLIENT_LIST();
		client = client_list_find_by_mac(mac);
		if(client) {
			debug(LOG_DEBUG, "Delete client(%s)", client->mac);
			client_list_delete(client);
		}
		UNLOCK_CLIENT_LIST();
		ubus_tc(ip, mac, tx, rx, 0);
	}
	return ret;
}

t_authcode authenticate(json_object *obj, const char *ip, const char *mac)
{
	json_object *jso;

	if(json_object_is_type(obj, json_type_array)){
		int idx = 0;	
		do {
			jso = json_object_array_get_idx(obj, idx);
			if(jso && json_object_is_type(jso, json_type_object)){
				/* only authenticate one client */
				return _authenticate(jso, ip, mac);
			}
			idx++;
		}while(jso);
	}
	else if (json_object_is_type(obj, json_type_object)){
		return 	_authenticate(obj, ip, mac);
	}

	return AUTH_ERROR;	
}

static void _accesscontrol(const char *site, int flag)
{
	char *str;
	if (!site){
		debug(LOG_ERR, "web site is NULL");
		if(!flag){
		//	fw_ac(FW_ACCESS_DENY, NULL);
			iptables_fw_accesscontrol(FW_ACCESS_DENY, NULL);
		}
		return;
	}
	str = strcasestr(site, "www.");
	if(str){
		debug(LOG_DEBUG, "block site:%s", str + 4);
//		fw_ac(FW_ACCESS_ALLOW, str + 4);
		iptables_fw_accesscontrol(FW_ACCESS_ALLOW, str + 4);
	}
	else if(strlen(site) > 1){
//		fw_ac(FW_ACCESS_ALLOW, site);
		iptables_fw_accesscontrol(FW_ACCESS_ALLOW, site);
	}

	return;
}

size_t accesscontrol(json_object *obj, const char *ip, const char *mac)
{
#if 1
	json_object *jso;
	if(sitelist == NULL){
		debug(LOG_DEBUG, "init sitelist");
		safe_asprintf(&sitelist, "%s", json_object_to_json_string(obj));
		debug(LOG_DEBUG, "sitelist:%s", sitelist);
	}
	else if(!strcmp(sitelist, json_object_to_json_string(obj))) {
		debug(LOG_DEBUG, "No changes");
		return 0;	
	}
	else {
		/* flush access control firewall rules */
	//	fw_ac(FW_ACCESS_DENY, NULL);
		iptables_fw_accesscontrol(FW_ACCESS_DENY, NULL);
		/* update sitelist */
		debug(LOG_DEBUG, "Update sitelist");
		free(sitelist);
		safe_asprintf(&sitelist, "%s", json_object_to_json_string(obj));
		debug(LOG_DEBUG, "sitelist:%s", sitelist);
	}
	if(json_object_is_type(obj, json_type_array)){
		int idx = 0;	
		do {
			jso = json_object_array_get_idx(obj, idx);
			if(jso){
				json_object_object_foreach(jso, key, val){
					if(!strcmp(key, "dn")){
						/* web site */		
						debug(LOG_DEBUG, "block :%s", json_object_get_string(val));
						_accesscontrol(json_object_get_string(val), 1);
					}
					else {
						debug(LOG_DEBUG, "delete site block rule");
						_accesscontrol(NULL, 0);
					}
				}
			}
			idx++;
		}while(jso);
	}
	else if (json_object_is_type(obj, json_type_object)){
		json_object_object_foreach(jso, key, val){
			if(!strcmp(key, "dn")){
				/* web site */
				debug(LOG_DEBUG, "block :%s", json_object_get_string(val));
				_accesscontrol(json_object_get_string(val), 1);
			}
			else {
				debug(LOG_DEBUG, "delete site block rule");
				_accesscontrol(NULL, 0);
			}
		}
	}
#endif
	return 0;
}

size_t synchronize(json_object *obj, const char *ip, const char *mac)
{
	json_object *jso;
	if(json_object_is_type(obj, json_type_array)){
		int idx = 0;	
		do {
			jso = json_object_array_get_idx(obj, idx);
			if(jso){
				json_object_object_foreach(jso, key, val){
					if(!strcmp(json_object_get_string(val), "true")){
						debug(LOG_DEBUG, "client(%s) counter update success", key);	
					}
					else if(!strcmp(json_object_get_string(val), "false")){
						debug(LOG_DEBUG, "client(%s) has been forbidden");
					}
				}
			}
			idx++;
		}while(jso);
	}
	else if (json_object_is_type(obj, json_type_object)){
		json_object_object_foreach(obj, key, val){
			if(!strcmp(json_object_get_string(val), "true")){
				debug(LOG_DEBUG, "client(%s) counter update success", key);	
			}
			else if(!strcmp(json_object_get_string(val), "false")){
				debug(LOG_DEBUG, "client(%s) has been forbidden");
			}
		}
	}
	return 0;
}

static void _trafficcontrol(json_object *obj)
{
	char tx[1024];
	char rx[1024];
	char m[18] = {'\0'};
	int tc_flag = 0;
	int update = 0;
	t_client *client;

	json_object_object_foreach(obj, key, val){
		if(!strcmp(key, "devmac")){
			strcpy(m, json_object_get_string(val));
			/* auth allowed */		
		}
		if(!strcmp(key, "uplimit")){
			/* tx */	
			strcpy(tx, json_object_get_string(val));
			strcat(tx, "bit");
			tc_flag = 1;
		}
		if(!strcmp(key, "downlimit")){
			/* rx */
			strcpy(rx, json_object_get_string(val));
			strcat(rx, "bit");
			tc_flag = 1;
		}
		if(!strcmp(key, "devtype")){
			/* device type */
			debug(LOG_DEBUG, "Client using %s", json_object_get_int(val) ? "phone" : "computer");
		}
	}

	if(tc_flag && strlen(m)){
		debug(LOG_DEBUG, "client:%s tx:%s rx:%s", m, tx, rx);
		LOCK_CLIENT_LIST();
		client = client_list_find_by_mac(m);
		if(client){
			if(client->tx && client->rx){
				/* update */
				if(strcmp(client->rx, rx) && strcmp(client->tx, tx)){
					free(client->rx);
					free(client->tx);
					client->rx = safe_strdup(rx);
					client->tx = safe_strdup(tx);
					debug(LOG_DEBUG, "Update Client(%s): tx:%s rx:%s", client->mac, client->tx, client->rx);
					update = 1;
				}
				else {
					update = 0;	
				}
			}	
			else {
				/* add */
				client->rx = safe_strdup(rx);
				client->tx = safe_strdup(tx);
				update = 1;
			}
		}
		UNLOCK_CLIENT_LIST();
		if(update) {
			ubus_tc(NULL, m, tx, rx, 1);
		}
	}

}

size_t trafficcontrol(json_object *obj, const char *ip, const char *mac)
{
	json_object *jso;

	if(json_object_is_type(obj, json_type_array)){
		int idx = 0;	
		do {
			jso = json_object_array_get_idx(obj, idx);
			if(jso){
				_trafficcontrol(jso);
			}
			idx++;
		}while(jso);
	}
	else if (json_object_is_type(obj, json_type_object)){
		_trafficcontrol(obj);
	}

	return 0;	
}

 t_authcode auth(const char *ip, const char *mac, const char *response)
{
	json_object *res; 
	json_object *jso;
	json_object *c;
	t_authcode ret = AUTH_DENIED;

	if(!response){
		debug(LOG_INFO, "nothing to parse");
 		return AUTH_ERROR;
	}
	debug(LOG_DEBUG, "string to parse:%s", response);

	res = json_tokener_parse(response);
	if (!res){
		debug(LOG_DEBUG, "response is invalide  json format string:\n:%s\n", response);
		return AUTH_ERROR;
	}

	if(json_object_object_get_ex(res, "get", &jso)){
		if(json_object_object_get_ex(jso, "devwl", &c)){
			ret = authenticate(c, ip, mac);	
		}
		else {
			debug(LOG_DEBUG, "deny client(%s)", mac);
			t_client *client;
			int invoke_tc = 0;
			LOCK_CLIENT_LIST();
			client = client_list_find_by_mac(mac);
			if(client) {
				invoke_tc = 1;
			}
			UNLOCK_CLIENT_LIST();
			if(invoke_tc){
				ubus_tc(ip, mac, NULL, NULL, 0);
			}
			ret = AUTH_DENIED;
		}
		if(json_object_object_get_ex(jso, "sitebl", &c)){
			debug(LOG_DEBUG, "block site action");
			accesscontrol(c, ip, mac);
		}
	}
	
	if(json_object_object_get_ex(res, "submit", &jso)){
		if(json_object_object_get_ex(jso, "setdevdf", &c)){
			debug(LOG_DEBUG, "count response action");
			synchronize(c, ip, mac);
		}
		if(json_object_object_get_ex(jso, "setdevlimit", &c)){
			debug(LOG_DEBUG, "tc action");
			trafficcontrol(c, ip, mac);
		}
		if(json_object_object_get_ex(jso, "setrouterdf", &c)){
			debug(LOG_DEBUG, "wan flow data");
			//
		}
	}

	json_object_put(res);

	debug(LOG_DEBUG, "return :%d", ret);
	return ret;
}
