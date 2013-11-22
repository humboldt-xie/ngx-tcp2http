/*
 * =====================================================================================
 *
 *       Filename:  ngx_tcp2http_session.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  11/22/2013 12:09:48 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *        Company:  
 *
 * =====================================================================================
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_probe.h>

ngx_http_request_t *
ngx_http_create_request(ngx_connection_t *c);

void
ngx_http_process_request(ngx_http_request_t *r);

void
ngx_http_free_request(ngx_http_request_t *r, ngx_int_t rc);

void
ngx_http_close_connection(ngx_connection_t *c);

static void
ngx_tcp2http_close_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_connection_t  *c;

    r = r->main;
    c = r->connection;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http request count:%d blk:%d", r->count, r->blocked);

    if (r->count == 0) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "http request count is zero");
    }

    r->count--;

    if (r->count || r->blocked) {
        return;
    }

#if (NGX_HTTP_SPDY)
    if (r->spdy_stream) {
        ngx_http_spdy_close_stream(r->spdy_stream, rc);
        return;
    }
#endif

    ngx_http_free_request(r, rc);
    ngx_http_close_connection(c);
}

ngx_int_t
ngx_http_process_request_uri(ngx_http_request_t *r);
static ngx_int_t
ngx_http_find_virtual_server(ngx_connection_t *c,
    ngx_http_virtual_names_t *virtual_names, ngx_str_t *host,
    ngx_http_request_t *r, ngx_http_core_srv_conf_t **cscfp)
{
    ngx_http_core_srv_conf_t  *cscf;

    if (virtual_names == NULL) {
        return NGX_DECLINED;
    }

    cscf = ngx_hash_find_combined(&virtual_names->names,
                                  ngx_hash_key(host->data, host->len),
                                  host->data, host->len);

    if (cscf) {
        *cscfp = cscf;
        return NGX_OK;
    }

#if (NGX_PCRE)

    if (host->len && virtual_names->nregex) {
        ngx_int_t                n;
        ngx_uint_t               i;
        ngx_http_server_name_t  *sn;

        sn = virtual_names->regex;

#if (NGX_HTTP_SSL && defined SSL_CTRL_SET_TLSEXT_HOSTNAME)

        if (r == NULL) {
            ngx_http_connection_t  *hc;

            for (i = 0; i < virtual_names->nregex; i++) {

                n = ngx_regex_exec(sn[i].regex->regex, host, NULL, 0);

                if (n == NGX_REGEX_NO_MATCHED) {
                    continue;
                }

                if (n >= 0) {
                    hc = c->data;
                    hc->ssl_servername_regex = sn[i].regex;

                    *cscfp = sn[i].server;
                    return NGX_OK;
                }

                ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                              ngx_regex_exec_n " failed: %i "
                              "on \"%V\" using \"%V\"",
                              n, host, &sn[i].regex->name);

                return NGX_ERROR;
            }

            return NGX_DECLINED;
        }

#endif /* NGX_HTTP_SSL && defined SSL_CTRL_SET_TLSEXT_HOSTNAME */

        for (i = 0; i < virtual_names->nregex; i++) {

            n = ngx_http_regex_exec(r, sn[i].regex, host);

            if (n == NGX_DECLINED) {
                continue;
            }

            if (n == NGX_OK) {
                *cscfp = sn[i].server;
                return NGX_OK;
            }

            return NGX_ERROR;
        }
    }

#endif /* NGX_PCRE */

    return NGX_DECLINED;
}

static ngx_int_t
ngx_http_validate_host(ngx_str_t *host, ngx_pool_t *pool, ngx_uint_t alloc)
{
    u_char  *h, ch;
    size_t   i, dot_pos, host_len;

    enum {
        sw_usual = 0,
        sw_literal,
        sw_rest
    } state;

    dot_pos = host->len;
    host_len = host->len;

    h = host->data;

    state = sw_usual;

    for (i = 0; i < host->len; i++) {
        ch = h[i];

        switch (ch) {

        case '.':
            if (dot_pos == i - 1) {
                return NGX_DECLINED;
            }
            dot_pos = i;
            break;

        case ':':
            if (state == sw_usual) {
                host_len = i;
                state = sw_rest;
            }
            break;

        case '[':
            if (i == 0) {
                state = sw_literal;
            }
            break;

        case ']':
            if (state == sw_literal) {
                host_len = i + 1;
                state = sw_rest;
            }
            break;

        case '\0':
            return NGX_DECLINED;

        default:

            if (ngx_path_separator(ch)) {
                return NGX_DECLINED;
            }

            if (ch >= 'A' && ch <= 'Z') {
                alloc = 1;
            }

            break;
        }
    }

    if (dot_pos == host_len - 1) {
        host_len--;
    }

    if (host_len == 0) {
        return NGX_DECLINED;
    }

    if (alloc) {
        host->data = ngx_pnalloc(pool, host_len);
        if (host->data == NULL) {
            return NGX_ERROR;
        }

        ngx_strlow(host->data, h, host_len);
    }

    host->len = host_len;

    return NGX_OK;
}

static ngx_int_t
ngx_http_set_virtual_server(ngx_http_request_t *r, ngx_str_t *host)
{
    ngx_int_t                  rc;
    ngx_http_connection_t     *hc;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_http_core_srv_conf_t  *cscf = NULL;

    hc = r->http_connection;

#if (NGX_HTTP_SSL && defined SSL_CTRL_SET_TLSEXT_HOSTNAME)

    if (hc->ssl_servername) {
        if (hc->ssl_servername->len == host->len
            && ngx_strncmp(hc->ssl_servername->data,
                           host->data, host->len) == 0)
        {
#if (NGX_PCRE)
            if (hc->ssl_servername_regex
                && ngx_http_regex_exec(r, hc->ssl_servername_regex,
                                          hc->ssl_servername) != NGX_OK)
            {
                ngx_tcp2http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                return NGX_ERROR;
            }
#endif
            return NGX_OK;
        }
    }

#endif

    rc = ngx_http_find_virtual_server(r->connection,
                                      hc->addr_conf->virtual_names,
                                      host, r, &cscf);

    if (rc == NGX_ERROR) {
        ngx_tcp2http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_ERROR;
    }

#if (NGX_HTTP_SSL && defined SSL_CTRL_SET_TLSEXT_HOSTNAME)

    if (hc->ssl_servername) {
        ngx_http_ssl_srv_conf_t  *sscf;

        if (rc == NGX_DECLINED) {
            cscf = hc->addr_conf->default_server;
            rc = NGX_OK;
        }

        sscf = ngx_http_get_module_srv_conf(cscf->ctx, ngx_http_ssl_module);

        if (sscf->verify) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "client attempted to request the server name "
                          "different from that one was negotiated");
            ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
            return NGX_ERROR;
        }
    }

#endif

    if (rc == NGX_DECLINED) {
        return NGX_OK;
    }

    r->srv_conf = cscf->ctx->srv_conf;
    r->loc_conf = cscf->ctx->loc_conf;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    ngx_http_set_connection_log(r->connection, clcf->error_log);

    return NGX_OK;
}
void
ngx_tcp2http_empty_handler(ngx_event_t *wev)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, wev->log, 0, "tcp2http empty handler");

    return;
}

static u_char *
ngx_tcp2http_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char              *p;
    ngx_http_request_t  *r;
    ngx_http_log_ctx_t  *ctx;

    if (log->action) {
        p = ngx_snprintf(buf, len, " while %s", log->action);
        len -= p - buf;
        buf = p;
    }

    ctx = log->data;

    p = ngx_snprintf(buf, len, ", client: %V", &ctx->connection->addr_text);
    len -= p - buf;

    r = ctx->request;

    if (r) {
        return r->log_handler(r, ctx->current_request, p, len);

    } else {
        p = ngx_snprintf(p, len, ", server: %V",
                         &ctx->connection->listening->addr_text);
    }

    return p;
}




void 
ngx_tcp2http_finalize_session(ngx_http_request_t *r)
{
    ngx_connection_t *c;
    ngx_http_cleanup_t *cln;

    c = r->connection;

    //ngx_tcp_log_handler(s);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "close tcp session: %d", c->fd);

    for (cln = r->cleanup; cln; cln = cln->next) {
        if (cln->handler) {
            cln->handler(cln->data);
            cln->handler = NULL;
        }
    }

	ngx_tcp2http_close_request(r, 0);

    return;
}

static void
ngx_tcp2http_session_handler(ngx_event_t *ev)
{
    ngx_connection_t    *c;
    ngx_http_request_t   *r;
    ngx_http_log_ctx_t  *ctx;

    c = ev->data;
    r = c->data;

    ctx = c->log->data;
    ctx->current_request = r;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "tcp2http run request: \"%V?%V\"", &r->uri, &r->args);

    if (ev->write) {
        r->write_event_handler(r);
    } else {
        r->read_event_handler(r);
    }
}

void
ngx_tcp2http_block_reading(ngx_http_request_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http reading blocked");

    /* aio does not call this handler */

    if ((ngx_event_flags & NGX_USE_LEVEL_EVENT)
        && r->connection->read->active)
    {
        if (ngx_del_event(r->connection->read, NGX_READ_EVENT, 0) != NGX_OK) {
            ngx_tcp2http_close_request(r, 0);
        }
    }
}

/*=wait_request*/
static void
ngx_tcp2http_process_session(ngx_event_t *rev)
{
    ssize_t              n;
    ngx_int_t            rc, rv;
    ngx_str_t            host;
    ngx_connection_t          *c;
    ngx_http_request_t  *r;
    ngx_http_core_srv_conf_t   *cscf;


    c = rev->data;
    r = c->data;

    cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

	ngx_log_error(NGX_LOG_DEBUG, c->log, 0,
			"http request line: \"%V\"", &r->request_line);

    rc = NGX_AGAIN;
	char * request="GET /\r\n\r\n";
	sprintf(r->header_in->last,request);
    r->header_in->last += ngx_strlen(request);

	rc = ngx_http_parse_request_line(r, r->header_in);

	if (rc == NGX_OK) {

		/* the request line has been parsed successfully */

		r->request_line.len = r->request_end - r->request_start;
		r->request_line.data = r->request_start;
		r->request_length = r->header_in->pos - r->request_start;

		ngx_http_probe_read_req_line_done(r);

		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
				"http request line: \"%V\"", &r->request_line);

		r->method_name.len = r->method_end - r->request_start + 1;
		r->method_name.data = r->request_line.data;

		if (r->http_protocol.data) {
			r->http_protocol.len = r->request_end - r->http_protocol.data;
		}

		if (ngx_http_process_request_uri(r) != NGX_OK) {
			return;
		}

		if (r->host_start && r->host_end) {

			host.len = r->host_end - r->host_start;
			host.data = r->host_start;

			rc = ngx_http_validate_host(&host, r->pool, 0);

			if (rc == NGX_DECLINED) {
				ngx_log_error(NGX_LOG_INFO, c->log, 0,
						"client sent invalid host in request line");
				ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
				return;
			}

			if (rc == NGX_ERROR) {
				ngx_tcp2http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
				return;
			}

			if (ngx_http_set_virtual_server(r, &host) == NGX_ERROR) {
				return;
			}

			r->headers_in.server = host;
		}

		if (r->http_version < NGX_HTTP_VERSION_10) {

			if (r->headers_in.server.len == 0
					&& ngx_http_set_virtual_server(r, &r->headers_in.server)
					== NGX_ERROR)
			{
				return;
			}

			ngx_http_process_request(r);
			return;
		}


		if (ngx_list_init(&r->headers_in.headers, r->pool, 20,
					sizeof(ngx_table_elt_t))
				!= NGX_OK)
		{
			ngx_tcp2http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
			return;
		}

		c->log->action = "reading client request headers";

		/*rev->handler = ngx_http_process_request_headers;
		ngx_http_process_request_headers(rev);*/

		return;
	}else{
		ngx_tcp2http_close_request(r, NGX_HTTP_REQUEST_TIME_OUT);
	}

	/*ngx_http_process_request(r);*/
    /* process the ACL */
    /*if (ngx_tcp_access_handler(s) == NGX_ERROR) {
        ngx_tcp2http_finalize_session(s);
        return;
    }*/

/*    if (cscf->protocol == NULL || cscf->protocol->init_session == NULL) {
        dd("protocol not initialized");
        ngx_tcp2http_finalize_session(s);
        return;
    }

    c->read->handler= ngx_tcp2http_session_handler;
    c->write->handler= ngx_tcp2http_session_handler;
    r->read_event_handler = tcp2http_block_reading;
    
    rev->handler(rev);*/
}

static void
ngx_tcp2http_init_session(ngx_event_t *rev)
{
    size_t                     size;
    ssize_t                    n;
    ngx_buf_t                 *b;
    ngx_connection_t          *c;
    ngx_http_connection_t     *hc;
    ngx_http_core_srv_conf_t  *cscf;

    c = rev->data;

    //ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http wait request handler");
	ngx_log_error(NGX_LOG_ERR, c->log, 0,
			"init session");

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        ngx_http_close_connection(c);
        return;
    }

    if (c->close) {
        ngx_http_close_connection(c);
        return;
    }

    hc = c->data;
    cscf = ngx_http_get_module_srv_conf(hc->conf_ctx, ngx_http_core_module);

    size = cscf->client_header_buffer_size;

    b = c->buffer;

    if (b == NULL) {
        b = ngx_create_temp_buf(c->pool, size);
        if (b == NULL) {
            ngx_http_close_connection(c);
            return;
        }

        c->buffer = b;

    } else if (b->start == NULL) {

        b->start = ngx_palloc(c->pool, size);
        if (b->start == NULL) {
            ngx_http_close_connection(c);
            return;
        }

        b->pos = b->start;
        b->last = b->start;
        b->end = b->last + size;
    }

    c->data = ngx_http_create_request(c);
    if (c->data == NULL) {
        ngx_http_close_connection(c);
        return;
    }

    rev->handler = ngx_tcp2http_process_session;
	ngx_tcp2http_process_session(rev);
}



void
ngx_tcp2http_init_connection(ngx_connection_t *c)
{
    ngx_uint_t              i;
    ngx_event_t            *rev;
    struct sockaddr_in     *sin;
    ngx_http_port_t        *port;
    ngx_http_in_addr_t     *addr;
    ngx_http_log_ctx_t     *ctx;
    ngx_http_connection_t  *hc;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6    *sin6;
    ngx_http_in6_addr_t    *addr6;
#endif

    hc = ngx_pcalloc(c->pool, sizeof(ngx_http_connection_t));
    if (hc == NULL) {
        ngx_http_close_connection(c);
        return;
    }

    c->data = hc;

    /* find the server configuration for the address:port */

    port = c->listening->servers;

    if (port->naddrs > 1) {

        /*
         * there are several addresses on this port and one of them
         * is an "*:port" wildcard so getsockname() in ngx_http_server_addr()
         * is required to determine a server address
         */

        if (ngx_connection_local_sockaddr(c, NULL, 0) != NGX_OK) {
            ngx_http_close_connection(c);
            return;
        }

        switch (c->local_sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) c->local_sockaddr;

            addr6 = port->addrs;

            /* the last address is "*" */

            for (i = 0; i < port->naddrs - 1; i++) {
                if (ngx_memcmp(&addr6[i].addr6, &sin6->sin6_addr, 16) == 0) {
                    break;
                }
            }

            hc->addr_conf = &addr6[i].conf;

            break;
#endif

        default: /* AF_INET */
            sin = (struct sockaddr_in *) c->local_sockaddr;

            addr = port->addrs;

            /* the last address is "*" */

            for (i = 0; i < port->naddrs - 1; i++) {
                if (addr[i].addr == sin->sin_addr.s_addr) {
                    break;
                }
            }

            hc->addr_conf = &addr[i].conf;

            break;
        }

    } else {

        switch (c->local_sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            addr6 = port->addrs;
            hc->addr_conf = &addr6[0].conf;
            break;
#endif

        default: /* AF_INET */
            addr = port->addrs;
            hc->addr_conf = &addr[0].conf;
            break;
        }
    }

    /* the default server configuration for the address:port */
    hc->conf_ctx = hc->addr_conf->default_server->ctx;

    ctx = ngx_palloc(c->pool, sizeof(ngx_http_log_ctx_t));
    if (ctx == NULL) {
        ngx_http_close_connection(c);
        return;
    }

    ctx->connection = c;
    ctx->request = NULL;
    ctx->current_request = NULL;

    c->log->connection = c->number;
    c->log->handler = ngx_tcp2http_log_error;
    c->log->data = ctx;
    c->log->action = "waiting for request";

    c->log_error = NGX_ERROR_INFO;

    rev = c->read;
    rev->handler = ngx_tcp2http_init_session;
	rev->data=c;
    c->write->handler = ngx_tcp2http_empty_handler;

/*
#if (NGX_STAT_STUB)
    (void) ngx_atomic_fetch_add(ngx_stat_reading, 1);
#endif
*/
    if (rev->ready) {
        /* the deferred accept(), rtsig, aio, iocp */

        if (ngx_use_accept_mutex) {
            ngx_post_event(rev, &ngx_posted_events);
            return;
        }

        rev->handler(rev);
        return;
    }

    ngx_add_timer(rev, c->listening->post_accept_timeout);

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
/*
#if (NGX_STAT_STUB)
        (void) ngx_atomic_fetch_add(ngx_stat_reading, -1);
#endif
*/
        ngx_http_close_connection(c);
        return;
    }

}
