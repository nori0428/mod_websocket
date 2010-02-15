/*
 * $Id$
 */

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <assert.h>

#include "buffer.h"
#include "server.h"
#include "keyvalue.h"
#include "log.h"
#include "http_chunk.h"
#include "fdevent.h"
#include "connections.h"
#include "response.h"
#include "joblist.h"
#include "network.h"
#include "plugin.h"
#include "inet_ntop_cache.h"
#include "crc32.h"

#include <fnmatch.h>

#ifdef HAVE_SYS_FILIO_H
# include <sys/filio.h>
#endif

#include "sys-socket.h"

#define	data_websocket		data_fastcgi
#define	data_websocket_init	data_fastcgi_init

/**
 * The websocket module is based on the proxy module,
 * which in turn is based on the fastcgi module.
 */

typedef struct {
	array *extensions;
	unsigned int debug;
} plugin_config;

typedef struct {
	PLUGIN_DATA;

	plugin_config **config_storage;
	plugin_config conf;
} plugin_data;

typedef enum {
	WEBSOCKET_STATE_INIT,
	WEBSOCKET_STATE_CONNECT,
	WEBSOCKET_STATE_CONNECTED,
} websocket_connection_state_t;

typedef enum {
    INITIAL,
    CONTINUE,
} websocket_frame_state_t;

typedef struct {
	websocket_connection_state_t state;
    websocket_frame_state_t frame;
	time_t state_timestamp;

	buffer *host;
	unsigned short port;
    buffer *origin;

	chunkqueue *toclient;

	int fd;						/* fd to the connect process */
	int fd_server_ndx;			/* index into the fd-event buffer */

	int client_closed, server_closed;

	int noresp;
	int path;					/* handle as /path based CONNECT */
	size_t path_info_offset;	/* start of path_info in uri.path */

	connection *remote_conn;	/* dump pointer */
	plugin_data *plugin_data;	/* dump pointer */
} handler_ctx;

/* ok, we need a prototype */
static handler_t websocket_handle_fdevent(void *s, void *ctx, int revents);

static void handle_websocket_frame(handler_ctx *hctx, chunkqueue *cq) {
	chunk *c;

	for(c = cq->first; c; c = c->next) {
        char first_byte, last_byte;

        assert(c->type == MEM_CHUNK); /* websocket chunk must be a MEM_CHUNK */
        if (c->mem->used == 0) {
            return;
        }
        first_byte = c->mem->ptr[0];
        last_byte = c->mem->ptr[c->mem->used - 2]; /* padded '\0' by buffer */
        if (0 <= first_byte && first_byte < 127 &&
            hctx->frame == INITIAL) {
            c->offset++;
            hctx->frame = CONTINUE;
        }
        if (-1 == last_byte) {
            c->mem->ptr[c->mem->used - 1] = 0;
            c->mem->used--;
            hctx->frame = INITIAL;
        }
    }
    return;
}
                                   
static handler_ctx *handler_ctx_init(void) {
	handler_ctx *hctx = calloc(1, sizeof(*hctx));

	hctx->state = WEBSOCKET_STATE_INIT;
	hctx->frame = INITIAL;
	hctx->host = buffer_init();
	hctx->origin = buffer_init();
	hctx->toclient = chunkqueue_init();
	hctx->fd = -1;
	hctx->fd_server_ndx = -1;
	hctx->path = 0;
	return hctx;
}

static void handler_ctx_free(handler_ctx *hctx) {
	buffer_free(hctx->host);
	buffer_free(hctx->origin);
	chunkqueue_free(hctx->toclient);
	free(hctx);
}

INIT_FUNC(mod_websocket_init) {
	plugin_data *p;

	p = calloc(1, sizeof(*p));
	return p;
}

FREE_FUNC(mod_websocket_free) {
	plugin_data *p = p_d;

	UNUSED(srv);
	if (p->config_storage) {
		size_t i;

		for (i = 0; i < srv->config_context->used; i++) {
			plugin_config *s = p->config_storage[i];

			if (s) {
				array_free(s->extensions);
				free(s);
			}
		}
		free(p->config_storage);
	}
	free(p);
	return HANDLER_GO_ON;
}

SETDEFAULTS_FUNC(mod_websocket_set_defaults) {
	plugin_data *p = p_d;
	data_unset *du;
	size_t i = 0;

	config_values_t cv[] = {
		{ "websocket.server", NULL, T_CONFIG_LOCAL, T_CONFIG_SCOPE_CONNECTION },
		{ "websocket.debug", NULL, T_CONFIG_INT, T_CONFIG_SCOPE_CONNECTION },
		{ NULL,	NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
	};

	p->config_storage = calloc(1, srv->config_context->used * sizeof(specific_config *));

	for (i = 0; i < srv->config_context->used; i++) {
		plugin_config *s;
		array *ca;

		s = malloc(sizeof(plugin_config));
		s->extensions = array_init();
		s->debug = 0;

		cv[0].destination = s->extensions;
		cv[1].destination = &(s->debug);

		p->config_storage[i] = s;
		ca = ((data_config *)srv->config_context->data[i])->value;

		if (config_insert_values_global(srv, ca, cv))
			return HANDLER_ERROR;

		du = array_get_element(ca, "websocket.server");
		if (du) {
			size_t j;
			data_array *da = (data_array *)du;

			if (du->type != TYPE_ARRAY) {
				log_error_write(srv, __FILE__, __LINE__, "sss",
                                "unexpected type for key: ",
                                "websocket.server", "array of strings");
				return HANDLER_ERROR;
			}

			/*
			 * websocket.server = ( "<regex>" => "<host>", ...)
			 */
			for (j = 0; j < da->value->used; j++) {
				data_array *da_ext = (data_array *)da->value->data[j];
				data_array *dca;
				data_websocket *dc;

				if (da_ext->type != TYPE_ARRAY) {
					log_error_write(srv, __FILE__, __LINE__, "sssbs",
                                    "unexpected type for key: ",
                                    "websocket.server",
                                    "[", da->value->data[j]->key,
                                    "](string)");
					return HANDLER_ERROR;
				}

				config_values_t pcv[] = {
					{ "host", NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },
					{ "port", NULL, T_CONFIG_INT, T_CONFIG_SCOPE_CONNECTION },
					{ NULL, NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
				};

				dc = data_websocket_init();
				buffer_copy_string_buffer(dc->key, da_ext->key);
				pcv[0].destination = dc->host;
				pcv[1].destination = &(dc->port);

				if (config_insert_values_internal(srv, da_ext->value, pcv))
					return HANDLER_ERROR;

				dca = (data_array *)array_get_element(s->extensions, da_ext->key->ptr);
				if (!dca) {
					dca = data_array_init();
					buffer_copy_string_buffer(dca->key, da_ext->key);
					array_insert_unique(s->extensions, (data_unset *)dca);
				}

				if (s->debug) {
					log_error_write(srv, __FILE__, __LINE__, "ssssd",
                                    da_ext->key->ptr, "=>", dc->host->ptr,
                                    ":", dc->port);
                }
				array_insert_unique(dca->value, (data_unset *)dc);
			}
		}
	}
	return HANDLER_GO_ON;
}

static void websocket_connection_close(server *srv, handler_ctx *hctx) {
	plugin_data *p;
	connection *con;

	if (!hctx)
		return;

	p = hctx->plugin_data;
	con = hctx->remote_conn;

	if (hctx->fd != -1) {
		fdevent_event_del(srv->ev, &(hctx->fd_server_ndx), hctx->fd);
		fdevent_unregister(srv->ev, hctx->fd);

		close(hctx->fd);
		srv->cur_fds--;
	}

	handler_ctx_free(hctx);
	con->plugin_ctx[p->id] = NULL;
}

static int websocket_establish_connection(server *srv, handler_ctx *hctx) {
	struct sockaddr *connect_addr;
	struct sockaddr_in connect_addr_in;

#if defined(HAVE_IPV6) && defined(HAVE_INET_PTON)
	struct sockaddr_in6 connect_addr_in6;
#endif

	socklen_t servlen;

	plugin_data *p = hctx->plugin_data;
	int connect_fd = hctx->fd;

#if defined(HAVE_IPV6) && defined(HAVE_INET_PTON)
	if (strstr(hctx->host->ptr, ":")) {
		memset(&connect_addr_in6, 0, sizeof(connect_addr_in6));
		connect_addr_in6.sin6_family = AF_INET6;
		inet_pton(AF_INET6, hctx->host->ptr, (char *) &connect_addr_in6.sin6_addr);
		connect_addr_in6.sin6_port = htons(hctx->port);
		servlen = sizeof(connect_addr_in6);
		connect_addr = (struct sockaddr *) &connect_addr_in6;
	} else
#endif
	{
		memset(&connect_addr_in, 0, sizeof(connect_addr_in));
		connect_addr_in.sin_family = AF_INET;
		connect_addr_in.sin_addr.s_addr = inet_addr(hctx->host->ptr);
		connect_addr_in.sin_port = htons(hctx->port);
		servlen = sizeof(connect_addr_in);
		connect_addr = (struct sockaddr *) &connect_addr_in;
	}

	if (-1 == connect(connect_fd, connect_addr, servlen)) {
		if (errno == EINPROGRESS || errno == EALREADY) {
			if (p->conf.debug)
				log_error_write(srv, __FILE__, __LINE__, "sd",
                                "connect delayed:", connect_fd);
			return 1;
		} else {
			log_error_write(srv, __FILE__, __LINE__, "sdsd",
                            "connect failed:", connect_fd,
                            strerror(errno), errno);
			return -1;
		}
	}
	if (p->conf.debug) {
		log_error_write(srv, __FILE__, __LINE__, "sd",
                        "connect succeeded: ", connect_fd);
    }
	return 0;
}

static int websocket_set_state(server *srv, handler_ctx *hctx,
                               websocket_connection_state_t state) {
	hctx->state = state;
	hctx->state_timestamp = srv->cur_ts;
	return 0;
}

static handler_t websocket_write_request(server *srv, handler_ctx *hctx) {
	plugin_data *p = hctx->plugin_data;
	connection *con = hctx->remote_conn;
	int ret;
    size_t i, j;
    struct {
        const char *key; const char *val; int pass;
    } m_hdrs[] = { /* mandatory headers */
        { "Upgrade", "WebSocket", 0 },
        { "Connection", "Upgrade", 0 },
        { "Host", NULL   , 0 },
        { "Origin", NULL, 0 },
    };

	switch(hctx->state) {
	case WEBSOCKET_STATE_INIT:
        /* validate request header */
        for (i = 0; i < con->request.headers->used; i++) {
            data_string *ds = (data_string *)con->request.headers->data[i];

            if (!ds->value->used || !ds->key->used) {
                break;
            }
            for (j = 0; j < (sizeof(m_hdrs) / sizeof(m_hdrs[0])); j++) {
                if (buffer_is_equal_string(ds->key,
                                           m_hdrs[j].key,
                                           strlen(m_hdrs[j].key))) {
                    if (!m_hdrs[j].val) {
                        m_hdrs[j].pass = 1;
                        if (buffer_is_equal_string(ds->key,
                                                   CONST_STR_LEN("Origin"))) {
                            buffer_copy_string_buffer(hctx->origin, ds->value);
                        }
                    } else {
                        if (buffer_is_equal_string(ds->value,
                                                   m_hdrs[j].val,
                                                   strlen(m_hdrs[j].val))) {
                            m_hdrs[j].pass = 1;
                        }
                    }
                    break;
                }
            }
        }
        for (j = 0; j < (sizeof(m_hdrs) / sizeof(m_hdrs[0])); j++) {
            if (!m_hdrs[j].pass) {
                log_error_write(srv, __FILE__, __LINE__, "ss",
                                "websocket handshake failed.");
                con->http_status = 404;
                con->mode = DIRECT;
                return HANDLER_FINISHED;
            }
        }

#if defined(HAVE_IPV6) && defined(HAVE_INET_PTON)
		if (strstr(hctx->host->ptr,":")) {
			if (-1 == (hctx->fd = socket(AF_INET6, SOCK_STREAM, 0))) {
				log_error_write(srv, __FILE__, __LINE__, "ss",
                                "socket failed: ", strerror(errno));
				return HANDLER_ERROR;
			}
		} else
#endif
		{
			if (-1 == (hctx->fd = socket(AF_INET, SOCK_STREAM, 0))) {
				log_error_write(srv, __FILE__, __LINE__, "ss",
                                "socket failed: ", strerror(errno));
				return HANDLER_ERROR;
			}
		}
		hctx->fd_server_ndx = -1;

		srv->cur_fds++;

		fdevent_register(srv->ev, hctx->fd, websocket_handle_fdevent, hctx);

		if (-1 == fdevent_fcntl_set(srv->ev, hctx->fd)) {
			log_error_write(srv, __FILE__, __LINE__, "ss",
                            "fcntl failed: ", strerror(errno));
			return HANDLER_ERROR;
		}

		/* fall through */

	case WEBSOCKET_STATE_CONNECT:
		/* try to finish the connect() */
		if (hctx->state == WEBSOCKET_STATE_INIT) {
			/* first round */
			switch (websocket_establish_connection(srv, hctx)) {
			case 1:
				websocket_set_state(srv, hctx, WEBSOCKET_STATE_CONNECT);

				/*
                 * connection is in progress,
                 * wait for an event and call getsockopt() below
                 */
				fdevent_event_add(srv->ev, &(hctx->fd_server_ndx), hctx->fd, FDEVENT_OUT);
				return HANDLER_WAIT_FOR_EVENT;
			case -1:
				hctx->fd_server_ndx = -1;
				return HANDLER_ERROR;
			default:
				/* everything is ok, go on */
				break;
			}
		} else {
			int socket_error;
			socklen_t socket_error_len = sizeof(socket_error);

			/* we don't need it anymore */
			fdevent_event_del(srv->ev, &(hctx->fd_server_ndx), hctx->fd);

			/* try to finish the connect() */
			if (0 != getsockopt(hctx->fd, SOL_SOCKET, SO_ERROR, &socket_error, &socket_error_len)) {
				log_error_write(srv, __FILE__, __LINE__, "ss",
                                "getsockopt failed:", strerror(errno));
				return HANDLER_ERROR;
			}
			if (socket_error != 0) {
				log_error_write(srv, __FILE__, __LINE__, "ss",
                                "establishing connection failed:",
                                strerror(socket_error),
                                "port:", hctx->port);
				con->http_status = 503;
				con->mode = DIRECT;
				return HANDLER_FINISHED;
			}
			if (p->conf.debug)
				log_error_write(srv, __FILE__, __LINE__,  "s",
                                "websocket - connect - delayed success");
		}

		websocket_set_state(srv, hctx, WEBSOCKET_STATE_CONNECTED);

		if (!hctx->noresp) {
			struct {
				const char *b; size_t l;
			} strs[] = {
				{ CONST_STR_LEN("HTTP/1.1 101 Web Socket Protocol Handshake\r\n") },
				{ CONST_STR_LEN("Upgrade: WebSocket\r\n") },
				{ CONST_STR_LEN("Connection: Upgrade\r\n") },
			};
			buffer *b = chunkqueue_get_append_buffer(hctx->toclient);

			for (i = 0; i < (int)(sizeof(strs)/sizeof(strs[0])); i++)
				buffer_append_string_len(b, strs[i].b, strs[i].l);
            buffer_append_string_len(b, CONST_STR_LEN("WebSocket-Origin: "));
            buffer_append_string_buffer(b, hctx->origin);
            buffer_append_string_len(b, CONST_STR_LEN("\r\nWebSocket-Location: ws://"));
            buffer_append_string_buffer(b, con->server_name);
            buffer_append_string_buffer(b, con->uri.path);
            buffer_append_string_len(b, CONST_STR_LEN("\r\n\r\n"));
		}
		connection_set_state(srv, con, CON_STATE_READ_CONTINUOUS);

		/* fall through */
	case WEBSOCKET_STATE_CONNECTED:
		if (!hctx->server_closed) {
            handle_websocket_frame(hctx, con->read_queue);
			ret = srv->network_backend_write(srv, con, hctx->fd, con->read_queue);
			chunkqueue_remove_finished_chunks(con->read_queue);

			if (-1 == ret) { /* error on our side */
				log_error_write(srv, __FILE__, __LINE__, "ssd",
                                "write failed:", strerror(errno), errno);
			} else if (-2 == ret) { /* remote close */
				log_error_write(srv, __FILE__, __LINE__, "ssd",
                                "write failed, remote connection close:",
                                strerror(errno), errno);
				hctx->server_closed = 1;
			}
		}

		if (!hctx->client_closed) {
			con->keep_alive = 1;
			ret = network_write_chunkqueue(srv, con, hctx->toclient);
			con->keep_alive = 0;
			chunkqueue_remove_finished_chunks(hctx->toclient);
			if (-1 == ret) { /* error on our side */
				log_error_write(srv, __FILE__, __LINE__, "ssd",
                                "write failed:", strerror(errno), errno);
			} else if (-2 == ret) { /* remote close */
				log_error_write(srv, __FILE__, __LINE__, "ssd",
                                "write failed, remote connection close:",
                                strerror(errno), errno);
				hctx->client_closed = 1;
			}
		}

		if (!chunkqueue_is_empty(con->read_queue)) {
			fdevent_event_del(srv->ev, &(hctx->fd_server_ndx), hctx->fd);
			fdevent_event_add(srv->ev, &(hctx->fd_server_ndx), hctx->fd, FDEVENT_OUT);
		} else {
			fdevent_event_del(srv->ev, &(hctx->fd_server_ndx), hctx->fd);
			if (hctx->client_closed)
				websocket_connection_close(srv, hctx);
			else if (chunkqueue_is_empty(hctx->toclient)) {
				fdevent_event_add(srv->ev, &(hctx->fd_server_ndx), hctx->fd, FDEVENT_IN);
            }
		}

		if (!chunkqueue_is_empty(hctx->toclient)) {
			fdevent_event_del(srv->ev, &(con->fde_ndx), con->fd);
			fdevent_event_add(srv->ev, &(con->fde_ndx), con->fd, FDEVENT_OUT);
		} else {
			fdevent_event_del(srv->ev, &(con->fde_ndx), con->fd);
			if (hctx->server_closed) {
				if (!hctx->client_closed) {
					connection_set_state(srv, con, CON_STATE_RESPONSE_END);
					hctx->client_closed = 1;
				}
			} else if (chunkqueue_is_empty(con->read_queue))
				fdevent_event_add(srv->ev, &(con->fde_ndx), con->fd, FDEVENT_IN);
		}
		return HANDLER_WAIT_FOR_EVENT;
	default:
		log_error_write(srv, __FILE__, __LINE__, "s", "(debug) unknown state");
		return HANDLER_ERROR;
	}
    return HANDLER_ERROR; /* never reach */
}

static int mod_websocket_patch_connection(server *srv, connection *con,
                                          plugin_data *p) {
	size_t i, j;
	plugin_config *s = p->config_storage[0];

#define PATCH(x) do { p->conf.x = s->x; } while (0)

	PATCH(extensions);
	PATCH(debug);

	/* skip the first, the global context */
	for (i = 1; i < srv->config_context->used; i++) {
		data_config *dc = (data_config *)srv->config_context->data[i];
		s = p->config_storage[i];

		/* condition didn't match */
		if (!config_check_cond(srv, con, dc))
			continue;

		/* merge config */
		for (j = 0; j < dc->value->used; j++) {
			data_unset *du = dc->value->data[j];

			if (buffer_is_equal_string(du->key, CONST_STR_LEN("websocket.server")))
				PATCH(extensions);
			else if (buffer_is_equal_string(du->key, CONST_STR_LEN("websocket.debug")))
				PATCH(debug);
		}
	}

#undef PATCH

	return 0;
}

SUBREQUEST_FUNC(mod_websocket_handle_subrequest) {
	plugin_data *p = p_d;
	handler_ctx *hctx = con->plugin_ctx[p->id];
	handler_t h;

	if (!hctx)
		return HANDLER_GO_ON;

	mod_websocket_patch_connection(srv, con, p);

	/* not my job */
	if (con->mode != p->id)
		return HANDLER_GO_ON;

	/* ok, create the request */
	h = websocket_write_request(srv, hctx);
	switch (h) {
	case HANDLER_ERROR:
		log_error_write(srv, __FILE__, __LINE__,
                        "sbdd", "websocket-server disabled:",
                        hctx->host, hctx->port, hctx->fd);
		websocket_connection_close(srv, hctx);

		/* reset the enviroment and restart the sub-request */
		buffer_reset(con->physical.path);
		con->mode = DIRECT;

		joblist_append(srv, con);

		return HANDLER_ERROR;
	default:
		return h;
	}
    return HANDLER_ERROR; /* never reach */
}

static handler_t websocket_handle_fdevent(void *s, void *ctx, int revents) {
	server *srv = (server *)s;
	handler_ctx *hctx = ctx;
	connection *con = hctx->remote_conn;
	plugin_data *p = hctx->plugin_data;
	int b;
	ssize_t r;
	buffer *buf;
	int fd = hctx->fd;
	char readbuf[4096];

	if ((revents & FDEVENT_IN) &&
	    hctx->state == WEBSOCKET_STATE_CONNECTED &&
	    chunkqueue_is_empty(hctx->toclient)) {
		/* check how much we have to read */
		if (ioctl(fd, FIONREAD, &b)) {
			log_error_write(srv, __FILE__, __LINE__, "sd",
                            "ioctl failed: ", fd);
			goto disconnect;
		}

		if (!b || b > (int)sizeof(readbuf))
			b = sizeof(readbuf);

		errno = 0;
		r = read(fd, readbuf, b);
		if (r > 0) {
            const char head = 0;
            const char tail = -1;

			buf = chunkqueue_get_append_buffer(hctx->toclient);
			buffer_append_memory(buf, &head, 1);
			buffer_append_memory(buf, readbuf, r);
            /* buffer.c replace buf[len - 1] = '\0' */
			buffer_append_memory(buf, &tail, 2);
		} else if (errno != EAGAIN)
			goto disconnect;
	}

	if (revents & FDEVENT_OUT) {
		if (p->conf.debug)
			log_error_write(srv, __FILE__, __LINE__, "sd",
                            "websocket: fdevent-out", hctx->state);

		if (hctx->state == WEBSOCKET_STATE_CONNECT ||
		    hctx->state == WEBSOCKET_STATE_CONNECTED) {
			/* unfinished websocket call or data to send */
			return mod_websocket_handle_subrequest(srv, con, p);
		} else {
			log_error_write(srv, __FILE__, __LINE__, "sd",
                            "websocket: out", hctx->state);
		}
	}

	/* perhaps this issue is already handled */
	if (revents & FDEVENT_HUP) {
		if (p->conf.debug)
			log_error_write(srv, __FILE__, __LINE__, "sd",
                            "websocket: fdevent-hup", hctx->state);
        
		if (hctx->state == WEBSOCKET_STATE_CONNECT) {
			/* connect() -> EINPROGRESS -> HUP */
			goto disconnect;
		}

		con->file_finished = 1;
		goto disconnect;
	} else if (revents & FDEVENT_ERR) {
		/* kill all connections to the websocket process */
		log_error_write(srv, __FILE__, __LINE__, "sd",
                        "websocket-FDEVENT_ERR, but no HUP", revents);
		goto disconnect;
	}
	joblist_append(srv, con);
	return HANDLER_FINISHED;

 disconnect:
	hctx->server_closed = 1;
	joblist_append(srv, con);
	websocket_write_request(srv, hctx);
	return HANDLER_FINISHED;
}

static handler_t mod_websocket_check(server *srv, connection *con, void *p_d) {
	plugin_data *p = p_d;
	size_t s_len;
	size_t k;
	buffer *fn;
	data_array *extension = NULL;
	size_t path_info_offset;
	data_websocket *host;
	handler_ctx *hctx;
	char *colon;
	int path = 0;

	if (con->request.http_method != HTTP_METHOD_GET)
		return HANDLER_GO_ON;

	if (con->mode != DIRECT)
		return HANDLER_GO_ON;

	/* Have we processed this request already? */
	if (con->file_started == 1)
		return HANDLER_GO_ON;

	mod_websocket_patch_connection(srv, con, p);

	fn = con->uri.path;

	if (fn->used == 0)
		return HANDLER_ERROR;

	s_len = fn->used - 1;

	path_info_offset = 0;

	if (p->conf.debug)
		log_error_write(srv, __FILE__, __LINE__,  "s", "websocket - start");

	/* check if prefix or host matches */
	for (k = 0; k < p->conf.extensions->used; k++) {
		data_array *ext = NULL;
		size_t ct_len;

		ext = (data_array *)p->conf.extensions->data[k];

		if (ext->key->used == 0)
			continue;

		ct_len = ext->key->used - 1;

		if (s_len < ct_len)
			continue;

		/* check host/prefix in the form "/path" */
		if (*(ext->key->ptr) == '/') {
			if (strncmp(fn->ptr, ext->key->ptr, ct_len) == 0) {
				if (s_len > ct_len + 1) {
					char *pi_offset;

					pi_offset = strchr(fn->ptr + ct_len + 1, '/');
					if (pi_offset)
						path_info_offset = pi_offset - fn->ptr;
				}
				extension = ext;
				path = 1;
				break;
			}
		} else if (fnmatch(ext->key->ptr, fn->ptr + 1, FNM_NOESCAPE|FNM_CASEFOLD) == 0) {
			/* check extension in the form ".fcg" */
			extension = ext;
			break;
		}
	}

	if (!extension)
		return HANDLER_GO_ON;

	if (p->conf.debug)
		log_error_write(srv, __FILE__, __LINE__,  "s", "websocket - ext found");

	host = (data_websocket *)extension->value->data[0];

	/*
	 * if check-local is disabled, use the uri.path handler
	 *
	 */

	/* init handler-context */
	hctx = handler_ctx_init();

	hctx->path_info_offset = path_info_offset;
	hctx->remote_conn = con;
	hctx->plugin_data = p;
	if (!host->host) {
		colon = strrchr(fn->ptr + 1, ':');
		if (!colon) {
			buffer_append_string(hctx->host, fn->ptr + 1);
			hctx->port = host->port ? host->port : 443;
		} else {
			hctx->port = atoi(colon + 1);
			buffer_append_string_len(hctx->host, fn->ptr + 1, colon - fn->ptr - 1);
		}
	} else {
		buffer_append_string(hctx->host, host->host->ptr);
		hctx->port = host->port;
	}
	hctx->noresp = host->usage; // XXX
	hctx->path = path;

	con->plugin_ctx[p->id] = hctx;

	con->mode = p->id;

	if (p->conf.debug)
		log_error_write(srv, __FILE__, __LINE__,  "sbd",
                        "websocket - found a host",
                        hctx->host, hctx->port);

	return HANDLER_GO_ON;
}

static handler_t mod_websocket_connection_close(server *srv, connection *con, void *p_d) {
	plugin_data *p = p_d;

	websocket_connection_close(srv, con->plugin_ctx[p->id]);
	return HANDLER_GO_ON;
}

/**
 *
 * the trigger re-enables the disabled connections after the timeout is over
 *
 */

TRIGGER_FUNC(mod_websocket_trigger) {
	plugin_data *p = p_d;

	if (p->config_storage) {
		size_t i, n, k;
		for (i = 0; i < srv->config_context->used; i++) {
			plugin_config *s = p->config_storage[i];

			if (!s)
				continue;

			/* get the extensions for all configs */

			for (k = 0; k < s->extensions->used; k++) {
				data_array *extension = (data_array *)s->extensions->data[k];

				/* get all hosts */
				for (n = 0; n < extension->value->used; n++) {
					data_websocket *host = (data_websocket *)extension->value->data[n];

					if (!host->is_disabled ||
					    srv->cur_ts - host->disable_ts < 5)
					    	continue;

					log_error_write(srv, __FILE__, __LINE__,  "sbd",
                                    "websocket - re-enabled:",
                                    host->host, host->port);

					host->is_disabled = 0;
				}
			}
		}
	}

	return HANDLER_GO_ON;
}


int mod_websocket_plugin_init(plugin *p) {
	p->version = LIGHTTPD_VERSION_ID;
	p->name = buffer_init_string("websocket");
	p->init = mod_websocket_init;
	p->cleanup = mod_websocket_free;
	p->set_defaults = mod_websocket_set_defaults;
	p->connection_reset = mod_websocket_connection_close;
	p->handle_connection_close = mod_websocket_connection_close;
	p->handle_uri_clean = mod_websocket_check;
	p->handle_subrequest = mod_websocket_handle_subrequest;
	p->handle_trigger = mod_websocket_trigger;
	p->read_continuous = mod_websocket_handle_subrequest;
	p->data = NULL;
	return 0;
}

/* EOF */
