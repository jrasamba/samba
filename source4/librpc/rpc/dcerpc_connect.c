/* 
   Unix SMB/CIFS implementation.

   dcerpc connect functions

   Copyright (C) Andrew Tridgell 2003
   Copyright (C) Jelmer Vernooij 2004
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005-2007
   Copyright (C) Rafal Szczesniak  2005
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/


#include "includes.h"
#include "libcli/composite/composite.h"
#include "libcli/smb_composite/smb_composite.h"
#include "lib/events/events.h"
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "libcli/smb/smbXcli_base.h"
#include "librpc/rpc/dcerpc.h"
#include "librpc/rpc/dcerpc_proto.h"
#include "auth/credentials/credentials.h"
#include "param/param.h"
#include "libcli/resolve/resolve.h"

struct dcerpc_pipe_connect {
	struct dcecli_connection *conn;
	const struct dcerpc_binding *binding;
	const char *pipe_name;
	const struct ndr_interface_table *interface;
	struct cli_credentials *creds;
	struct resolve_context *resolve_ctx;
};

struct pipe_np_smb_state {
	struct smb_composite_connect conn;
	struct dcerpc_pipe_connect io;
};


/*
  Stage 3 of ncacn_np_smb: Named pipe opened (or not)
*/
static void continue_pipe_open_smb(struct composite_context *ctx)
{
	struct composite_context *c = talloc_get_type(ctx->async.private_data,
						      struct composite_context);

	/* receive result of named pipe open request on smb */
	c->status = dcerpc_pipe_open_smb_recv(ctx);
	if (!composite_is_ok(c)) return;

	composite_done(c);
}


/*
  Stage 2 of ncacn_np_smb: Open a named pipe after successful smb connection
*/
static void continue_smb_connect(struct composite_context *ctx)
{
	struct composite_context *open_ctx;
	struct composite_context *c = talloc_get_type(ctx->async.private_data,
						      struct composite_context);
	struct pipe_np_smb_state *s = talloc_get_type(c->private_data,
						      struct pipe_np_smb_state);
	struct smbcli_tree *t;
	struct smbXcli_conn *conn;
	struct smbXcli_session *session;
	struct smbXcli_tcon *tcon;
	uint32_t timeout_msec;

	/* receive result of smb connect request */
	c->status = smb_composite_connect_recv(ctx, s->io.conn);
	if (!composite_is_ok(c)) return;

	/* prepare named pipe open parameters */
	s->io.pipe_name = dcerpc_binding_get_string_option(s->io.binding, "endpoint");
	if (s->io.pipe_name == NULL) {
		composite_error(c, NT_STATUS_INVALID_PARAMETER_MIX);
		return;
	}

	t = s->conn.out.tree;
	conn = t->session->transport->conn;
	session = t->session->smbXcli;
	tcon = t->smbXcli;
	smb1cli_tcon_set_id(tcon, t->tid);
	timeout_msec = t->session->transport->options.request_timeout * 1000;

	/* send named pipe open request */
	open_ctx = dcerpc_pipe_open_smb_send(s->io.conn,
					     conn, session,
					     tcon, timeout_msec,
					     s->io.pipe_name);
	if (composite_nomem(open_ctx, c)) return;

	composite_continue(c, open_ctx, continue_pipe_open_smb, c);
}


/*
  Initiate async open of a rpc connection to a rpc pipe on SMB using
  the binding structure to determine the endpoint and options
*/
static struct composite_context *dcerpc_pipe_connect_ncacn_np_smb_send(TALLOC_CTX *mem_ctx, struct dcerpc_pipe_connect *io, struct loadparm_context *lp_ctx)
{
	struct composite_context *c;
	struct pipe_np_smb_state *s;
	struct composite_context *conn_req;
	struct smb_composite_connect *conn;
	uint32_t flags;

	/* composite context allocation and setup */
	c = composite_create(mem_ctx, io->conn->event_ctx);
	if (c == NULL) return NULL;

	s = talloc_zero(c, struct pipe_np_smb_state);
	if (composite_nomem(s, c)) return c;
	c->private_data = s;

	s->io  = *io;
	conn   = &s->conn;

	/* prepare smb connection parameters: we're connecting to IPC$ share on
	   remote rpc server */
	conn->in.dest_host = dcerpc_binding_get_string_option(s->io.binding, "host");
	conn->in.dest_ports = lpcfg_smb_ports(lp_ctx);
	conn->in.called_name =
		dcerpc_binding_get_string_option(s->io.binding, "target_hostname");
	if (conn->in.called_name == NULL) {
		conn->in.called_name = "*SMBSERVER";
	}
	conn->in.socket_options         = lpcfg_socket_options(lp_ctx);
	conn->in.service                = "IPC$";
	conn->in.service_type           = NULL;
	conn->in.workgroup		= lpcfg_workgroup(lp_ctx);
	conn->in.gensec_settings = lpcfg_gensec_settings(conn, lp_ctx);

	lpcfg_smbcli_options(lp_ctx, &conn->in.options);
	lpcfg_smbcli_session_options(lp_ctx, &conn->in.session_options);

	/*
	 * provide proper credentials - user supplied, but allow a
	 * fallback to anonymous if this is an schannel connection
	 * (might be NT4 not allowing machine logins at session
	 * setup) or if asked to do so by the caller (perhaps a SAMR password change?)
	 */
	s->conn.in.credentials = s->io.creds;
	flags = dcerpc_binding_get_flags(s->io.binding);
	if (flags & (DCERPC_SCHANNEL|DCERPC_ANON_FALLBACK)) {
		conn->in.fallback_to_anonymous  = true;
	} else {
		conn->in.fallback_to_anonymous  = false;
	}

	/* send smb connect request */
	conn_req = smb_composite_connect_send(conn, s->io.conn,
					      s->io.resolve_ctx,
					      c->event_ctx);
	if (composite_nomem(conn_req, c)) return c;

	composite_continue(c, conn_req, continue_smb_connect, c);
	return c;
}


/*
  Receive result of a rpc connection to a rpc pipe on SMB
*/
static NTSTATUS dcerpc_pipe_connect_ncacn_np_smb_recv(struct composite_context *c)
{
	NTSTATUS status = composite_wait(c);

	talloc_free(c);
	return status;
}


struct pipe_np_smb2_state {
	struct dcerpc_pipe_connect io;
};


/*
  Stage 3 of ncacn_np_smb: Named pipe opened (or not)
*/
static void continue_pipe_open_smb2(struct composite_context *ctx)
{
	struct composite_context *c = talloc_get_type(ctx->async.private_data,
						      struct composite_context);

	/* receive result of named pipe open request on smb2 */
	c->status = dcerpc_pipe_open_smb_recv(ctx);
	if (!composite_is_ok(c)) return;

	composite_done(c);
}


/*
  Stage 2 of ncacn_np_smb2: Open a named pipe after successful smb2 connection
*/
static void continue_smb2_connect(struct tevent_req *subreq)
{
	struct composite_context *open_req;
	struct composite_context *c =
		tevent_req_callback_data(subreq,
		struct composite_context);
	struct pipe_np_smb2_state *s = talloc_get_type(c->private_data,
						       struct pipe_np_smb2_state);
	struct smb2_tree *t;
	struct smbXcli_conn *conn;
	struct smbXcli_session *session;
	struct smbXcli_tcon *tcon;
	uint32_t timeout_msec;

	/* receive result of smb2 connect request */
	c->status = smb2_connect_recv(subreq, s->io.conn, &t);
	TALLOC_FREE(subreq);
	if (!composite_is_ok(c)) return;

	/* prepare named pipe open parameters */
	s->io.pipe_name = dcerpc_binding_get_string_option(s->io.binding, "endpoint");
	if (s->io.pipe_name == NULL) {
		composite_error(c, NT_STATUS_INVALID_PARAMETER_MIX);
		return;
	}

	conn = t->session->transport->conn;
	session = t->session->smbXcli;
	tcon = t->smbXcli;
	timeout_msec = t->session->transport->options.request_timeout * 1000;

	/* send named pipe open request */
	open_req = dcerpc_pipe_open_smb_send(s->io.conn,
					     conn, session,
					     tcon, timeout_msec,
					     s->io.pipe_name);
	if (composite_nomem(open_req, c)) return;

	composite_continue(c, open_req, continue_pipe_open_smb2, c);
}


/* 
   Initiate async open of a rpc connection request on SMB2 using
   the binding structure to determine the endpoint and options
*/
static struct composite_context *dcerpc_pipe_connect_ncacn_np_smb2_send(
					TALLOC_CTX *mem_ctx,
					struct dcerpc_pipe_connect *io,
					struct loadparm_context *lp_ctx)
{
	struct composite_context *c;
	struct pipe_np_smb2_state *s;
	struct tevent_req *subreq;
	struct smbcli_options options;
	const char *host;
	uint32_t flags;

	/* composite context allocation and setup */
	c = composite_create(mem_ctx, io->conn->event_ctx);
	if (c == NULL) return NULL;

	s = talloc_zero(c, struct pipe_np_smb2_state);
	if (composite_nomem(s, c)) return c;
	c->private_data = s;

	s->io = *io;

	host = dcerpc_binding_get_string_option(s->io.binding, "host");
	flags = dcerpc_binding_get_flags(s->io.binding);

	/*
	 * provide proper credentials - user supplied or anonymous in case this is
	 * schannel connection
	 */
	if (flags & DCERPC_SCHANNEL) {
		s->io.creds = cli_credentials_init_anon(mem_ctx);
		if (composite_nomem(s->io.creds, c)) return c;
	}

	lpcfg_smbcli_options(lp_ctx, &options);

	/* send smb2 connect request */
	subreq = smb2_connect_send(s, c->event_ctx,
			host,
			lpcfg_parm_string_list(mem_ctx, lp_ctx, NULL, "smb2", "ports", NULL),
			"IPC$",
			s->io.resolve_ctx,
			s->io.creds,
			0, /* previous_session_id */
			&options,
			lpcfg_socket_options(lp_ctx),
			lpcfg_gensec_settings(mem_ctx, lp_ctx));
	if (composite_nomem(subreq, c)) return c;
	tevent_req_set_callback(subreq, continue_smb2_connect, c);
	return c;
}


/*
  Receive result of a rpc connection to a rpc pipe on SMB2
*/
static NTSTATUS dcerpc_pipe_connect_ncacn_np_smb2_recv(struct composite_context *c)
{
	NTSTATUS status = composite_wait(c);
	
	talloc_free(c);
	return status;
}


struct pipe_ip_tcp_state {
	struct dcerpc_pipe_connect io;
	const char *localaddr;
	const char *host;
	const char *target_hostname;
	uint32_t port;
};


/*
  Stage 2 of ncacn_ip_tcp: rpc pipe opened (or not)
*/
static void continue_pipe_open_ncacn_ip_tcp(struct composite_context *ctx)
{
	struct composite_context *c = talloc_get_type(ctx->async.private_data,
						      struct composite_context);

	/* receive result of named pipe open request on tcp/ip */
	c->status = dcerpc_pipe_open_tcp_recv(ctx);
	if (!composite_is_ok(c)) return;

	composite_done(c);
}


/*
  Initiate async open of a rpc connection to a rpc pipe on TCP/IP using
  the binding structure to determine the endpoint and options
*/
static struct composite_context* dcerpc_pipe_connect_ncacn_ip_tcp_send(TALLOC_CTX *mem_ctx,
								       struct dcerpc_pipe_connect *io)
{
	struct composite_context *c;
	struct pipe_ip_tcp_state *s;
	struct composite_context *pipe_req;
	const char *endpoint;

	/* composite context allocation and setup */
	c = composite_create(mem_ctx, io->conn->event_ctx);
	if (c == NULL) return NULL;

	s = talloc_zero(c, struct pipe_ip_tcp_state);
	if (composite_nomem(s, c)) return c;
	c->private_data = s;

	/* store input parameters in state structure */
	s->io = *io;
	s->localaddr = dcerpc_binding_get_string_option(io->binding,
							"localaddress");
	s->host = dcerpc_binding_get_string_option(io->binding, "host");
	s->target_hostname = dcerpc_binding_get_string_option(io->binding,
							      "target_hostname");
	endpoint = dcerpc_binding_get_string_option(io->binding, "endpoint");
	/* port number is a binding endpoint here */
	if (endpoint != NULL) {
		s->port = atoi(endpoint);
	}

	if (s->port == 0) {
		composite_error(c, NT_STATUS_INVALID_PARAMETER_MIX);
		return c;
	}

	/* send pipe open request on tcp/ip */
	pipe_req = dcerpc_pipe_open_tcp_send(s->io.conn, s->localaddr, s->host, s->target_hostname,
					     s->port, io->resolve_ctx);
	composite_continue(c, pipe_req, continue_pipe_open_ncacn_ip_tcp, c);
	return c;
}


/*
  Receive result of a rpc connection to a rpc pipe on TCP/IP
*/
static NTSTATUS dcerpc_pipe_connect_ncacn_ip_tcp_recv(struct composite_context *c)
{
	NTSTATUS status = composite_wait(c);
	
	talloc_free(c);
	return status;
}


struct pipe_unix_state {
	struct dcerpc_pipe_connect io;
	const char *path;
};


/*
  Stage 2 of ncacn_unix: rpc pipe opened (or not)
*/
static void continue_pipe_open_ncacn_unix_stream(struct composite_context *ctx)
{
	struct composite_context *c = talloc_get_type(ctx->async.private_data,
						      struct composite_context);

	/* receive result of pipe open request on unix socket */
	c->status = dcerpc_pipe_open_unix_stream_recv(ctx);
	if (!composite_is_ok(c)) return;

	composite_done(c);
}


/*
  Initiate async open of a rpc connection to a rpc pipe on unix socket using
  the binding structure to determine the endpoint and options
*/
static struct composite_context* dcerpc_pipe_connect_ncacn_unix_stream_send(TALLOC_CTX *mem_ctx,
									    struct dcerpc_pipe_connect *io)
{
	struct composite_context *c;
	struct pipe_unix_state *s;
	struct composite_context *pipe_req;

	/* composite context allocation and setup */
	c = composite_create(mem_ctx, io->conn->event_ctx);
	if (c == NULL) return NULL;

	s = talloc_zero(c, struct pipe_unix_state);
	if (composite_nomem(s, c)) return c;
	c->private_data = s;

	/* prepare pipe open parameters and store them in state structure
	   also, verify whether biding endpoint is not null */
	s->io = *io;

	s->path = dcerpc_binding_get_string_option(io->binding, "endpoint");
	if (s->path == NULL) {
		composite_error(c, NT_STATUS_INVALID_PARAMETER_MIX);
		return c;
	}

	/* send pipe open request on unix socket */
	pipe_req = dcerpc_pipe_open_unix_stream_send(s->io.conn, s->path);
	composite_continue(c, pipe_req, continue_pipe_open_ncacn_unix_stream, c);
	return c;
}


/*
  Receive result of a rpc connection to a pipe on unix socket
*/
static NTSTATUS dcerpc_pipe_connect_ncacn_unix_stream_recv(struct composite_context *c)
{
	NTSTATUS status = composite_wait(c);

	talloc_free(c);
	return status;
}


struct pipe_ncalrpc_state {
	struct dcerpc_pipe_connect io;
};

static NTSTATUS dcerpc_pipe_connect_ncalrpc_recv(struct composite_context *c);

/*
  Stage 2 of ncalrpc: rpc pipe opened (or not)
*/
static void continue_pipe_open_ncalrpc(struct composite_context *ctx)
{
	struct composite_context *c = talloc_get_type(ctx->async.private_data,
						      struct composite_context);

	/* receive result of pipe open request on ncalrpc */
	c->status = dcerpc_pipe_connect_ncalrpc_recv(ctx);
	if (!composite_is_ok(c)) return;

	composite_done(c);
}


/* 
   Initiate async open of a rpc connection request on NCALRPC using
   the binding structure to determine the endpoint and options
*/
static struct composite_context* dcerpc_pipe_connect_ncalrpc_send(TALLOC_CTX *mem_ctx,
								  struct dcerpc_pipe_connect *io, struct loadparm_context *lp_ctx)
{
	struct composite_context *c;
	struct pipe_ncalrpc_state *s;
	struct composite_context *pipe_req;
	const char *endpoint;

	/* composite context allocation and setup */
	c = composite_create(mem_ctx, io->conn->event_ctx);
	if (c == NULL) return NULL;

	s = talloc_zero(c, struct pipe_ncalrpc_state);
	if (composite_nomem(s, c)) return c;
	c->private_data = s;
	
	/* store input parameters in state structure */
	s->io  = *io;

	endpoint = dcerpc_binding_get_string_option(io->binding, "endpoint");
	if (endpoint == NULL) {
		composite_error(c, NT_STATUS_INVALID_PARAMETER_MIX);
		return c;
	}

	/* send pipe open request */
	pipe_req = dcerpc_pipe_open_pipe_send(s->io.conn,
					      lpcfg_ncalrpc_dir(lp_ctx),
					      endpoint);
	composite_continue(c, pipe_req, continue_pipe_open_ncalrpc, c);
	return c;
}


/*
  Receive result of a rpc connection to a rpc pipe on NCALRPC
*/
static NTSTATUS dcerpc_pipe_connect_ncalrpc_recv(struct composite_context *c)
{
	NTSTATUS status = composite_wait(c);
	
	talloc_free(c);
	return status;
}


struct pipe_connect_state {
	struct dcerpc_pipe *pipe;
	struct dcerpc_binding *binding;
	const struct ndr_interface_table *table;
	struct cli_credentials *credentials;
	struct loadparm_context *lp_ctx;
};


static void continue_map_binding(struct composite_context *ctx);
static void continue_connect(struct composite_context *c, struct pipe_connect_state *s);
static void continue_pipe_connect_ncacn_np_smb2(struct composite_context *ctx);
static void continue_pipe_connect_ncacn_np_smb(struct composite_context *ctx);
static void continue_pipe_connect_ncacn_ip_tcp(struct composite_context *ctx);
static void continue_pipe_connect_ncacn_unix(struct composite_context *ctx);
static void continue_pipe_connect_ncalrpc(struct composite_context *ctx);
static void continue_pipe_connect(struct composite_context *c, struct pipe_connect_state *s);
static void continue_pipe_auth(struct composite_context *ctx);


/*
  Stage 2 of pipe_connect_b: Receive result of endpoint mapping
*/
static void continue_map_binding(struct composite_context *ctx)
{
	struct composite_context *c = talloc_get_type(ctx->async.private_data,
						      struct composite_context);
	struct pipe_connect_state *s = talloc_get_type(c->private_data,
						       struct pipe_connect_state);
	const char *endpoint;

	c->status = dcerpc_epm_map_binding_recv(ctx);
	if (!composite_is_ok(c)) return;

	endpoint = dcerpc_binding_get_string_option(s->binding, "endpoint");
	DEBUG(4,("Mapped to DCERPC endpoint %s\n", endpoint));

	continue_connect(c, s);
}


/*
  Stage 2 of pipe_connect_b: Continue connection after endpoint is known
*/
static void continue_connect(struct composite_context *c, struct pipe_connect_state *s)
{
	struct dcerpc_pipe_connect pc;

	/* potential exits to another stage by sending an async request */
	struct composite_context *ncacn_np_smb2_req;
	struct composite_context *ncacn_np_smb_req;
	struct composite_context *ncacn_ip_tcp_req;
	struct composite_context *ncacn_unix_req;
	struct composite_context *ncalrpc_req;
	enum dcerpc_transport_t transport;
	uint32_t flags;

	/* dcerpc pipe connect input parameters */
	pc.conn         = s->pipe->conn;
	pc.binding      = s->binding;
	pc.pipe_name    = NULL;
	pc.interface    = s->table;
	pc.creds        = s->credentials;
	pc.resolve_ctx  = lpcfg_resolve_context(s->lp_ctx);

	transport = dcerpc_binding_get_transport(s->binding);
	flags = dcerpc_binding_get_flags(s->binding);

	/* connect dcerpc pipe depending on required transport */
	switch (transport) {
	case NCACN_NP:
		if (flags & DCERPC_SMB2) {
			/* new varient of SMB a.k.a. SMB2 */
			ncacn_np_smb2_req = dcerpc_pipe_connect_ncacn_np_smb2_send(c, &pc, s->lp_ctx);
			composite_continue(c, ncacn_np_smb2_req, continue_pipe_connect_ncacn_np_smb2, c);
			return;

		} else {
			/* good old ordinary SMB */
			ncacn_np_smb_req = dcerpc_pipe_connect_ncacn_np_smb_send(c, &pc, s->lp_ctx);
			composite_continue(c, ncacn_np_smb_req, continue_pipe_connect_ncacn_np_smb, c);
			return;
		}
		break;

	case NCACN_IP_TCP:
		ncacn_ip_tcp_req = dcerpc_pipe_connect_ncacn_ip_tcp_send(c, &pc);
		composite_continue(c, ncacn_ip_tcp_req, continue_pipe_connect_ncacn_ip_tcp, c);
		return;

	case NCACN_UNIX_STREAM:
		ncacn_unix_req = dcerpc_pipe_connect_ncacn_unix_stream_send(c, &pc);
		composite_continue(c, ncacn_unix_req, continue_pipe_connect_ncacn_unix, c);
		return;

	case NCALRPC:
		ncalrpc_req = dcerpc_pipe_connect_ncalrpc_send(c, &pc, s->lp_ctx);
		composite_continue(c, ncalrpc_req, continue_pipe_connect_ncalrpc, c);
		return;

	default:
		/* looks like a transport we don't support now */
		composite_error(c, NT_STATUS_NOT_SUPPORTED);
	}
}


/*
  Stage 3 of pipe_connect_b: Receive result of pipe connect request on
  named pipe on smb2
*/
static void continue_pipe_connect_ncacn_np_smb2(struct composite_context *ctx)
{
	struct composite_context *c = talloc_get_type(ctx->async.private_data,
						      struct composite_context);
	struct pipe_connect_state *s = talloc_get_type(c->private_data,
						       struct pipe_connect_state);

	c->status = dcerpc_pipe_connect_ncacn_np_smb2_recv(ctx);
	if (!composite_is_ok(c)) return;

	continue_pipe_connect(c, s);
}


/*
  Stage 3 of pipe_connect_b: Receive result of pipe connect request on
  named pipe on smb
*/
static void continue_pipe_connect_ncacn_np_smb(struct composite_context *ctx)
{
	struct composite_context *c = talloc_get_type(ctx->async.private_data,
						      struct composite_context);
	struct pipe_connect_state *s = talloc_get_type(c->private_data,
						       struct pipe_connect_state);

	c->status = dcerpc_pipe_connect_ncacn_np_smb_recv(ctx);
	if (!composite_is_ok(c)) return;
	
	continue_pipe_connect(c, s);
}


/*
  Stage 3 of pipe_connect_b: Receive result of pipe connect request on tcp/ip
*/
static void continue_pipe_connect_ncacn_ip_tcp(struct composite_context *ctx)
{
	struct composite_context *c = talloc_get_type(ctx->async.private_data,
						      struct composite_context);
	struct pipe_connect_state *s = talloc_get_type(c->private_data,
						       struct pipe_connect_state);

	c->status = dcerpc_pipe_connect_ncacn_ip_tcp_recv(ctx);
	if (!composite_is_ok(c)) return;

	continue_pipe_connect(c, s);
}


/*
  Stage 3 of pipe_connect_b: Receive result of pipe connect request on unix socket
*/
static void continue_pipe_connect_ncacn_unix(struct composite_context *ctx)
{
	struct composite_context *c = talloc_get_type(ctx->async.private_data,
						      struct composite_context);
	struct pipe_connect_state *s = talloc_get_type(c->private_data,
						       struct pipe_connect_state);
	
	c->status = dcerpc_pipe_connect_ncacn_unix_stream_recv(ctx);
	if (!composite_is_ok(c)) return;
	
	continue_pipe_connect(c, s);
}


/*
  Stage 3 of pipe_connect_b: Receive result of pipe connect request on local rpc
*/
static void continue_pipe_connect_ncalrpc(struct composite_context *ctx)
{
	struct composite_context *c = talloc_get_type(ctx->async.private_data,
						      struct composite_context);
	struct pipe_connect_state *s = talloc_get_type(c->private_data,
						       struct pipe_connect_state);
	
	c->status = dcerpc_pipe_connect_ncalrpc_recv(ctx);
	if (!composite_is_ok(c)) return;

	continue_pipe_connect(c, s);
}


/*
  Stage 4 of pipe_connect_b: Start an authentication on connected dcerpc pipe
  depending on credentials and binding flags passed.
*/
static void continue_pipe_connect(struct composite_context *c, struct pipe_connect_state *s)
{
	struct composite_context *auth_bind_req;

	s->pipe->binding = dcerpc_binding_dup(s->pipe, s->binding);
	if (composite_nomem(s->pipe->binding, c)) {
		return;
	}

	auth_bind_req = dcerpc_pipe_auth_send(s->pipe, s->binding, s->table,
					      s->credentials, s->lp_ctx);
	composite_continue(c, auth_bind_req, continue_pipe_auth, c);
}


/*
  Stage 5 of pipe_connect_b: Receive result of pipe authentication request
  and say if all went ok
*/
static void continue_pipe_auth(struct composite_context *ctx)
{
	struct composite_context *c = talloc_get_type(ctx->async.private_data,
						      struct composite_context);
	struct pipe_connect_state *s = talloc_get_type(c->private_data, struct pipe_connect_state);

	c->status = dcerpc_pipe_auth_recv(ctx, s, &s->pipe);
	if (!composite_is_ok(c)) return;

	composite_done(c);
}


/*
  handle timeouts of a dcerpc connect
*/
static void dcerpc_connect_timeout_handler(struct tevent_context *ev, struct tevent_timer *te, 
					   struct timeval t, void *private_data)
{
	struct composite_context *c = talloc_get_type_abort(private_data,
						      struct composite_context);
	struct pipe_connect_state *s = talloc_get_type_abort(c->private_data, struct pipe_connect_state);
	if (!s->pipe->inhibit_timeout_processing) {
		composite_error(c, NT_STATUS_IO_TIMEOUT);
	} else {
		s->pipe->timed_out = true;
	}
}

/*
  start a request to open a rpc connection to a rpc pipe, using
  specified binding structure to determine the endpoint and options
*/
_PUBLIC_ struct composite_context* dcerpc_pipe_connect_b_send(TALLOC_CTX *parent_ctx,
						     const struct dcerpc_binding *binding,
						     const struct ndr_interface_table *table,
						     struct cli_credentials *credentials,
						     struct tevent_context *ev,
						     struct loadparm_context *lp_ctx)
{
	struct composite_context *c;
	struct pipe_connect_state *s;
	enum dcerpc_transport_t transport;
	const char *endpoint = NULL;

	/* composite context allocation and setup */
	c = composite_create(parent_ctx, ev);
	if (c == NULL) {
		return NULL;
	}

	s = talloc_zero(c, struct pipe_connect_state);
	if (composite_nomem(s, c)) return c;
	c->private_data = s;

	/* initialise dcerpc pipe structure */
	s->pipe = dcerpc_pipe_init(c, ev);
	if (composite_nomem(s->pipe, c)) return c;

	if (DEBUGLEVEL >= 10)
		s->pipe->conn->packet_log_dir = lpcfg_lock_directory(lp_ctx);

	/* store parameters in state structure */
	s->binding      = dcerpc_binding_dup(s, binding);
	if (composite_nomem(s->binding, c)) return c;
	s->table        = table;
	s->credentials  = credentials;
	s->lp_ctx 	= lp_ctx;

	s->pipe->timed_out = false;
	s->pipe->inhibit_timeout_processing = false;

	tevent_add_timer(c->event_ctx, c,
			 timeval_current_ofs(DCERPC_REQUEST_TIMEOUT, 0),
			 dcerpc_connect_timeout_handler, c);

	transport = dcerpc_binding_get_transport(s->binding);

	switch (transport) {
	case NCACN_NP:
	case NCACN_IP_TCP:
	case NCALRPC:
		endpoint = dcerpc_binding_get_string_option(s->binding, "endpoint");
		break;
	default:
		break;
	}

	if (endpoint == NULL) {
		struct composite_context *binding_req;

		binding_req = dcerpc_epm_map_binding_send(c, s->binding, s->table,
							  s->pipe->conn->event_ctx,
							  s->lp_ctx);
		composite_continue(c, binding_req, continue_map_binding, c);
		return c;
	}

	continue_connect(c, s);
	return c;
}


/*
  receive result of a request to open a rpc connection to a rpc pipe
*/
_PUBLIC_ NTSTATUS dcerpc_pipe_connect_b_recv(struct composite_context *c, TALLOC_CTX *mem_ctx,
				    struct dcerpc_pipe **p)
{
	NTSTATUS status;
	struct pipe_connect_state *s;
	
	status = composite_wait(c);
	
	if (NT_STATUS_IS_OK(status)) {
		s = talloc_get_type(c->private_data, struct pipe_connect_state);
		talloc_steal(mem_ctx, s->pipe);
		*p = s->pipe;
	}
	talloc_free(c);
	return status;
}


/*
  open a rpc connection to a rpc pipe, using the specified 
  binding structure to determine the endpoint and options - sync version
*/
_PUBLIC_ NTSTATUS dcerpc_pipe_connect_b(TALLOC_CTX *parent_ctx,
			       struct dcerpc_pipe **pp,
			       const struct dcerpc_binding *binding,
			       const struct ndr_interface_table *table,
			       struct cli_credentials *credentials,
			       struct tevent_context *ev,
			       struct loadparm_context *lp_ctx)
{
	struct composite_context *c;
	
	c = dcerpc_pipe_connect_b_send(parent_ctx, binding, table,
				       credentials, ev, lp_ctx);
	return dcerpc_pipe_connect_b_recv(c, parent_ctx, pp);
}


struct pipe_conn_state {
	struct dcerpc_pipe *pipe;
};


static void continue_pipe_connect_b(struct composite_context *ctx);


/*
  Initiate rpc connection to a rpc pipe, using the specified string
  binding to determine the endpoint and options.
  The string is to be parsed to a binding structure first.
*/
_PUBLIC_ struct composite_context* dcerpc_pipe_connect_send(TALLOC_CTX *parent_ctx,
						   const char *binding,
						   const struct ndr_interface_table *table,
						   struct cli_credentials *credentials,
						   struct tevent_context *ev, struct loadparm_context *lp_ctx)
{
	struct composite_context *c;
	struct pipe_conn_state *s;
	struct dcerpc_binding *b;
	struct composite_context *pipe_conn_req;

	/* composite context allocation and setup */
	c = composite_create(parent_ctx, ev);
	if (c == NULL) {
		return NULL;
	}

	s = talloc_zero(c, struct pipe_conn_state);
	if (composite_nomem(s, c)) return c;
	c->private_data = s;

	/* parse binding string to the structure */
	c->status = dcerpc_parse_binding(c, binding, &b);
	if (!NT_STATUS_IS_OK(c->status)) {
		DEBUG(0, ("Failed to parse dcerpc binding '%s'\n", binding));
		composite_error(c, c->status);
		return c;
	}

	DEBUG(3, ("Using binding %s\n", dcerpc_binding_string(c, b)));

	/* 
	   start connecting to a rpc pipe after binding structure
	   is established
	 */
	pipe_conn_req = dcerpc_pipe_connect_b_send(c, b, table,
						   credentials, ev, lp_ctx);
	composite_continue(c, pipe_conn_req, continue_pipe_connect_b, c);
	return c;
}


/*
  Stage 2 of pipe_connect: Receive result of actual pipe connect request
  and say if we're done ok
*/
static void continue_pipe_connect_b(struct composite_context *ctx)
{
	struct composite_context *c = talloc_get_type(ctx->async.private_data,
						      struct composite_context);
	struct pipe_conn_state *s = talloc_get_type(c->private_data,
						    struct pipe_conn_state);

	c->status = dcerpc_pipe_connect_b_recv(ctx, c, &s->pipe);
	talloc_steal(s, s->pipe);
	if (!composite_is_ok(c)) return;

	composite_done(c);
}


/*
  Receive result of pipe connect (using binding string) request
  and return connected pipe structure.
*/
NTSTATUS dcerpc_pipe_connect_recv(struct composite_context *c,
				  TALLOC_CTX *mem_ctx,
				  struct dcerpc_pipe **pp)
{
	NTSTATUS status;
	struct pipe_conn_state *s;

	status = composite_wait(c);
	if (NT_STATUS_IS_OK(status)) {
		s = talloc_get_type(c->private_data, struct pipe_conn_state);
		*pp = talloc_steal(mem_ctx, s->pipe);
	}
	talloc_free(c);
	return status;
}


/*
  Open a rpc connection to a rpc pipe, using the specified string
  binding to determine the endpoint and options - sync version
*/
_PUBLIC_ NTSTATUS dcerpc_pipe_connect(TALLOC_CTX *parent_ctx, 
			     struct dcerpc_pipe **pp, 
			     const char *binding,
			     const struct ndr_interface_table *table,
			     struct cli_credentials *credentials,
			     struct tevent_context *ev,
			     struct loadparm_context *lp_ctx)
{
	struct composite_context *c;
	c = dcerpc_pipe_connect_send(parent_ctx, binding, 
				     table, credentials, ev, lp_ctx);
	return dcerpc_pipe_connect_recv(c, parent_ctx, pp);
}

