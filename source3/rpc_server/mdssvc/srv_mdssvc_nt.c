/*
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines for mdssvc
 *  Copyright (C) Ralph Boehme 2014
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "ntdomain.h"
#include "rpc_server/mdssvc/srv_mdssvc_nt.h"
#include "../librpc/gen_ndr/srv_mdssvc.h"
#include "mdssvc/mdssvc.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

bool init_service_mdssvc(struct messaging_context *msg_ctx)
{
	return mds_init(msg_ctx);
}

bool shutdown_service_mdssvc(void)
{
	return mds_shutdown();
}

void _mdssvc_open(struct pipes_struct *p, struct mdssvc_open *r)
{
	char *service = NULL;
	int snum = -1;
	char *path = NULL;

	DEBUG(10, ("mdssvc_open: [%s]\n", r->in.share_name));

	service = talloc_strdup(talloc_tos(), r->in.share_name);
	if(!service) {
		p->fault_state = DCERPC_FAULT_CANT_PERFORM;
		return;
	}

	snum = find_service(talloc_tos(), service, &service);
	if (!service || !VALID_SNUM(snum)) {
		p->fault_state = DCERPC_FAULT_CANT_PERFORM;
		return;
	}

	path = lp_path(talloc_tos(), snum);
	if (!path) {
		p->fault_state = DCERPC_FAULT_CANT_PERFORM;
		return;
	}

	if (lp_spotlight(snum)) {
		DEBUG(10, ("Spotlight enabled: %s\n", path));

		/*
		 * Fake a share UUID using the snum and the service
		 * name for some more uniqueness.
		 */

		strlcpy(r->out.share_path, path, 1024);
		r->out.share_handle->handle_type = 0;
		r->out.share_handle->uuid.time_low = snum;
		strlcpy(r->out.share_handle->uuid.node, service,
			sizeof(r->out.share_handle->uuid.node));
		*r->out.device_id = *r->in.device_id;
	}

	*r->out.unkn2 = 0x17;
	*r->out.unkn3 = 0;

	return;
}

void _mdssvc_unknown1(struct pipes_struct *p, struct mdssvc_unknown1 *r)
{
	int snum = -1;
	char *path = NULL;

	DEBUG(10, ("mdssvc_unknown1\n"));

	snum = r->in.share_handle.uuid.time_low;
	if (!VALID_SNUM(snum)) {
		p->fault_state = DCERPC_FAULT_CANT_PERFORM;
		return;
	}

	path = lp_path(talloc_tos(), snum);
	if (!path) {
		p->fault_state = DCERPC_FAULT_CANT_PERFORM;
		return;
	}

	DEBUG(10, ("mdssvc_unknown1: path: %s\n", path));

	*r->out.status = 0;
	*r->out.flags = UINT32_C(0x6b000001);
	*r->out.unkn7 = 0;

	return;
}

void _mdssvc_cmd(struct pipes_struct *p, struct mdssvc_cmd *r)
{
	bool ok;
	int snum = -1;
	char *rbuf;
	struct mds_query_ctx *query_ctx;

	DEBUG(10, ("mdssvc_cmd\n"));

	snum = r->in.share_handle.uuid.time_low;
	if (!VALID_SNUM(snum)) {
		p->fault_state = DCERPC_FAULT_CANT_PERFORM;
		return;
	}

	rbuf = talloc_array(p->mem_ctx, char, r->in.max_fragment_size1);
	if (rbuf == NULL) {
		p->fault_state = DCERPC_FAULT_CANT_PERFORM;
		return;
	}
	r->out.response_blob->spotlight_blob = rbuf;
	r->out.response_blob->size = r->in.max_fragment_size1;

	query_ctx = talloc_zero(talloc_tos(), struct mds_query_ctx);
	if (query_ctx == NULL) {
		p->fault_state = DCERPC_FAULT_CANT_PERFORM;
		return;
	}
	query_ctx->spath = lp_path(query_ctx, snum);
	if (query_ctx->spath == NULL) {
		p->fault_state = DCERPC_FAULT_CANT_PERFORM;
		return;
	}

	query_ctx->session_info = p->session_info;
	query_ctx->snum = snum;
	query_ctx->request_blob = &r->in.request_blob;
	query_ctx->response_blob = r->out.response_blob;

	ok = mds_dispatch(query_ctx);
	if (ok) {
		*r->out.status = 0;
		*r->out.unkn9 = 0;
	} else {
		/* FIXME: just interpolating from AFP, needs verification */
		*r->out.status = UINT32_MAX;
		*r->out.unkn9 = UINT32_MAX;
	}

	return;
}
