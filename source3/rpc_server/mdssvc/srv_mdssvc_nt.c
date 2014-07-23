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
#include "../librpc/gen_ndr/srv_mdssvc.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

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

	DEBUG(10, ("mdssvc_open: path: %s\n", path));

	strlcpy(r->out.share_path, path, 1024);
	r->out.share_handle->handle_type = 0;
	r->out.share_handle->uuid.time_low = snum;
	strlcpy(r->out.share_handle->uuid.node, service, sizeof(r->out.share_handle->uuid.node));
	*r->out.device_id = *r->in.device_id;
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
	DEBUG(10, ("mdssvc_cmd\n"));
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;

	return;
}
