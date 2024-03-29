/*
   Unix SMB/Netbios implementation.
   RPC Server Headers
   Copyright (C) Andrew Tridgell 1992-1997
   Copyright (C) Luke Kenneth Casson Leighton 1996-1997
   Copyright (C) Paul Ashton 1997
   Copyright (C) Jeremy Allison 2000-2004
   Copyright (C) Simo Sorce 2010-2011

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

#ifndef _RPC_PIPES_H_
#define _RPC_PIPES_H_

#include "librpc/rpc/dcerpc.h"

typedef struct _output_data {
	/*
	 * Raw RPC output data. This does not include RPC headers or footers.
	 */
	DATA_BLOB rdata;

	/* The amount of data sent from the current rdata struct. */
	uint32 data_sent_length;

	/*
	 * The current fragment being returned. This inclues
	 * headers, data and authentication footer.
	 */
	DATA_BLOB frag;

	/* The amount of data sent from the current PDU. */
	uint32 current_pdu_sent;
} output_data;

typedef struct _input_data {
	/*
	 * This is the current incoming pdu. The data here
	 * is collected via multiple writes until a complete
	 * pdu is seen, then the data is copied into the in_data
	 * structure. The maximum size of this is 0x1630 (RPC_MAX_PDU_FRAG_LEN).
	 * If length is zero, then we are at the start of a new
	 * pdu.
	 */
	DATA_BLOB pdu;

	/*
	 * The amount of data needed to complete the in_pdu.
	 * If this is zero, then we are at the start of a new
	 * pdu.
	 */
	uint32 pdu_needed_len;

	/*
	 * This is the collection of input data with all
	 * the rpc headers and auth footers removed.
	 * The maximum length of this (1Mb) is strictly enforced.
	 */
	DATA_BLOB data;

} input_data;

struct dcesrv_ep_entry_list;
struct tsocket_address;
struct handle_list;
struct pipes_struct;

struct api_struct {
	const char *name;
	uint8 opnum;
	bool (*fn) (struct pipes_struct *);
};

struct pipe_rpc_fns {

	struct pipe_rpc_fns *next, *prev;

	/* RPC function table associated with the current rpc_bind (associated by context) */

	const struct api_struct *cmds;
	int n_cmds;
	uint32_t context_id;
	struct ndr_syntax_id syntax;

};

/*
 * DCE/RPC-specific samba-internal-specific handling of data on
 * NamedPipes.
 */
struct pipes_struct {
	struct pipes_struct *next, *prev;

	const struct tsocket_address *local_address;
	const struct tsocket_address *remote_address;

	enum dcerpc_transport_t transport;

	struct auth_session_info *session_info;
	struct messaging_context *msg_ctx;

	struct dcesrv_ep_entry_list *ep_entries;

	/* linked list of rpc dispatch tables associated 
	   with the open rpc contexts */

	struct pipe_rpc_fns *contexts;

	struct pipe_auth_data auth;

	bool ncalrpc_as_system;

	/*
	 * Set to true when an RPC bind has been done on this pipe.
	 */

	bool pipe_bound;

	/*
	 * Set the DCERPC_FAULT to return.
	 */
	int fault_state;

	/*
	 * Set to RPC_BIG_ENDIAN when dealing with big-endian PDU's
	 */

	bool endian;

	/*
	 * Struct to deal with multiple pdu inputs.
	 */

	input_data in_data;

	/*
	 * Struct to deal with multiple pdu outputs.
	 */

	output_data out_data;

	/* This context is used for PDU data and is freed between each pdu.
		Don't use for pipe state storage. */
	TALLOC_CTX *mem_ctx;

	/* handle database to use on this pipe. */
	struct handle_list *pipe_handles;

	/* call id retrieved from the pdu header */
	uint32_t call_id;

	/* operation number retrieved from the rpc header */
	uint16_t opnum;

	/* rpc header information to check fragments for consistency */
	struct dcerpc_sec_vt_header2 header2;

	/* private data for the interface implementation */
	void *private_data;

};

int make_base_pipes_struct(TALLOC_CTX *mem_ctx,
			   struct messaging_context *msg_ctx,
			   const char *pipe_name,
			   enum dcerpc_transport_t transport,
			   bool endian, bool ncalrpc_as_system,
			   const struct tsocket_address *remote_address,
			   const struct tsocket_address *local_address,
			   struct pipes_struct **_p);
bool check_open_pipes(void);
int close_internal_rpc_pipe_hnd(struct pipes_struct *p);

size_t num_pipe_handles(struct pipes_struct *p);
bool init_pipe_handles(struct pipes_struct *p, const struct ndr_syntax_id *syntax);
bool create_policy_hnd(struct pipes_struct *p, struct policy_handle *hnd, void *data_ptr);
bool find_policy_by_hnd(struct pipes_struct *p, const struct policy_handle *hnd,
			void **data_p);
bool close_policy_hnd(struct pipes_struct *p, struct policy_handle *hnd);
void close_policy_by_pipe(struct pipes_struct *p);
bool pipe_access_check(struct pipes_struct *p);

void *_policy_handle_create(struct pipes_struct *p, struct policy_handle *hnd,
			    uint32_t access_granted, size_t data_size,
			    const char *type, NTSTATUS *pstatus);
#define policy_handle_create(_p, _hnd, _access, _type, _pstatus) \
	(_type *)_policy_handle_create((_p), (_hnd), (_access), sizeof(_type), #_type, \
				       (_pstatus))

void *_policy_handle_find(struct pipes_struct *p,
			  const struct policy_handle *hnd,
			  uint32_t access_required, uint32_t *paccess_granted,
			  const char *name, const char *location,
			  NTSTATUS *pstatus);
#define policy_handle_find(_p, _hnd, _access_required, _access_granted, _type, _pstatus) \
	(_type *)_policy_handle_find((_p), (_hnd), (_access_required), \
				     (_access_granted), #_type, __location__, (_pstatus))

#endif /* _RPC_PIPES_H_ */
