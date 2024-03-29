/*
   Unix SMB/CIFS implementation.

   Copyright (C) Stefan Metzmacher 2010

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

#ifndef _CLI_NP_TSTREAM_H_
#define _CLI_NP_TSTREAM_H_

struct tevent_context;
struct tevent_req;
struct tstream_context;
struct smbXcli_conn;
struct smbXcli_session;
struct smbXcli_tcon;

struct tevent_req *tstream_smbXcli_np_open_send(TALLOC_CTX *mem_ctx,
						struct tevent_context *ev,
						struct smbXcli_conn *conn,
						struct smbXcli_session *session,
						struct smbXcli_tcon *tcon,
						uint16_t pid,
						unsigned int timeout,
						const char *npipe);
NTSTATUS _tstream_smbXcli_np_open_recv(struct tevent_req *req,
				       TALLOC_CTX *mem_ctx,
				       struct tstream_context **_stream,
				       const char *location);
#define tstream_smbXcli_np_open_recv(req, mem_ctx, stream) \
		_tstream_smbXcli_np_open_recv(req, mem_ctx, stream, __location__)

bool tstream_is_smbXcli_np(struct tstream_context *stream);

NTSTATUS tstream_smbXcli_np_use_trans(struct tstream_context *stream);

unsigned int tstream_smbXcli_np_set_timeout(struct tstream_context *stream,
					    unsigned int timeout);

#endif /*  _CLI_NP_TSTREAM_H_ */
