/*
   Unix SMB/CIFS implementation.
   Main metadata server / Spotlight routines

   Copyright (C) Ralph Boehme			2012-2014

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

#ifndef _MDSSVC_H
#define _MDSSVC_H

#include "dalloc.h"
#include "lib/util/dlinklist.h"
#include "librpc/gen_ndr/mdssvc.h"
#include "lib/ccan/htable/htable.h"

#include <gio/gio.h>
#include <tracker-sparql.h>

#define MAX_SL_RESULTS 30

/******************************************************************************
 * Spotlight RPC and marshalling stuff
 ******************************************************************************/

/* Can be ored and used as flags */
#define SL_ENC_LITTLE_ENDIAN 1
#define SL_ENC_BIG_ENDIAN    2
#define SL_ENC_UTF_16        4

typedef DALLOC_CTX     sl_array_t;    /* an array of elements */
typedef DALLOC_CTX     sl_dict_t;     /* an array of key/value elements */
typedef DALLOC_CTX     sl_filemeta_t; /* contains one sl_array_t */
typedef int            sl_nil_t;      /* a nil element */
typedef bool           sl_bool_t;
typedef struct timeval sl_time_t;
typedef struct {
	char sl_uuid[16];
}  sl_uuid_t;
typedef struct {
	uint16_t   ca_unkn1;
	uint32_t   ca_context;
	DALLOC_CTX *ca_cnids;
}  sl_cnids_t; /* an array of CNIDs */

/******************************************************************************
 * Some helper stuff dealing with queries
 ******************************************************************************/

/* query state */
typedef enum {
	SLQ_STATE_NEW,       /* Query received from client         */
	SLQ_STATE_RUNNING,   /* Query dispatched to Tracker        */
	SLQ_STATE_RESULTS,   /* Async Tracker query read           */
	SLQ_STATE_FULL,	     /* the max amount of result has beed queued */
	SLQ_STATE_DONE,      /* Got all results from Tracker       */
	SLQ_STATE_END,       /* Query results returned to client   */
	SLQ_STATE_ERROR	     /* an error happended somewhere       */
} slq_state_t;

/* query structure */
struct sl_query {
	struct mds_ctx  *mds_ctx;        /* context handle */
	slq_state_t      state;          /* query state */
	int              snum;           /* share snum  */
	time_t           started;        /* timestamp when we received this query */
	uint64_t         ctx1;           /* client context 1 */
	uint64_t         ctx2;           /* client context 2 */
	sl_array_t      *reqinfo;        /* array with requested metadata */
	const char      *query_string;   /* the Spotlight query string */
	uint64_t        *cnids;          /* restrict query to these CNIDs */
	size_t           cnids_num;      /* Size of slq_cnids array */
	const char      *path_scope;	 /* path to directory to search */
	void            *tracker_cursor; /* Tracker SPARQL query result cursor */
	struct sl_rslts *query_results;  /* query results */
	struct sl_query *prev, *next;	 /* list pointers */
};

struct sl_rslts {
	int         num_results;
	sl_cnids_t *cnids;
	sl_array_t *fm_array;
};

struct sl_ino_path {
	struct mds_ctx  *mds_ctx;
	uint64_t         ino;
	char            *path;
};

struct mds_ctx {
	struct mds_query_ctx *query_ctx;
	TrackerSparqlConnection *tracker_con;
	GCancellable *cancellable;
	GMainLoop *mainloop;
	struct sl_query *query_list; /* list of active queries */
	struct htable slprpc_cmd_ht; /* Spotlight RPC commands */
	struct htable results_ht; /* Hash table with Spotlight query results */
};

struct mds_query_ctx {
	const struct auth_session_info *session_info;
	int snum;
	const char *spath;
	struct mdssvc_blob *request_blob;
	struct mdssvc_blob *response_blob;
};

/******************************************************************************
 * Function declarations
 ******************************************************************************/

/*
 * marshalling.c
 */
extern ssize_t sl_pack(DALLOC_CTX *query, char *buf);
extern bool sl_unpack(DALLOC_CTX *query, const char *buf);

/*
 * mdssvc.c
 */
extern bool mds_init(struct messaging_context *msg_ctx);
extern bool mds_shutdown(void);
extern bool mds_dispatch(struct mds_query_ctx *query_ctx);

#endif /* _MDSSVC_H */
