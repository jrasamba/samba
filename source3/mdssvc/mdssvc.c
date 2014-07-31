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

#include "includes.h"
#include "mdssvc.h"
#include "sparql_parser.h"
#include "lib/ccan/htable/htable.h"
#include "lib/ccan/hash/hash.h"
#include "lib/util/dlinklist.h"

#include <gio/gio.h>
#include <tracker-sparql.h>

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

struct sl_rpc_cmd {
	const char *name;
	bool (*function)(struct mds_ctx *, const DALLOC_CTX *, DALLOC_CTX *);
};

/*
 * If these functions return an error, they hit something like a non
 * recoverable talloc error. Most errors are dealt with by returning
 * an errror code in the Spotlight RPC reply.
 */
static bool slrpc_fetch_properties(struct mds_ctx *mds_ctx,
				   const DALLOC_CTX *query, DALLOC_CTX *reply);
static bool slrpc_open_query(struct mds_ctx *mds_ctx,
			     const DALLOC_CTX *query, DALLOC_CTX *reply);
static bool slrpc_fetch_query_results(struct mds_ctx *mds_ctx,
				      const DALLOC_CTX *query, DALLOC_CTX *reply);
static bool slrpc_store_attributes(struct mds_ctx *mds_ctx,
				   const DALLOC_CTX *query, DALLOC_CTX *reply);
static bool slrpc_fetch_attributenames(struct mds_ctx *mds_ctx,
				       const DALLOC_CTX *query, DALLOC_CTX *reply);
static bool slrpc_fetch_attributes(struct mds_ctx *mds_ctx,
				   const DALLOC_CTX *query, DALLOC_CTX *reply);
static bool slrpc_close_query(struct mds_ctx *mds_ctx,
			      const DALLOC_CTX *query, DALLOC_CTX *reply);

static struct sl_rpc_cmd sl_rpc_cmds[] = {
	{ "fetchPropertiesForContext:", slrpc_fetch_properties},
	{ "openQueryWithParams:forContext:", slrpc_open_query},
	{ "fetchQueryResultsForContext:", slrpc_fetch_query_results},
	{ "storeAttributes:forOIDArray:context:", slrpc_store_attributes},
	{ "fetchAttributeNamesForOIDArray:context:", slrpc_fetch_attributenames},
	{ "fetchAttributes:forOIDArray:context:", slrpc_fetch_attributes},
	{ "closeQueryForContext:", slrpc_close_query},
	{ NULL, NULL }
};

struct slq_state {
	struct tevent_context *ev;
	struct sl_query *slq;
};

static struct tevent_req *slq_destroy_send(TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev,
					   struct sl_query *slq)
{
	struct tevent_req *req;
	struct slq_state *state;

	req = tevent_req_create(mem_ctx, &state, struct slq_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->slq = slq;
	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static void slq_destroy_done(struct tevent_req *req)
{
	struct slq_state *state;

	state = tevent_req_data(req, struct slq_state);
	talloc_free(state->slq);

	DEBUG(10, ("slq_destroy_done\n"));

	return;
}

/************************************************
 * Misc utility functions
 ************************************************/

static char *tab_level(TALLOC_CTX *mem_ctx, int level)
{
	int i;
	char *string = talloc_array(mem_ctx, char, level + 1);

	for (i = 0; i < level; i++) {
		string[i] = '\t';
	}

	string[i] = '\0';
	return string;
}

static char *dd_dump(DALLOC_CTX *dd, int nestinglevel)
{
	const char *type;
	int n;
	uint64_t i;
	sl_bool_t bl;
	sl_time_t t;
	struct tm *tm;
	char datestring[256];
	sl_cnids_t cnids;
	char *logstring, *nested_logstring;
	char *tab_string1, *tab_string2;

	tab_string1 = tab_level(dd, nestinglevel);
	tab_string2 = tab_level(dd, nestinglevel + 1);
	if (tab_string1 == NULL || tab_string2 == NULL) {
		return NULL;
	}

	logstring = talloc_asprintf(dd,
				    "%s%s(#%lu): {\n",
				    tab_string1,
				    talloc_get_name(dd),
				    talloc_array_length(dd->dd_talloc_array));

	for (n = 0; n < talloc_array_length(dd->dd_talloc_array); n++) {
		type = talloc_get_name(dd->dd_talloc_array[n]);
		if (strequal(type, "DALLOC_CTX")
		    || strequal(type, "sl_array_t")
		    || strequal(type, "sl_filemeta_t")
		    || strequal(type, "sl_dict_t")) {
			nested_logstring = dd_dump(dd->dd_talloc_array[n],
						   nestinglevel + 1);
			if (!nested_logstring) {
				return NULL;
			}
			logstring = talloc_strdup_append(logstring,
							 nested_logstring);
			if (!logstring) {
				return NULL;
			}
		} else if (strequal(type, "uint64_t")) {
			memcpy(&i, dd->dd_talloc_array[n], sizeof(uint64_t));
			logstring = talloc_asprintf_append(
				logstring,
				"%suint64_t: 0x%04" PRIx64 "\n",
				tab_string2, i);
			if (!logstring) {
				return NULL;
			}
		} else if (strequal(type, "char *")) {
			logstring = talloc_asprintf_append(
				logstring,
				"%sstring: %s\n",
				tab_string2,
				(char *)dd->dd_talloc_array[n]);
			if (!logstring) {
				return NULL;
			}
		} else if (strequal(type, "smb_ucs2_t *")) {
			logstring = talloc_asprintf_append(
				logstring,
				"%sUTF16-string: %s\n",
				tab_string2,
				(char *)dd->dd_talloc_array[n]);
			if (!logstring) {
				return NULL;
			}
		} else if (strequal(type, "sl_bool_t")) {
			memcpy(&bl, dd->dd_talloc_array[n], sizeof(sl_bool_t));
			logstring = talloc_asprintf_append(
				logstring,
				"%sbool: %s\n",
				tab_string2,
				bl ? "true" : "false");
			if (!logstring) {
				return NULL;
			}
		} else if (strequal(type, "sl_nil_t")) {
			logstring = talloc_asprintf_append(
				logstring,
				"%snil\n",
				tab_string2);
			if (!logstring) {
				return NULL;
			}
		} else if (strequal(type, "sl_time_t")) {
			memcpy(&t, dd->dd_talloc_array[n], sizeof(sl_time_t));
			tm = localtime(&t.tv_sec);
			strftime(datestring,
				 sizeof(datestring),
				 "%Y-%m-%d %H:%M:%S", tm);
			logstring = talloc_asprintf_append(
				logstring,
				"%ssl_time_t: %s.%06lu\n",
				tab_string2,
				datestring,
				(unsigned long)t.tv_usec);
			if (!logstring) {
				return NULL;
			}
		} else if (strequal(type, "sl_cnids_t")) {
			memcpy(&cnids, dd->dd_talloc_array[n], sizeof(sl_cnids_t));
			logstring = talloc_asprintf_append(
				logstring,
				"%sCNIDs: unkn1: 0x%" PRIx16 ", unkn2: 0x%" PRIx32 "\n",
				tab_string2,
				cnids.ca_unkn1,
				cnids.ca_context);
			if (!logstring) {
				return NULL;
			}
			if (cnids.ca_cnids) {
				nested_logstring = dd_dump(
					cnids.ca_cnids,
					nestinglevel + 2);
				if (!nested_logstring) {
					return NULL;
				}
				logstring = talloc_strdup_append(logstring,
								 nested_logstring);
				if (!logstring) {
					return NULL;
				}
			}
		} else {
			logstring = talloc_asprintf_append(
				logstring,
				"%stype: %s\n",
				tab_string2,
				type);
			if (!logstring) {
				return NULL;
			}
		}
	}
	logstring = talloc_asprintf_append(logstring,
					   "%s}\n",
					   tab_string1);
	if (!logstring) {
		return NULL;
	}
	return logstring;
}

static char *tracker_to_unix_path(TALLOC_CTX *mem_ctx, const char *uri)
{
	GFile *f;
	char *path;
	char *talloc_path = NULL;

	f = g_file_new_for_uri(uri);
	if (!f) {
		return NULL;
	}

	path = g_file_get_path(f);
	g_object_unref(f);

	if (!path) {
		return NULL;
	}

	talloc_path = talloc_strdup(mem_ctx, path);
	g_free(path);

	return talloc_path;
}

/**
 * Add requested metadata for a query result element
 *
 * This could be rewritten to something more sophisticated like
 * querying metadata from Tracker.
 *
 * If path or sp is NULL, simply add nil values for all attributes.
 **/
static bool add_filemeta(sl_array_t *reqinfo,
			 sl_array_t *fm_array,
			 const char *path,
			 const struct stat_ex *sp)
{
	sl_array_t *meta;
	sl_nil_t nil;
	int i, metacount;
	uint64_t uint64var;
	sl_time_t sl_time;
	char *p, *name;

	metacount = talloc_array_length(reqinfo->dd_talloc_array);
	if (metacount == 0 || path == NULL || sp == NULL) {
		dalloc_add_copy(fm_array, &nil, sl_nil_t);
		return true;
	}

	meta = talloc_zero(fm_array, sl_array_t);

	for (i = 0; i < metacount; i++) {
		if (strequal(reqinfo->dd_talloc_array[i], "kMDItemDisplayName")
		    || strequal(reqinfo->dd_talloc_array[i], "kMDItemFSName")) {
			if ((p = strrchr(path, '/'))) {
				name = dalloc_strdup(meta, p + 1);
				dalloc_add(meta, name, "char *");
			}
		} else if (strequal(reqinfo->dd_talloc_array[i],
				    "kMDItemPath")) {
			name = dalloc_strdup(meta, path);
			dalloc_add(meta, name, "char *");
		} else if (strequal(reqinfo->dd_talloc_array[i],
				    "kMDItemFSSize")) {
			uint64var = sp->st_ex_size;
			dalloc_add_copy(meta, &uint64var, uint64_t);
		} else if (strequal(reqinfo->dd_talloc_array[i],
				    "kMDItemFSOwnerUserID")) {
			uint64var = sp->st_ex_uid;
			dalloc_add_copy(meta, &uint64var, uint64_t);
		} else if (strequal(reqinfo->dd_talloc_array[i],
				    "kMDItemFSOwnerGroupID")) {
			uint64var = sp->st_ex_gid;
			dalloc_add_copy(meta, &uint64var, uint64_t);
		} else if (strequal(reqinfo->dd_talloc_array[i],
				    "kMDItemFSContentChangeDate")) {
			sl_time.tv_sec = sp->st_ex_mtime.tv_sec;
			dalloc_add_copy(meta, &sl_time, sl_time_t);
		} else {
			dalloc_add_copy(meta, &nil, sl_nil_t);
		}
	}

	dalloc_add(fm_array, meta, sl_array_t);
	return true;
}

static int cnid_comp_fn(const void *p1, const void *p2)
{
	const uint64_t *cnid1 = p1, *cnid2 = p2;
	if (*cnid1 == *cnid2) {
		return 0;
	}
	if (*cnid1 < *cnid2) {
		return -1;
	}
	return 1;
}

/**
 * Create a sorted copy of a CNID array
 **/
static bool sort_cnids(struct sl_query *slq, const DALLOC_CTX *p)
{
	uint64_t *cnids = NULL;
	int i;

	cnids = talloc_array(slq, uint64_t, talloc_array_length(p));
	if (!cnids) {
		return false;
	}
	for (i = 0; i < talloc_array_length(p); i++) {
		memcpy(&cnids[i], p->dd_talloc_array[i], sizeof(uint64_t));
	}
	qsort(cnids, talloc_array_length(p), sizeof(uint64_t), cnid_comp_fn);

	slq->cnids = cnids;
	slq->cnids_num = talloc_array_length(p);

	return true;
}

/**
 * Allocate result handle used in the async Tracker cursor result
 * handler for storing results
 **/
static bool create_result_handle(struct sl_query *slq)
{
	sl_nil_t nil = 0;
	struct sl_rslts *query_results;

	if (slq->query_results) {
		DEBUG(1, ("unexpected existing result handle\n"));
		return false;
	}

	query_results = talloc_zero(slq, struct sl_rslts);

	/* CNIDs */
	query_results->cnids = talloc_zero(query_results, sl_cnids_t);
	if (query_results->cnids == NULL) {
		return false;
	}
	query_results->cnids->ca_cnids = talloc_zero(query_results->cnids,
						     DALLOC_CTX);
	if (query_results->cnids->ca_cnids == NULL) {
		return false;
	}

	query_results->cnids->ca_unkn1 = 0xadd;
	query_results->cnids->ca_context = slq->ctx2;

	/* FileMeta */
	query_results->fm_array = talloc_zero(query_results, sl_array_t);
	if (query_results->fm_array == NULL) {
		return false;
	}

	/* For some reason the list of results always starts with a nil entry */
	dalloc_add_copy(query_results->fm_array, &nil, sl_nil_t);

	slq->query_results = query_results;
	return true;
}

static bool add_results(sl_array_t *array, struct sl_query *slq)
{
	sl_filemeta_t *fm;
	uint64_t status = 0;

	/* FileMeta */
	fm = talloc_zero(array, sl_filemeta_t);
	if (!fm) {
		return false;
	}

	dalloc_add_copy(array, &status, uint64_t);
	dalloc_add(array, slq->query_results->cnids, sl_cnids_t);
	if (slq->query_results->num_results > 0) {
		dalloc_add(fm, slq->query_results->fm_array, sl_array_t);
	}
	dalloc_add(array, fm, sl_filemeta_t);

	/* This ensure the results get clean up after been sent to the client */
	talloc_steal(array, slq->query_results);
	slq->query_results = NULL;

	if (!create_result_handle(slq)) {
		DEBUG(1, ("couldn't add result handle\n"));
		slq->state = SLQ_STATE_ERROR;
		return false;
	}

	return true;
}

/************************************************
 * Hash functions
 ************************************************/

static bool sl_ino_cmp(const void *candidate, void *ptr)
{
	uint64_t key = *((uint64_t *)ptr);
	const struct sl_ino_path *elem = candidate;

	if (elem->ino == key) {
		return true;
	}
	return false;
}

static size_t sl_ino_hash(const void *elem, void *unused)
{
	return hash(&((struct sl_ino_path *)elem)->ino, 1, 0);
}

static int sl_ino_unhash(struct sl_ino_path *elem)
{
	if (!htable_del(&elem->mds_ctx->results_ht,
			hash(&elem->ino, 1, 0),
			elem)) {
		return -1;
	}
	return 0;
}

static bool slrpc_cmd_cmp(const void *candidate, void *ptr)
{
	char *key = ptr;
	const struct sl_rpc_cmd *elem = candidate;

	if (strequal(elem->name, key)) {
		return true;
	}
	return false;
}

static size_t slrpc_hash(const void *elem, void *unused)
{
	return hash_string(((struct sl_rpc_cmd *)elem)->name);
}

/************************************************
 * Maintain a list of active Spotlight queries
 ************************************************/

/**
 * Add a query to the list of active queries
 **/
static void slq_add(struct mds_ctx *mds_ctx, struct sl_query *slq)
{
	DLIST_ADD(mds_ctx->query_list, slq);
}

/**
 * Remove a query from the list of active queries
 **/
static bool slq_remove(struct mds_ctx *mds_ctx, struct sl_query *slq)
{
    struct sl_query *q = mds_ctx->query_list;

    while (q) {
	    if ((q->ctx1 == slq->ctx1) && (q->ctx2 == slq->ctx2)) {
		    DLIST_REMOVE(mds_ctx->query_list, q);
		    break;
	    }
	    q = q->next;
    }

    if (q == NULL) {
	    /*
	     * The query was not found in the list, this is not
	     * supposed to happen!
	     */
	    DEBUG(1, ("slq_remove: slq not in active query list\n"));
	    return false;
    }

    return true;
}

/**
 * Search the list of active queries given their context ids
 **/
static struct sl_query *slq_for_ctx(struct mds_ctx *mds_ctx,
				    uint64_t ctx1, uint64_t ctx2)
{
	struct sl_query *q = mds_ctx->query_list;

	while (q) {
		if ((q->ctx1 == ctx1) && (q->ctx2 == ctx2)) {
			return q;
		}
		q = q->next;
	}

	return NULL;
}

/**
 * Error handling for queries
 **/
static void slq_error(struct mds_ctx *mds_ctx, struct sl_query *slq)
{
	if (!slq) {
		return;
	}
	if (slq->tracker_cursor) {
		g_object_unref(slq->tracker_cursor);
	}
	(void)slq_remove(mds_ctx, slq);
	talloc_free(slq);
}

static int slq_destructor_cb(struct sl_query *slq)
{
	if (slq->tracker_cursor) {
		g_object_unref(slq->tracker_cursor);
	}
	return 0;
}

/************************************************
 * Tracker async callbacks
 ************************************************/

static void tracker_con_cb(GObject      *object,
			   GAsyncResult *res,
			   gpointer      user_data)
{
	struct mds_ctx *mds_ctx = user_data;
	GError *error = NULL;

	mds_ctx->tracker_con = tracker_sparql_connection_get_finish(res,
								    &error);
	if (error) {
		DEBUG(1, ("Could not connect to Tracker: %s\n",
			  error->message));
		g_error_free(error);
	}
	DEBUG(10, ("connected to Tracker\n"));
}

static void tracker_cursor_cb(GObject      *object,
			      GAsyncResult *res,
			      gpointer      user_data)
{
	GError *error = NULL;
	struct sl_query *slq = user_data;
	gboolean more_results;
	const gchar *uri;
	char *path;
	int result;
	struct stat_ex sb;
	struct sl_ino_path *result_elem;
	uint64_t uint64var;
	bool ok;
	struct tevent_req *req;

	DEBUG(10,("tracker_cursor_cb(%" PRIx64 ", %" PRIx64 ")\n",
		 slq->ctx1, slq->ctx2));

	more_results = tracker_sparql_cursor_next_finish(slq->tracker_cursor,
							 res,
							 &error);

	if (slq->state == SLQ_STATE_DONE) {
		DEBUG(10,("tracker_cursor_cb(%" PRIx64 ", %" PRIx64 "): done\n",
			 slq->ctx1, slq->ctx2));
		/*
		 * We have to shedule the deallocation via tevent,
		 * because we have to unref the cursor glib object and
		 * we can't do it here, because it's still used after
		 * we return.
		 *
		 * We're not interested in the tevent req so we don't
		 * keep a reference on it, by using slq as the memory
		 * context for the tevent req, we ensure it gets
		 * deallocated in slq_destroy_done().
		 */
		req = slq_destroy_send(slq, server_event_context(), slq);
		if (req == NULL) {
			slq->state = SLQ_STATE_ERROR;
			return;
		}
		tevent_req_set_callback(req, slq_destroy_done, slq);
		return;
	}

	if (error) {
		DEBUG(1, ("Tracker cursor: %s\n", error->message));
		g_error_free(error);
		slq->state = SLQ_STATE_ERROR;
		return;
	}

	if (!more_results) {
		slq->state = SLQ_STATE_DONE;
		return;
	}

	uri = tracker_sparql_cursor_get_string(slq->tracker_cursor, 0, NULL);
	path = tracker_to_unix_path(slq->query_results, uri);
	if (!path) {
		DEBUG(1, ("error converting Tracker URI to path: %s\n", uri));
		slq->state = SLQ_STATE_ERROR;
		return;
	}

	/*
	 * This would be the place to add additional permission checks.
	 * The stat() already fails if the user doesn't have access to
	 * the directory. What's missing would be a check for read
	 * access to a file.
	 */
	result = sys_stat(path, &sb, false);
	if (result != 0) {
		goto exit;
	}
	result = access(path, R_OK);
	if (result != 0) {
		goto exit;
	}

	uint64var = sb.st_ex_ino;
	if (slq->cnids) {
		/*
		 * Check whether the found element is in the requested
		 * set of IDs. Note that we're faking CNIDs by using
		 * filesystem inode numbers here
		 */
		ok = bsearch(&uint64var, slq->cnids, slq->cnids_num,
			     sizeof(uint64_t), cnid_comp_fn);
		if (!ok) {
			goto exit;
		}
	}

	/* Add ino and path to our result hash table */
	result_elem = talloc_zero(slq, struct sl_ino_path);
	if (result_elem == NULL) {
		DEBUG(1, ("talloc error\n"));
		slq->state = SLQ_STATE_ERROR;
		return;
	}
	talloc_set_destructor(result_elem, sl_ino_unhash);
	result_elem->mds_ctx = slq->mds_ctx;
	result_elem->ino = sb.st_ex_ino;
	result_elem->path = talloc_strdup(result_elem, path);
	ok = htable_add(&slq->mds_ctx->results_ht,
			sl_ino_hash(result_elem, NULL),
			result_elem);
	if (!ok) {
		DEBUG(1, ("htable_add error\n"));
		slq->state = SLQ_STATE_ERROR;
		return;
	}

	/* Add inode number and filemeta to result set */
	dalloc_add_copy(slq->query_results->cnids->ca_cnids,
			&uint64var, uint64_t);
	ok = add_filemeta(slq->reqinfo, slq->query_results->fm_array,
			  path, &sb);
	if (!ok) {
		DEBUG(1, ("add_filemeta error\n"));
		slq->state = SLQ_STATE_ERROR;
		return;
	}

	slq->query_results->num_results++;

exit:
	if (slq->query_results->num_results < MAX_SL_RESULTS) {
		slq->state = SLQ_STATE_RESULTS;
		DEBUG(10,("tracker_cursor_cb(%" PRIx64 ", %" PRIx64 "): cursor next\n",
			 slq->ctx1, slq->ctx2));
		tracker_sparql_cursor_next_async(slq->tracker_cursor,
						 slq->mds_ctx->cancellable,
						 tracker_cursor_cb,
						 slq);
	} else {
		slq->state = SLQ_STATE_FULL;
	}
}

static void tracker_query_cb(GObject      *object,
			     GAsyncResult *res,
			     gpointer      user_data)
{
	bool ok;
	GError *error = NULL;
	struct sl_query *slq = user_data;

	DEBUG(10,("tracker_query_cb(%" PRIx64 ", %" PRIx64 ")\n",
		 slq->ctx1, slq->ctx2));

	slq->tracker_cursor = tracker_sparql_connection_query_finish(
		TRACKER_SPARQL_CONNECTION(object),
		res,
		&error);

	if (slq->state == SLQ_STATE_DONE) {
		DEBUG(10,("tracker_query_cb(%" PRIx64 ", %" PRIx64 "): done\n",
			 slq->ctx1, slq->ctx2));
		return;;
	}

	if (error) {
		slq->state = SLQ_STATE_ERROR;
		DEBUG(1, ("Tracker query error: %s\n", error->message));
		g_error_free(error);
		return;
	}

	slq->state = SLQ_STATE_RESULTS;

	tracker_sparql_cursor_next_async(slq->tracker_cursor,
					 slq->mds_ctx->cancellable,
					 tracker_cursor_cb,
					 slq);
}

/***********************************************************
 * Spotlight RPC functions
 ***********************************************************/

static bool slrpc_fetch_properties(struct mds_ctx *mds_ctx,
				   const DALLOC_CTX *query, DALLOC_CTX *reply)
{
	sl_dict_t *dict;
	sl_array_t *array;
	char *s;
	uint64_t u;
	sl_bool_t b;
	sl_uuid_t uuid;

	DEBUG(10, ("slrpc_fetch_properties\n"));

	dict = talloc_zero(reply, sl_dict_t);
	if (dict == NULL) {
		return false;
	}

	/* kMDSStoreHasPersistentUUID = false */
	s = dalloc_strdup(dict, "kMDSStoreHasPersistentUUID");
	dalloc_add(dict, s, char *);
	b = false;
	dalloc_add_copy(dict, &b, sl_bool_t);

	/* kMDSStoreIsBackup = false */
	s = dalloc_strdup(dict, "kMDSStoreIsBackup");
	dalloc_add(dict, s, char *);
	b = false;
	dalloc_add_copy(dict, &b, sl_bool_t);

	/* kMDSStoreUUID = uuid */
	s = dalloc_strdup(dict, "kMDSStoreUUID");
	dalloc_add(dict, s, char *);
	memcpy(uuid.sl_uuid, "fakeuuidfakeuuid", strlen("fakeuuidfakeuuid"));
	dalloc_add_copy(dict, &uuid, sl_uuid_t);

	/* kMDSStoreSupportsVolFS = true */
	s = dalloc_strdup(dict, "kMDSStoreSupportsVolFS");
	dalloc_add(dict, s, char *);
	b = true;
	dalloc_add_copy(dict, &b, sl_bool_t);

	/* kMDSVolumeUUID = uuid */
	s = dalloc_strdup(dict, "kMDSVolumeUUID");
	dalloc_add(dict, s, char *);
	memcpy(uuid.sl_uuid, "fakeuuidfakeuuid", strlen("fakeuuidfakeuuid"));
	dalloc_add_copy(dict, &uuid, sl_uuid_t);

	/* kMDSDiskStoreSpindleNumber = 1 (fake) */
	s = dalloc_strdup(dict, "kMDSDiskStoreSpindleNumber");
	dalloc_add(dict, s, char *);
	u = 1;
	dalloc_add_copy(dict, &u, uint64_t);

	/* kMDSDiskStorePolicy = 3 (whatever that means, taken from OS X) */
	s = dalloc_strdup(dict, "kMDSDiskStorePolicy");
	dalloc_add(dict, s, char *);
	u = 3;
	dalloc_add_copy(dict, &u, uint64_t);

	/* kMDSStoreMetaScopes array */
	array = talloc_zero(dict, sl_array_t);
	s = dalloc_strdup(dict, "kMDQueryScopeComputer");
	dalloc_add(array, s, char *);
	s = dalloc_strdup(dict, "kMDQueryScopeAllIndexed");
	dalloc_add(array, s, char *);
	s = dalloc_strdup(dict, "kMDQueryScopeComputerIndexed");
	dalloc_add(array, s, char *);
	dalloc_add(dict, array, sl_array_t);

	/* kMDSStoreDevice = 0x1000003 (whatever that means, taken from OS X) */
	s = dalloc_strdup(dict, "kMDSStoreDevice");
	dalloc_add(dict, s, char *);
	u = 0x1000003;
	dalloc_add_copy(dict, &u, uint64_t);

	/* kMDSStoreSupportsTCC = true (whatever that means, taken from OS X) */
	s = dalloc_strdup(dict, "kMDSStoreSupportsTCC");
	dalloc_add(dict, s, char *);
	b = true;
	dalloc_add_copy(dict, &b, sl_bool_t);

	/* kMDSStorePathScopes = ["/"] (whatever that means, taken from OS X) */
	s = dalloc_strdup(dict, "kMDSStorePathScopes");
	dalloc_add(dict, s, char *);
	array = talloc_zero(dict, sl_array_t);
	s = talloc_strdup(dict, "/");
	talloc_set_name(s, "smb_ucs2_t *");
	dalloc_add(array, s, smb_ucs2_t *);
	dalloc_add(dict, array, sl_array_t);

	dalloc_add(reply, dict, sl_dict_t);

	return true;
}

/**
 * Begin a search query
 **/
static bool slrpc_open_query(struct mds_ctx *mds_ctx,
			     const DALLOC_CTX *query, DALLOC_CTX *reply)
{
	bool ok;
	uint64_t sl_result;
	uint64_t *uint64p;
	DALLOC_CTX *reqinfo;
	sl_array_t *array, *path_scope;
	sl_cnids_t *cnids;
	struct sl_query *slq = NULL;
	gchar *sparql_query;
	GError *error = NULL;

	array = talloc_zero(reply, sl_array_t);
	if (array == NULL) {
		return false;
	}

	if (mds_ctx->tracker_con == NULL) {
		DEBUG(1, ("no connection to Tracker\n"));
		goto error;
	}

	/* Allocate and initialize query object */
	slq = talloc_zero(mds_ctx, struct sl_query);
	if (slq == NULL) {
		return false;
	}
	talloc_set_destructor(slq, slq_destructor_cb);
	slq->state = SLQ_STATE_NEW;
	slq->mds_ctx = mds_ctx;
	slq->query_string = dalloc_value_for_key(query, "DALLOC_CTX", 0,
						 "DALLOC_CTX", 1,
						 "kMDQueryString");
	if (slq->query_string == NULL) {
		DEBUG(1, ("missing kMDQueryString\n"));
		goto error;
	}

	/*
	 * FIXME:
	 * convert spotlight query charset UTF8-MAC to host charset
	 */

	DEBUG(10, ("sl_rpc_openQuery: %s\n", slq->query_string));

	slq->started = time(NULL);
	uint64p = dalloc_get(query, "DALLOC_CTX", 0, "DALLOC_CTX", 0,
			     "uint64_t", 1);
	if (uint64p == NULL) {
		goto error;
	}
	slq->ctx1 = *uint64p;
	uint64p = dalloc_get(query, "DALLOC_CTX", 0, "DALLOC_CTX", 0,
			     "uint64_t", 2);
	if (uint64p == NULL) {
		goto error;
	}
	slq->ctx2 = *uint64p;

	path_scope = dalloc_value_for_key(query, "DALLOC_CTX", 0,
					  "DALLOC_CTX", 1, "kMDScopeArray");
	if (path_scope == NULL) {
		goto error;
	}

	slq->path_scope = dalloc_get(path_scope, "char *", 0);
	if (slq->path_scope == NULL) {
		goto error;
	}

	slq->path_scope = talloc_strdup(slq, slq->path_scope);
	if (slq->path_scope == NULL) {
		goto error;
	}

	DEBUG(10, ("path scope: %s\n", slq->path_scope));

	reqinfo = dalloc_value_for_key(query, "DALLOC_CTX", 0,
				       "DALLOC_CTX", 1, "kMDAttributeArray");
	if (reqinfo == NULL) {
		goto error;
	}

	slq->reqinfo = talloc_steal(slq, reqinfo);
	DEBUG(10, ("requested attributes: %s", dd_dump(reqinfo, 0)));

	cnids = dalloc_value_for_key(query, "DALLOC_CTX", 0,
				     "DALLOC_CTX", 1, "kMDQueryItemArray");
	if (cnids) {
		ok = sort_cnids(slq, cnids->ca_cnids);
		if (!ok) {
			goto error;
		}
	}

	ok = create_result_handle(slq);
	if (!ok) {
		DEBUG(1, ("create_result_handle error\n"));
		slq->state = SLQ_STATE_ERROR;
		return;
	}

	slq_add(mds_ctx, slq);

	ok = map_spotlight_to_sparql_query(slq, &sparql_query);
	if (!ok) {
		/*
		 * Two cases:
		 *
		 * 1) the query string is "false", the parser returns
		 * an error for that. We're supposed to return -1
		 * here.
		 *
		 * 2) the parsing really failed, in that case we're
		 * probably supposed to return -1 too, this needs
		 * verification though
		 */
		goto error;
	}

	DEBUG(10, ("SPARQL query: \"%s\"\n", sparql_query));

	tracker_sparql_connection_query_async(mds_ctx->tracker_con,
					      sparql_query,
					      mds_ctx->cancellable,
					      tracker_query_cb,
					      slq);

	if (error) {
		DEBUG(1, ("Couldn't query the Tracker Store: '%s'\n",
			  error ? error->message : "unknown error"));
		g_clear_error(&error);
		goto error;
	}

	slq->state = SLQ_STATE_RUNNING;
	sl_result = 0;
	dalloc_add_copy(array, &sl_result, uint64_t);
	dalloc_add(reply, array, sl_array_t);
	return true;

error:
	sl_result = UINT64_MAX;
	slq_error(mds_ctx, slq);
	dalloc_add_copy(array, &sl_result, uint64_t);
	dalloc_add(reply, array, sl_array_t);
	return true;
}

/**
 * Fetch results of a query
 **/
static bool slrpc_fetch_query_results(struct mds_ctx *mds_ctx,
				      const DALLOC_CTX *query,
				      DALLOC_CTX *reply)
{
	bool ok;
	struct sl_query *slq = NULL;
	uint64_t *uint64p, ctx1, ctx2;
	uint64_t status;
	sl_array_t *array;

	array = talloc_zero(reply, sl_array_t);
	if (array == NULL) {
		return false;
	}

	/* Get query for context */
	uint64p = dalloc_get(query, "DALLOC_CTX", 0, "DALLOC_CTX", 0,
			     "uint64_t", 1);
	if (uint64p == NULL) {
		goto error;
	}
	ctx1 = *uint64p;

	uint64p = dalloc_get(query, "DALLOC_CTX", 0, "DALLOC_CTX", 0,
			     "uint64_t", 2);
	if (uint64p == NULL) {
		goto error;
	}
	ctx2 = *uint64p;

	slq = slq_for_ctx(mds_ctx, ctx1, ctx2);
	if (slq == NULL) {
		DEBUG(1, ("slrpc_fetch_query_results: bad context\n"));
		goto error;
	}

	switch (slq->state) {
	case SLQ_STATE_RUNNING:
	case SLQ_STATE_RESULTS:
	case SLQ_STATE_FULL:
	case SLQ_STATE_DONE:
		ok = add_results(array, slq);
		if (!ok) {
			DEBUG(1, ("error adding results\n"));
			goto error;
		}
		if (slq->state == SLQ_STATE_FULL) {
			slq->state = SLQ_STATE_RESULTS;
			tracker_sparql_cursor_next_async(
				slq->tracker_cursor,
				slq->mds_ctx->cancellable,
				tracker_cursor_cb,
				slq);
		}
		break;

	case SLQ_STATE_ERROR:
		DEBUG(1, ("query in error state\n"));
		goto error;

	default:
		DEBUG(1, ("unexpected query state %d\n", slq->state));
		status = UINT64_MAX;
		slq_error(mds_ctx, slq);
		goto error;
	}

	dalloc_add(reply, array, sl_array_t);
	return true;

error:
	status = UINT64_MAX;
	slq_error(mds_ctx, slq);
	dalloc_add_copy(array, &status, uint64_t);
	dalloc_add(reply, array, sl_array_t);
	return true;
}

/**
 * Store metadata attributes for a CNID
 **/
static bool slrpc_store_attributes(struct mds_ctx *mds_ctx,
				   const DALLOC_CTX *query, DALLOC_CTX *reply)
{
	uint64_t sl_result;
	sl_array_t *array;

	array = talloc_zero(reply, sl_array_t);
	if (array == NULL) {
		return false;
	}

	/*
	 * FIXME: not implemented. Used by the client for eg setting
	 * the modification date of the shared directory which clients
	 * poll indicating changes on the share and cause the client
	 * to refresh view.
	 */

	sl_result = 0;
	dalloc_add_copy(array, &sl_result, uint64_t);
	dalloc_add(reply, array, sl_array_t);

	return true;
}

/**
 * Fetch supported metadata attributes for a CNID
 **/
static bool slrpc_fetch_attributenames(struct mds_ctx *mds_ctx,
				       const DALLOC_CTX *query,
				       DALLOC_CTX *reply)
{
	uint64_t id;
	sl_cnids_t *cnids;
	sl_array_t *array;
	uint64_t sl_result;
	sl_cnids_t *replycnids;
	sl_array_t *mdattrs;
	sl_filemeta_t *fmeta;

	cnids = dalloc_get(query, "DALLOC_CTX", 0, "sl_cnids_t", 1);
	if (!cnids) {
		return false;
	}

	memcpy(&id, cnids->ca_cnids->dd_talloc_array[0], sizeof(uint64_t));

	/* Result array */
	array = talloc_zero(reply, sl_array_t);
	if (!array) {
		return false;
	}

	dalloc_add(reply, array, sl_array_t);

	/* Return result value 0 */
	sl_result = 0;
	dalloc_add_copy(array, &sl_result, uint64_t);

	/* Return CNID array */
	replycnids = talloc_zero(reply, sl_cnids_t);
	if (!replycnids) {
		return false;
	}

	replycnids->ca_cnids = talloc_zero(cnids, DALLOC_CTX);
	if (!replycnids->ca_cnids) {
		return false;
	}

	replycnids->ca_unkn1 = 0xfec;
	replycnids->ca_context = cnids->ca_context;
	dalloc_add_copy(replycnids->ca_cnids, &id, uint64_t);
	dalloc_add(array, replycnids, sl_cnids_t);

	/*
	 * FIXME: this should return the real attributes from all
	 * known metadata sources (Tracker and filesystem)
	 */
	mdattrs = talloc_zero(reply, sl_array_t);
	if (!mdattrs) {
		return false;
	}

	dalloc_add(mdattrs,
		   dalloc_strdup(mdattrs, "kMDItemFSName"), "char *");
	dalloc_add(mdattrs,
		   dalloc_strdup(mdattrs, "kMDItemDisplayName"),
		   "char *");
	dalloc_add(mdattrs, dalloc_strdup(mdattrs, "kMDItemFSSize"), "char *");
	dalloc_add(mdattrs,
		   dalloc_strdup(mdattrs, "kMDItemFSOwnerUserID"),
		   "char *");
	dalloc_add(mdattrs,
		   dalloc_strdup(mdattrs, "kMDItemFSOwnerGroupID"),
		   "char *");
	dalloc_add(mdattrs,
		   dalloc_strdup(mdattrs, "kMDItemFSContentChangeDate"),
		   "char *");

	fmeta = talloc_zero(reply, sl_filemeta_t);
	if (!fmeta) {
		return false;
	}
	dalloc_add(fmeta, mdattrs, sl_array_t);
	dalloc_add(array, fmeta, sl_filemeta_t);

	return true;
}

/**
 * Fetch metadata attribute values for a CNID
 **/
static bool slrpc_fetch_attributes(struct mds_ctx *mds_ctx,
				   const DALLOC_CTX *query, DALLOC_CTX *reply)
{
	int result;
	bool ok;
	sl_array_t *array;
	sl_cnids_t *cnids;
	sl_cnids_t *replycnids;
	sl_array_t *reqinfo;
	uint64_t ino;
	uint64_t sl_result;
	sl_filemeta_t *fm;
	sl_array_t *fm_array;
	sl_nil_t nil;
	struct stat_ex sb;
	struct sl_ino_path *elem;

	array = talloc_zero(reply, sl_array_t);
	if (array == NULL) {
		return false;
	}
	replycnids = talloc_zero(reply, sl_cnids_t);
	if (replycnids == NULL) {
		goto error;
	}
	replycnids->ca_cnids = talloc_zero(replycnids, DALLOC_CTX);
	if (replycnids->ca_cnids == NULL) {
		goto error;
	}
	fm = talloc_zero(array, sl_filemeta_t);
	if (fm == NULL) {
		goto error;
	}
	fm_array = talloc_zero(fm, sl_array_t);
	if (fm_array == NULL) {
		goto error;
	}
	/* For some reason the list of results always starts with a nil entry */
	dalloc_add_copy(fm_array, &nil, sl_nil_t);

	reqinfo = dalloc_get(query, "DALLOC_CTX", 0, "sl_array_t", 1);
	if (reqinfo == NULL) {
		goto error;
	}

	cnids = dalloc_get(query, "DALLOC_CTX", 0, "sl_cnids_t", 2);
	if (cnids == NULL) {
		goto error;
	}
	memcpy(&ino, cnids->ca_cnids->dd_talloc_array[0], sizeof(uint64_t));

	replycnids->ca_unkn1 = 0xfec;
	replycnids->ca_context = cnids->ca_context;
	dalloc_add_copy(replycnids->ca_cnids, &ino, uint64_t);

	/* Search hash table with result set */
	elem = htable_get(&mds_ctx->results_ht, hash(&ino, 1, 0),
			  sl_ino_cmp, &ino);
	if (elem) {
		result = sys_stat(elem->path, &sb, false);
		if (result != 0) {
			goto error;
		}
	}

	ok = add_filemeta(reqinfo, fm_array,
			  elem ? elem->path : NULL,
			  elem ? &sb : NULL);
	if (!ok) {
		goto error;
	}

	sl_result = 0;
	dalloc_add_copy(array, &sl_result, uint64_t);
	dalloc_add(array, replycnids, sl_cnids_t);
	dalloc_add(fm, fm_array, fm_array_t);
	dalloc_add(array, fm, sl_filemeta_t);
	dalloc_add(reply, array, sl_array_t);

	return true;

error:
	sl_result = UINT64_MAX;
	dalloc_add_copy(array, &sl_result, uint64_t);
	dalloc_add(reply, array, sl_array_t);

	return true;
}

/**
 * Close a query
 **/
static bool slrpc_close_query(struct mds_ctx *mds_ctx,
			      const DALLOC_CTX *query, DALLOC_CTX *reply)
{
	bool ok;
	struct sl_query *slq = NULL;
	uint64_t *uint64p, ctx1, ctx2;
	sl_array_t *array;
	uint64_t sl_res;

	array = talloc_zero(reply, sl_array_t);
	if (array == NULL) {
		return false;
	}

	/* Context */
	uint64p = dalloc_get(query, "DALLOC_CTX", 0, "DALLOC_CTX", 0,
			     "uint64_t", 1);
	if (uint64p == NULL) {
		goto exit;
	}
	ctx1 = *uint64p;

	uint64p = dalloc_get(query, "DALLOC_CTX", 0, "DALLOC_CTX", 0,
			     "uint64_t", 2);
	if (uint64p == NULL) {
		goto exit;
	}
	ctx2 = *uint64p;

	/* Get query for context and free it */
	slq = slq_for_ctx(mds_ctx, ctx1, ctx2);
	if (slq == NULL) {
		goto exit;
	}

	switch (slq->state) {
	case SLQ_STATE_RUNNING:
	case SLQ_STATE_RESULTS:
		DEBUG(10, ("close: requesting query close\n"));
		/*
		 * Mark the query is done so the cursor callback can
		 * act accordingly by stopping to request more results
		 * and sheduling query resource deallocation via
		 * tevent.
		 */
		slq->state = SLQ_STATE_DONE;
		slq_remove(mds_ctx, slq);
		break;

	case SLQ_STATE_FULL:
	case SLQ_STATE_DONE:
		DEBUG(10, ("close: query was done or result queue was full\n"));
		slq_remove(mds_ctx, slq);
		/*
		 * We can directly deallocate the query because there
		 * are no pending Tracker async calls in flight in
		 * these query states.
		 */
		talloc_free(slq);
		break;

	default:
		DEBUG(1, ("close: unexpected state: %d\n", slq->state));
		break;
	}


exit:
	sl_res = 0;
	dalloc_add_copy(array, &sl_res, uint64_t);
	dalloc_add(reply, array, sl_array_t);
	return true;
}

/**
 * Init callbacks in main smbd, nothing to do here really
 **/
bool mds_init(struct messaging_context *msg_ctx)
{
	return true;
}

bool mds_shutdown(void)
{
	return true;
}

/**
 * Initialisation after forking smbd
 **/
static struct mds_ctx *mds_init_proc(void)
{
	int i;
	static struct mds_ctx *mds_ctx = NULL;

	if (mds_ctx) {
		return mds_ctx;
	}

	mds_ctx = talloc_zero(NULL, struct mds_ctx);
	if (mds_ctx == NULL) {
		return false;
	}

	/*
	 * Tracker uses glibs event dispatching, so we need a mainloop
	 */
	mds_ctx->mainloop = g_main_loop_new(NULL, false);
	mds_ctx->cancellable = g_cancellable_new();

	tracker_sparql_connection_get_async(mds_ctx->cancellable,
					    tracker_con_cb, mds_ctx);

	/* Initialize hashtable for results */
	htable_init(&mds_ctx->results_ht, sl_ino_hash, NULL);

	/* Initialize hashtable with RPC commands */
	htable_init(&mds_ctx->slprpc_cmd_ht, slrpc_hash, NULL);
	i = 0;
	while (sl_rpc_cmds[i].name != NULL) {
		if (!htable_add(&mds_ctx->slprpc_cmd_ht,
				hash_string(sl_rpc_cmds[i].name),
				&sl_rpc_cmds[i])) {
			talloc_free(mds_ctx);
			return NULL;
		}
		i++;
	}

	return mds_ctx;
}

/**
 * Tear down connections and free all resources, not used atm
 **/
#if 0
static bool mds_shutdown_proc(struct mds_ctx *mds_ctx)
{
	htable_clear(&mds_ctx->slprpc_cmd_ht);
	if (mds_ctx->tracker_con) {
		g_object_unref(mds_ctx->tracker_con);
	}
	g_cancellable_cancel(mds_ctx->cancellable);
	g_object_unref(mds_ctx->cancellable);
	g_main_loop_unref(mds_ctx->mainloop);

	talloc_free(mds_ctx);
	return true;
}
#endif

/**
 * Dispatch a Spotlight RPC command
 **/
bool mds_dispatch(struct mds_query_ctx *query_ctx)
{
	bool ok, event;
	ssize_t len;
	DALLOC_CTX *query;
	DALLOC_CTX *reply;
	char *rpccmd;
	struct sl_rpc_cmd *sl_rpc_cmd;
	struct mds_ctx *mds_ctx = NULL;

	query_ctx->response_blob->length = 0;

	mds_ctx = mds_init_proc();
	if (mds_ctx == NULL) {
		return false;
	}

	mds_ctx->query_ctx = query_ctx;

	/*
	 * Process finished glib events
	 */
	event = true;
	while (event) {
		event = g_main_context_iteration(NULL, false);
	}

	DEBUG(10, ("share path: %s\n", query_ctx->spath));

	query = talloc_zero(query_ctx, DALLOC_CTX);
	reply = talloc_zero(query_ctx, DALLOC_CTX);
	if (!query || !reply) {
		return false;
	}

	ok = sl_unpack(query, query_ctx->request_blob->spotlight_blob);
	if (!ok) {
		DEBUG(1, ("error unpacking Spotlight RPC blob\n"));
		return false;
	}

	DEBUG(10, ("%s", dd_dump(query, 0)));

	rpccmd = dalloc_get(query, "DALLOC_CTX", 0, "DALLOC_CTX", 0,
			    "char *", 0);
	if (rpccmd == NULL) {
		DEBUG(1, ("missing primary Spotlight RPC command\n"));
		return false;
	}

	DEBUG(10, ("Spotlight RPC cmd: %s\n", rpccmd));

	sl_rpc_cmd = htable_get(&mds_ctx->slprpc_cmd_ht,
				hash_string(rpccmd),
				slrpc_cmd_cmp, rpccmd);
	if (sl_rpc_cmd == NULL) {
		DEBUG(1, ("unsupported primary Spotlight RPC command %s\n",
			  rpccmd));
		return false;
	}

	/*
	 * If these functions return an error, they hit something like
	 * a non recoverable talloc error
	 */
	ok = (*(sl_rpc_cmd->function))(mds_ctx, query, reply);
	if (!ok) {
		DEBUG(1, ("error in Spotlight RPC handler\n"));
		return false;
	}

	DEBUG(10, ("%s", dd_dump(reply, 0)));

	len = sl_pack(reply, query_ctx->response_blob->spotlight_blob);
	if (len == -1) {
		DEBUG(1, ("error packing Spotlight RPC reply\n"));
		return false;
	}

	query_ctx->response_blob->length = len;

	return true;
}
