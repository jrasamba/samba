/*
   Unix SMB/CIFS implementation.
   Main metadata server / Spotlight routines

   Copyright (C) Ralph Boehme 2012-2014

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

%{
	#include "includes.h"
	#include "mdssvc.h"
	#include "sparql_mapping.h"

	#define YYMALLOC SMB_MALLOC
	#define YYREALLOC SMB_REALLOC

	struct yy_buffer_state;
	typedef struct yy_buffer_state *YY_BUFFER_STATE;
	extern int yylex (void);
	extern void yyerror (char const *);
	extern void *yyterminate(void);
	extern YY_BUFFER_STATE yy_scan_string( const char *str);
	extern void yy_delete_buffer ( YY_BUFFER_STATE buffer );

	/* forward declarations */
	static const char *map_expr(const char *attr, char op, const char *val);
	static const char *map_daterange(const char *dateattr,
					 time_t date1, time_t date2);
	static time_t isodate2unix(const char *s);
 
	/* global vars, eg needed by the lexer */
	struct sl_query *ssp_slq;

	/* local vars */
	static char *ssp_result;
	static char sparqlvar;
%}

%code provides {
	#define SPRAW_TIME_OFFSET 978307200
	extern bool map_spotlight_to_sparql_query(struct sl_query *slq,
						  char **sparql_result);
	extern struct sl_query *ssp_slq;
}

%union {
	int ival;
	const char *sval;
	bool bval;
	time_t tval;
}

%expect 5
%error-verbose

%type <sval> match expr line function
%type <tval> date

%token <sval> WORD
%token <bval> BOOL
%token FUNC_INRANGE
%token DATE_ISO
%token OBRACE CBRACE EQUAL UNEQUAL GT LT COMMA QUOTE
%left AND
%left OR
%%

input:
/* empty */
| input line
;
     
line:
expr {
	ssp_result = talloc_asprintf(
		ssp_slq,
		"SELECT ?url WHERE { %s . ?obj nie:url ?url . "
		"FILTER(tracker:uri-is-descendant('file://%s/', ?url)) }",
		$1, ssp_slq->path_scope);
	$$ = ssp_result;
}
;

expr:
BOOL {
	/*
	 * We can't properly handle these in expressions, fortunately this
	 * is probably only ever used by OS X as sole element in an
	 * expression ie "False" (when Finder window selected our share
	 * but no search string entered yet). Packet traces showed that OS
	 * X Spotlight server then returns a failure (ie -1) which is what
	 * we do here too by calling YYABORT.
	 */
	YYABORT;
}
| match OR match {
	if (strcmp($1, $3) != 0) {
		$$ = talloc_asprintf(ssp_slq, "{ %s } UNION { %s }", $1, $3);
	} else {
		$$ = talloc_asprintf(ssp_slq, "%s", $1);
	}
}
| match {
	$$ = $1; if ($$ == NULL) YYABORT;
}
| function {
	$$ = $1;
}
| OBRACE expr CBRACE {
	$$ = talloc_asprintf(ssp_slq, "%s", $2);
}
| expr AND expr {
	$$ = talloc_asprintf(ssp_slq, "%s . %s", $1, $3);
}
| expr OR expr {
	if (strcmp($1, $3) != 0) {
		$$ = talloc_asprintf(ssp_slq, "{ %s } UNION { %s }", $1, $3);
	} else {
		$$ = talloc_asprintf(ssp_slq, "%s", $1);
	}
}
;

match:
WORD EQUAL QUOTE WORD QUOTE     {$$ = map_expr($1, '=', $4);}
| WORD UNEQUAL QUOTE WORD QUOTE {$$ = map_expr($1, '!', $4);}
| WORD LT QUOTE WORD QUOTE      {$$ = map_expr($1, '<', $4);}
| WORD GT QUOTE WORD QUOTE      {$$ = map_expr($1, '>', $4);}
| WORD EQUAL QUOTE WORD QUOTE WORD    {$$ = map_expr($1, '=', $4);}
| WORD UNEQUAL QUOTE WORD QUOTE WORD {$$ = map_expr($1, '!', $4);}
| WORD LT QUOTE WORD QUOTE WORD     {$$ = map_expr($1, '<', $4);}
| WORD GT QUOTE WORD QUOTE WORD     {$$ = map_expr($1, '>', $4);}
;

function:
FUNC_INRANGE OBRACE WORD COMMA date COMMA date CBRACE {
	$$ = map_daterange($3, $5, $7);
}
;

date:
DATE_ISO OBRACE WORD CBRACE    {$$ = isodate2unix($3);}
| WORD                         {$$ = atoi($1) + SPRAW_TIME_OFFSET;}
;

%%

static time_t isodate2unix(const char *s)
{
	struct tm tm;

	if (strptime(s, "%Y-%m-%dT%H:%M:%SZ", &tm) == NULL)
		return (time_t)-1;
	return mktime(&tm);
}

static const char *map_daterange(const char *dateattr,
				 time_t date1, time_t date2)
{
	int result = 0;
	char *sparql = NULL;
	struct spotlight_sparql_map *p;
	struct tm *tmp;
	char buf1[64], buf2[64];

	tmp = localtime(&date1);
	if (!tmp) {
		result = -1;
		goto exit;
	}
	strftime(buf1, sizeof(buf1), "%Y-%m-%dT%H:%M:%SZ", tmp);

	tmp = localtime(&date2);
	if (!tmp) {
		result = -1;
		goto exit;
	}
	strftime(buf2, sizeof(buf2), "%Y-%m-%dT%H:%M:%SZ", tmp);

	for (p = spotlight_sparql_map; p->ssm_spotlight_attr; p++) {
		if (strequal(dateattr, p->ssm_spotlight_attr)) {
			sparql = talloc_asprintf(
				ssp_slq,
				"?obj %s ?%c FILTER (?%c > '%s' && ?%c < '%s')",
				p->ssm_sparql_attr,
				sparqlvar,
				sparqlvar,
				buf1,
				sparqlvar,
				buf2);
			sparqlvar++;
			break;
		}
	}

exit:
	if (result != 0)
		return NULL;
	return sparql;
}

static char *map_type_search(const char *attr, char op, const char *val)
{
	char *result = NULL;
	const char *sparqlAttr;
	struct MDTypeMap *p;

	for (p = MDTypeMap; p->mdtm_value; p++) {
		if (strcmp(p->mdtm_value, val) == 0) {
			switch (p->mdtm_type) {
			case kMDTypeMapRDF:
				sparqlAttr = "rdf:type";
				break;
			case kMDTypeMapMime:
				sparqlAttr = "nie:mimeType";
				break;
			default:
				return NULL;
			}
			result = talloc_asprintf(ssp_slq, "?obj %s '%s'",
						 sparqlAttr,
						 p->mdtm_sparql);
			break;
		}
	}
	return result;
}

static const char *map_expr(const char *attr, char op, const char *val)
{
	int result = 0;
	char *sparql = NULL;
	struct spotlight_sparql_map *p;
	time_t t;
	struct tm *tmp;
	char buf1[64];
	char *q;
	const char *start;

	for (p = spotlight_sparql_map; p->ssm_spotlight_attr; p++) {
		if (strcmp(p->ssm_spotlight_attr, attr) == 0) {
			if (p->ssm_type != ssmt_type
			    && p->ssm_sparql_attr == NULL) {
				yyerror("unsupported Spotlight attribute");
				result = -1;
				goto exit;
			}
			switch (p->ssm_type) {
			case ssmt_bool:
				sparql = talloc_asprintf(
					ssp_slq, "?obj %s '%s'",
					p->ssm_sparql_attr, val);
				if (!sparql) {
					result = -1;
					goto exit;
				}
				break;
			case ssmt_num:
				sparql = talloc_asprintf(
					ssp_slq,
					"?obj %s ?%c FILTER(?%c %c%c '%s')",
					p->ssm_sparql_attr,
					sparqlvar,
					sparqlvar,
					op,
					/* append '=' to '!' */
					op == '!' ? '=' : ' ',
					val);
				if (!sparql) {
					result = -1;
					goto exit;
				}
				sparqlvar++;
				break;
			case ssmt_str:
				q = talloc_strdup(ssp_slq, "");
				if (!q) {
					result = -1;
					goto exit;
				}
				start = val;
				while (*val) {
					if (*val != '*') {
						val++;
						continue;
					}
					if (val > start) {
						q = talloc_strndup_append(
							q, start, val - start);
						if (!q) {
							result = -1;
							goto exit;
						}
					}
					q = talloc_strdup_append(q, ".*");
					if (!q) {
						result = -1;
						goto exit;
					}
					val++;
					start = val;
				}
				if (val > start) {
					q = talloc_strndup_append(
						q, start, val - start);
					if (!q) {
						result = -1;
						goto exit;
					}
				}
				sparql = talloc_asprintf(
					ssp_slq,
					"?obj %s ?%c "
					"FILTER(regex(?%c, '^%s$'))",
					p->ssm_sparql_attr,
					sparqlvar,
					sparqlvar,
					q);
				if (!sparql) {
					result = -1;
					goto exit;
				}
				sparqlvar++;
				break;
			case ssmt_fts:
				sparql = talloc_asprintf(
					ssp_slq, "?obj %s '%s'",
					p->ssm_sparql_attr, val);
				if (!sparql) {
					result = -1;
					goto exit;
				}
				break;
			case ssmt_date:
				t = atoi(val) + SPRAW_TIME_OFFSET;
				tmp = localtime(&t);
				if (!tmp) {
					result = -1;
					goto exit;
				}
				strftime(buf1, sizeof(buf1),
					 "%Y-%m-%dT%H:%M:%SZ", tmp);
				sparql = talloc_asprintf(
					ssp_slq,
					"?obj %s ?%c FILTER(?%c %c '%s')",
					p->ssm_sparql_attr,
					sparqlvar,
					sparqlvar,
					op,
					buf1);
				if (!sparql) {
					result = -1;
					goto exit;
				}
				sparqlvar++;
				break;
			case ssmt_type:
				sparql = map_type_search(attr, op, val);
				if (!sparql) {
					result = -1;
					goto exit;
				}
				break;
			default:
				result = -1;
				goto exit;

			}
			break;
		}
	}

exit:
	if (result != 0) {
		TALLOC_FREE(sparql);
	}
	return sparql;
}

void yyerror(const char *str)
{
#ifdef MAIN
	printf("yyerror: %s\n", str);
#else
	DEBUG(1, ("yyerror: %s", str));
#endif
}
 
int yywrap(void)
{
	return 1;
} 

/**
 * Map a Spotlight RAW query string to a SPARQL query string
 *
 * @param[in]     slq            Spotlight query handle
 * @param[out]    sparql_result  Mapped SPARQL query, string is allocated in
 *                               talloc context of slq
 * @return        true on success, false on error
 **/
bool map_spotlight_to_sparql_query(struct sl_query *slq, char **sparql_result)
{
	int result;
	YY_BUFFER_STATE s = NULL;
	ssp_result = NULL;

	ssp_slq = slq;
	s = yy_scan_string(slq->query_string);
	sparqlvar = 'a';

	result = yyparse();

	if (s) {
		yy_delete_buffer(s);
	}

	if (result != 0) {
		*sparql_result = NULL;
		return false;
	}
	*sparql_result = ssp_result;
	return true;
}

#ifdef MAIN
int main(int argc, char **argv)
{
	int ret;
	YY_BUFFER_STATE s;

	if (argc != 2) {
		printf("usage: %s QUERY\n", argv[0]);
		return 1;
	}

	ssp_slq = talloc_zero(NULL, struct sl_query);
	ssp_slq->path_scope = talloc_strdup(ssp_slq, "/Volumes/test");
	sparqlvar = 'a';

	s = yy_scan_string(argv[1]);

	ret = yyparse();

	yy_delete_buffer(s);

	if (ret == 0)
		printf("SPARQL: %s\n", ssp_result ? ssp_result : "(empty)");

	return 0;
} 
#endif
