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
#include "dalloc.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

#define MAX_SLQ_DAT (64 * 1024)	/* artificial limit */
#define MAX_SLQ_TOC 8192

/******************************************************************************
 * RPC data marshalling and unmarshalling
 ******************************************************************************/

/* Spotlight epoch is UNIX epoch minus SPOTLIGHT_TIME_DELTA */
#define SPOTLIGHT_TIME_DELTA INT64_C(280878921600U)

#define SQ_TYPE_NULL    0x0000
#define SQ_TYPE_COMPLEX 0x0200
#define SQ_TYPE_INT64   0x8400
#define SQ_TYPE_BOOL    0x0100
#define SQ_TYPE_FLOAT   0x8500
#define SQ_TYPE_DATA    0x0700
#define SQ_TYPE_CNIDS   0x8700
#define SQ_TYPE_UUID    0x0e00
#define SQ_TYPE_DATE    0x8600
#define SQ_TYPE_TOC     0x8800

#define SQ_CPX_TYPE_ARRAY           0x0a00
#define SQ_CPX_TYPE_STRING          0x0c00
#define SQ_CPX_TYPE_UTF16_STRING    0x1c00
#define SQ_CPX_TYPE_DICT            0x0d00
#define SQ_CPX_TYPE_CNIDS           0x1a00
#define SQ_CPX_TYPE_FILEMETA        0x1b00

#define SUBQ_SAFETY_LIM 20

/* Forward declarations */
static int sl_pack_loop(DALLOC_CTX *query, char *buf, int offset,
			char *toc_buf, int *toc_idx);
static int sl_unpack_loop(DALLOC_CTX *query, const char *buf, int offset,
			  uint count, const uint toc_offset, const uint encoding);

/******************************************************************************
 * Wrapper functions for the *VAL macros with bound checking
 ******************************************************************************/

static int sivalc(char *buf, off_t off, off_t maxoff, uint32_t val)
{
	if (off + sizeof(val) >= maxoff) {
		DEBUG(1, ("sivalc: off: %zd, maxoff: %zd", off, maxoff));
		return -1;
	}
	SIVAL(buf, off, val);
	return 0;
}

static int slvalc(char *buf, off_t off, off_t maxoff, uint64_t val)
{
	if (off + sizeof(val) >= maxoff) {
		DEBUG(1, ("slvalc: off: %zd, maxoff: %zd", off, maxoff));
		return -1;
	}
	SBVAL(buf, off, val);
	return 0;
}

/*
 * Returns the UTF-16 string encoding, by checking the 2-byte byte order mark.
 * If there is no byte order mark, -1 is returned.
 */
static uint spotlight_get_utf16_string_encoding(const char *buf, int offset,
						int query_length, uint encoding)
{
	uint utf16_encoding;

	/* Assumed encoding in absence of a bom is little endian */
	utf16_encoding = SL_ENC_LITTLE_ENDIAN;

	if (query_length >= 2) {
		uint8_t le_bom[] = {0xff, 0xfe};
		uint8_t be_bom[] = {0xfe, 0xff};
		if (memcmp(le_bom, buf + offset, sizeof(uint16_t)) == 0)
			utf16_encoding = SL_ENC_LITTLE_ENDIAN | SL_ENC_UTF_16;
		else if (memcmp(be_bom, buf + offset, sizeof(uint16_t)) == 0)
			utf16_encoding = SL_ENC_BIG_ENDIAN | SL_ENC_UTF_16;
	}

	return utf16_encoding;
}

/******************************************************************************
 * marshalling functions
 ******************************************************************************/

#define SL_OFFSET_DELTA 16

static uint64_t sl_pack_tag(uint16_t type, uint16_t size_or_count, uint32_t val)
{
	uint64_t tag = ((uint64_t)val << 32) | ((uint64_t)type << 16) | size_or_count;
	return tag;
}

static int sl_pack_float(double d, char *buf, int offset)
{
	int result;

	union {
		double d;
		uint64_t w;
	} ieee_fp_union;

	result = slvalc(buf, offset, MAX_SLQ_DAT, sl_pack_tag(SQ_TYPE_FLOAT, 2, 1));
	if (result != 0) {
		return -1;
	}
	result = slvalc(buf, offset + 8, MAX_SLQ_DAT, ieee_fp_union.w);
	if (result != 0) {
		return -1;
	}

	return offset + 2 * sizeof(uint64_t);
}

static int sl_pack_uint64(uint64_t u, char *buf, int offset)
{
	int result;

	result = slvalc(buf, offset, MAX_SLQ_DAT, sl_pack_tag(SQ_TYPE_INT64, 2, 1));
	if (result != 0) {
		return -1;
	}
	result = slvalc(buf, offset + 8, MAX_SLQ_DAT, u);
	if (result != 0) {
		return -1;
	}

	return offset + 2 * sizeof(uint64_t);
}

static int sl_pack_bool(sl_bool_t bl, char *buf, int offset)
{
	int result;

	result = slvalc(buf, offset, MAX_SLQ_DAT,
			sl_pack_tag(SQ_TYPE_BOOL, 1, bl ? 1 : 0));
	if (result != 0) {
		return -1;
	}

	return offset + sizeof(uint64_t);
}

static int sl_pack_nil(char *buf, int offset)
{
	int result;

	result = slvalc(buf, offset, MAX_SLQ_DAT, sl_pack_tag(SQ_TYPE_NULL, 1, 1));
	if (result != 0) {
		return -1;
	}

	return offset + sizeof(uint64_t);
}

static int sl_pack_date(sl_time_t t, char *buf, int offset)
{
	int result;
	uint64_t data = 0;

	data = (t.tv_sec + SPOTLIGHT_TIME_DELTA) << 24;

	result = slvalc(buf, offset, MAX_SLQ_DAT, sl_pack_tag(SQ_TYPE_DATE, 2, 1));
	if (result != 0) {
		return -1;
	}

	result = slvalc(buf, offset + 8, MAX_SLQ_DAT, data);
	if (result != 0) {
		return -1;
	}

	return offset + 2 * sizeof(uint64_t);
}

static int sl_pack_uuid(sl_uuid_t *uuid, char *buf, int offset)
{
	int result;

	result = slvalc(buf, offset, MAX_SLQ_DAT, sl_pack_tag(SQ_TYPE_UUID, 3, 1));
	if (result != 0) {
		return -1;
	}
	if (offset + 8 + 16 >= MAX_SLQ_DAT) {
		return -1;
	}
	memcpy(buf + offset + 8, uuid, 16);

	return offset + sizeof(uint64_t) + 16;
}

static int sl_pack_CNID(sl_cnids_t *cnids, char *buf, int offset,
			char *toc_buf, int *toc_idx)
{
	int result;
	int len, i;
	int cnid_count = talloc_array_length(cnids->ca_cnids->dd_talloc_array);
	uint64_t id;

	result = slvalc(toc_buf, *toc_idx * 8, MAX_SLQ_TOC,
			sl_pack_tag(SQ_CPX_TYPE_CNIDS, (offset + SL_OFFSET_DELTA) / 8, 0));
	if (result != 0) {
		return -1;
	}

	result = slvalc(buf, offset, MAX_SLQ_DAT,
			sl_pack_tag(SQ_TYPE_COMPLEX, 1, *toc_idx + 1));
	if (result != 0) {
		return -1;
	}

	*toc_idx += 1;
	offset += 8;

	len = cnid_count + 1;
	if (cnid_count > 0) {
		len ++;
	}

	result = slvalc(buf, offset, MAX_SLQ_DAT,
			sl_pack_tag(SQ_TYPE_CNIDS, len, 8 /* unknown meaning, but always 8 */));
	if (result != 0)
		return -1;
	offset += 8;

	if (cnid_count > 0) {
		result = slvalc(buf, offset, MAX_SLQ_DAT,
				sl_pack_tag(cnids->ca_unkn1, cnid_count, cnids->ca_context));
		if (result != 0) {
			return -1;
		}
		offset += 8;

		for (i = 0; i < cnid_count; i++) {
			memcpy(&id, cnids->ca_cnids->dd_talloc_array[i], sizeof(uint64_t));
			result = slvalc(buf, offset, MAX_SLQ_DAT, id);
			if (result != 0) {
				return -1;
			}
			offset += 8;
		}
	}

	return offset;
}

static int sl_pack_array(sl_array_t *array, char *buf, int offset,
			 char *toc_buf, int *toc_idx)
{
	int result;
	int count = talloc_array_length(array->dd_talloc_array);
	int octets = (offset + SL_OFFSET_DELTA) / 8;

	result = slvalc(toc_buf, *toc_idx * 8, MAX_SLQ_TOC,
			sl_pack_tag(SQ_CPX_TYPE_ARRAY, octets, count));
	if (result != 0) {
		return -1;
	}
	result = slvalc(buf, offset, MAX_SLQ_DAT,
			sl_pack_tag(SQ_TYPE_COMPLEX, 1, *toc_idx + 1));
	if (result != 0) {
		return -1;
	}
	*toc_idx += 1;
	offset += 8;

	offset = sl_pack_loop(array, buf, offset, toc_buf, toc_idx);

	return offset;
}

static int sl_pack_dict(sl_array_t *dict, char *buf, int offset,
			char *toc_buf, int *toc_idx)
{
	int result;

	result = slvalc(toc_buf, *toc_idx * 8, MAX_SLQ_TOC,
			sl_pack_tag(SQ_CPX_TYPE_DICT,
				    (offset + SL_OFFSET_DELTA) / 8,
				    talloc_array_length(dict->dd_talloc_array)));
	if (result != 0) {
		return -1;
	}

	result = slvalc(buf, offset, MAX_SLQ_DAT,
			sl_pack_tag(SQ_TYPE_COMPLEX, 1, *toc_idx + 1));
	if (result != 0) {
		return -1;
	}

	*toc_idx += 1;
	offset += 8;

	offset = sl_pack_loop(dict, buf, offset, toc_buf, toc_idx);

	return offset;
}

static int sl_pack_filemeta(sl_filemeta_t *fm, char *buf, int offset,
			    char *toc_buf, int *toc_idx)
{
	int result;
	int fmlen;                  /* lenght of filemeta */
	int saveoff = offset;

	result = slvalc(buf, offset, MAX_SLQ_DAT,
			sl_pack_tag(SQ_TYPE_COMPLEX, 1, *toc_idx + 1));
	if (result != 0) {
		return -1;
	}
	offset += 16;

	fmlen = sl_pack(fm, buf + offset);
	if (fmlen == -1) {
		return -1;
	}

	/*
	 * Check for empty filemeta array, if it's only 40 bytes, it's
	 * only the header but no content
	 */
	if (fmlen > 40) {
		offset += fmlen;
	} else {
		fmlen = 0;
	}

	result = slvalc(buf, saveoff + 8, MAX_SLQ_DAT,
			sl_pack_tag(SQ_TYPE_DATA, (fmlen / 8) + 1,
				    8 /* unknown meaning, but always 8 */));
	if (result != 0) {
		return -1;
	}

	result = slvalc(toc_buf, *toc_idx * 8, MAX_SLQ_TOC,
			sl_pack_tag(SQ_CPX_TYPE_FILEMETA,
				    (saveoff + SL_OFFSET_DELTA) / 8,
				    fmlen / 8));
	if (result != 0) {
		return -1;
	}

	*toc_idx += 1;

	return offset;
}

static int sl_pack_string(char *s, char *buf, int offset,
			  char *toc_buf, int *toc_idx)
{
	int result;
	int len, octets, used_in_last_octet;

	len = strlen(s);
	octets = (len / 8) + (len & 7 ? 1 : 0);
	used_in_last_octet = 8 - (octets * 8 - len);

	result = slvalc(toc_buf, *toc_idx * 8, MAX_SLQ_TOC,
			sl_pack_tag(SQ_CPX_TYPE_STRING,
				    (offset + SL_OFFSET_DELTA) / 8,
				    used_in_last_octet));
	if (result != 0) {
		return -1;
	}

	result = slvalc(buf, offset, MAX_SLQ_DAT,
			sl_pack_tag(SQ_TYPE_COMPLEX, 1, *toc_idx + 1));
	if (result != 0) {
		return -1;
	}

	*toc_idx += 1;
	offset += 8;

	result = slvalc(buf, offset, MAX_SLQ_DAT,
			sl_pack_tag(SQ_TYPE_DATA, octets + 1, used_in_last_octet));
	if (result != 0) {
		return -1;
	}
	offset += 8;

	if (offset + octets * 8 > MAX_SLQ_DAT) {
		return -1;
	}
	memset(buf + offset, 0, octets * 8);
	strncpy(buf + offset, s, len);
	offset += octets * 8;

	return offset;
}

static int sl_pack_string_as_utf16(char *s, char *buf, int offset,
				   char *toc_buf, int *toc_idx)
{
	int result;
	int utf16_plus_bom_len, octets, used_in_last_octet;
	char *utf16string;
	char bom[] = { 0xff, 0xfe };
	size_t utf16len;

	if (!convert_string_talloc(talloc_tos(),
				   CH_UTF8,
				   CH_UTF16LE,
				   s,
				   strlen(s),
				   &utf16string,
				   &utf16len))
		return -1;

	utf16_plus_bom_len = utf16len + 2;

	octets = (utf16_plus_bom_len / 8) + (utf16_plus_bom_len  & 7 ? 1 : 0);
	used_in_last_octet = 8 - (octets * 8 - utf16_plus_bom_len);

	result = slvalc(toc_buf, *toc_idx * 8, MAX_SLQ_TOC,
			sl_pack_tag(SQ_CPX_TYPE_UTF16_STRING,
				    (offset + SL_OFFSET_DELTA) / 8,
				    used_in_last_octet));
	if (result != 0) {
		return -1;
	}

	result = slvalc(buf, offset, MAX_SLQ_DAT,
			sl_pack_tag(SQ_TYPE_COMPLEX, 1, *toc_idx + 1));
	if (result != 0) {
		return -1;
	}

	*toc_idx += 1;
	offset += 8;

	result = slvalc(buf, offset, MAX_SLQ_DAT,
			sl_pack_tag(SQ_TYPE_DATA, octets + 1, used_in_last_octet));
	if (result != 0) {
		return -1;
	}
	offset += 8;

	if (offset + octets * 8 > MAX_SLQ_DAT) {
		return -1;
	}

	memset(buf + offset, 0, octets * 8);

	memcpy(buf + offset, &bom, sizeof(bom));
	memcpy(buf + offset + 2, utf16string, utf16len);
	offset += octets * 8;

	return offset;
}

static int sl_pack_loop(DALLOC_CTX *query, char *buf, int offset,
			char *toc_buf, int *toc_idx)
{
	const char *type;
	int n;

	for (n = 0; n < talloc_array_length(query->dd_talloc_array); n++) {

		type = talloc_get_name(query->dd_talloc_array[n]);

		if (strequal(type, "sl_array_t")) {
			offset = sl_pack_array(query->dd_talloc_array[n], buf,
					       offset, toc_buf, toc_idx);
		} else if (strequal(type, "sl_dict_t")) {
			offset = sl_pack_dict(query->dd_talloc_array[n], buf,
					      offset, toc_buf, toc_idx);
		} else if (strequal(type, "sl_filemeta_t")) {
			offset = sl_pack_filemeta(query->dd_talloc_array[n], buf,
						  offset, toc_buf, toc_idx);
		} else if (strequal(type, "uint64_t")) {
			uint64_t i;
			memcpy(&i, query->dd_talloc_array[n], sizeof(uint64_t));
			offset = sl_pack_uint64(i, buf, offset);
		} else if (strequal(type, "char *")) {
			offset = sl_pack_string(query->dd_talloc_array[n], buf,
						offset, toc_buf, toc_idx);
		} else if (strequal(type, "smb_ucs2_t *")) {
			offset = sl_pack_string_as_utf16(query->dd_talloc_array[n], buf,
							 offset, toc_buf, toc_idx);
		} else if (strequal(type, "sl_bool_t")) {
			sl_bool_t bl;
			memcpy(&bl, query->dd_talloc_array[n], sizeof(sl_bool_t));
			offset = sl_pack_bool(bl, buf, offset);
		} else if (strequal(type, "double")) {
			double d;
			memcpy(&d, query->dd_talloc_array[n], sizeof(double));
			offset = sl_pack_float(d, buf, offset);
		} else if (strequal(type, "sl_nil_t")) {
			offset = sl_pack_nil(buf, offset);
		} else if (strequal(type, "sl_time_t")) {
			sl_time_t t;
			memcpy(&t, query->dd_talloc_array[n], sizeof(sl_time_t));
			offset = sl_pack_date(t, buf, offset);
		} else if (strequal(type, "sl_uuid_t")) {
			offset = sl_pack_uuid(query->dd_talloc_array[n], buf, offset);
		} else if (strequal(type, "sl_cnids_t")) {
			offset = sl_pack_CNID(query->dd_talloc_array[n], buf, offset,
					      toc_buf, toc_idx);
		} else {
			DEBUG(1, ("unknown type: %s", type));
			return -1;
		}
		if (offset == -1) {
			return -1;
		}
	}

	return offset;
}

/******************************************************************************
 * unmarshalling functions
 ******************************************************************************/

static uint64_t sl_unpack_uint64(const char *buf, int offset, uint encoding)
{
	if (encoding == SL_ENC_LITTLE_ENDIAN) {
		return BVAL(buf, offset);
	} else {
		return RBVAL(buf, offset);
	}
}

static int sl_unpack_ints(DALLOC_CTX *query, const char *buf,
			  int offset, uint encoding)
{
	int count, i;
	uint64_t query_data64;

	query_data64 = sl_unpack_uint64(buf, offset, encoding);
	count = query_data64 >> 32;
	offset += 8;

	i = 0;
	while (i++ < count) {
		query_data64 = sl_unpack_uint64(buf, offset, encoding);
		dalloc_add_copy(query, &query_data64, uint64_t);
		offset += 8;
	}

	return count;
}

static int sl_unpack_date(DALLOC_CTX *query, const char *buf,
			  int offset, uint encoding)
{
	int count, i;
	uint64_t query_data64;
	sl_time_t t;

	query_data64 = sl_unpack_uint64(buf, offset, encoding);
	count = query_data64 >> 32;
	offset += 8;

	i = 0;
	while (i++ < count) {
		query_data64 = sl_unpack_uint64(buf, offset, encoding) >> 24;
		t.tv_sec = query_data64 - SPOTLIGHT_TIME_DELTA;
		t.tv_usec = 0;
		dalloc_add_copy(query, &t, sl_time_t);
		offset += 8;
	}

	return count;
}

static int sl_unpack_uuid(DALLOC_CTX *query, const char *buf,
			  int offset, uint encoding)
{
	int count, i;
	uint64_t query_data64;
	sl_uuid_t uuid;
	query_data64 = sl_unpack_uint64(buf, offset, encoding);
	count = query_data64 >> 32;
	offset += 8;

	i = 0;
	while (i++ < count) {
		memcpy(uuid.sl_uuid, buf + offset, 16);
		dalloc_add_copy(query, &uuid, sl_uuid_t);
		offset += 16;
	}

	return count;
}

static int sl_unpack_floats(DALLOC_CTX *query, const char *buf,
			    int offset, uint encoding)
{
	int count, i;
	uint64_t query_data64;
	union {
		double d;
		uint32_t w[2];
	} ieee_fp_union;

	query_data64 = sl_unpack_uint64(buf, offset, encoding);
	count = query_data64 >> 32;
	offset += 8;

	i = 0;
	while (i++ < count) {
		if (encoding == SL_ENC_LITTLE_ENDIAN) {
#ifdef WORDS_BIGENDIAN
			ieee_fp_union.w[0] = IVAL(buf, offset + 4);
			ieee_fp_union.w[1] = IVAL(buf, offset);
#else
			ieee_fp_union.w[0] = IVAL(buf, offset);
			ieee_fp_union.w[1] = IVAL(buf, offset + 4);
#endif
		} else {
#ifdef WORDS_BIGENDIAN
			ieee_fp_union.w[0] = RIVAL(buf, offset);
			ieee_fp_union.w[1] = RIVAL(buf, offset + 4);
#else
			ieee_fp_union.w[0] = RIVAL(buf, offset + 4);
			ieee_fp_union.w[1] = RIVAL(buf, offset);
#endif
		}
		dalloc_add_copy(query, &ieee_fp_union.d, double);
		offset += 8;
	}

	return count;
}

static int sl_unpack_CNID(DALLOC_CTX *query, const char *buf, int offset,
			  int length, uint encoding)
{
	int count;
	uint64_t query_data64;
	sl_cnids_t *cnids;

	cnids = talloc_zero(query, sl_cnids_t);
	if (!cnids) {
		return -1;
	}
	cnids->ca_cnids = talloc_zero(cnids, DALLOC_CTX);
	if (!cnids->ca_cnids) {
		return -1;
	}

	if (length <= 16) {
		/* that's permitted, it's an empty array */
		return 0;
	}
    
	query_data64 = sl_unpack_uint64(buf, offset, encoding);
	count = query_data64 & 0xffff;

	cnids->ca_unkn1 = (query_data64 & 0xffff0000) >> 16;
	cnids->ca_context = query_data64 >> 32;

	offset += 8;

	while (count --) {
		query_data64 = sl_unpack_uint64(buf, offset, encoding);
		dalloc_add_copy(cnids->ca_cnids, &query_data64, uint64_t);
		offset += 8;
	}

	dalloc_add(query, cnids, sl_cnids_t);

	return 0;
}

static int sl_unpack_cpx(DALLOC_CTX *query,
                         const char *buf,
                         const int offset,
                         uint cpx_query_type,
                         uint cpx_query_count,
                         const uint toc_offset,
                         const uint encoding)
{
	int result;
	int roffset = offset;
	uint64_t query_data64;
	uint unicode_encoding;
	uint8_t mark_exists;
	char *p;
	int qlen, used_in_last_block, slen;
	sl_array_t *sl_array;
	sl_dict_t *sl_dict;
	sl_filemeta_t *sl_fm;
	size_t tmp_len;

	switch (cpx_query_type) {
	case SQ_CPX_TYPE_ARRAY:
		sl_array = talloc_zero(query, sl_array_t);
		if (!sl_array) {
			return -1;
		}
		roffset = sl_unpack_loop(sl_array, buf, offset, cpx_query_count,
					 toc_offset, encoding);
		if (roffset == -1) {
			return -1;
		}
		dalloc_add(query, sl_array, sl_array_t);
		break;

	case SQ_CPX_TYPE_DICT:
		sl_dict = talloc_zero(query, sl_dict_t);
		if (!sl_dict) {
			return -1;
		}
		roffset = sl_unpack_loop(sl_dict, buf, offset, cpx_query_count,
					 toc_offset, encoding);
		if (roffset == -1) {
			return -1;
		}
		dalloc_add(query, sl_dict, sl_dict_t);
		break;

	case SQ_CPX_TYPE_STRING:
	case SQ_CPX_TYPE_UTF16_STRING:
		query_data64 = sl_unpack_uint64(buf, offset, encoding);
		qlen = (query_data64 & 0xffff) * 8;
		used_in_last_block = query_data64 >> 32;
		slen = qlen - 16 + used_in_last_block;

		if (cpx_query_type == SQ_CPX_TYPE_STRING) {
			p = dalloc_strndup(query, buf + offset + 8, slen);
			if (!p) {
				return -1;
			}
		} else {
			unicode_encoding = spotlight_get_utf16_string_encoding(buf, offset + 8,
									       slen, encoding);
			mark_exists = (unicode_encoding & SL_ENC_UTF_16);
			if (unicode_encoding & SL_ENC_BIG_ENDIAN) {
				DEBUG(1, ("Unsupported big endian UTF16 string"));
				return -1;
			}
			slen -= mark_exists ? 2 : 0;
			if (!convert_string_talloc(query,
						   CH_UTF16LE,
						   CH_UTF8,
						   buf + offset + (mark_exists ? 10 : 8),
						   slen,
						   &p,
						   &tmp_len)) {
				return -1;
			}
			if (!p) {
				return -1;
			}
		}

		dalloc_add(query, p, char *);
		roffset += qlen;
		break;

	case SQ_CPX_TYPE_FILEMETA:
		query_data64 = sl_unpack_uint64(buf, offset, encoding);
		qlen = (query_data64 & 0xffff) * 8;
		if (qlen <= 8) {
			DEBUG(1, ("SQ_CPX_TYPE_FILEMETA: query_length <= 8: %d", qlen));
			return -1;
		} else {
			sl_fm = talloc_zero(query, sl_filemeta_t);
			if (!sl_fm) {
				return -1;
			}
			result = sl_unpack(sl_fm, buf + offset + 8);
			if (result == -1) {
				return -1;
			}
			dalloc_add(query, sl_fm, sl_filemeta_t);
		}
		roffset += qlen;
		break;

	case SQ_CPX_TYPE_CNIDS:
		query_data64 = sl_unpack_uint64(buf, offset, encoding);
		qlen = (query_data64 & 0xffff) * 8;
		result = sl_unpack_CNID(query, buf, offset + 8, qlen, encoding);
		if (result == -1) {
			return -1;
		}
		roffset += qlen;
		break;

	default:
		DEBUG(1, ("unkown complex query type: %u", cpx_query_type));
		return -1;
	}
            
	return roffset;
}

static int sl_unpack_loop(DALLOC_CTX *query,
                          const char *buf,
                          int offset,
                          uint count,
                          const uint toc_offset,
                          const uint encoding)
{
	int i, toc_index, query_length;
	uint subcount;
	uint64_t query_data64, query_type;
	uint cpx_query_type, cpx_query_count;
	sl_nil_t nil;
	sl_bool_t b;

	while (count > 0 && (offset < toc_offset)) {
		query_data64 = sl_unpack_uint64(buf, offset, encoding);
		query_length = (query_data64 & 0xffff) * 8;
		query_type = (query_data64 & 0xffff0000) >> 16;
		if (query_length == 0) {
			return -1;
		}

		switch (query_type) {
		case SQ_TYPE_COMPLEX:
			toc_index = (query_data64 >> 32) - 1;
			query_data64 = sl_unpack_uint64(buf, toc_offset + toc_index * 8, encoding);
			cpx_query_type = (query_data64 & 0xffff0000) >> 16;
			cpx_query_count = query_data64 >> 32;

			offset = sl_unpack_cpx(query, buf, offset + 8, cpx_query_type,
					       cpx_query_count, toc_offset, encoding);
			if (offset == -1) {
				return -1;
			}
			count--;
			break;
		case SQ_TYPE_NULL:
			subcount = query_data64 >> 32;
			if (subcount > 64) {
				return -1;
			}
			nil = 0;
			for (i = 0; i < subcount; i++) {
				dalloc_add_copy(query, &nil, sl_nil_t);
			}
			offset += query_length;
			count -= subcount;
			break;
		case SQ_TYPE_BOOL:
			b = query_data64 >> 32;
			dalloc_add_copy(query, &b, sl_bool_t);
			offset += query_length;
			count--;
			break;
		case SQ_TYPE_INT64:
			subcount = sl_unpack_ints(query, buf, offset, encoding);
			if (subcount == -1) {
				return -1;
			}
			offset += query_length;
			count -= subcount;
			break;
		case SQ_TYPE_UUID:
			subcount = sl_unpack_uuid(query, buf, offset, encoding);
			if (subcount == -1) {
				return -1;
			}
			offset += query_length;
			count -= subcount;
			break;
		case SQ_TYPE_FLOAT:
			subcount = sl_unpack_floats(query, buf, offset, encoding);
			if (subcount == -1) {
				return -1;
			}
			offset += query_length;
			count -= subcount;
			break;
		case SQ_TYPE_DATE:
			subcount = sl_unpack_date(query, buf, offset, encoding);
			if (subcount == -1) {
				return -1;
			}
			offset += query_length;
			count -= subcount;
			break;
		default:
			DEBUG(1, ("unknown query type: %" PRIu64, query_type));
			return -1;
		}
	}

	return offset;
}

/******************************************************************************
 * Global functions for packing und unpacking
 ******************************************************************************/

ssize_t sl_pack(DALLOC_CTX *query, char *buf)
{
	int result;
	char toc_buf[MAX_SLQ_TOC];
	int toc_index = 0;
	ssize_t len = 0;

	memcpy(buf, "432130dm", strlen("432130dm"));
	len = sl_pack_loop(query, buf + 16, 0, toc_buf + 8, &toc_index);
	if (len == -1) {
		return -1;
	}

	result = sivalc(buf, 8, MAX_SLQ_DAT, len / 8 + 1 + toc_index + 1);
	if (result != 0) {
		return -1;
	}

	result = sivalc(buf, 12, MAX_SLQ_DAT, len / 8 + 1);
	if (result != 0) {
		return -1;
	}

	result = slvalc(toc_buf, 0, MAX_SLQ_TOC,
			sl_pack_tag(SQ_TYPE_TOC, toc_index + 1, 0));
	if (result != 0) {
		return -1;
	}

	if ((16 + len + ((toc_index + 1 ) * 8)) >= MAX_SLQ_DAT) {
		return -1;
	}
	memcpy(buf + 16 + len, toc_buf, (toc_index + 1 ) * 8);
	len += 16 + (toc_index + 1 ) * 8;

	return len;
}

bool sl_unpack(DALLOC_CTX *query, const char *buf)
{
	int result;
	int encoding, toc_entries;
	uint64_t toc_offset;

	if (strncmp(buf, "md031234", strlen("md031234")) == 0) {
		encoding = SL_ENC_BIG_ENDIAN;
	} else {
		encoding = SL_ENC_LITTLE_ENDIAN;
	}
	buf += 8;

	toc_offset = ((sl_unpack_uint64(buf, 0, encoding) >> 32) - 1 ) * 8;
	if (toc_offset < 0 || (toc_offset > 65000)) {
		return false;
	}
	buf += 8;

	toc_entries = (int)(sl_unpack_uint64(buf, toc_offset, encoding) & 0xffff);

	result = sl_unpack_loop(query, buf, 0, 1, toc_offset + 8, encoding);
	if (result == -1) {
		return false;
	}
	return true;
}
