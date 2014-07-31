/*
  Copyright (c) Ralph Boehme			2012-2014

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
#include "dalloc.h"

int _dalloc_add_talloc_chunk(DALLOC_CTX *dd, void *talloc_chunk, void *obj, size_t size)
{
	size_t array_len = talloc_array_length(dd->dd_talloc_array);
	void *p = talloc_chunk ? talloc_chunk : obj;

	if (talloc_chunk)
		memcpy(talloc_chunk, obj, size);

	dd->dd_talloc_array = talloc_realloc(dd,
					     dd->dd_talloc_array,
					     void *,
					     array_len + 1);

	dd->dd_talloc_array[array_len] = p;
	return 0;
}

/* Get number of elements, returns 0 if the structure is empty or not initialized */
int dalloc_size(DALLOC_CTX *d)
{
	if (!d || !d->dd_talloc_array)
		return 0;
	return talloc_array_length(d->dd_talloc_array);
}

/*
 * Get pointer to value from a DALLOC object
 *
 * Returns pointer to object from a DALLOC object. Nested object interation
 * is supported by using the type string "DALLOC_CTX". Any other type string
 * designates the requested objects type.
 */
void *dalloc_get(const DALLOC_CTX *d, ...)
{
	int result = 0;
	void *p = NULL;
	va_list args;
	const char *type;
	int elem;

	va_start(args, d);
	type = va_arg(args, const char *);

	while (strcmp(type,"DALLOC_CTX") == 0) {
		elem = va_arg(args, int);
		if (elem >= talloc_array_length(d->dd_talloc_array)) {
			DEBUG(1, ("dalloc_get(%s): bound check error: %d >= %zu",
				  type, elem, talloc_array_length(d->dd_talloc_array)));
			result = -1;
			goto exit;
		}
		d = d->dd_talloc_array[elem];
		type = va_arg(args, const char *);
	}

	elem = va_arg(args, int);
	if (elem >= talloc_array_length(d->dd_talloc_array)) {
		DEBUG(1, ("dalloc_get(%s): bound check error: %d >= %zu",
			  type, elem,  talloc_array_length(d->dd_talloc_array)));
			result = -1;
			goto exit;
	}

	if (!(p = talloc_check_name(d->dd_talloc_array[elem], type))) {
		DEBUG(1, ("dalloc_get(%s/%d): type mismatch: %s",
			  type, elem, talloc_get_name(d->dd_talloc_array[elem])));
		result = -1;
		goto exit;
	}

exit:
	va_end(args);
	if (result != 0)
		p = NULL;
	return p;
}

void *dalloc_value_for_key(const DALLOC_CTX *d, ...)
{
	int result = 0;
	void *p = NULL;
	va_list args;
	const char *type;
	int elem;
	size_t array_len;

	va_start(args, d);
	type = va_arg(args, const char *);

	while (strcmp(type, "DALLOC_CTX") == 0) {
		array_len = talloc_array_length(d->dd_talloc_array);
		elem = va_arg(args, int);
		if (elem >= array_len) {
			DEBUG(1, ("bound check error: %d/%zu", elem, array_len));
			result = -1;
			goto exit;
		}
		d = d->dd_talloc_array[elem];
		type = va_arg(args, const char *);
	}

	array_len = talloc_array_length(d->dd_talloc_array);

	for (elem = 0; elem + 1 < array_len; elem += 2) {
		if (strcmp(talloc_get_name(d->dd_talloc_array[elem]), "char *") != 0) {
			DEBUG(1, ("key not a string: %s",
				  talloc_get_name(d->dd_talloc_array[elem])));
			result = -1;
			goto exit;
		}
		if (strcmp((char *)d->dd_talloc_array[elem],type) == 0) {
			p = d->dd_talloc_array[elem + 1];
			break;
		}            
	}
	va_end(args);

exit:
	if (result != 0)
		p = NULL;
	return p;
}

char *dalloc_strdup(const void *ctx, const char *string)
{
	int result = 0;
	char *p;

	p = talloc_strdup(ctx, string);
	if (!p) {
		result = -1;
		goto exit;
	}
	talloc_set_name(p, "char *");

exit:
	if (result != 0) {
		if (p)
			talloc_free(p);
		p = NULL;
	}
	return p;
}

char *dalloc_strndup(const void *ctx, const char *string, size_t n)
{
	int result = 0;
	char *p;

	p = talloc_strndup(ctx, string, n);
	if (!p) {
		result = -1;
		goto exit;
	}
	talloc_set_name(p, "char *");

exit:
	if (result != 0) {
		if (p)
			talloc_free(p);
		p = NULL;
	}
	return p;
}
