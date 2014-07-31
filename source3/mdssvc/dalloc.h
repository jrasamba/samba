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

/*
  Typesafe, dynamic object store based on talloc
 
  Usage
  =====

  Define some types:
  
  A key/value store aka dictionary that supports retrieving elements
  by key:

    typedef dict_t DALLOC_CTX;

  An ordered set that can store different objects which can be
  retrieved by number:

    typedef set_t DALLOC_CTX;

  Create an dalloc object and add elementes of different type:

    TALLOC_CTX *mem_ctx = talloc_new(NULL);
    DALLOC_CTX *d = talloc_zero(mem_ctx, DALLOC_CTX);
 
  Store an int value in the object:

    uint64_t i = 1;
    dalloc_add_copy(d, &i, uint64_t);
 
  Store a string:

    char *str = dalloc_strdup(d, "hello world");
    dalloc_add(d, str, char *);
 
  Add a nested object (note: you later can't fetch this directly):

    DALLOC_CTX *nested = talloc_zero(d, DALLOC_CTX);
    dalloc_add(d, nested, DALLOC_CTX);

  Add an int value to the nested object, this can be fetched:

    i = 2;
    dalloc_add_copy(nested, &i, uint64_t);

  Add a nested set:

    set_t *set = talloc_zero(nested, set_t);
    dalloc_add(nested, set, set_t);
 
  Add an int value to the set:

    i = 3;
    dalloc_add_copy(set, &i, uint64_t);

  Add a dictionary (key/value store):

    dict_t *dict = talloc_zero(nested, dict_t);
    dalloc_add(nested, dict, dict_t);

  Store a string as key in the dict:

    str = dalloc_strdup(d, "key");
    dalloc_add(dict, str, char *);

  Add a value for the key:

    i = 4;
    dalloc_add_copy(dict, &i, uint64_t);

  Fetching value references
  =========================

  You can fetch anything that is not a DALLOC_CTXs, because passing
  "DALLOC_CTXs" as type to the functions dalloc_get() and
  dalloc_value_for_key() tells the function to step into that object
  and expect more arguments that specify which element to fetch.
  
  Get reference to an objects element by position:

    uint64_t *p = dalloc_get(d, "uint64_t", 0);

  p now points to the first int with a value of 1.

  Get reference to the "hello world" string:

    str = dalloc_get(d, "char *", 1);

  You can't fetch a DALLOC_CTX itself:

    nested = dalloc_get(d, "DALLOC_CTX", 2);

  But you can fetch elements from the neseted DALLOC_CTX:

    p = dalloc_get(d, "DALLOC_CTX", 2, "uint64_t", 0);

  p now points to the value 2.

  You can fetch types that are typedefd DALLOC_CTXs:

    set = dalloc_get(d, "DALLOC_CTX", 2, "set_t", 1);

  Fetch int from set, must use DALLOC_CTX as type for the set:

    p = dalloc_get(d, "DALLOC_CTX", 2, "DALLOC_CTX", 1, "uint64_t", 0);

  p points to 3.

  Fetch value by key from dictionary:

    p = dalloc_value_for_key(d, "DALLOC_CTX", 2, "DALLOC_CTX", 2, "key");

  p now points to 4.
*/

#ifndef DALLOC_H
#define DALLOC_H

#include "talloc.h"

/* dynamic datastore */
typedef struct {
    void **dd_talloc_array;
} DALLOC_CTX;

#define dalloc_add_copy(d, obj, type) _dalloc_add_talloc_chunk((d), talloc((d), type), (obj), sizeof(type))
#define dalloc_add(d, obj, type) _dalloc_add_talloc_chunk((d), NULL, (obj), 0)
extern void *dalloc_get(const DALLOC_CTX *d, ...);
extern void *dalloc_value_for_key(const DALLOC_CTX *d, ...);
extern int dalloc_size(DALLOC_CTX *d);
extern char *dalloc_strdup(const void *ctx, const char *string);
extern char *dalloc_strndup(const void *ctx, const char *string, size_t n);

extern int _dalloc_add_talloc_chunk(DALLOC_CTX *dd, void *talloc_chunk, void *obj, size_t size);
#endif  /* DALLOC_H */
