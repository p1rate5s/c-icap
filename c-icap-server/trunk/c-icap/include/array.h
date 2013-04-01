/*
 *  Copyright (C) 2011 Christos Tsantilas
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA.
 */

#ifndef __ARRAY_H
#define __ARRAY_H

#include "c-icap.h"
#include "mem.h"

#ifdef __cplusplus
extern "C"
{
#endif

/**
 \defgroup ARRAYS  Arrays, stacks, queues and vectors related API
 \ingroup API
 * Arrays, stacks, queues and vectors related API.
 */

typedef struct ci_array_item{
    char *name;
    void *value;
} ci_array_item_t;

/**
 \defgroup SIMPLE_ARRAYS  Simple arrays related API
 \ingroup ARRAYS
 * Arrays which store  name/value pair items
*/

/**
   \typedef ci_array_t
   \ingroup SIMPLE_ARRAYS
   * The ci_array_t objects can store a list of name/value pairs. Currently 
   * can grow up to a fixed size.
 */
typedef struct ci_array {
    ci_array_item_t *items;
    char *mem;
    size_t max_size;
    unsigned int count;
    ci_mem_allocator_t *alloc;
} ci_array_t;

/**
 * Allocate the required memory and initialize an ci_array_t object 
 \ingroup SIMPLE_ARRAYS
 \param max_mem_size the maximum memory to use
 \return the allocated object on success, or NULL on failure
 *
 */
CI_DECLARE_FUNC(ci_array_t *) ci_array_new(size_t max_mem_size);

/**
 * Create and initialize an ci_array_t object for the given number of items
 \ingroup SIMPLE_ARRAYS
 \param items the maximum aray items
 \param item_size the items size
 \return the allocated object on success, or NULL on failure
 */
CI_DECLARE_FUNC(ci_array_t *) ci_array_new2(size_t items, size_t item_size);

/**
 * Destroy an ci_array_t object 
 \ingroup SIMPLE_ARRAYS
 \param array a pointer to ci_array_t object to be destroyed
 *
 */
CI_DECLARE_FUNC(void) ci_array_destroy(ci_array_t *array);

/**
 * Add an name/value pair item to the array.
 \ingroup SIMPLE_ARRAYS
 \param array a pointer to the ci_array_t object
 \param name the name part of the name/value pair item to add
 \param value the value part of the name/value pair item to add
 \param size the size of the value part of the new item.
 \return a pointer to the new array item on success, NULL otherwise
 */
CI_DECLARE_FUNC(const ci_array_item_t *) ci_array_add(ci_array_t *array, const char *name, const void *value, size_t size);

/**
 * Delete the last element of the array.
 \ingroup SIMPLE_ARRAYS
 \param array a pointer to the ci_array_t object
 \return a pointer to the popped array item on success, NULL otherwise
 */
CI_DECLARE_FUNC(const ci_array_item_t *)ci_array_pop(ci_array_t *array);

/**
 * Search in an array for an item with the given name
 \ingroup SIMPLE_ARRAYS
 \param array a pointer to the ci_array_t object
 \param name the item to be search for.
 \return pointer to the value pair of the array item if found, NULL otherwise
 */
CI_DECLARE_FUNC(const void *) ci_array_search(ci_array_t *array, const char *name);

/**
 * Run the given function for each array item
 \ingroup SIMPLE_ARRAYS
 \param array a pointer to the ci_array_t object
 \param data a pointer to data which will be passed on fn function
 \param fn a pointer to the function which will be run for each array item. The iteration will stop if the fn function return non zero value
 */
CI_DECLARE_FUNC(void) ci_array_iterate(ci_array_t *array, void *data, int (*fn)(void *data, const char *name, const void *));

/**
 \defgroup STR_ARRAYS   Arrays of strings related API
 \ingroup SIMPLE_ARRAYS
 * Arrays which store  name/value pair items
*/

/**
 \typedef ci_str_array_t
 \ingroup STR_ARRAYS
 * An alias to the ci_array_t object. It is used to store items with string
 * values to an array.
 * The ci_str_array_new, ci_str_array_destroy, ci_str_array_add, ci_str_array_search
 * and ci_str_array_iterate defines are similar to the equivalent ci_array_* 
 * functions with the required typecasting to work with strings.
 */
typedef ci_array_t ci_str_array_t;
#define ci_str_array_new ci_array_new
#define ci_str_array_destroy ci_array_destroy
#define ci_str_array_add(array, name, value) ci_array_add(array, name, value, (strlen(value)+1))
#define ci_str_array_pop(array) ci_array_pop(array)
#define ci_str_array_search(array, name) (const char *)ci_array_search(array, name)
#define ci_str_array_iterate ci_array_iterate


/**
 \defgroup PTR_ARRAYS  Arrays of pointers
 \ingroup SIMPLE_ARRAYS
 * Arrays of name/pointers to objects pairs
 */

/**
 \typedef ci_ptr_array_t
 \ingroup PTR_ARRAYS
 * The ci_ptr_array_t objects can store a list of name and pointer to object 
 * pairs. It is similar to the ci_array_t object but does not store the value
 * but a pointer to the value.
 */
typedef ci_array_t ci_ptr_array_t;

/**
 \def ci_ptr_array_new()
 \ingroup PTR_ARRAYS
 * Create a new ci_ptr_array_t object. Similar to the ci_array_new() function.
 */
#define ci_ptr_array_new ci_array_new

/**
 \def ci_ptr_array_destroy(ptr_array)
 \ingroup PTR_ARRAYS
 * Destroy a ci_ptr_array_t object. Similar to the ci_array_destroy function
 */
#define ci_ptr_array_destroy(ptr_array) ci_array_destroy(ptr_array)

/**
 \def ci_ptr_array_search(ptr_array, name)
 \ingroup PTR_ARRAYS
 * Search for a name/value pair item in a ci_ptr_array_t object. Similar to 
 * the ci_array_search function
 */
#define ci_ptr_array_search(ptr_array, name) ci_array_search(ptr_array, name)

/**
 \def ci_ptr_array_iterate(ptr_array, data, fn)
 \ingroup PTR_ARRAYS
 * Run the function fn for each item of the ci_ptr_array_t object. Similar to
 * the ci_array_iterate function
 */
#define ci_ptr_array_iterate(ptr_array, data, fn) ci_array_iterate(ptr_array, data, fn)

/**
 * Add an name/value pair item to the ci_ptr_array_t object.
 \ingroup PTR_ARRAYS
 \param ptr_array a pointer to the ci_ptr_array_t object
 \ param name the name part of the name/value pair item to be added
 \ param value a pointer to the value part of the name/value pair item to be added
 \return a pointer to the new array item on success, NULL otherwise
 *
 */
CI_DECLARE_FUNC(const ci_array_item_t *) ci_ptr_array_add(ci_ptr_array_t *ptr_array, const char *name, void *value);

/**
 * Pop and delete the last item of a  ci_ptr_array_t object.
 \ingroup PTR_ARRAYS
 \param ptr_array a pointer to the ci_ptr_array_t object
 \return a pointer to the popped array item
*/
CI_DECLARE_FUNC(const ci_array_item_t *) ci_ptr_array_pop(ci_ptr_array_t *ptr_array);

/**
 * Pop and delete the last item of a  ci_ptr_array_t object.
 \ingroup PTR_ARRAYS
 \param ptr_array a pointer to the ci_ptr_array_t object
 \param name a pointer to a buffer where the name of the poped item will be store, or NULL
 \param name_size the size of name buffer
 \return a pointer to the value of the popped item
*/
CI_DECLARE_FUNC(void *) ci_ptr_array_pop_value(ci_ptr_array_t *ptr_array, char *name, size_t name_size);

/**
 \defgroup DYNAMIC_ARRAYS Dynamic arrays related API
 \ingroup ARRAYS
 * Arrays which store  name/value pair items, and can grow unlimited.
 *
 */

typedef struct ci_dyn_array_item{
    char *name;
    void *value;
    struct ci_dyn_array_item *next;
} ci_dyn_array_item_t;

/**
 \typedef ci_dyn_array_t
 \ingroup DYNAMIC_ARRAYS
 * The ci_dyn_array_t objects can store a list of name/value pairs.
 * The memory RAM space of dynamic array items can not be released
 * before the ci_dyn_array destroyed.
 */
typedef struct ci_dyn_array {
    ci_dyn_array_item_t *items;
    ci_dyn_array_item_t *last;
    size_t max_size;
    ci_mem_allocator_t *alloc;
} ci_dyn_array_t;

/**
 * Allocate the required memory and initialize an ci_dyn_array_t object 
 \ingroup DYNAMIC_ARRAYS
 \param max_mem_size the maximum memory to use
 \return the allocated object on success, or NULL on failure
 *
 */
CI_DECLARE_FUNC(ci_dyn_array_t *) ci_dyn_array_new(size_t max_mem_size);

/**
 * Create and initialize an ci_dyn_array_t object for the given number of items
 \ingroup DYNAMIC_ARRAYS
 \param items the maximum aray items
 \param item_size the items size
 \return the allocated object on success, or NULL on failure
 */
CI_DECLARE_FUNC(ci_dyn_array_t *) ci_dyn_array_new2(size_t items, size_t item_size);

/**
 * Destroy an ci_dyn_array_t object 
 \ingroup DYNAMIC_ARRAYS
 \param array a pointer to ci_dyn_array_t object to be destroyed
 */
CI_DECLARE_FUNC(void) ci_dyn_array_destroy(ci_dyn_array_t *array);

/**
 * Add an name/value pair item to a dynamic array.
 \ingroup DYNAMIC_ARRAYS
 \param array a pointer to the ci_dyn_array_t object
 \param name the name part of the name/value pair item to be added
 \param value the value part of the name/value pair item to be added
 \param size the size of the value part of the new item.
 \return a pointer to the new array item on success, NULL otherwise
 */
CI_DECLARE_FUNC(const ci_dyn_array_item_t *) ci_dyn_array_add(ci_dyn_array_t *array, const char *name, const void *value, size_t size);

/**
 * Search in an dynamic array for an item with the given name
 \ingroup DYNAMIC_ARRAYS
 \param array a pointer to the ci_dyn_array_t object
 \param name the item to be search for.
 \return pointer to the value pair of the array item if found, NULL otherwise
 */
CI_DECLARE_FUNC(const void *) ci_dyn_array_search(ci_dyn_array_t *array, const char *name);

/**
 * Run the given function for each dynamic array item
 \ingroup DYNAMIC_ARRAYS
 \param array a pointer to the ci_dyn_array_t object
 \param data a pointer to data which will be passed on fn function
 \param fn a pointer to the function which will be run for each array item.  The iteration will stop if the fn function return non zero value.
 */
CI_DECLARE_FUNC(void) ci_dyn_array_iterate(ci_dyn_array_t *array, void *data, int (*fn)(void *data, const char *name, const void *));

/**
 \defgroup PTR_DYNAMIC_ARRAYS   Dynamic arrays of pointers related API
 \ingroup DYNAMIC_ARRAYS
 * Arrays which store  name/value pair items
*/

/**
 \typedef ci_ptr_dyn_array_t
 \ingroup PTR_DYNAMIC_ARRAYS
 * An alias to the ci_dyn_array_t object. It is used to store pointers 
 * to an array.
 * The ci_ptr_dyn_array_new, ci_ptr_dyn_array_destroy, ci_ptr_dyn_array_search
 * and ci_ptr_dyn_array_iterate defines are  equivalent to the ci_dyn_array_* 
 * functions with the required typecasting.
 */
typedef ci_dyn_array_t ci_ptr_dyn_array_t;
#define ci_ptr_dyn_array_new ci_dyn_array_new
#define ci_ptr_dyn_array_destroy(ptr_array) ci_dyn_array_destroy(ptr_array)
#define ci_ptr_dyn_array_search(ptr_array, name) ci_dyn_array_search(ptr_array, name)
#define ci_ptr_dyn_array_iterate(ptr_array, data, fn) ci_dyn_array_iterate(ptr_array, data, fn)

/**
 * Add an name/value pair item to the array.
 \ingroup  PTR_DYNAMIC_ARRAYS
 \param ptr_array a pointer to the ci_ptr_dyn_array_t object
 \param name the name part of the name/pointer pair item to be added
 \param pointer the pointer part of the name/value pair item to be added
 \return a pointer to the new array item on success, NULL otherwise
 */
CI_DECLARE_FUNC(const ci_dyn_array_item_t *) ci_dyn_ptr_array_add(ci_ptr_dyn_array_t *ptr_array, const char *name, void *pointer);


/**
 \defgroup VECTORS  Simple vectors related API
 \ingroup ARRAYS
 * Structure which can store lists of objects
 */

/**
 \typedef ci_vector_t
 \ingroup VECTORS
 * The ci_vector_t objects can store a list of objects. Currently can grow up
 * to a fixed size.
 */
typedef struct ci_vector {
    void **items;
    void **last;
    char *mem;
    size_t max_size;
    int count;
    ci_mem_allocator_t *alloc;
} ci_vector_t;

/**
 * Allocate the required memory and initialize a ci_vector_t object 
 \ingroup VECTORS
 \param max_size the maximum memory to use
 \return the allocated object on success, or NULL on failure
 */
CI_DECLARE_FUNC(ci_vector_t *) ci_vector_create(size_t max_size);

/**
 * Destroy an ci_vector_t object 
 \ingroup VECTORS
 \param vector a pointer to ci_vector_t object to be destroyed
 */
CI_DECLARE_FUNC(void) ci_vector_destroy(ci_vector_t *vector);

/**
 * Add an  item to the vector.
 \ingroup VECTORS
 \param vector a pointer to the ci_vector_t object
 \param obj pointer to the object to add in vector
 \param size the size of the new item.
 \return a pointer to the new  item on success, NULL otherwise
 */
CI_DECLARE_FUNC(void *) ci_vector_add(ci_vector_t *vector, const void *obj, size_t size);

/**
 * Run the given function for each vector item
 \ingroup VECTORS
 \param vector a pointer to the ci_vector_t object
 \param data a pointer to data which will be passed to the fn function
 \param fn a pointer to the function which will be run for each vector item. The iteration will stop if the fn function return non zero value.
 */
CI_DECLARE_FUNC(void) ci_vector_iterate(ci_vector_t *vector, void *data, int (*fn)(void *data, const void *));

/**
 * Delete the last element of a vector.
 \ingroup VECTORS
 \param vector a pointer to the ci_vector_t object
 \return a pointer to the popped vector item on success, NULL otherwise
 */
CI_DECLARE_FUNC(void *) ci_vector_pop(ci_vector_t *vector);

/**
 \def ci_vector_get(vector, i)
 \ingroup VECTORS
 * Return a pointer to the i item of the vector
 */
#define ci_vector_get(vector, i) (i < vector->count ? (const void *)vector->items[i]:  (const void *)NULL)


const void **ci_vector_cast_to_voidvoid(ci_vector_t *vector);
ci_vector_t *ci_vector_cast_from_voidvoid(const void **p);

/**
 \defgroup STR_VECTORS  Vectors of strings
 \ingroup VECTORS
 * 
 */

/**
 \typedef ci_str_vector_t
 \ingroup STR_VECTORS
 * The ci_str_vector is used to implement string vectors.
 * The  ci_str_vector_create, ci_str_vector_destroy,  ci_str_vector_add,
 * and ci_str_vector_pop defines are similar and equivalent to the ci_vector_* 
 * functions.
 */
typedef ci_vector_t ci_str_vector_t;
#define ci_str_vector_create ci_vector_create
#define ci_str_vector_destroy ci_vector_destroy
#define ci_str_vector_add(vect, string) ((const char *)ci_vector_add(vect, string, (strlen(string)+1)))
#define ci_str_vector_get(vector, i) (i < vector->count ? (const char *)vector->items[i]:  (const char *)NULL)
#define ci_str_vector_pop(vect)  ((const char *)ci_vector_pop(vect))
#define ci_str_vector_cast_to_charchar(vector) ((const char **)ci_vector_cast_to_voidvoid(vector))
#define ci_str_vector_cast_from_charchar(p) (ci_vector_cast_from_voidvoid((void **)p))

/**
 * Run the given function for each string vector item
 \ingroup STR_VECTORS
 \param vector a pointer to the ci_vector_t object
 \param data a pointer to data which will be passed to the fn function
 \param fn a pointer to the function which will be run for each string vector item. The iteration will stop if the fn function return non zero value.
 */
CI_DECLARE_FUNC(void) ci_str_vector_iterate(ci_str_vector_t *vector, void *data, int (*fn)(void *data, const char *));

/**
 * Search for a string in a string vector.
 \ingroup STR_VECTORS
 \param vector a pointer to the ci_vector_t object
 \param str the string to search for
 \return a pointer to the new  item on success, NULL otherwise
 */
CI_DECLARE_FUNC(const char *) ci_str_vector_search(ci_str_vector_t *vector, const char *str);

/**
 \defgroup PTR_VECTORS  Vectors of pointers
 \ingroup VECTORS
 */

/**
 \typedef ci_ptr_vector_t
 \ingroup PTR_VECTORS
 * The ci_ptr_vector is used to implement vectors storing pointers.
 * The ci_ptr_vector_create, ci_ptr_vector_destroy, ci_ptr_vector_iterate,
 * and ci_ptr_vector_get defines are similar and equivalent to the ci_vector_* functions.
 */
typedef ci_vector_t ci_ptr_vector_t;
#define ci_ptr_vector_create ci_vector_create
#define ci_ptr_vector_destroy ci_vector_destroy
#define ci_ptr_vector_iterate ci_vector_iterate
#define ci_ptr_vector_get ci_vector_get

/**
 * Add an  item to the vector.
 \ingroup PTR_VECTORS
 \param vector a pointer to the ci_vector_t object
 \param pointer the pointer to store in vector
 \return a pointer to the new  item on success, NULL otherwise
 */
CI_DECLARE_FUNC(void *) ci_ptr_vector_add(ci_vector_t *vector, void *pointer);


#ifdef __cplusplus
}
#endif

#endif /*__ARRAY_H*/
