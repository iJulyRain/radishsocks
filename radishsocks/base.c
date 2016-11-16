/*
 * =====================================================================================
 *
 *       Filename:  base.c
 *
 *    Description:  base of radishsocks
 *
 *        Version:  1.0
 *        Created:  11/14/2016 01:56:03 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  lizhixian (group3), lizhixian@integritytech.com.cn
 *   Organization:  
 *
 * =====================================================================================
 */

#include "base.h"

#include <assert.h>

static void run(void *self)
{
    struct rs_object_base *rs_obj = (struct rs_object_base *)self;

    event_base_dispatch(rs_obj->base);
}

struct rs_object_base *new_rs_object(const char *name, int type)
{
    object_t obj;
    struct rs_object_base *rs_obj = NULL;

    rs_obj = (struct rs_object_base *)calloc(1, sizeof(struct rs_object_base));
    assert(rs_obj);

    obj = object_find(name, type);
    if (!obj)
    {
        vlog(ERROR, "<%s> does not support now.\n");
        return NULL;
    }

    rs_obj->parent  = *obj;
    rs_obj->init    = ((struct rs_object_base *)obj)->init;
    rs_obj->run     = run;
    rs_obj->destroy = ((struct rs_object_base *)obj)->destroy;
    rs_obj->user_data = NULL;

    return rs_obj;
}

void delete_rs_object(struct rs_object_base *rs_object_base)
{
    if (!rs_object_base)
        return ;

    rs_object_base->run     = NULL;
    rs_object_base->init    = NULL;
    rs_object_base->destroy = NULL;

    return;
}
