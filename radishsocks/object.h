/*
 * =====================================================================================
 *
 *       Filename:  object.h
 *
 *    Description:  object of radishsocks
 *
 *        Version:  1.0
 *        Created:  11/13/2016 11:26:43 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  lizhixian (group3), lizhixian@integritytech.com.cn
 *   Organization:  
 *
 * =====================================================================================
 */

#ifndef __RS_OBJECT_H__
#define __RS_OBJECT_H__

#include "list.h"

#define OBJ_NAME_MAX    32

enum{
    rs_obj_type_client = 0,
    rs_obj_type_server,
    rs_obj_type_rclient,
    rs_obj_type_rserver,
    rs_obj_type_unknown
};

/**
 * @brief 对象基类
 */
typedef struct object
{
	char name[OBJ_NAME_MAX];	///<基类名称
	int type;		///<对象类型

	list_t list;	///<节点
}*object_t;

/**
 * @brief 对象容器类型
 */
struct object_container
{
	int type;	///<容器类型

	int size;					///<长度
	list_t list;				///<链表头
};

struct object_container object_container[rs_obj_type_unknown]; //全局对象容器

void container_init(void);
object_t object_find(const char *name, int type);
void object_addend(object_t object, const char *name, int type);
void object_delete(object_t object);

void object_container_init(struct object_container *container);
object_t object_container_first(struct object_container *container);
object_t object_container_last(struct object_container *container);
object_t object_container_find(const char *name, struct object_container *container);
void object_container_addend(object_t object, struct object_container *container);
void object_container_delete(object_t object, struct object_container *container);

void object_set_name(object_t object, const char *name);

const char *object_name(object_t object);
int object_type(object_t object);

#define CONTAINER_FOREACH(container, T, pt)	\
	list_t *node;\
	for(node = container->list.next; \
		node != &container->list; \
		node = node->next)	\
	{	\
		pt = (T)list_entry(node, struct object, list);

#define CONTAINER_FOREACH_END	}

#define CONTAINER_FOREACH_RESET(container) node = container->list.next;continue; 

#define OBJECT_FOREACH(type, T, pt) \
	list_t *node;\
	for(node = object_container[type].list.next; \
		node != &object_container[type].list; \
		node = node->next)	\
	{	\
		pt = (T)list_entry(node, struct object, list);

#define OBJECT_FOREACH_END	}

#define OBJECT_FOREACH_RESET(type) node = object_container[type].list.next;continue;

#endif
