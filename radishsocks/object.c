/*
 * =====================================================================================
 *
 *       Filename:  object.c
 *
 *    Description:  object
 *
 *        Version:  1.0
 *        Created:  11/13/2016 11:27:32 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  lizhixian (group3), lizhixian@integritytech.com.cn
 *   Organization:  
 *
 * =====================================================================================
 */

#include "object.h"

#include <stdio.h>
#include <string.h>

/**
* @brief 初始化全局对象容器
*/
void container_init(void)
{
	int i;

	for(i = 0; i < rs_obj_type_unknown; i++)
	{
		object_container[i].type = i;
		object_container_init(object_container + i);
	}
}

/**
* @brief 初始化对象容器
*
* @param container 容器
*/
void object_container_init(struct object_container *container)
{
	container->list.prev = &container->list;
	container->list.next = &container->list;

	container->size = 0;
}

/**
* @brief 获取容器中第一个对象
*
* @param container 容器
*
* @return 对象
*/
object_t object_container_first(struct object_container *container)
{
	list_t *node;
	object_t p = NULL;

	node = container->list.next;
	p = list_entry(node, struct object, list);

	return p;
}

/**
* @brief 获取容器中最后一个对象
*
* @param container 容器
*
* @return 对象
*/
object_t object_container_last(struct object_container *container)
{
	list_t *node;
	object_t p = NULL;

	node = container->list.prev;;
	p = list_entry(node, struct object, list);

	return p;
}

/**
* @brief 根据name查找容器中的对象
*
* @param name 名称
* @param container 容器
*
* @return 对象
*/
object_t object_container_find(const char *name, struct object_container *container)
{
    int find_obj = 0;
	list_t *node;
	object_t p = NULL;

	for(node = container->list.next; node != &container->list; node = node->next)
	{
		p = list_entry(node, struct object, list);
		if(!strcmp(p->name, name))
        {
            find_obj = 1;
            break;
        }
	}

    if(find_obj == 0)
        return NULL;

	return p;
}

/**
* @brief 从全局容器中查找对象
*
* @param name 对象名称
* @param type 对象类型
*
* @return 查找成功返回对象地址，失败返回NULL 
*/
object_t object_find(const char *name, int type)
{
	struct object_container *container;

	if(type < 0 || type > rs_obj_type_unknown)
		return NULL;

	container = &object_container[type];

	return object_container_find(name, container);
}

/**
* @brief 添加对象到容器
*
* @param object 对象
* @param container 容器
*/
void object_container_addend(object_t object, struct object_container *container)
{
	list_t *list;

	list = &container->list;
	list_insert_before(list, &object->list);

	container->size ++;
}

/**
* @brief 添加对象到全局容器
*
* @param object 对象
* @param name 对象名称
* @param type 对象类型
*/
void object_addend(object_t object, const char *name, int type)
{
	struct object_container *container;

	if(type < 0 || type > rs_obj_type_unknown)
		return;
	
	strncpy(object->name, name, OBJ_NAME_MAX);
	object->type = type;

	container = object_container + type;
	object_container_addend(object, container);
}

/**
* @brief 从容器中移除对象
*
* @param object
* @param container
*/
void object_container_delete(object_t object, struct object_container *container)
{
	list_remove(&object->list);
	container->size --;
}

/**
* @brief 从全局容器中删除对象
*
* @param object 对象
*/
void object_delete(object_t object)
{
	struct object_container *container;

	container = object_container + object->type; 
	object_container_delete(object, container);
}

void object_set_name(object_t object, const char *name)
{
	strncpy(object->name, name, OBJ_NAME_MAX);
}

const char *object_name(object_t object)
{
	return object->name;
}

int object_type(object_t object)
{
	return object->type;
}
