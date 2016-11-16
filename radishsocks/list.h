/*
 * =====================================================================================
 *
 *       Filename:  list.h
 *
 *    Description:  list header file
 *
 *        Version:  1.0
 *        Created:  2014年09月22日 09时06分54秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  lizhixian (R&D), lzx1442@163.com
 *        Company:  wanwei-tech
 *
 * =====================================================================================
 */
#ifndef __LIST_H__
#define __LIST_H__

/**
* @brief 链表节点
*/
typedef struct list_node
{
	struct list_node *prev;	///<前一个
	struct list_node *next;	///<后一个
}list_t;

void list_init(list_t *l);

void list_insert_after(list_t *l, list_t *n);

void list_insert_before(list_t *l, list_t *n);

void list_remove(list_t *n);

int list_isempty(const list_t *l);

#define list_entry(node, type, member) \
    ((type *)((char *)(node) - (unsigned long)(&((type *)0)->member)))

#endif
