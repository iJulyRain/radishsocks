/*
 * =====================================================================================
 *
 *       Filename:  main.c
 *
 *    Description:  main of radishsocks 
 *
 *        Version:  1.0
 *        Created:  11/13/2016 11:26:07 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  lizhixian (group3), lizhixian@integritytech.com.cn
 *   Organization:  
 *
 * =====================================================================================
 */

#include "base.h"
#include "log.h"

#include "client.h"

#include <stdlib.h>
#include <getopt.h>

const char *typename[] = {
    "client",  //0
    "server"   //1
};

static void usage(void)
{
    vlog(ERROR, 
        "Usage: ./rssocks -t typeid [-v 0/1/2] ...\n"
        "\t-t <typeid>: 0 client/1 server"
        "\t-v <verbose>: 0 DEFAULT/1 DEBUG/2 INFO\n"
    );
}

static void register_modules(void)
{
	register_rs_object_client();
}

int main(int argc, char **argv)
{
    int rc = 0;
    int option;
    struct rs_object_base *rs_obj = NULL;

    loglevel = DEBUG;

	container_init();
	register_modules();

	/*
    while((option = getopt(argc, argv, "t:v:")) > 0)
    {
        switch (option)
        {
            case 't':
            {
                int index = atoi(optarg);
                if (index >= (sizeof(typename) / sizeof(const char *)))
                {
                    usage();
                    return -1;
                }

                rs_obj = new_rs_object(typename[index], index);
            }
            	break;

            case 'v':
            {
	            loglevel = atoi(optarg);
                if (loglevel > INFO)
                {
                    usage();
                    return -1;
                }
            }
            	break;
			default:
				break;
        }
    }
	*/

    rs_obj = new_rs_object(typename[0], 0);
    if (!rs_obj)
    {
        usage();
        return -1;
    }

    rc = rs_obj->init(argc, argv, rs_obj);
    if (rc != 0)
    {
        vlog(ERROR, "<%s> initial falied!\n");
        return -1;
    }

    rs_obj->run(rs_obj);

    //won't be here
    rs_obj->destroy(rs_obj);
    delete_rs_object(rs_obj);

    return 0;
}
