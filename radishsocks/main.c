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
#include "server.h"

#include <stdlib.h>
#include <getopt.h>

#include <libgen.h>

const char *appname_arr[] = {
    "rs-client",  //0
    "rs-server",  //1
	"rs-manage",  //2
};

static void init(void)
{
	container_init();
	register_rs_object_client();
	register_rs_object_server();
}

int main(int argc, char **argv)
{
    int type, gotit, rc = 0;
    const char *appname = NULL;
    struct rs_object_base *rs_obj = NULL;

    init();

    appname = basename(argv[0]);

    gotit = 0;
    for (type = 0; type < (sizeof(appname_arr) / sizeof(const char *)); type++){
        if (strcmp(appname, appname_arr[type]))
            continue;

        gotit = 1;
        break;
    }

    if (!gotit){
        vlog(ERROR, "unknown appname: <%s>\n", appname);
        vlog(ERROR, "try: rs-server or  rs-client\n");
        return -1;
    }

    rs_obj = new_rs_object(appname, type);
    if (!rs_obj){
        vlog(ERROR, "appname <%s> will support soon..\n");
        return -1;
    }

    rc = rs_obj->init(argc, argv, rs_obj);
    if (rc != 0){
        vlog(ERROR, "<%s> initial falied!\n", appname);
        return -1;
    }

    rs_obj->run(rs_obj);

    //won't be here
    rs_obj->destroy(rs_obj);
    delete_rs_object(rs_obj);

    return 0;
}
