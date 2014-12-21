#include "lua-probe.h"
#include "lua-dynload.h"
#include "logger.h"
#include "proto-tcp-transmit.h"
#include <string.h>

/****************************************************************************
 ****************************************************************************/
static int
socket_send(lua_State *L)
{
    int argc = lua.gettop(L); /* get number of arguments */
    struct TCP_Control_Block *tcb;
    const char *buf;
    size_t buf_size;

    /* Ignore bad script input */
    if (argc != 2) {
        LOG(0, "script error\n");
        return 0;
    }

    /* Get socket file descriptor */
    lua.getfield(L, 1, "fd");
    tcb = lua.touserdata(L, -1);
    
    /* Get the buffer */
    buf = lua.tolstring(L, 2, &buf_size);
    printf("send = %.*s\n", (unsigned)buf_size, buf);


    /* send it */
    tcp_add_xmit(tcb, buf, buf_size, XMIT_DYNAMIC);

    return 0;
}



/****************************************************************************
 ****************************************************************************/
static int
push_socket(lua_State *L, struct TCP_Control_Block *tcb)
{
    static const char *script = 
        "local args = {...};\r\n"
        "local x = {};\r\n"
        "x.fd = args[1];\r\n"
        "x.send = args[2];\r\n"
        "x.send2 = args[3];\r\n"
        "x.buf = '';\r\n"
        "return x;\r\n";
    int x;
    x = luaL_loadbuffer(L, script, strlen(script), "socket");
    if (x) {
        const char *msg = lua_tostring(L, -1);
        fprintf(stderr, "%s: %s\n", "socket", msg);
        lua_pop(L, 1); /* cleanup error message */
        return -1;
    }

    lua.pushlightuserdata(L, tcb);
    lua_pushcfunction(L, socket_send);
    lua_pushcfunction(L, socket_send);
    x = lua_pcall(L, 3, 1, 0);
    if (x) {
        const char *msg = lua_tostring(L, -1);
        fprintf(stderr, "%s: %s\n", "socket", msg);
        lua_pop(L, 1); /* cleanup error message */
        return -1;
    }
    return 0;
}

/***************************************************************************
 * [LUAPROBE]
 *  Start running the script for the first time. This happen after
 *  
 ***************************************************************************/
struct lua_State *
luaprobe_event_connect(struct lua_State *L, struct TCP_Control_Block *tcb)
{
    struct lua_State *thread;

    LOG(1, "LUAPROBE: connect\n");
    thread = lua.newthread(L);

    return L;
}

/***************************************************************************
 * [LUAPROBE]
 *  
 ***************************************************************************/
int
luaprobe_event_packet(  struct lua_State *L,
                    struct TCP_Control_Block *tcb,
                    const void *payload,
                    size_t payload_length)
{
    LOG(1, "LUAPROBE: packet %u-bytes\n", (unsigned)payload_length);

    return 0;
}

/***************************************************************************
 * [LUAPROBE]
 *  
 ***************************************************************************/
void
luaprobe_event_close(  struct lua_State *L,
                    struct TCP_Control_Block *tcb)
{
    LOG(1, "LUAPROBE: close\n");

}

/***************************************************************************
 * [LUAPROBE]
 ***************************************************************************/
static int
luaprobe_load_script(struct lua_State *L, const char *scriptname)
{
    int x;
    unsigned i;

    /*
     * Reset the known global variables to 'nil'. That so when we load
     * multiple scripts, if they are missing something, they won't default
     * to the previous script.
     */
    {
        static const char *vars[] = {
            "description",
            "author",
            "license",
            "categories",
            "portrule",
            "action",
            "probe",
            0
        };

        for (i=0; vars[i]; i++) {
            lua.pushnil(L);
            lua.setglobal(L, vars[i]);
        }
    }

    
    /* 
     * Load the LUA file and compile it. If there is a syntax error, we'll
     * be notified at this point.
     */
    x = luaL_loadfile(L, scriptname);
    if (x) {
        const char *msg = lua_tostring(L, -1);
        fprintf(stderr, "%s: %s\n", scriptname, msg);
        lua_pop(L, 1); /* cleanup error message */
        return -1;
    }

    /*
     * Run the file, to setup variables 
     */
    x = lua_pcall(L, 0, 0, 0);
    if (x) {
        const char *msg = lua_tostring(L, -1);
        fprintf(stderr, "%s\n", msg);
        lua_pop(L, 1); /* cleanup error message */
        return -1;
    }

    return 0;
}

/***************************************************************************
 * [LUAPROBE]
 ***************************************************************************/
struct lua_State *
luaprobe_init(const char *scriptname)
{
    struct lua_State *L;

    L = lua.newstate();
    luaL_openlibs(L);

    if (luaprobe_load_script(L, scriptname) != 0) {
        lua.close(L);
        return NULL;
    }

    return L;
}

