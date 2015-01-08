#ifndef LUA_PROBE_H
#define LUA_PROBE_H
#include <stdlib.h>
struct lua_State;
struct TCP_Control_Block;


/**
 * Initial the Lua scripting subsystem. We call this once for
 * each transmit thread.
 */
struct lua_State *
scripting_init(const char *scriptname);

/**
 * Once the TCP connection is established, call this function to
 * start running the script
 * @return a coroutine/thread state object for this TCP connection
 */
struct lua_State *
luaprobe_event_connect( struct lua_State *L, 
                        struct TCP_Control_Block *tcb
                        );


/**
 * Process an incoming packet
 */
int
luaprobe_event_packet(  struct lua_State *L,
                        struct TCP_Control_Block *tcb,
                        const void *payload,
                        size_t payload_length
                        );

/**
 * Close the Lua thread data associated with this TCP
 * connection
 */
void
luaprobe_event_close(   struct lua_State *L,
                        struct TCP_Control_Block *tcb);

#endif
