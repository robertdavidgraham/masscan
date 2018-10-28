#include "masscan.h"
#include "scripting.h"
#include "stub-lua.h"
#include "logger.h"

#include <stdlib.h>

/***************************************************************************
 ***************************************************************************/
void
scripting_init(struct Masscan *masscan)
{
    int version;
    struct lua_State *L;
    const char *filename = masscan->scripting.name;
    int x;

    
    if (filename == 0 || filename[0] == '\0') {
        LOG(0, "%s: no script specified, use --script option\n", "SCRIPTING");
        exit(1);
    }
    
    /* Dynamically link the library */
    stublua_init();
    
    /* Test to see if the loading was successful */
    version = (int)*lua_version(0);
    LOG(1, "Lua version = %d\n", version);
    if (version != 503 && version != 502) {
        LOG(0, "Unable to load Lua library\n");
        exit(1);
    }
    
    /*
     * Create a Lua VM
     */
    L = luaL_newstate();
    luaL_openlibs(L);
    masscan->scripting.L = L;
    
    /*
     * TODO: Sanbox stuff
     */
    /* We need to do a bunch of sandboxing here to prevent hostile or badly
     * written scripts from disrupting the system */
    
    /*
     * Create the Masscan object
     */
    scripting_masscan_init(masscan);
    
    /*
     * Load the script. This will verify the syntax.
     */
    x = luaL_loadfile(L, filename);
    if (x != LUA_OK) {
        LOG(0, "%s error loading: %s: %s\n", "SCRIPTING:", filename, lua_tostring(L, -1));
        lua_close(L);
        exit(1);
    }
    
    /*
     * Lua: Start running the script. At this stage, the "onConnection()" function doesn't
     * run. Instead, it's registered as a global function to be called later.
     */
    LOG(1, "%s running script: %s\n", "SCRIPTING:", filename);
    x = lua_pcall(L, 0, 0, 0);
    if (x != LUA_OK) {
        LOG(0, "%s error running: %s: %s\n", "SCRIPTING:", filename, lua_tostring(L, -1));
        lua_close(L);
        exit(1);
    }

}
