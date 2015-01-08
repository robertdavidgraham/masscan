#include "scripting.h"
#include "lua/lua.h"
#include "lua/lauxlib.h"
#include "lua/lualib.h"
#include "logger.h"


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
            lua_pushnil(L);
            lua_setglobal(L, vars[i]);
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
 * [LUAPROBE] [SCRIPTING]
 ***************************************************************************/
int
scripting_selftest(void)
{
    struct lua_State *L;
    int x;
    
    L = luaL_newstate();
    if (L == NULL)
        return 1; /* failure */
    luaL_openlibs(L);
    
    
    x = luaL_loadstring(L, "return 5 + '7';");
    if (x) {
        const char *msg = lua_tostring(L, -1);
        fprintf(stderr, "%s: %s\n", "test", msg);
        lua_pop(L, 1); /* cleanup error message */
        return 1;
    }
    
    /*
     * Run the file, to setup variables 
     */
    x = lua_pcall(L, 0, 1, 0);
    if (x) {
        const char *msg = lua_tostring(L, -1);
        fprintf(stderr, "%s\n", msg);
        lua_pop(L, 1); /* cleanup error message */
        return 1;
    }
    
    /*
     * Make sure we get the correct result from the script
     */
    {
        int result;
        
        result = lua_tonumber(L, -1);
        if (result != 12) {
            fprintf(stderr, "lua: calculated wrong result: %d\n", result);
            return 1;
        }
    }
    
    lua_close(L);
    return 0;
}

