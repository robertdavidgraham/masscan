#include "masscan.h"
#include "scripting.h"
#include "stub-lua.h"

#define MASSCAN_CLASS "Masscan Class"

struct MasscanWrapper
{
    struct Masscan *masscan;
};

/***************************************************************************
 * "setconfig" function in Lua.
 *
 * Called to set a generic name=value parameter. Any configuration
 * option that can be set on the command-line, or from within a config
 * file, can be set via this function.
 ***************************************************************************/
static int mass_setconfig(struct lua_State *L)
{
    struct MasscanWrapper *wrapper;
    struct Masscan *masscan;
    const char *name;
    const char *value;
    
    wrapper = luaL_checkudata(L, 1, MASSCAN_CLASS);
    masscan = wrapper->masscan;
    name = luaL_checkstring(L, 2);
    value = luaL_checkstring(L, 3);
    
    masscan_set_parameter(masscan, name, value);
    
    return 0;
}

/***************************************************************************
 ***************************************************************************/
static int mass_gc(struct lua_State *L)
{
    struct MasscanWrapper *wrapper;
    struct Masscan *masscan;

    wrapper = luaL_checkudata(L, 1, MASSCAN_CLASS);
    masscan = wrapper->masscan;

    /* I'm hot sure what I should do here for shutting down this object,
     * but I'm registering a garbage collection function anyway */
    
    return 0;
}


/***************************************************************************
 * This function creases the object called "Masscan" in the global
 * variable space of a Lua script. The script can then interact
 * with this object in order to setup the scan that it wants to
 * do.
 ***************************************************************************/
void scripting_masscan_init(struct Masscan *masscan)
{
    struct MasscanWrapper *wrapper;
    struct lua_State *L = masscan->scripting.L;

    static const luaL_Reg my_methods[] = {
        {"setconfig",   mass_setconfig},
        {"__gc",        mass_gc},
        {NULL, NULL}
    };

    /*
     * Lua: Create a class to wrap a 'socket'
     */
    
    luaL_newmetatable(L, MASSCAN_CLASS);
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "__index");
    luaL_setfuncs(L, my_methods, 0);
    lua_pop(L, 1);
    
    /* Lua: create a  wrapper object and push it onto the stack */
    wrapper = lua_newuserdata(L, sizeof(*wrapper));
    memset(wrapper, 0, sizeof(*wrapper));
    wrapper->masscan = masscan;
    
    /* Lua: set the class/type */
    luaL_setmetatable(L, MASSCAN_CLASS);
    
    lua_setglobal(L, "Masscan");
    
}
