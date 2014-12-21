#include "lua-dynload.h"
#include <stdio.h>

#ifdef WIN32
#include <Windows.h>
#include <WinError.h>
#endif


struct LUA lua;


const char *lua_names[] = {
    "luaL_newstate",
    "lua_close",
    "luaL_openlibs",
    "lua_newthread",
    "luaL_loadfilex",
    "luaL_loadbufferx",
    "lua_settop",
    "lua_pcallk",

    "lua_getglobal",
    "lua_gettable",
    "lua_getfield",
    "lua_rawget",
    "lua_rawgeti",
    "lua_rawgetp",
    "lua_createtable",
    "lua_newuserdata",
    "lua_getmetatable", 
    "lua_getuservalue", 

    "lua_setglobal",
    "lua_settable",
    "lua_setfield",
    "lua_rawset",
    "lua_rawseti",
    "lua_rawsetp",
    "lua_setmetatable", 
    "lua_setuservalue", 

    "lua_pushnil",
    "lua_pushnumber",
    "lua_pushinteger",
    "lua_pushunsigned",
    "lua_pushlstring",
    "lua_pushstring",
    "lua_pushvfstring",
    "lua_pushfstring",
    "lua_pushcclosure",
    "lua_pushboolean",
    "lua_pushlightuserdata",
    "lua_pushthread",

    "lua_isnumber",
    "lua_isstring",
    "lua_iscfunction",
    "lua_isuserdata", 
    "lua_type",
    "lua_typename",

    "lua_tonumberx",
    "lua_tointegerx",
    "lua_tounsignedx",
    "lua_toboolean",
    "lua_tolstring",
    "lua_rawlen", 
    "lua_tocfunction",
    "lua_touserdata", 
    "lua_tothread", 
    "lua_topointer", 

    "lua_gettop",

    "lua_yieldk",
    "lua_resume",
    "lua_status",

    (0)
};

/******************************************************************************
 ******************************************************************************/
static int
load_library(const char *name, const char **function_names, void (**functions)())
{
    HMODULE h;
    unsigned i;
    int return_code = 0;

    h = LoadLibraryA(name);
    if (h == NULL) {
        switch (GetLastError()) {
        case ERROR_MOD_NOT_FOUND:
            fprintf(stderr, "%s: not found\n", name);
            break;

        case ERROR_BAD_EXE_FORMAT:
            fprintf(stderr, "%s: bad format\n", name);
            break;

        default:
            fprintf(stderr, "LoadModule(%s) returned %u\n", name, GetLastError());
            break;
        }
        return -1;
    }

    for (i=0; function_names[i]; i++) {
        functions[i] = (void(*)())GetProcAddress(h, function_names[i]);
        if (functions[i] == NULL) {
            switch (GetLastError()) {
            case ERROR_PROC_NOT_FOUND:
                fprintf(stderr, "%s: %s: procedure not found\n",
                    name, function_names[i]);
                break;
            default:
                fprintf(stderr, "%s: error loading: %s (%u)\n",
                    name, function_names[i], GetLastError());
            return_code = -1;
            }
        }
    }

    return return_code;
}

int
lua_dynamic_load(void)
{
    if (lua.newstate)
        return 0; /* already loaded */
    return load_library("lua52.dll", lua_names, (void(**)())&lua);
}

int
lua_selftest(void)
{
    return -1;
}


