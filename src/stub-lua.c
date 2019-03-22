#define LUAAPI
#include "stub-lua.h"

#if defined(WIN32)
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#pragma warning(disable: 4133 4113 4047)
#else
#include <dlfcn.h>
#endif

#if defined(__GNUC__)
/* Disable MinGW warnings for Windows */
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"
#endif


int stublua_init(void)
{
    void *lib = NULL;
    
    {
#if defined(__APPLE__)
        static const char *possible_names[] = {

            "liblua.5.3.5.dylib",
            "liblua.5.3.dylib",
            "liblua5.3.dylib",
            "liblua.dylib",
            0
        };
#elif defined(WIN32) || defined(WIN64) || defined(_WIN32) || defined(_WIN64)
        static const char *possible_names[] = {
            "lua53.dll",
            "lua.dll",
            0
        };
#else
        static const char *possible_names[] = {
            "liblua5.3.so",
            "liblua5.3.so.0",
            "liblua5.3.so.0.0.0",
            0
        };
#endif
        unsigned i;
        for (i=0; possible_names[i]; i++) {
#if defined(WIN32)
            lib = LoadLibraryA(possible_names[i]);
#else
            lib = dlopen(possible_names[i], RTLD_LAZY);
#endif
            if (lib) {
                break;
            } else {
                ;
            }
        }
        
        if (lib == NULL) {
            fprintf(stderr, "liblua: failed to load Lua shared library\n");
            fprintf(stderr, "    HINT: you must install Lua library\n");
        }
    }

#if defined(WIN32)
#define DOLINK(name) \
    name = GetProcAddress(lib, #name); \
    if (name == NULL) fprintf(stderr, "liblua: %s: failed\n", #name);
#else
#define DOLINK(name) \
    name = dlsym(lib, #name); \
    if (name == NULL) fprintf(stderr, "liblua: %s: failed\n", #name);
#endif
    
    DOLINK(lua_version);
    
    
    DOLINK(lua_close)
    DOLINK(lua_getfield)
    DOLINK(lua_getglobal)
    DOLINK(lua_geti)
    DOLINK(lua_gettop)
    DOLINK(lua_isnumber);
    DOLINK(lua_isstring);
    DOLINK(lua_iscfunction);
    DOLINK(lua_isinteger);
    DOLINK(lua_isuserdata);
    DOLINK(lua_newthread)
    DOLINK(lua_newuserdata)
    DOLINK(lua_pcallk)
    DOLINK(lua_pushcclosure)
    DOLINK(lua_pushinteger)
    DOLINK(lua_pushlstring)
    DOLINK(lua_pushnumber)
    DOLINK(lua_pushstring)
    DOLINK(lua_pushvalue)
    DOLINK(lua_resume)
    DOLINK(lua_setfield)
    DOLINK(lua_setglobal)
    DOLINK(lua_seti)
    DOLINK(lua_settop)
    DOLINK(lua_toboolean)
    DOLINK(lua_tointegerx)
    DOLINK(lua_tolstring)
    DOLINK(lua_tonumberx)
    DOLINK(lua_type)
    DOLINK(lua_typename)
    DOLINK(lua_version)
    DOLINK(lua_xmove)
    DOLINK(lua_yieldk)
    
    DOLINK(luaL_checkinteger)
    DOLINK(luaL_checklstring)
    DOLINK(luaL_checkudata)
    DOLINK(luaL_len)
    DOLINK(luaL_loadbufferx)
    DOLINK(luaL_loadfilex)
    DOLINK(luaL_loadstring)
    DOLINK(luaL_newmetatable)
    DOLINK(luaL_newstate)
    DOLINK(luaL_openlibs)
    DOLINK(luaL_ref)
    DOLINK(luaL_setfuncs)
    DOLINK(luaL_setmetatable)
    DOLINK(luaL_unref)
    
    return 0;
}
