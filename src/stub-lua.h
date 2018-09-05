/*
    Stub declarations, for loading Lua dynamicaly at runtime using
    openlib() or LoadLibrary().
 */

#ifndef STUB_LUA_H
#define STUB_LUA_H
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

/**
 * Called to load the Lua dynamic library, suh as lua53.dll or lua5.3.so.0,
 * and link all the function pointers. This must be called before calling any
 * Lua functions, or the program will crash.
 */
int stublua_init(void);

struct lua_State;
typedef struct lua_State lua_State;
typedef long long lua_Integer;
typedef double lua_Number;
typedef unsigned long long lua_Unsigned;
typedef ptrdiff_t lua_KContext;
typedef int (*lua_KFunction) (lua_State *L, int status, lua_KContext ctx);
typedef int (*lua_CFunction) (lua_State *L);
typedef struct luaL_Reg {
    const char *name;
    lua_CFunction func;
} luaL_Reg;

#define LUA_MULTRET    (-1)
#define LUAI_MAXSTACK        1000000
#define LUA_REGISTRYINDEX    (-LUAI_MAXSTACK - 1000)

#define LUA_OK          0
#define LUA_YIELD       1
#define LUA_ERRRUN      2
#define LUA_ERRSYNTAX   3
#define LUA_ERRMEM      4
#define LUA_ERRGCMM     5
#define LUA_ERRERR      6

#define LUA_TNONE           (-1)
#define LUA_TNIL            0
#define LUA_TBOOLEAN        1
#define LUA_TLIGHTUSERDATA  2
#define LUA_TNUMBER         3
#define LUA_TSTRING         4
#define LUA_TTABLE          5
#define LUA_TFUNCTION       6
#define LUA_TUSERDATA       7
#define LUA_TTHREAD         8
#define LUA_NUMTAGS         9


#define lua_isfunction(L,n)         (lua_type(L, (n)) == LUA_TFUNCTION)
#define lua_istable(L,n)            (lua_type(L, (n)) == LUA_TTABLE)
#define lua_islightuserdata(L,n)    (lua_type(L, (n)) == LUA_TLIGHTUSERDATA)
#define lua_isnil(L,n)              (lua_type(L, (n)) == LUA_TNIL)
#define lua_isboolean(L,n)          (lua_type(L, (n)) == LUA_TBOOLEAN)
#define lua_isthread(L,n)           (lua_type(L, (n)) == LUA_TTHREAD)
#define lua_isnone(L,n)             (lua_type(L, (n)) == LUA_TNONE)
#define lua_isnoneornil(L, n)       (lua_type(L, (n)) <= 0)
#define lua_pcall(L,n,r,f)          lua_pcallk(L, (n), (r), (f), 0, NULL)
#define lua_pop(L,n)                lua_settop(L, -(n)-1)
#define lua_pushcfunction(L,f)      lua_pushcclosure(L, (f), 0)
#define lua_register(L,n,f)         (lua_pushcfunction(L, (f)), lua_setglobal(L, (n)))
#define lua_tonumber(L,i)           lua_tonumberx(L,(i),NULL)
#define lua_tointeger(L,i)          lua_tointegerx(L,(i),NULL)
#define lua_tostring(L,i)           lua_tolstring(L, (i), NULL)
#define lua_upvalueindex(i)         (LUA_REGISTRYINDEX - (i))
#define lua_yield(L,n)              lua_yieldk(L, (n), 0, NULL)

#define luaL_checkstring(L,n)       (luaL_checklstring(L, (n), NULL))
#define luaL_dofile(L, fn)          (luaL_loadfile(L, fn) || lua_pcall(L, 0, LUA_MULTRET, 0))
#define luaL_dostring(L, s)         (luaL_loadstring(L, s) || lua_pcall(L, 0, LUA_MULTRET, 0))
#define luaL_getmetatable(L,n)      (lua_getfield(L, LUA_REGISTRYINDEX, (n)))
#define luaL_loadbuffer(L,s,sz,n)   luaL_loadbufferx(L,s,sz,n,NULL)
#define luaL_loadfile(L,f)          luaL_loadfilex(L,f,NULL)
#define luaL_opt(L,f,n,d)           (lua_isnoneornil(L,(n)) ? (d) : f(L,(n)))
#define luaL_typename(L,i)          lua_typename(L, lua_type(L,(i)))

#ifndef LUAAPI
#define LUAAPI extern
#endif

LUAAPI void        (*lua_close)(lua_State *L);
LUAAPI int         (*lua_getfield)(lua_State *L, int idx, const char *k);
LUAAPI int         (*lua_getglobal)(lua_State *L, const char *name);
LUAAPI int         (*lua_geti)(lua_State *L, int idx, lua_Integer n);
LUAAPI int         (*lua_gettop)(lua_State *L);
LUAAPI int         (*lua_isnumber)(lua_State *L, int idx);
LUAAPI int         (*lua_isstring)(lua_State *L, int idx);
LUAAPI int         (*lua_iscfunction)(lua_State *L, int idx);
LUAAPI int         (*lua_isinteger)(lua_State *L, int idx);
LUAAPI int         (*lua_isuserdata)(lua_State *L, int idx);
LUAAPI lua_State * (*lua_newthread)(lua_State *L);
LUAAPI void *      (*lua_newuserdata)(lua_State *L, size_t size);
LUAAPI int         (*lua_pcallk)(lua_State *L, int nargs, int nresults, int errfunc,lua_KContext ctx,lua_KFunction k);
LUAAPI void        (*lua_pushcclosure)(lua_State *L,lua_CFunction fn, int n);
LUAAPI void        (*lua_pushinteger)(lua_State *L,lua_Integer n);
LUAAPI const char *(*lua_pushlstring)(lua_State *L, const char *s, size_t len);
LUAAPI void        (*lua_pushnumber)(lua_State *L,lua_Number n);
LUAAPI const char *(*lua_pushstring)(lua_State *L, const char *s);
LUAAPI void        (*lua_pushvalue )(lua_State *L, int idx);
LUAAPI int         (*lua_resume)(lua_State *L,lua_State *from, int nargs);
LUAAPI void        (*lua_setfield)(lua_State *L, int idx, const char *k);
LUAAPI void        (*lua_setglobal)(lua_State *L, const char *name);
LUAAPI void        (*lua_seti)(lua_State *L, int idx, lua_Integer n);
LUAAPI void        (*lua_settop)(lua_State *L, int idx);
LUAAPI int         (*lua_toboolean)(lua_State *L, int idx);
LUAAPI lua_Integer (*lua_tointegerx)(lua_State *L, int idx, int *pisnum);
LUAAPI const char *(*lua_tolstring)(lua_State *L, int idx, size_t *len);
LUAAPI lua_Number  (*lua_tonumberx)(lua_State *L, int idx, int *pisnum);
LUAAPI int         (*lua_type)(lua_State *L, int idx);
LUAAPI const char *(*lua_typename)(lua_State *L, int t);
LUAAPI const lua_Number *(*lua_version)(lua_State *L);
LUAAPI void        (*lua_xmove)(lua_State *from,lua_State *to, int n);
LUAAPI int         (*lua_yieldk)(lua_State *L, int nresults,lua_KContext ctx,lua_KFunction k);

LUAAPI lua_Integer (*luaL_checkinteger)(lua_State *L, int arg);
LUAAPI const char *(*luaL_checklstring)(lua_State *L, int arg, size_t *len);
LUAAPI void *      (*luaL_checkudata)(lua_State *L, int ud, const char *tname);
LUAAPI lua_Integer (*luaL_len)(lua_State *L, int idx);
LUAAPI int         (*luaL_loadbufferx)(lua_State *L, const char *buff, size_t size, const char *name, const char *mode);
LUAAPI int         (*luaL_loadfilex)(lua_State *L, const char *filename, const char *mode);
LUAAPI int         (*luaL_loadstring)(lua_State *L, const char *s);
LUAAPI int         (*luaL_newmetatable)(lua_State *L, const char *tname);
LUAAPI lua_State * (*luaL_newstate)(void);
LUAAPI void        (*luaL_openlibs)(lua_State *L);
LUAAPI int         (*luaL_ref)(lua_State *L, int t);
LUAAPI void        (*luaL_setfuncs)(lua_State *L, const luaL_Reg *l, int nup);
LUAAPI void        (*luaL_setmetatable)(lua_State *L, const char *tname);
LUAAPI void        (*luaL_unref)(lua_State *L, int t, int ref);

#endif

