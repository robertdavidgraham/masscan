#ifndef DYN_LUA_H
#define DYN_LUA_H
#include <stdio.h>

#define LUAI_BITSINT 32

/*
@@ LUAI_MAXSTACK limits the size of the Lua stack.
** CHANGE it if you need a different limit. This limit is arbitrary;
** its only purpose is to stop Lua to consume unlimited stack
** space (and to reserve some numbers for pseudo-indices).
*/
#if LUAI_BITSINT >= 32
#define LUAI_MAXSTACK		1000000
#else
#define LUAI_MAXSTACK		15000
#endif

/* reserve some space for error handling */
#define LUAI_FIRSTPSEUDOIDX	(-LUAI_MAXSTACK - 1000)

/*
** pseudo-indices
*/
#define LUA_REGISTRYINDEX	LUAI_FIRSTPSEUDOIDX
#define lua_upvalueindex(i)	(LUA_REGISTRYINDEX - (i))


/* thread status; 0 is OK */
#define LUA_YIELD       1
#define LUA_ERRRUN      2
#define LUA_ERRSYNTAX   3
#define LUA_ERRMEM      4
#define LUA_ERRERR      5

/* option for multiple returns in 'lua_pcall' and 'lua_call' */
#define LUA_MULTRET	(-1)

#define LUA_INT32	int
#define LUAI_UMEM	size_t
#define LUAI_MEM	ptrdiff_t
#define LUA_NUMBER	double
#define LUA_INTEGER	ptrdiff_t
#define LUA_UNSIGNED	unsigned LUA_INT32

typedef LUA_NUMBER lua_Number;
typedef LUA_INTEGER lua_Integer;
typedef LUA_UNSIGNED lua_Unsigned;



struct lua_State;
typedef struct lua_State lua_State;
typedef int (*lua_CFunction) (lua_State *L);
#define lua_pop(L,n)  lua.settop(L, -(n)-1)
#define lua_tostring(L,i)       lua.tolstring(L, (i), NULL)
#define luaL_loadfile(L,f)      lua.loadfilex(L,f,NULL)
#define lua_pcall(L,n,r,f)      lua.pcallk(L, (n), (r), (f), 0, NULL)
#define luaL_newstate           lua.newstate
#define luaL_openlibs           lua.openlibs
#define lua_setglobal            lua.setglobal
#define lua_getglobal            lua.getglobal
#define luaL_dofile(L, filename) (luaL_loadfile(L, filename) || lua_pcall(L, 0, LUA_MULTRET, 0))
#define luaL_loadbuffer(L,s,sz,n)	lua.loadbufferx(L,s,sz,n,NULL)
#define lua_pushcfunction(L,f)  lua.pushcclosure(L,f,0)
#define lua_yield(L,n)		lua.yieldk(L, (n), 0, NULL)

#define LUA_OK          0
#define LUA_YIELD       1
#define LUA_ERRRUN      2
#define LUA_ERRSYNTAX   3
#define LUA_ERRMEM      4
#define LUA_ERRGCMM     5
//#define LUA_ERRERR      6
#define LUA_ERRFILE     7


#define LUA_TNONE		(-1)

#define LUA_TNIL		0
#define LUA_TBOOLEAN		1
#define LUA_TLIGHTUSERDATA	2
#define LUA_TNUMBER		3
#define LUA_TSTRING		4
#define LUA_TTABLE		5
#define LUA_TFUNCTION		6
#define LUA_TUSERDATA		7
#define LUA_TTHREAD		8

#define LUA_NUMTAGS		9


struct LUA {
    struct lua_State *(*newstate)(void);
    void            (*close) (lua_State *L);
    void            (*openlibs)(struct lua_State *L);
    struct lua_State *(*newthread)(struct lua_State *L);
    int             (*loadfilex)(struct lua_State *L, const char *filename, const char *mode);
    int             (*loadbufferx)(lua_State *L, const char *buf, size_t sizeof_buf, const char *name, const char *mode);
    void            (*settop)(struct lua_State *L, int index);
    int             (*pcallk)(lua_State *L, int nargs, int nresults, int errfunc, int ctx, lua_CFunction k);
    
    void  (*getglobal) (lua_State *L, const char *var);
    void  (*gettable) (lua_State *L, int idx);
    void  (*getfield) (lua_State *L, int idx, const char *k);
    void  (*rawget) (lua_State *L, int idx);
    void  (*rawgeti) (lua_State *L, int idx, int n);
    void  (*rawgetp) (lua_State *L, int idx, const void *p);
    void  (*createtable) (lua_State *L, int narr, int nrec);
    void *(*newuserdata) (lua_State *L, size_t sz);
    int   (*getmetatable) (lua_State *L, int objindex);
    void  (*getuservalue) (lua_State *L, int idx);

    void  (*setglobal) (lua_State *L, const char *var);
    void  (*settable) (lua_State *L, int idx);
    void  (*setfield) (lua_State *L, int idx, const char *k);
    void  (*rawset) (lua_State *L, int idx);
    void  (*rawseti) (lua_State *L, int idx, int n);
    void  (*rawsetp) (lua_State *L, int idx, const void *p);
    int   (*setmetatable) (lua_State *L, int objindex);
    void  (*setuservalue) (lua_State *L, int idx);

    void        (*pushnil) (lua_State *L);
    void        (*pushnumber) (lua_State *L, lua_Number n);
    void        (*pushinteger) (lua_State *L, lua_Integer n);
    void        (*pushunsigned) (lua_State *L, lua_Unsigned n);
    const char *(*pushlstring) (lua_State *L, const char *s, size_t l);
    const char *(*pushstring) (lua_State *L, const char *s);
    const char *(*pushvfstring) (lua_State *L, const char *fmt, va_list argp);
    const char *(*pushfstring) (lua_State *L, const char *fmt, ...);
    void  (*pushcclosure) (lua_State *L, lua_CFunction fn, int n);
    void  (*pushboolean) (lua_State *L, int b);
    void  (*pushlightuserdata) (lua_State *L, void *p);
    int   (*pushthread) (lua_State *L);

    int             (*isnumber) (lua_State *L, int idx);
    int             (*isstring) (lua_State *L, int idx);
    int             (*iscfunction) (lua_State *L, int idx);
    int             (*isuserdata) (lua_State *L, int idx);
    int             (*type) (lua_State *L, int idx);
    const char     *(*typename) (lua_State *L, int tp);

    lua_Number      (*tonumberx) (lua_State *L, int idx, int *isnum);
    lua_Integer     (*tointegerx) (lua_State *L, int idx, int *isnum);
    lua_Unsigned    (*tounsignedx) (lua_State *L, int idx, int *isnum);
    int             (*toboolean) (lua_State *L, int idx);
    const char     *(*tolstring) (lua_State *L, int idx, size_t *len);
    size_t          (*rawlen) (lua_State *L, int idx);
    lua_CFunction   (*tocfunction) (lua_State *L, int idx);
    void	       *(*touserdata) (lua_State *L, int idx);
    lua_State      *(*tothread) (lua_State *L, int idx);
    const void     *(*topointer) (lua_State *L, int idx);

    int (*gettop)(lua_State *L);

    int  (*yieldk) (lua_State *L, int nresults, int ctx, lua_CFunction k);
    int  (*resume) (lua_State *L, lua_State *from, int narg);
    int  (*status) (lua_State *L);

    void (*foo)(void);
};

extern struct LUA lua;

#endif
