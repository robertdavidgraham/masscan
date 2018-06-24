#ifndef RANGES_AVL_H
#define RANGES_AVL_H

struct RavlNode * 
ravl_insert(unsigned ip_begin, unsigned ip_end, struct RavlNode *t);

void 
ravl_free(struct RavlNode* node);

typedef void (*RAVL_CALLBACK)(void *callback_data, unsigned ip_begin, unsigned ip_end);

void
ravl_enumerate(struct RavlNode *t, RAVL_CALLBACK callback_func, void *callback_data);

#define ravl_create() (0)




#endif
