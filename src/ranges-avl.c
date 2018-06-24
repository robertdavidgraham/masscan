/***************************************************************************

    RANGES - AVL TREE

    Reading in a million UNSORTED IP addresses is slow, as in it could
    takes hours. That's because the internal table is a linear sorted
    array of entries. That means for every random IP address we add to
    the list, we'll need to do a memmove() of a few megabytes of RAM.

    The solution is to first read in the IP addresses in a sort-friendly
    manner, such as a binary tree. However, a normal binary tree is bad
    because if the input isn't random (already sorted), then we end up
    creating a linked-list instead, and are back to the same problem
    of taking hours to read in all the IP addresses.
    
    To solve this, we first read in a file containing IP addresses into
    an AVL tree. This will keep the tree balanced, preventing an unbalanced
    tree. Thus, reading in a sorted and unsorted list is roughly the same
    speed.
 ***************************************************************************/
#include "ranges-avl.h"
#include <stdio.h>
#include <stdlib.h>

#ifndef max
#define max(a,b)   (((a) > (b)) ? (a) : (b))
#endif

struct RavlNode
{
    unsigned ip_begin;
    unsigned ip_end;
    int      height;
    struct RavlNode*  left;
    struct RavlNode*  right;
};


/***************************************************************************
 ***************************************************************************/
void 
ravl_free(struct RavlNode *node)
{
    if (node != NULL) {
        ravl_free(node->left);
        ravl_free(node->right);
        free(node);
    }
}
 
 
 
/***************************************************************************
 ***************************************************************************/
static int 
height(const struct RavlNode *node)
{
    if (node == NULL)
        return -1;
    else
        return node->height;
}
 
 
 
/***************************************************************************
 ***************************************************************************/
static struct RavlNode *
single_rotate_with_left(struct RavlNode* k2)
{
    struct RavlNode* k1 = NULL;
 
    k1 = k2->left;
    k2->left = k1->right;
    k1->right = k2;
 
    k2->height = max( height( k2->left ), height( k2->right ) ) + 1U;
    k1->height = max( height( k1->left ), k2->height ) + 1U;
    return k1; /* new root */
}
 
 
/***************************************************************************
 ***************************************************************************/
static struct RavlNode *
single_rotate_with_right(struct RavlNode* k1)
{
    struct RavlNode* k2;
 
    k2 = k1->right;
    k1->right = k2->left;
    k2->left = k1;
 
    k1->height = max( height( k1->left ), height( k1->right ) ) + 1;
    k2->height = max( height( k2->right ), k1->height ) + 1;
 
    return k2;  /* New root */
}
 
 
/***************************************************************************
 ***************************************************************************/
static struct RavlNode *
double_rotate_with_left(struct RavlNode* k3)
{
    /* Rotate between k1 and k2 */
    k3->left = single_rotate_with_right(k3->left);
 
    /* Rotate between K3 and k2 */
    return single_rotate_with_left(k3);
}
 
 
/***************************************************************************
 ***************************************************************************/
static struct RavlNode *
double_rotate_with_right( struct RavlNode* k1 )
{
    /* rotate between K3 and k2 */
    k1->right = single_rotate_with_left(k1->right);
 
    /* rotate between k1 and k2 */
    return single_rotate_with_right(k1);
}


/***************************************************************************
 * Recursively insert and perhaps rebalance.
 ***************************************************************************/
struct RavlNode * 
ravl_insert(unsigned ip_begin, unsigned ip_end, struct RavlNode *node)
{
    if (node == NULL) {
        node = malloc(sizeof(struct RavlNode));
        node->ip_begin = ip_begin;
        node->ip_end = ip_end;
        node->height = 0;
        node->left = node->right = NULL;
    } else if (ip_begin < node->ip_begin) {
        node->left = ravl_insert(ip_begin, ip_end, node->left);
        
        if (height(node->left) - height(node->right) == 2) {
            if (ip_begin < node->left->ip_begin)
                node = single_rotate_with_left(node);
            else
                node = double_rotate_with_left(node);
        }
    } else if (ip_begin > node->ip_begin) {
        node->right = ravl_insert(ip_begin, ip_end, node->right);

        if (height(node->right) - height(node->left) == 2) {
            if (ip_begin > node->right->ip_begin)
                node = single_rotate_with_right(node);
            else
                node = double_rotate_with_right(node);
        }
    } else {
        /* ip_begin == node->ip_begin*/
        ;
    }

    node->height = max( height( node->left ), height( node->right ) ) + 1;

    return node;
}
 
 
/***************************************************************************
 * Recursively enumerate the tree.
 * This will be called to build the "rangelist_add()" function recursivley
 * on all the nodes. Where this structure is a binary tree, the "rangelist"
 * structure is a linear, sorted array. We'll essentially just be
 * continuously appending all these nodes onto the end of the "rangelist"
 * array.
 ***************************************************************************/
void
ravl_enumerate(struct RavlNode *node, RAVL_CALLBACK callback_func, void *callback_data)
{
    if (node == NULL)
        return;

    callback_func(callback_data, node->ip_begin, node->ip_end);

    ravl_enumerate(node->left, callback_func, callback_data);
    ravl_enumerate(node->right, callback_func, callback_data);
}

