#include <stdint.h>
#include <string.h>

#include "utils.h"
#include "16_times/utilsx16.h"
#include "8_times/utilsx8.h"
#include "wots.h"
#include "16_times/wotsx16.h"
#include "8_times/wotsx8.h"
#include "merkle.h"
#include "address.h"
#include "params.h"

/*
 * This generates a Merkle signature (WOTS signature followed by the Merkle
 * authentication path).
 */ 
void merkle_sign(uint8_t *sig, unsigned char *root,
                 const unsigned char *sk_seed, const unsigned char *pub_seed,
                 uint32_t wots_addr[8], uint32_t tree_addr[8],
                 uint32_t idx_leaf)
{
    if(SPX_TREE_HEIGHT >= 4)
    {
        unsigned char *auth_path = sig + SPX_WOTS_BYTES;
        uint32_t tree_addrx16[16*8] = { 0 };
        int j;
        struct leaf_info_x16 info = { 0 };
        unsigned steps[ SPX_WOTS_LEN ];

        info.wots_sig = sig;
        chain_lengths(steps, root);
        info.wots_steps = steps;

        for (j=0; j<16; j++) {
            set_type(&tree_addrx16[8*j], SPX_ADDR_TYPE_HASHTREE);
            set_type(&info.leaf_addr[8*j], SPX_ADDR_TYPE_WOTS);
            set_type(&info.pk_addr[8*j], SPX_ADDR_TYPE_WOTSPK);
            copy_subtree_addr(&tree_addrx16[8*j], tree_addr);
            copy_subtree_addr(&info.leaf_addr[8*j], wots_addr);
            copy_subtree_addr(&info.pk_addr[8*j], wots_addr);
        }

        info.wots_sign_leaf = idx_leaf;

        treehashx16(root, auth_path, sk_seed, pub_seed,
                    idx_leaf, 0,
                    SPX_TREE_HEIGHT,
                    wots_gen_leafx16,
                    tree_addrx16, &info);
    }
    else
    {
        unsigned char *auth_path = sig + SPX_WOTS_BYTES;
        uint32_t tree_addrx8[8*8] = { 0 };
        int j;
        struct leaf_info_x8 info = { 0 };
        unsigned steps[ SPX_WOTS_LEN ];

        info.wots_sig = sig;
        chain_lengths(steps, root);
        info.wots_steps = steps;

        for (j=0; j<8; j++) {
            set_type(&tree_addrx8[8*j], SPX_ADDR_TYPE_HASHTREE);
            set_type(&info.leaf_addr[8*j], SPX_ADDR_TYPE_WOTS);
            set_type(&info.pk_addr[8*j], SPX_ADDR_TYPE_WOTSPK);
            copy_subtree_addr(&tree_addrx8[8*j], tree_addr);
            copy_subtree_addr(&info.leaf_addr[8*j], wots_addr);
            copy_subtree_addr(&info.pk_addr[8*j], wots_addr);
        }

        info.wots_sign_leaf = idx_leaf;

        treehashx8(root, auth_path, sk_seed, pub_seed,
                    idx_leaf, 0,
                    SPX_TREE_HEIGHT,
                    wots_gen_leafx16,
                    tree_addrx8, &info);   
    }
}

/* Compute root node of the top-most subtree. */
/* Again, in this file because wots_gen_leaf is most of the work */
void merkle_gen_root(unsigned char *root,
           const unsigned char *sk_seed, const unsigned char *pub_seed)
{
    /* We do not need the auth path in key generation, but it simplifies the
       code to have just one treehash routine that computes both root and path
       in one function. */
    unsigned char auth_path[SPX_TREE_HEIGHT * SPX_N + SPX_WOTS_BYTES];
    uint32_t top_tree_addr[8] = {0};
    uint32_t wots_addr[8] = {0};

    set_layer_addr(top_tree_addr, SPX_D - 1);
    set_layer_addr(wots_addr, SPX_D - 1);

    merkle_sign(auth_path, root, sk_seed, pub_seed,
                wots_addr, top_tree_addr,
                ~0 /* ~0 means "don't bother generating an auth path */ );
}
