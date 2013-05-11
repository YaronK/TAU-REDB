
#ifndef CLIQUER_H
#define CLIQUER_H

#include <string.h>

#include "set.h"
#include "graph.h"
#include "reorder.h"

typedef struct _clique_options clique_options;
struct _clique_options {
	int *(*reorder_function)(graph_t *, boolean);
	int *reorder_map;

	FILE *output;

	boolean (*user_function)(set_t,graph_t *,clique_options *);
	void *user_data;
	set_t *clique_list;
	int clique_list_length;
};

extern clique_options *clique_default_options;

/* Weighted clique functions */
extern int clique_max_weight(graph_t *g,clique_options *opts);
extern int clique_max_size(graph_t *g,clique_options *opts);
extern set_t clique_find_single(graph_t *g,int min_weight,int max_weight,
				boolean maximal, clique_options *opts);

extern clique_options * clique_options_new_redb(int *(*reorder_function)(graph_t *, boolean));

extern void clique_options_free_redb(clique_options * opts);

/* Alternate spelling (let's be a little forgiving): */
#define cliquer_options clique_options
#define cliquer_default_options clique_default_options

#endif /* !CLIQUER_H */
