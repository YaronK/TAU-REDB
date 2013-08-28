
/*
 * This file contains the graph handling routines.
 *
 * Copyright (C) 2002 Sampo Niskanen, Patric Östergård.
 * Licensed under the GNU GPL, read the file LICENSE for details.
 */


#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include "graph.h"


int graph_add_edge_redb(graph_t * g, int i, int j)
{
	int n = g->n;
	if ((NULL!=g) && (i<n) && (j<n))
	{
		GRAPH_ADD_EDGE(g,i,j);
		return 0;
	}
	return -1;
}

int graph_set_vertex_weight_redb(graph_t * g, int i, int w)
{
	int n = g->n;
	if ((NULL!=g) && (i<n) && (0<=w))
	{
		g->weights[i]=w;
		return 0;
	}
	return -1;
}

/*
 * graph_new()
 *
 * Returns a newly allocated graph with n vertices all with weight 1,
 * and no edges.
 */
graph_t *graph_new(int n) {
	graph_t *g;
	int i;

	ASSERT((sizeof(setelement)*8)==ELEMENTSIZE);
	ASSERT(n>0);

	g=malloc(sizeof(graph_t));
	g->n=n;
	g->edges=malloc(g->n * sizeof(set_t));
	g->weights=malloc(g->n * sizeof(int));
	for (i=0; i < g->n; i++) {
		g->edges[i]=set_new(n);
		g->weights[i]=1;
	}
	return g;
}

/*
 * graph_free()
 *
 * Frees the memory associated with the graph g.
 */
void graph_free(graph_t *g) {
	int i;

	ASSERT((sizeof(setelement)*8)==ELEMENTSIZE);
	ASSERT(g!=NULL);
	ASSERT(g->n > 0);

	for (i=0; i < g->n; i++) {
		set_free(g->edges[i]);
	}
	free(g->weights);
	free(g->edges);
	free(g);
	return;
}


/*
 * graph_resize()
 *
 * Resizes graph g to given size.  If size > g->n, the new vertices are
 * not connected to any others and their weights are set to 1.
 * If size < g->n, the last g->n - size vertices are removed.
 */
void graph_resize(graph_t *g, int size) {
	int i;

	ASSERT(g!=NULL);
	ASSERT(g->n > 0);
	ASSERT(size > 0);

	if (g->n == size)
		return;

	/* Free/alloc extra edge-sets */
	for (i=size; i < g->n; i++)
		set_free(g->edges[i]);
	g->edges=realloc(g->edges, size * sizeof(set_t));
	for (i=g->n; i < size; i++)
		g->edges[i]=set_new(size);

	/* Resize original sets */
	for (i=0; i < MIN(g->n,size); i++) {
		g->edges[i]=set_resize(g->edges[i],size);
	}

	/* Weights */
	g->weights=realloc(g->weights,size * sizeof(int));
	for (i=g->n; i<size; i++)
		g->weights[i]=1;
	
	g->n=size;
	return;
}

/*
 * graph_crop()
 *
 * Resizes the graph so as to remove all highest-valued isolated vertices.
 */
void graph_crop(graph_t *g) {
	int i;
	
	for (i=g->n-1; i>=1; i--)
		if (set_size(g->edges[i])>0)
			break;
	graph_resize(g,i+1);
	return;
}


/*
 * graph_weighted()
 *
 * Returns TRUE if all vertex weights of graph g are all the same.
 *
 * Note: Does NOT require weights to be 1.
 */
boolean graph_weighted(graph_t *g) {
	int i,w;

	w=g->weights[0];
	for (i=1; i < g->n; i++)
		if (g->weights[i] != w)
			return TRUE;
	return FALSE;
}

/*
 * graph_edge_count()
 *
 * Returns the number of edges in graph g.
 */
int graph_edge_count(graph_t *g) {
	int i;
	int count=0;

	for (i=0; i < g->n; i++) {
		count += set_size(g->edges[i]);
	}
	return count/2;
}


/*
 * graph_print()
 *
 * Prints a representation of the graph g to stdout (along with any errors
 * noticed).  Mainly useful for debugging purposes and trivial output.
 *
 * The output consists of a first line describing the dimensions and then
 * one line per vertex containing the vertex number (numbered 0,...,n-1),
 * the vertex weight (if the graph is weighted), "->" and then a list
 * of all vertices it is adjacent to.
 */
void graph_print(graph_t *g) {
	int i,j;
	int asymm=0;
	int refl=0;
	int nonpos=0;
	int extra=0;
	unsigned int weight=0;
	boolean weighted;
	
	ASSERT((sizeof(setelement)*8)==ELEMENTSIZE);

	if (g==NULL) {
		printf("   WARNING: Graph pointer is NULL!\n");
		return;
	}
	if (g->n <= 0) {
		printf("   WARNING: Graph has %d vertices "
		       "(should be positive)!\n",g->n);
		return;
	}
	
	weighted=graph_weighted(g);

	printf("%s graph has %d vertices, %d edges (density %.2f).\n",
	       weighted?"Weighted":((g->weights[0]==1)?
				    "Unweighted":"Semi-weighted"),
	       g->n,graph_edge_count(g),
	       (float)graph_edge_count(g)/((float)(g->n - 1)*(g->n)/2));

	for (i=0; i < g->n; i++) {
		printf("%2d",i);
		if (weighted) {
			printf(" w=%d",g->weights[i]);
			if (g->weights[i] <= 0) {
				printf("*NON-POSITIVE*");
				nonpos++;
			}
		}
		if (weight < INT_MAX)
			weight+=g->weights[i];
		printf(" ->");
		for (j=0; j < g->n; j++) {
			if (SET_CONTAINS_FAST(g->edges[i],j)) {
				printf(" %d",j);
				if (i==j) {
					printf("*REFLEXIVE*");
					refl++;
				}
				if (!SET_CONTAINS_FAST(g->edges[j],i)) {
					printf("*ASYMMERTIC*");
					asymm++;
				}
			}
		}
		for (j=g->n; j < SET_ARRAY_LENGTH(g->edges[i])*ELEMENTSIZE;
		     j++) {
			if (SET_CONTAINS_FAST(g->edges[i],j)) {
				printf(" %d*NON-EXISTENT*",j);
				extra++;
			}
		}
		printf("\n");
	}

	if (asymm)
		printf("   WARNING: Graph contained %d asymmetric edges!\n",
		       asymm);
	if (refl)
		printf("   WARNING: Graph contained %d reflexive edges!\n",
		       refl);
	if (nonpos)
		printf("   WARNING: Graph contained %d non-positive vertex "
		       "weights!\n",nonpos);
	if (extra)
		printf("   WARNING: Graph contained %d edges to "
		       "non-existent vertices!\n",extra);
	if (weight>=INT_MAX)
		printf("   WARNING: Total graph weight >= INT_MAX!\n");
	return;
}


/*
 * graph_test()
 *
 * Tests graph g to be valid.  Checks that g is non-NULL, the edges are
 * symmetric and anti-reflexive, and that all vertex weights are positive.
 * If output is non-NULL, prints a few lines telling the status of the graph
 * to file descriptor output.
 * 
 * Returns TRUE if the graph is valid, FALSE otherwise.
 */
boolean graph_test(graph_t *g,FILE *output) {
	int i,j;
	int edges=0;
	int asymm=0;
	int nonpos=0;
	int refl=0;
	int extra=0;
	unsigned int weight=0;
	boolean weighted;

	ASSERT((sizeof(setelement)*8)==ELEMENTSIZE);

	if (g==NULL) {
		if (output)
			fprintf(output,"   WARNING: Graph pointer is NULL!\n");
		return FALSE;
	}

	weighted=graph_weighted(g);
	
	for (i=0; i < g->n; i++) {
		if (g->edges[i]==NULL) {
			if (output)
				fprintf(output,"   WARNING: Graph edge set "
					"NULL!\n"
					"   (further warning suppressed)\n");
			return FALSE;
		}
		if (SET_MAX_SIZE(g->edges[i]) < g->n) {
			if (output)
				fprintf(output,"   WARNING: Graph edge set "
					"too small!\n"
					"   (further warnings suppressed)\n");
			return FALSE;
		}
		for (j=0; j < g->n; j++) {
			if (SET_CONTAINS_FAST(g->edges[i],j)) {
				edges++;
				if (i==j) {
					refl++;
				}
				if (!SET_CONTAINS_FAST(g->edges[j],i)) {
					asymm++;
				}
			}
		}
		for (j=g->n; j < SET_ARRAY_LENGTH(g->edges[i])*ELEMENTSIZE;
		     j++) {
			if (SET_CONTAINS_FAST(g->edges[i],j))
				extra++;
		}
		if (g->weights[i] <= 0)
			nonpos++;
		if (weight<INT_MAX)
			weight += g->weights[i];
	}
	
	edges/=2;  /* Each is counted twice. */
	
	if (output) {
		/* Semi-weighted means all weights are equal, but not 1. */
		fprintf(output,"%s graph has %d vertices, %d edges "
			"(density %.2f).\n",
			weighted?"Weighted":
			((g->weights[0]==1)?"Unweighted":"Semi-weighted"),
			g->n,edges,(float)edges/((float)(g->n - 1)*(g->n)/2));
		
		if (asymm)
			fprintf(output,"   WARNING: Graph contained %d "
				"asymmetric edges!\n",asymm);
		if (refl)
			fprintf(output,"   WARNING: Graph contained %d "
				"reflexive edges!\n",refl);
		if (nonpos)
			fprintf(output,"   WARNING: Graph contained %d "
				"non-positive vertex weights!\n",nonpos);
		if (extra)
			fprintf(output,"   WARNING: Graph contained %d edges "
				"to non-existent vertices!\n",extra);
		if (weight>=INT_MAX)
			fprintf(output,"   WARNING: Total graph weight >= "
				"INT_MAX!\n");
		if (asymm==0 && refl==0 && nonpos==0 && extra==0 &&
		    weight<INT_MAX)
			fprintf(output,"Graph OK.\n");
	}
	
	if (asymm || refl || nonpos || extra || weight>=INT_MAX)
		return FALSE;

	return TRUE;
}


/*
 * graph_test_regular()
 *
 * Returns the vertex degree for regular graphs, or -1 if the graph is
 * not regular.
 */
int graph_test_regular(graph_t *g) {
	int i,n;

	n=set_size(g->edges[0]);

	for (i=1; i < g->n; i++) {
		if (set_size(g->edges[i]) != n)
			return -1;
	}
	return n;
}

