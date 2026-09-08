/* Matching exact FLINT oracle for examples/rational_polynomial_shapes.rs.
 * See ../rational_polynomial_shapes.md for compilation and measurement notes. */
#define _POSIX_C_SOURCE 200809L
#include <flint/flint.h>
#include <flint/fmpq_mpoly.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static unsigned long long now_ns(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) abort();
    return (unsigned long long)value.tv_sec * 1000000000ULL + value.tv_nsec;
}

static void load(fmpq_mpoly_t p, const fmpq_mpoly_ctx_t ctx,
                 const char **variables, const char *directory,
                 const char *name, const char *suffix) {
    char path[1024];
    snprintf(path,sizeof(path),"%s/%s.%s",directory,name,suffix);
    FILE *input=fopen(path,"rb");
    if (!input) { perror(path); exit(2); }
    if(fseek(input,0,SEEK_END)!=0) abort();
    long length=ftell(input);
    if(length<0 || fseek(input,0,SEEK_SET)!=0) abort();
    char *text=malloc((size_t)length+1);
    if(!text || fread(text,1,length,input)!=(size_t)length) abort();
    text[length]=0;
    fclose(input);
    if (fmpq_mpoly_set_str_pretty(p,text,variables,ctx)!=0) {
        fprintf(stderr,"Cannot parse %s\n",path); exit(2);
    }
    free(text);
}

int main(int argc, char **argv) {
    if(argc<3 || argc>4) return 2;
    int rounds=atoi(argv[1]);
    if(rounds<1) return 2;
    flint_set_num_threads(1);
    const char *variables[]={"x","y","z","a","b","c","d","e"};
    const char *shapes[]={"sparse8_d128","dense3_d12","dense3_d20","sparse8_div127","sparse8_div128"};
    int bits[]={12,63,127};
    puts("shape,bits,rational,operation,domain,nvars,left_terms,right_terms,output_terms,rounds,elapsed_ns");
    for(size_t shape=0;shape<sizeof(shapes)/sizeof(shapes[0]);shape++) for(int bit=0;bit<3;bit++) for(int rational=0;rational<2;rational++) {
        if(argc==4 && strcmp(argv[3],shapes[shape])!=0) continue;
        int nvars=strncmp(shapes[shape],"sparse",6)==0?8:3;
        fmpq_mpoly_ctx_t ctx;
        fmpq_mpoly_ctx_init(ctx,nvars,ORD_LEX);
        fmpq_mpoly_t left,right,product,result;
        fmpq_mpoly_init(left,ctx); fmpq_mpoly_init(right,ctx); fmpq_mpoly_init(product,ctx); fmpq_mpoly_init(result,ctx);
        char name[128];
        snprintf(name,sizeof(name),"%s-b%d-q%s",shapes[shape],bits[bit],rational?"true":"false");
        load(left,ctx,variables,argv[2],name,"left");
        load(right,ctx,variables,argv[2],name,"right");
        load(product,ctx,variables,argv[2],name,"product");
        fmpq_mpoly_mul(result,left,right,ctx);
        if(!fmpq_mpoly_equal(result,product,ctx)) abort();
        if(!fmpq_mpoly_divides(result,product,left,ctx) || !fmpq_mpoly_equal(result,right,ctx)) abort();
        for(int operation=0;operation<2;operation++) {
            unsigned long long start=now_ns();
            for(int round=0;round<rounds;round++) {
                fmpq_mpoly_t output;
                fmpq_mpoly_init(output,ctx);
                if(operation==0) fmpq_mpoly_mul(output,left,right,ctx);
                else if(!fmpq_mpoly_divides(output,product,left,ctx)) abort();
                fmpq_mpoly_clear(output,ctx);
            }
            printf("%s,%d,%s,%s,FLINT_Q,%d,%ld,%ld,%ld,%d,%llu\n",shapes[shape],bits[bit],rational?"true":"false",operation==0?"multiply":"exact_division",nvars,fmpq_mpoly_length(left,ctx),fmpq_mpoly_length(right,ctx),fmpq_mpoly_length(product,ctx),rounds,now_ns()-start);
            fflush(stdout);
        }
        fmpq_mpoly_clear(left,ctx); fmpq_mpoly_clear(right,ctx); fmpq_mpoly_clear(product,ctx); fmpq_mpoly_clear(result,ctx);
        fmpq_mpoly_ctx_clear(ctx);
    }
    flint_cleanup();
    return 0;
}
