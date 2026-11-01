#ifndef MURMUR_MANAGED_HARNESS_NATIVE_H
#define MURMUR_MANAGED_HARNESS_NATIVE_H
#include "../../../../libmurmur.h"
typedef struct { char *json; size_t bytes; } mh_result;
#ifdef __cplusplus
extern "C" {
#endif
int mh_execute(murmur_managed_t *,int,const char **,size_t,mh_result *);
int mh_rows(murmur_managed_t *,int,mh_result *);
int mh_apply(murmur_managed_t *,const void *,size_t,int,int *);
int mh_migrate(murmur_managed_t *,const char *,const murmur_rename_t *,size_t,int);
int mh_capabilities(void);
int mh_execute_hold(murmur_managed_t *,int,const char **,size_t,const char *,mh_result *);
#ifdef __cplusplus
}
#endif
#endif
