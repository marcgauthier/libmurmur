#ifndef MURMUR_MANAGED_POLICY_STATE_H
#define MURMUR_MANAGED_POLICY_STATE_H
#include "managed_value.h"
#include "causal.h"
#include <memory>
/* Shared by local operations and replicated row joins. Baselines are
 * immutable within one row epoch. Deterministic seed tags use that epoch. */
struct ManagedPolicyState {
  ManagedValue baseline;
  std::unique_ptr<murmur_causal_t,decltype(&murmur_causal_free)> causal{nullptr,murmur_causal_free};
};
std::string managed_causal_bytes(const murmur_causal_t *);
ManagedPolicyState managed_policy_initial(sqlite3 *,int,const ManagedValue &,const std::string &epoch);
ManagedValue managed_policy_project(int,ManagedPolicyState &);
ManagedPolicyState managed_policy_decode(int,const std::string &baseline,const std::string &causal);
#endif
