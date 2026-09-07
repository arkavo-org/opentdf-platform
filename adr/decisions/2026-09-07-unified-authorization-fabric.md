---
status: 'proposed'
date: '2026-09-07'
tags:
 - authorization
 - authentication
driver: '@paul'
---
# One authorization fabric: AuthZEN/SARC over OpenTDF Authorization v2

## Context and Problem Statement

The platform ran two authorization systems.

The control plane was governed by Casbin: a role, an RPC route, and a method,
matched against a CSV policy table loaded at startup. The data plane was
governed by OpenTDF Authorization v2: entities, actions, attributes, subject
mappings, registered resources, obligations, and a policy decision point that
answers "may this entity take this action on this resource?".

```text
CWT/JWT
   │
   ├──► Casbin
   │      (role, RPC route, method)
   │             │
   │          allow/deny
   ▼
OpenTDF API
   │
   ▼
Authorization v2
   │
   └── data/resource authorization
```

Two systems meant two policy languages, two places to reason about a
privilege, and no way to express a control-plane rule in terms of the entity
model the platform already had.

## Decision

Collapse the two into one. Authorization v2 becomes the platform's single
PDP, SARC (Subject, Action, Resource, Context) becomes the shape of every
question, AuthZEN becomes its public contract, and platform API operations
become resources like any other.

```text
                   OpenTDF Authorization
                     AuthZEN SARC
                          │
           ┌──────────────┼──────────────┐
           │              │              │
      Platform API       KAS          TDF/Data
      authorization   authorization   authorization
           │              │              │
           └──────────────┼──────────────┘
                          │
                     One PDP
                          │
                OpenTDF Policy v2
```

Casbin is removed.

### API operations are resources

An RPC procedure or HTTP route is normalized into a resource identifier, and —
when endpoint policy is enabled — into a registered resource value FQN the
policy graph can govern:

```text
policy.attributes.AttributeService/CreateAttribute
  → https://<namespace>/reg_res/endpoint/value/policy_attributes_attributeservice_createattribute
```

The AuthZEN objects map onto the v2 objects that already exist:

```text
AuthZEN                    OpenTDF v2
────────────────────────────────────────────
Subject       ──────────►  Entity + SubjectMappings
Action        ──────────►  Action
Resource      ──────────►  RegisteredResource / attribute values
Context       ──────────►  request facts
Decision      ◄──────────  GetDecision
```

### The PDP is in-process, not an RPC hop

A middleware that authorized requests by making an authorized request would
recurse. The evaluator is therefore an interface — `authz.Evaluator` — that the
authorization service registers itself with at startup, and that the Connect
interceptor, the HTTP middleware and the AuthZEN endpoint all reach directly:

```text
                   ┌── external AuthZEN API
                   │
                   ▼
            Authorization Engine
                   ▲
                   │
Connect interceptor│
───────────────────┘
```

### Bootstrap is a root of trust, not a policy

A request that writes a subject mapping is governed by the policy graph it is
about to change. A platform with an empty graph would have no way in, and a
policy that can authorize itself into existence is not a root of trust.

The way in is a small, fixed set of capabilities asserted by a CWT from a
configured authority — `policy.bootstrap`, `policy.admin`, `authority.rotate` —
honored only for that authority's issuer, and (by default) only when the token
is key-bound. They only ever permit, and policy never grants them.

```text
                   Root Authority
                        │
                 signs root CWT
                        │
                        ▼
                 Root Principal
                        │
              ┌─────────┴──────────┐
              ▼                    ▼
       bootstrap policy       normal policies
```

### Decision order

1. Bootstrap root of trust (permit only).
2. OpenTDF policy, for resources policy represents.
3. Platform grants — the baseline table for platform operations.
4. Deny.

## Consequences

**Good**

* One policy model, one PDP, one audit trail for control and data planes.
* Control-plane privileges become expressible in the entity/attribute model:
  an endpoint can be governed by the same subject mappings that govern data.
* The platform gains a standards-shaped public authorization contract.
* One fewer dependency, and no second policy language to learn.

**Costs and mitigations**

* Policy-governed endpoints add a PDP evaluation per request. Endpoint policy
  is therefore opt-in and incremental: endpoints with no registered resource
  fall back to the grant table, so operations move into policy one at a time.
* The Casbin CSV table is gone. Existing configuration keeps working: the
  legacy policy lines are translated into grants at startup, and the platform's
  own default table is now data (`default_grants.yaml`) rather than a CSV
  embedded in the enforcer.
* `WithCasbinAdapter` is removed from the server options.
