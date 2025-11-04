# Auth Checker Script

> [!IMPORTANT]
> Script is intended to run over supergraphs generated using older federation versions that rely on outdated composition logic (`<= v2.9.3`, `<= v2.10.2`, `<= v2.11.3`). Running the script against supergraphs composed with federation `v2.9.4+`, `v2.10.3+`, `v2.11.4+` or `v2.12+` may result in false positives.

Script used to verify whether target schema may be potentially vulnerable.

## Usage

Script requires a target graphql supergraph schema to validate. See [rover documentation](https://www.apollographql.com/docs/rover/commands/supergraphs#fetching-a-supergraph-schema-from-graphos)
for details on how to download your supergraph.

```shell
# fetching supergraph
APOLLO_KEY=<your API KEY> rover supergraph fetch my-supergraph@my-variant > mysupergraph.graphql

# install dependencies
npm install
# run script
npm run check mysupergraph.graphql
```

Errors and warnings (if any) will be reported to std out.

### Warnings

#### Authorization on Interface

`WARNING: Interface "I" specifies authorization directives. Future versions of federation may no longer allow them on interfaces.`

If you cannot upgrade your composition to use latest federation version, you can make your supergraph secure by applying
same auth requirements on the interface and its implementations. Future versions of federation will no longer support
authorization on interfaces and will fail composition.

#### Possible Inconsistent Authorization Requirements

`WARNING: Object "T"/Field "T.foo" specifies authorization directives and is defined in multiple graphs. Verify authorization configuration.`

Latest federation versions changed merging behavior of authorization directives to always follow `AND` rules (previously
`@requiresScopes` and `@policy` were merged using `OR` rules). New merge rules result in enforcing stricter requirements.
Verify your subgraph and client configurations to ensure proper authorization is configured/enforced.

### Errors

#### Inconsistent Authorization On Polymorphic Types

* `ERROR: Interface "I" defines authorization requirements that are different from requirements on the implementations`
* `ERROR: Interface "I" does not define authorization requirements and ALL implementations define same requirements`

Recompose your supergraph with latest federation version (`v2.9.4+`, `v2.10.3+`, `v2.11.4+`, `v2.12.0+`) and/or deploy the latest
version of the router (`v2.8.1+` or `1.61.12+`). If you cannot do those updates, update your subgraph configurations immediately
to define exactly the same authorization requirements on the interfaces and their implementations.

#### Transitive Auth Requirement Errors

* `ERROR: Field "T.foo" does not specify necessary @authenticated, @requiresScopes and/or @policy auth requirements to access the transitive data in context ${name} from @fromContext selection set.`
* `ERROR: Field "T.foo" does not specify necessary @authenticated, @requiresScopes and/or @policy auth requirements to access the transitive field "T.extra" data from @requires selection set.`

Those errors indicate that fields reference transitive private data (through `@requires` and `@fromContext`) without requiring
any authorization. Verify you authorization configuration and add missing requirements to the fields.
