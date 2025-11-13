import {readFileSync} from "fs";
import {
    AUTHENTICATED_VERSIONS,
    AuthenticatedSpecDefinition,
    Directive,
    DirectiveDefinition,
    FieldDefinition,
    InterfaceType,
    JOIN_VERSIONS,
    joinIdentity,
    ObjectType,
    POLICY_VERSIONS,
    PolicySpecDefinition,
    REQUIRES_SCOPES_VERSIONS,
    RequiresScopesSpecDefinition,
    ROUTER_SUPPORTED_SUPERGRAPH_FEATURES,
    Schema, Supergraph
} from "@apollo/federation-internals";
import {AuthValidator} from "@apollo/composition";

// custom validator to verify interface auth usage
class InterfaceAuthValidator {
    supergraph: Supergraph;
    schema: Schema;
    authenticatedDirective?: DirectiveDefinition<{}>;
    requiresScopesDirective?: DirectiveDefinition<{ scopes: string[][] }>;
    policyDirective?: DirectiveDefinition<{ policies: string[][] }>;
    authReqMap: Map<string, AuthRequirements> = new Map();
    interfacesThatNeedsToBeChecked: Set<string> = new Set();
    fieldsWithRequires: Set<string> = new Set();
    fieldsWithContext: Set<string> = new Set();

    constructor(supergraph: Supergraph) {
        this.supergraph = supergraph;
        this.schema = supergraph.schema;
        const authenticatedFeature = this.schema.coreFeatures?.getByIdentity(AuthenticatedSpecDefinition.identity);
        const authenticatedSpec = authenticatedFeature && AUTHENTICATED_VERSIONS.find(authenticatedFeature.url.version);
        this.authenticatedDirective = authenticatedSpec?.authenticatedDirective(this.schema);

        const requiresScopesFeature = this.schema.coreFeatures?.getByIdentity(RequiresScopesSpecDefinition.identity);
        const requiresScopesSpec = requiresScopesFeature && REQUIRES_SCOPES_VERSIONS.find(requiresScopesFeature.url.version);
        this.requiresScopesDirective = requiresScopesSpec?.requiresScopesDirective(this.schema);

        const policyFeature = this.schema.coreFeatures?.getByIdentity(PolicySpecDefinition.identity);
        const policySpec = policyFeature && POLICY_VERSIONS.find(policyFeature.url.version);
        this.policyDirective = policySpec?.policyDirective(this.schema);
    }

    checkRenamedAuthDirectives(): boolean {
        const renamedDirectives = [];
        if (this.authenticatedDirective && this.authenticatedDirective.name != AuthenticatedSpecDefinition.directiveName) {
            renamedDirectives.push([AuthenticatedSpecDefinition.directiveName, this.authenticatedDirective.name]);
        }
        if (this.requiresScopesDirective && this.requiresScopesDirective.name != RequiresScopesSpecDefinition.directiveName) {
            renamedDirectives.push([RequiresScopesSpecDefinition.directiveName, this.requiresScopesDirective.name]);
        }
        if (this.policyDirective && this.policyDirective.name != PolicySpecDefinition.directiveName) {
            renamedDirectives.push([PolicySpecDefinition.directiveName, this.policyDirective.name]);
        }
        if (renamedDirectives.length > 0) {
            console.log(`ERROR: One or more authorization directive have been renamed. Make sure router version supports renamed authorization directives (v1.61.12+ or v2.8.1+).`);
            for (const [original, renamed] of renamedDirectives) {
                console.log(`- "@${original}" is renamed to "@${renamed}"`);
            }
            return false;
        }
        return true;
    }

    requirementsOnType(type: ObjectType | InterfaceType): AuthRequirements | undefined {
        const authenticated = this.authenticatedDirective && type.appliedDirectivesOf(this.authenticatedDirective)?.[0];
        const requiresScopes = this.requiresScopesDirective && type.appliedDirectivesOf(this.requiresScopesDirective)?.[0];
        const policy = this.policyDirective && type.appliedDirectivesOf(this.policyDirective)?.[0];
        return this.authRequirementsOnElement(authenticated, requiresScopes, policy);
    }

    requirementsOnField(field: FieldDefinition<any>): AuthRequirements | undefined {
        const authenticated = this.authenticatedDirective && field.appliedDirectivesOf(this.authenticatedDirective)?.[0];
        const requiresScopes = this.requiresScopesDirective && field.appliedDirectivesOf(this.requiresScopesDirective)?.[0];
        const policy = this.policyDirective && field.appliedDirectivesOf(this.policyDirective)?.[0];
        return this.authRequirementsOnElement(authenticated, requiresScopes, policy);
    }

    authRequirementsOnElement(authenticated: Directive<any, {}> | undefined,
         requiresScopes: Directive<any, { scopes: string[][] }> | undefined,
         policy: Directive<any, { policies: string[][] }> | undefined
    ): AuthRequirements | undefined {
        const requirements = new AuthRequirements();
        if (authenticated) {
            requirements.isAuthenticated = true;
        }
        if (requiresScopes) {
            const { scopes } = requiresScopes.arguments();
            requirements.scopes = scopes.map((scope) => scope.sort().join(','))
                .sort((a, b) => {
                    const left = JSON.stringify(a);
                    const right = JSON.stringify(b);
                    return left > right ? 1 : left < right ? -1 : 0;
                })
                .join(',');
        }
        if (policy) {
            const { policies } = policy.arguments();
            requirements.policies = policies.map((policy) => policy.sort().join(','))
                .sort((a, b) => {
                    const left = JSON.stringify(a);
                    const right = JSON.stringify(b);
                    return left > right ? 1 : left < right ? -1 : 0;
                })
                .join(',');
        }
        if (requirements.isAuthenticated || requirements.scopes || requirements.policies) {
            return requirements;
        } else {
            return;
        }
    }

    isInterfaceSecure(intfName: string): boolean {
        let isSecure = true;

        const intf = this.schema.type(intfName) as InterfaceType;
        const intfReq = this.authReqMap.get(intfName);

        // verify type reqs
        for (const impl of intf.possibleRuntimeTypes()) {
            const currentReq = this.authReqMap.get(impl.name);
            if (intfReq?.toString() !== currentReq?.toString()) {
                isSecure = false;
                console.log(`ERROR: Interface "${intfName}" and object type "${impl.name}" define different access control requirements.\n\t${intf} ${intf.appliedDirectives}\n\t${impl} ${impl.appliedDirectives}`);
            }
        }

        // now we need to validate interface field reqs
        for (const intfField of intf.fields()) {
            // check each field individually
            const intfFieldReqs = this.authReqMap.get(intfField.coordinate);
            for (const impl of intf.possibleRuntimeTypes()) {
                const implField = impl.field(intfField.name);
                // only check impls that define the field
                if (implField) {
                    const currentFieldReq = this.authReqMap.get(implField.coordinate);
                    if (intfFieldReqs?.toString() !== currentFieldReq?.toString()) {
                        isSecure = false;
                        console.log(`ERROR: Interface field "${intfField.coordinate}" and object field "${implField.coordinate}" defines different access control requirements.\n\t${intfName}.${intfField} ${intfField.appliedDirectives}\n\t${impl.name}.${implField} ${implField.appliedDirectives}`)
                    }
                }
            }
        }
        return isSecure;
    }

    collectInterfaceAuthReqs() {
        for (const intf of this.schema.interfaceTypes()) {
            let isInterfaceWithAuth = false;
            const intfReqs = intfValidator.requirementsOnType(intf);
            if (intfReqs) {
                isInterfaceWithAuth = true;
                console.log(`WARNING: Interface "${intf.name}" specifies authorization directives. Future versions of federation may no longer allow them on interfaces.`);
                this.authReqMap.set(intf.coordinate, intfReqs);
            }

            const interfaceObjectGraphs = new Set(
                intf.appliedDirectivesOf(joinTypeDirective)
                    .filter((directive) => directive.arguments().isInterfaceObject ?? false)
                    .map((directive) => directive.arguments().graph)
            );
            const isInterfaceObject = interfaceObjectGraphs.size > 0;
            for (const field of intf.fields()) {
                const fieldReqs = intfValidator.requirementsOnField(field);
                const isInterfaceObjectField = isInterfaceObject
                    && field.appliedDirectivesOf(joinFieldDirective)
                        .filter((directive) => interfaceObjectGraphs.has(directive.arguments().graph))
                        .length > 0;
                if (fieldReqs) {
                    isInterfaceWithAuth = true;
                    // check if this is an interface object field
                    if (!isInterfaceObjectField) {
                        console.log(`WARNING: Interface field "${field.coordinate}" specifies authorization directives. Future versions of federation may no longer allow them on interfaces fields.`);
                    }
                    this.authReqMap.set(field.coordinate, fieldReqs);
                }

                if (isInterfaceObjectField) {
                    // check for @requires and @fromContext
                    const joinFields = field.appliedDirectivesOf(joinFieldDirective);
                    let joinFieldCount = 0;
                    for (const joinField of joinFields) {
                        joinFieldCount += 1;
                        const joinFieldArgs = joinField.arguments();
                        const requires = joinFieldArgs.requires;
                        if (requires) {
                            this.fieldsWithRequires.add(field.coordinate);
                        }
                        const contexts = joinFieldArgs.contextArguments;
                        if (contexts) {
                            this.fieldsWithContext.add(field.coordinate);
                        }
                    }
                }
            }

            if (isInterfaceWithAuth) {
                this.interfacesThatNeedsToBeChecked.add(intf.name);
            }
        }
    }

    collectObjectAuthReqs() {
        for (let object of supergraphSchema.objectTypes()) {
            let isObjectWithAuth = false;
            const typeReqs = intfValidator.requirementsOnType(object);
            if (typeReqs) {
                isObjectWithAuth = true;
                this.authReqMap.set(object.coordinate, typeReqs);
            }

            const joinTypes = object.appliedDirectivesOf(joinTypeDirective);
            const typeInMultipleGraphs = joinTypes.length != 1;
            if (typeReqs && typeInMultipleGraphs) {
                console.log(`WARNING: Object "${object.name}" specifies authorization directives on its type and is defined in multiple graphs. Verify authorization configuration.`);
            }

            for (let field of object.fields()) {
                // capture auth on field
                const fieldReqs = intfValidator.requirementsOnField(field);
                if (fieldReqs) {
                    isObjectWithAuth = true;
                    this.authReqMap.set(field.coordinate, fieldReqs);
                }

                // capture @requires and @fromContext info
                const joinFields = field.appliedDirectivesOf(joinFieldDirective);
                let joinFieldCount = 0;
                for (const joinField of joinFields) {
                    joinFieldCount += 1;
                    const joinFieldArgs = joinField.arguments();
                    const requires = joinFieldArgs.requires;
                    if (requires) {
                        this.fieldsWithRequires.add(field.coordinate);
                    }
                    const contexts = joinFieldArgs.contextArguments;
                    if (contexts) {
                        this.fieldsWithContext.add(field.coordinate);
                    }
                }

                if (fieldReqs && typeInMultipleGraphs && joinFieldCount != 1) {
                    console.log(`WARNING: Field "${object.name}.${field.name}" specifies authorization directives and is defined in multiple graphs. Verify authorization configuration.`);
                }
            }

            // now lets record the interfaces that needs to be checked
            if (isObjectWithAuth) {
                for (const intf of object.interfaces()) {
                    this.interfacesThatNeedsToBeChecked.add(intf.name);
                }
            }
        }
    }

    validateInterfaces() {
        let isSecure = true;
        for (let intfName of this.interfacesThatNeedsToBeChecked) {
            isSecure = isSecure && intfValidator.isInterfaceSecure(intfName);
        }
        return isSecure;
    }
}

class AuthRequirements {
    isAuthenticated: boolean = false;
    scopes?: string
    policies?: string

    toString(): string {
        let result = `{ is_authenticated: ${this.isAuthenticated}`;
        if (this.scopes) {
            result += `, scopes: ${this.scopes}`;
        }
        if (this.policies) {
            result += `, policies: ${this.policies}`;
        }
        result += ' }';
        return result;
    }
}

const supergraphPath = process.argv[2];
if (!supergraphPath) {
    console.log("supergraph not specified");
    process.exit(1);
}

const sdl = readFileSync(supergraphPath, 'utf-8');
const supergraph = Supergraph.build(sdl, {
    supportedFeatures: ROUTER_SUPPORTED_SUPERGRAPH_FEATURES, validateSupergraph: false
});
const supergraphSchema = supergraph.schema;

const joinFeature = supergraphSchema.coreFeatures?.getByIdentity(joinIdentity);
const joinSpec = joinFeature && JOIN_VERSIONS.find(joinFeature.url.version);
const joinFieldDirective = joinSpec.fieldDirective(supergraphSchema)!;
const joinTypeDirective = joinSpec.typeDirective(supergraphSchema)!;

const authValidator = new AuthValidator(supergraphSchema, joinSpec, supergraph.subgraphNameToGraphEnumValue());
const intfValidator = new InterfaceAuthValidator(supergraph);

// first we record all interfaces coordinates that specify auth
intfValidator.collectInterfaceAuthReqs();
// now we record objects coordinates with auth that implement interfaces
intfValidator.collectObjectAuthReqs();

/// VALIDATIONS
let isSecure = true;

// Check renamed auth directives
isSecure = isSecure && intfValidator.checkRenamedAuthDirectives();

// interface validations
isSecure = isSecure && intfValidator.validateInterfaces();

// @requires validations
for (const coordinate of intfValidator.fieldsWithRequires) {
    const errors = authValidator.validateRequiresFieldSet(coordinate);
    for (const error of errors) {
        console.log(`ERROR: ${error.message}`);
        isSecure = false;
    }
}
// @context validations
for (const coordinate of intfValidator.fieldsWithContext) {
    const errors = authValidator.validateFromContext(coordinate);
    for (const error of errors) {
        console.log(`ERROR: ${error.message}`);
        isSecure = false;
    }
}

if (!isSecure) {
    process.exit(1);
}