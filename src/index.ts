import {readFileSync} from "fs";
import {
    AUTHENTICATED_VERSIONS,
    AuthenticatedSpecDefinition,
    buildSchema,
    Directive,
    DirectiveDefinition,
    FieldDefinition,
    InterfaceType, JOIN_VERSIONS, joinIdentity,
    ObjectType,
    POLICY_VERSIONS,
    PolicySpecDefinition,
    REQUIRES_SCOPES_VERSIONS,
    RequiresScopesSpecDefinition,
    Schema
} from "@apollo/federation-internals";
import {AuthValidator} from "@apollo/composition";

// custom validator to verify interface auth usage
class InterfaceAuthValidator {
    authenticatedDirective?: DirectiveDefinition<{}>;
    requiresScopesDirective?: DirectiveDefinition<{ scopes: string[][] }>;
    policyDirective?: DirectiveDefinition<{ policies: string[][] }>;

    constructor(supergraph: Schema) {
        const authenticatedFeature = supergraph.coreFeatures?.getByIdentity(AuthenticatedSpecDefinition.identity);
        const authenticatedSpec = authenticatedFeature && AUTHENTICATED_VERSIONS.find(authenticatedFeature.url.version);
        this.authenticatedDirective = authenticatedSpec?.authenticatedDirective(supergraph);

        const requiresScopesFeature = supergraph.coreFeatures?.getByIdentity(RequiresScopesSpecDefinition.identity);
        const requiresScopesSpec = requiresScopesFeature && REQUIRES_SCOPES_VERSIONS.find(requiresScopesFeature.url.version);
        this.requiresScopesDirective = requiresScopesSpec?.requiresScopesDirective(supergraph);

        const policyFeature = supergraph.coreFeatures?.getByIdentity(PolicySpecDefinition.identity);
        const policySpec = policyFeature && POLICY_VERSIONS.find(policyFeature.url.version);
        this.policyDirective = policySpec?.policyDirective(supergraph);
    }

    requirementsOnType(type: ObjectType | InterfaceType): AuthRequirements | undefined {
        const authenticated = type.appliedDirectivesOf(this.authenticatedDirective)?.[0];
        const requiresScopes = type.appliedDirectivesOf(this.requiresScopesDirective)?.[0];
        const policy = type.appliedDirectivesOf(this.policyDirective)?.[0];
        return this.authRequirementsOnElement(authenticated, requiresScopes, policy);
    }

    requirementsOnField(field: FieldDefinition<any>): AuthRequirements | undefined {
        const authenticated = field.appliedDirectivesOf(this.authenticatedDirective)?.[0];
        const requiresScopes = field.appliedDirectivesOf(this.requiresScopesDirective)?.[0];
        const policy = field.appliedDirectivesOf(this.policyDirective)?.[0];
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
                .sort().join(',');
        }
        if (policy) {
            const { policies } = policy.arguments();
            requirements.policies = policies.map((policy) => policy.sort().join(','))
                .sort().join(',');
        }
        if (requirements.isAuthenticated || requirements.scopes || requirements.policies) {
            return requirements;
        } else {
            return;
        }
    }

    validateInterface(intfName: string): Error | undefined {
        const intf = supergraph.type(intfName) as InterfaceType;
        const intfReq = authReqMap.get(intfName);

        let allImplsDefineSameAuth = true;
        let implReq: TypeAuthRequirements;
        for (let impl of intf.possibleRuntimeTypes()) {
            const currentReq = authReqMap.get(impl.name);
            if (currentReq) {
                if (!implReq) {
                    implReq = currentReq;
                    continue;
                }
                allImplsDefineSameAuth = implReq.equals(currentReq);
            } else {
                // implementation missing auth
                allImplsDefineSameAuth = false;
            }

            if (!allImplsDefineSameAuth) {
                break;
            }
        }

        // if there are different auth requirements between impls then we are fine
        if (allImplsDefineSameAuth) {
            // if interface defines auth then they all have to match
            if (intfReq && !intfReq.equals(implReq)) {
                return new Error(`Interface "${intfName}" defines authorization requirements that are different from requirements on the implementations`);
            } else {
                return new Error(`Interface "${intfName}" does not define authorization requirements and ALL implementations define same requirements`);
            }
        }
    }
}

class TypeAuthRequirements {
    name: string;
    reqs?: AuthRequirements;
    fieldReqs: Map<String, AuthRequirements>

    constructor(name: string) {
        this.name = name;
        this.fieldReqs = new Map();
    }

    equals(other: TypeAuthRequirements | undefined): boolean {
        if (other) {
            const reqsOnType = this.reqs?.toString();
            const reqsOnOtherType = other.reqs?.toString();
            if (reqsOnType !== reqsOnOtherType) {
                return false;
            }

            // compare each field
            if (this.fieldReqs.size == other.fieldReqs.size) {
                for (let [fieldName, fieldReq] of this.fieldReqs.entries()) {
                    let otherFieldReq = other.fieldReqs.get(fieldName);
                    if (fieldReq !== otherFieldReq) {
                        return false;
                    }
                }
            }
            return true;
        } else {
            return false;
        }
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
const supergraph = buildSchema(sdl);

const joinFeature = supergraph.coreFeatures?.getByIdentity(joinIdentity);
const joinSpec = joinFeature && JOIN_VERSIONS.find(joinFeature.url.version);
const joinFieldDirective = joinSpec.fieldDirective(supergraph)!;
const joinTypeDirective = joinSpec.typeDirective(supergraph)!;

const intfValidator = new InterfaceAuthValidator(supergraph);
// we don't have access to subgraph names
const authValidator = new AuthValidator(supergraph, joinSpec, new Map());

const authReqMap: Map<string, TypeAuthRequirements> = new Map();
const interfacesThatNeedsToBeChecked: Set<string> = new Set();
const fieldsWithRequires: Set<string> = new Set();
const fieldsWithContext: Set<string> = new Set();

// first we record all interfaces with auth
for (let intf of supergraph.interfaceTypes()) {
    const typeAuthRequirements = new TypeAuthRequirements(intf.name);
    typeAuthRequirements.reqs = intfValidator.requirementsOnType(intf);

    for (let field of intf.fields()) {
        const fieldReqs = intfValidator.requirementsOnField(field);
        if (fieldReqs) {
            typeAuthRequirements.fieldReqs.set(field.name, fieldReqs);
        }
    }

    if (typeAuthRequirements.reqs || typeAuthRequirements.fieldReqs.size > 0) {
        // record all interfaces with auth
        console.log(`WARNING: Interface "${intf.name}" specifies authorization directives. Future versions of federation may no longer allow them on interfaces.`);
        authReqMap.set(intf.name, typeAuthRequirements);
    }
}

// now we record objects with auth that implement interfaces
for (let object of supergraph.objectTypes()) {
    const typeAuthRequirements = new TypeAuthRequirements(object.name);
    const typeReqs = intfValidator.requirementsOnType(object);
    typeAuthRequirements.reqs = typeReqs;

    const joinTypes = object.appliedDirectivesOf(joinTypeDirective);
    const typeInMultipleGraphs = joinTypes.length != 1;
    if (typeReqs && typeInMultipleGraphs) {
        console.log(`WARNING: Object "${object.name}" specifies authorization directives and is defined in multiple graphs. Verify authorization configuration.`);
    }

    for (let field of object.fields()) {
        // capture auth on field
        const fieldReqs = intfValidator.requirementsOnField(field);
        if (fieldReqs) {
            typeAuthRequirements.fieldReqs.set(field.name, fieldReqs);
        }

        // capture @requires info
        const joinFields = field.appliedDirectivesOf(joinFieldDirective);
        let joinFieldCount = 0;
        for (const joinField of joinFields) {
            joinFieldCount += 1;
            const joinFieldArgs = joinField.arguments();
            const requires = joinFieldArgs.requires;
            if (requires) {
                fieldsWithRequires.add(field.coordinate);
            }
            const contexts = joinFieldArgs.contextArguments;
            if (contexts) {
                fieldsWithContext.add(field.coordinate);
            }
        }

        if (fieldReqs && typeInMultipleGraphs && joinFieldCount != 1) {
            console.log(`WARNING: Field "${object.name}.${field.name}" specifies authorization directives and is defined in multiple graphs. Verify authorization configuration.`);
        }
    }
    
    if (typeAuthRequirements.reqs || typeAuthRequirements.fieldReqs.size > 0) {
        let implementsInterface = false;
        for (let intf of object.interfaces()) {
            implementsInterface = true;
            interfacesThatNeedsToBeChecked.add(intf.name);
        }

        // we only care about objects implementing interfaces
        if (implementsInterface) {
            authReqMap.set(object.name, typeAuthRequirements);
        }
    }
}

/// VALIDATIONS
let isSecure = true;
// interface validations
for (let intfName of interfacesThatNeedsToBeChecked) {
    const error = intfValidator.validateInterface(intfName);
    if (error) {
        console.log(`ERROR: ${error.message}`);
        isSecure = false;
    }
}

// @requires validations
for (const coordinate of fieldsWithRequires) {
    const errors = authValidator.validateRequiresFieldSet(coordinate);
    for (const error of errors) {
        console.log(`ERROR: ${error.message}`);
        isSecure = false;
    }
}
// @context validations
for (const coordinate of fieldsWithContext) {
    const errors = authValidator.validateFromContext(coordinate);
    for (const error of errors) {
        console.log(`ERROR: ${error.message}`);
        isSecure = false;
    }
}

if (!isSecure) {
    process.exit(1);
}