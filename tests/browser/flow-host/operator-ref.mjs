import crypto from "node:crypto";

const OPERATOR_REF_DOMAIN = "pharos:oidc-principal:operator-ref:v2:";

export function operatorRef(issuer, subject) {
  return crypto
    .createHash("sha256")
    .update(OPERATOR_REF_DOMAIN)
    .update(issuer)
    .update(Buffer.from([0]))
    .update(subject)
    .digest("hex");
}
