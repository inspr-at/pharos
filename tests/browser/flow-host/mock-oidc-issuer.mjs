import http from "node:http";
import { createSign, generateKeyPairSync } from "node:crypto";
import { URL } from "node:url";

const ISSUER_SUBJECT = "flow-harness-subject";
const CLIENT_ID = "pharos-flow-harness";
const KID = "flow-harness-oidc";

let pendingNonce = null;

const { privateKey, publicKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
});
const jwk = publicKey.export({ format: "jwk" });

function base64url(value) {
  return Buffer.from(value).toString("base64url");
}

function signIdToken(issuer, nonce) {
  const header = { alg: "RS256", typ: "JWT", kid: KID };
  const now = Math.floor(Date.now() / 1000);
  const claims = {
    iss: issuer,
    sub: ISSUER_SUBJECT,
    aud: CLIENT_ID,
    exp: now + 300,
    iat: now,
    nonce,
    preferred_username: "flow-harness-user",
    email: "flow-harness@example.invalid",
    email_verified: true,
  };
  const encodedHeader = base64url(JSON.stringify(header));
  const encodedClaims = base64url(JSON.stringify(claims));
  const signingInput = `${encodedHeader}.${encodedClaims}`;
  const signature = createSign("RSA-SHA256")
    .update(signingInput)
    .sign(privateKey)
    .toString("base64url");
  return `${signingInput}.${signature}`;
}

function writeJson(response, status, body) {
  const payload = JSON.stringify(body);
  response.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(payload),
  });
  response.end(payload);
}

export function createMockOidcIssuer() {
  return new Promise((resolve, reject) => {
    const server = http.createServer((request, response) => {
      const url = new URL(request.url ?? "/", "http://127.0.0.1");
      const issuer = `http://127.0.0.1:${server.address().port}`;
      if (url.pathname === "/.well-known/openid-configuration") {
        writeJson(response, 200, {
          issuer,
          authorization_endpoint: `${issuer}/authorize`,
          token_endpoint: `${issuer}/token`,
          userinfo_endpoint: `${issuer}/userinfo`,
          jwks_uri: `${issuer}/jwks`,
          response_types_supported: ["code"],
          subject_types_supported: ["public"],
          id_token_signing_alg_values_supported: ["RS256"],
          token_endpoint_auth_methods_supported: ["none"],
          scopes_supported: ["openid", "profile", "email"],
        });
        return;
      }
      if (url.pathname === "/jwks") {
        writeJson(response, 200, {
          keys: [
            {
              kty: "RSA",
              kid: KID,
              use: "sig",
              alg: "RS256",
              n: jwk.n,
              e: jwk.e,
            },
          ],
        });
        return;
      }
      if (url.pathname === "/authorize") {
        pendingNonce = url.searchParams.get("nonce");
        const redirectUri = url.searchParams.get("redirect_uri");
        const state = url.searchParams.get("state");
        const location = `${redirectUri}?code=flow-harness-code&state=${encodeURIComponent(state ?? "")}`;
        response.writeHead(302, { Location: location });
        response.end();
        return;
      }
      if (url.pathname === "/token" && request.method === "POST") {
        const nonce = pendingNonce ?? "missing-nonce";
        writeJson(response, 200, {
          access_token: "flow-harness-access-token",
          token_type: "Bearer",
          expires_in: 300,
          id_token: signIdToken(issuer, nonce),
        });
        return;
      }
      if (url.pathname === "/userinfo") {
        writeJson(response, 200, {
          sub: ISSUER_SUBJECT,
          preferred_username: "flow-harness-user",
          email: "flow-harness@example.invalid",
          email_verified: true,
        });
        return;
      }
      response.writeHead(404);
      response.end();
    });
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const port = server.address().port;
      const issuer = `http://127.0.0.1:${port}`;
      resolve({
        server,
        issuer,
        clientId: CLIENT_ID,
        subject: ISSUER_SUBJECT,
        close: () =>
          new Promise((done, fail) => {
            server.close((error) => (error ? fail(error) : done()));
          }),
      });
    });
  });
}
