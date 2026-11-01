import { UserManager, WebStorageStateStore } from "oidc-client-ts";
import type { IdentityPort } from "../application/auth";
import { CognitoIdentity } from "./cognito";
const authority =
  import.meta.env.VITE_OIDC_ISSUER ||
  "http://localhost:8080/realms/security-testing";
const clientId = import.meta.env.VITE_OIDC_CLIENT_ID || "security-testing-web";
export const identity: IdentityPort = authority.startsWith(
  "https://cognito-idp.",
)
  ? new CognitoIdentity(authority, clientId)
  : new UserManager({
      authority:
        import.meta.env.VITE_OIDC_ISSUER ||
        "http://localhost:8080/realms/security-testing",
      client_id: import.meta.env.VITE_OIDC_CLIENT_ID || "security-testing-web",
      redirect_uri: `${window.location.origin}/callback`,
      post_logout_redirect_uri: window.location.origin,
      response_type: "code",
      scope: "openid profile",
      userStore: new WebStorageStateStore({ store: window.sessionStorage }),
    });
