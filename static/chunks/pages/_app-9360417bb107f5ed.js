(self.webpackChunk_N_E=self.webpackChunk_N_E||[]).push([[888],{6660:function(e,t,n){"use strict";n.d(t,{$:function(){return tc},A:function(){return c},B:function(){return d},G:function(){return eT},H:function(){return ek},J:function(){return eV},L:function(){return ei},M:function(){return eK},N:function(){return eJ},P:function(){return nE},Q:function(){return eZ},R:function(){return ny},T:function(){return e0},U:function(){return eX},V:function(){return e2},W:function(){return e3},X:function(){return e8},Y:function(){return to},Z:function(){return ta},_:function(){return tl},a:function(){return tJ},a0:function(){return tp},a1:function(){return tm},a2:function(){return tg},a3:function(){return ty},a4:function(){return tv},a5:function(){return t_},a6:function(){return tw},a7:function(){return tb},a8:function(){return tI},a9:function(){return tT},aA:function(){return nZ},aB:function(){return nX},aC:function(){return nq},aD:function(){return nV},aE:function(){return eb},aI:function(){return t0},aL:function(){return e1},aa:function(){return tS},ab:function(){return tk},ac:function(){return tx},af:function(){return tN},ag:function(){return tA},ah:function(){return tR},ak:function(){return tt},al:function(){return tU},an:function(){return t$},ao:function(){return tW},ap:function(){return eg},aq:function(){return T},ar:function(){return em},as:function(){return ed},at:function(){return g},au:function(){return rs},av:function(){return n2},aw:function(){return y},ax:function(){return b},ay:function(){return S},az:function(){return es},b:function(){return tY},c:function(){return nD},d:function(){return nP},e:function(){return nO},f:function(){return nz},g:function(){return nK},h:function(){return nW},i:function(){return ns},j:function(){return nY},k:function(){return ra},l:function(){return nw},m:function(){return rc},o:function(){return u},r:function(){return nb},s:function(){return n_},u:function(){return nT},v:function(){return tV}});var r,i=n(4444),s=n(5816),o=n(3333);function a(e,t){var n={};for(var r in e)Object.prototype.hasOwnProperty.call(e,r)&&0>t.indexOf(r)&&(n[r]=e[r]);if(null!=e&&"function"==typeof Object.getOwnPropertySymbols)for(var i=0,r=Object.getOwnPropertySymbols(e);i<r.length;i++)0>t.indexOf(r[i])&&Object.prototype.propertyIsEnumerable.call(e,r[i])&&(n[r[i]]=e[r[i]]);return n}var l=n(8463);let u={FACEBOOK:"facebook.com",GITHUB:"github.com",GOOGLE:"google.com",PASSWORD:"password",PHONE:"phone",TWITTER:"twitter.com"},c={EMAIL_SIGNIN:"EMAIL_SIGNIN",PASSWORD_RESET:"PASSWORD_RESET",RECOVER_EMAIL:"RECOVER_EMAIL",REVERT_SECOND_FACTOR_ADDITION:"REVERT_SECOND_FACTOR_ADDITION",VERIFY_AND_CHANGE_EMAIL:"VERIFY_AND_CHANGE_EMAIL",VERIFY_EMAIL:"VERIFY_EMAIL"};function h(){return{"dependent-sdk-initialized-before-auth":"Another Firebase SDK was initialized and is trying to use Auth before Auth is initialized. Please be sure to call `initializeAuth` or `getAuth` before starting any other Firebase SDK."}}let d=/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function(){return{"admin-restricted-operation":"This operation is restricted to administrators only.","argument-error":"","app-not-authorized":"This app, identified by the domain where it's hosted, is not authorized to use Firebase Authentication with the provided API key. Review your key configuration in the Google API console.","app-not-installed":"The requested mobile application corresponding to the identifier (Android package name or iOS bundle ID) provided is not installed on this device.","captcha-check-failed":"The reCAPTCHA response token provided is either invalid, expired, already used or the domain associated with it does not match the list of whitelisted domains.","code-expired":"The SMS code has expired. Please re-send the verification code to try again.","cordova-not-ready":"Cordova framework is not ready.","cors-unsupported":"This browser is not supported.","credential-already-in-use":"This credential is already associated with a different user account.","custom-token-mismatch":"The custom token corresponds to a different audience.","requires-recent-login":"This operation is sensitive and requires recent authentication. Log in again before retrying this request.","dependent-sdk-initialized-before-auth":"Another Firebase SDK was initialized and is trying to use Auth before Auth is initialized. Please be sure to call `initializeAuth` or `getAuth` before starting any other Firebase SDK.","dynamic-link-not-activated":"Please activate Dynamic Links in the Firebase Console and agree to the terms and conditions.","email-change-needs-verification":"Multi-factor users must always have a verified email.","email-already-in-use":"The email address is already in use by another account.","emulator-config-failed":'Auth instance has already been used to make a network call. Auth can no longer be configured to use the emulator. Try calling "connectAuthEmulator()" sooner.',"expired-action-code":"The action code has expired.","cancelled-popup-request":"This operation has been cancelled due to another conflicting popup being opened.","internal-error":"An internal AuthError has occurred.","invalid-app-credential":"The phone verification request contains an invalid application verifier. The reCAPTCHA token response is either invalid or expired.","invalid-app-id":"The mobile app identifier is not registed for the current project.","invalid-user-token":"This user's credential isn't valid for this project. This can happen if the user's token has been tampered with, or if the user isn't for the project associated with this API key.","invalid-auth-event":"An internal AuthError has occurred.","invalid-verification-code":"The SMS verification code used to create the phone auth credential is invalid. Please resend the verification code sms and be sure to use the verification code provided by the user.","invalid-continue-uri":"The continue URL provided in the request is invalid.","invalid-cordova-configuration":"The following Cordova plugins must be installed to enable OAuth sign-in: cordova-plugin-buildinfo, cordova-universal-links-plugin, cordova-plugin-browsertab, cordova-plugin-inappbrowser and cordova-plugin-customurlscheme.","invalid-custom-token":"The custom token format is incorrect. Please check the documentation.","invalid-dynamic-link-domain":"The provided dynamic link domain is not configured or authorized for the current project.","invalid-email":"The email address is badly formatted.","invalid-emulator-scheme":"Emulator URL must start with a valid scheme (http:// or https://).","invalid-api-key":"Your API key is invalid, please check you have copied it correctly.","invalid-cert-hash":"The SHA-1 certificate hash provided is invalid.","invalid-credential":"The supplied auth credential is malformed or has expired.","invalid-message-payload":"The email template corresponding to this action contains invalid characters in its message. Please fix by going to the Auth email templates section in the Firebase Console.","invalid-multi-factor-session":"The request does not contain a valid proof of first factor successful sign-in.","invalid-oauth-provider":"EmailAuthProvider is not supported for this operation. This operation only supports OAuth providers.","invalid-oauth-client-id":"The OAuth client ID provided is either invalid or does not match the specified API key.","unauthorized-domain":"This domain is not authorized for OAuth operations for your Firebase project. Edit the list of authorized domains from the Firebase console.","invalid-action-code":"The action code is invalid. This can happen if the code is malformed, expired, or has already been used.","wrong-password":"The password is invalid or the user does not have a password.","invalid-persistence-type":"The specified persistence type is invalid. It can only be local, session or none.","invalid-phone-number":"The format of the phone number provided is incorrect. Please enter the phone number in a format that can be parsed into E.164 format. E.164 phone numbers are written in the format [+][country code][subscriber number including area code].","invalid-provider-id":"The specified provider ID is invalid.","invalid-recipient-email":"The email corresponding to this action failed to send as the provided recipient email address is invalid.","invalid-sender":"The email template corresponding to this action contains an invalid sender email or name. Please fix by going to the Auth email templates section in the Firebase Console.","invalid-verification-id":"The verification ID used to create the phone auth credential is invalid.","invalid-tenant-id":"The Auth instance's tenant ID is invalid.","login-blocked":"Login blocked by user-provided method: {$originalMessage}","missing-android-pkg-name":"An Android Package Name must be provided if the Android App is required to be installed.","auth-domain-config-required":"Be sure to include authDomain when calling firebase.initializeApp(), by following the instructions in the Firebase console.","missing-app-credential":"The phone verification request is missing an application verifier assertion. A reCAPTCHA response token needs to be provided.","missing-verification-code":"The phone auth credential was created with an empty SMS verification code.","missing-continue-uri":"A continue URL must be provided in the request.","missing-iframe-start":"An internal AuthError has occurred.","missing-ios-bundle-id":"An iOS Bundle ID must be provided if an App Store ID is provided.","missing-or-invalid-nonce":"The request does not contain a valid nonce. This can occur if the SHA-256 hash of the provided raw nonce does not match the hashed nonce in the ID token payload.","missing-multi-factor-info":"No second factor identifier is provided.","missing-multi-factor-session":"The request is missing proof of first factor successful sign-in.","missing-phone-number":"To send verification codes, provide a phone number for the recipient.","missing-verification-id":"The phone auth credential was created with an empty verification ID.","app-deleted":"This instance of FirebaseApp has been deleted.","multi-factor-info-not-found":"The user does not have a second factor matching the identifier provided.","multi-factor-auth-required":"Proof of ownership of a second factor is required to complete sign-in.","account-exists-with-different-credential":"An account already exists with the same email address but different sign-in credentials. Sign in using a provider associated with this email address.","network-request-failed":"A network AuthError (such as timeout, interrupted connection or unreachable host) has occurred.","no-auth-event":"An internal AuthError has occurred.","no-such-provider":"User was not linked to an account with the given provider.","null-user":"A null user object was provided as the argument for an operation which requires a non-null user object.","operation-not-allowed":"The given sign-in provider is disabled for this Firebase project. Enable it in the Firebase console, under the sign-in method tab of the Auth section.","operation-not-supported-in-this-environment":'This operation is not supported in the environment this application is running on. "location.protocol" must be http, https or chrome-extension and web storage must be enabled.',"popup-blocked":"Unable to establish a connection with the popup. It may have been blocked by the browser.","popup-closed-by-user":"The popup has been closed by the user before finalizing the operation.","provider-already-linked":"User can only be linked to one identity for the given provider.","quota-exceeded":"The project's quota for this operation has been exceeded.","redirect-cancelled-by-user":"The redirect operation has been cancelled by the user before finalizing.","redirect-operation-pending":"A redirect sign-in operation is already pending.","rejected-credential":"The request contains malformed or mismatching credentials.","second-factor-already-in-use":"The second factor is already enrolled on this account.","maximum-second-factor-count-exceeded":"The maximum allowed number of second factors on a user has been exceeded.","tenant-id-mismatch":"The provided tenant ID does not match the Auth instance's tenant ID",timeout:"The operation has timed out.","user-token-expired":"The user's credential is no longer valid. The user must sign in again.","too-many-requests":"We have blocked all requests from this device due to unusual activity. Try again later.","unauthorized-continue-uri":"The domain of the continue URL is not whitelisted.  Please whitelist the domain in the Firebase console.","unsupported-first-factor":"Enrolling a second factor or signing in with a multi-factor account requires sign-in with a supported first factor.","unsupported-persistence-type":"The current environment does not support the specified persistence type.","unsupported-tenant-operation":"This operation is not supported in a multi-tenant context.","unverified-email":"The operation requires a verified email.","user-cancelled":"The user did not grant your application the permissions it requested.","user-not-found":"There is no user record corresponding to this identifier. The user may have been deleted.","user-disabled":"The user account has been disabled by an administrator.","user-mismatch":"The supplied credentials do not correspond to the previously signed in user.","user-signed-out":"","weak-password":"The password must be 6 characters long or more.","web-storage-unsupported":"This browser is not supported or 3rd party cookies and data may be disabled.","already-initialized":"initializeAuth() has already been called with different options. To avoid this error, call initializeAuth() with the same options as when it was originally called, or call getAuth() to return the already initialized instance."}},f=new i.LL("auth","Firebase",h()),p=new o.Yd("@firebase/auth");function m(e,...t){p.logLevel<=o.in.ERROR&&p.error(`Auth (${s.SDK_VERSION}): ${e}`,...t)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function g(e,...t){throw w(e,...t)}function y(e,...t){return w(e,...t)}function v(e,t,n){let r=Object.assign(Object.assign({},h()),{[t]:n}),s=new i.LL("auth","Firebase",r);return s.create(t,{appName:e.name})}function _(e,t,n){if(!(t instanceof n))throw n.name!==t.constructor.name&&g(e,"argument-error"),v(e,"argument-error",`Type of ${t.constructor.name} does not match expected instance.Did you pass a reference from a different Auth SDK?`)}function w(e,...t){if("string"!=typeof e){let n=t[0],r=[...t.slice(1)];return r[0]&&(r[0].appName=e.name),e._errorFactory.create(n,...r)}return f.create(e,...t)}function b(e,t,...n){if(!e)throw w(t,...n)}function I(e){let t="INTERNAL ASSERTION FAILED: "+e;throw m(t),Error(t)}function T(e,t){e||I(t)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let E=new Map;function S(e){T(e instanceof Function,"Expected a class definition");let t=E.get(e);return t?(T(t instanceof e,"Instance stored in cache mismatched with class"),t):(t=new e,E.set(e,t),t)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function k(){var e;return"undefined"!=typeof self&&(null===(e=self.location)||void 0===e?void 0:e.href)||""}function x(){return"http:"===C()||"https:"===C()}function C(){var e;return"undefined"!=typeof self&&(null===(e=self.location)||void 0===e?void 0:e.protocol)||null}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class N{constructor(e,t){this.shortDelay=e,this.longDelay=t,T(t>e,"Short delay should be less than long delay!"),this.isMobile=(0,i.uI)()||(0,i.b$)()}get(){return!("undefined"!=typeof navigator&&navigator&&"onLine"in navigator&&"boolean"==typeof navigator.onLine&&(x()||(0,i.ru)()||"connection"in navigator))||navigator.onLine?this.isMobile?this.longDelay:this.shortDelay:Math.min(5e3,this.shortDelay)}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function A(e,t){T(e.emulator,"Emulator should always be set here");let{url:n}=e.emulator;return t?`${n}${t.startsWith("/")?t.slice(1):t}`:n}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class R{static initialize(e,t,n){this.fetchImpl=e,t&&(this.headersImpl=t),n&&(this.responseImpl=n)}static fetch(){return this.fetchImpl?this.fetchImpl:"undefined"!=typeof self&&"fetch"in self?self.fetch:void I("Could not find fetch implementation, make sure you call FetchProvider.initialize() with an appropriate polyfill")}static headers(){return this.headersImpl?this.headersImpl:"undefined"!=typeof self&&"Headers"in self?self.Headers:void I("Could not find Headers implementation, make sure you call FetchProvider.initialize() with an appropriate polyfill")}static response(){return this.responseImpl?this.responseImpl:"undefined"!=typeof self&&"Response"in self?self.Response:void I("Could not find Response implementation, make sure you call FetchProvider.initialize() with an appropriate polyfill")}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let D={CREDENTIAL_MISMATCH:"custom-token-mismatch",MISSING_CUSTOM_TOKEN:"internal-error",INVALID_IDENTIFIER:"invalid-email",MISSING_CONTINUE_URI:"internal-error",INVALID_PASSWORD:"wrong-password",MISSING_PASSWORD:"internal-error",EMAIL_EXISTS:"email-already-in-use",PASSWORD_LOGIN_DISABLED:"operation-not-allowed",INVALID_IDP_RESPONSE:"invalid-credential",INVALID_PENDING_TOKEN:"invalid-credential",FEDERATED_USER_ID_ALREADY_LINKED:"credential-already-in-use",MISSING_REQ_TYPE:"internal-error",EMAIL_NOT_FOUND:"user-not-found",RESET_PASSWORD_EXCEED_LIMIT:"too-many-requests",EXPIRED_OOB_CODE:"expired-action-code",INVALID_OOB_CODE:"invalid-action-code",MISSING_OOB_CODE:"internal-error",CREDENTIAL_TOO_OLD_LOGIN_AGAIN:"requires-recent-login",INVALID_ID_TOKEN:"invalid-user-token",TOKEN_EXPIRED:"user-token-expired",USER_NOT_FOUND:"user-token-expired",TOO_MANY_ATTEMPTS_TRY_LATER:"too-many-requests",INVALID_CODE:"invalid-verification-code",INVALID_SESSION_INFO:"invalid-verification-id",INVALID_TEMPORARY_PROOF:"invalid-credential",MISSING_SESSION_INFO:"missing-verification-id",SESSION_EXPIRED:"code-expired",MISSING_ANDROID_PACKAGE_NAME:"missing-android-pkg-name",UNAUTHORIZED_DOMAIN:"unauthorized-continue-uri",INVALID_OAUTH_CLIENT_ID:"invalid-oauth-client-id",ADMIN_ONLY_OPERATION:"admin-restricted-operation",INVALID_MFA_PENDING_CREDENTIAL:"invalid-multi-factor-session",MFA_ENROLLMENT_NOT_FOUND:"multi-factor-info-not-found",MISSING_MFA_ENROLLMENT_ID:"missing-multi-factor-info",MISSING_MFA_PENDING_CREDENTIAL:"missing-multi-factor-session",SECOND_FACTOR_EXISTS:"second-factor-already-in-use",SECOND_FACTOR_LIMIT_EXCEEDED:"maximum-second-factor-count-exceeded",BLOCKING_FUNCTION_ERROR_RESPONSE:"internal-error"},O=new N(3e4,6e4);function P(e,t){return e.tenantId&&!t.tenantId?Object.assign(Object.assign({},t),{tenantId:e.tenantId}):t}async function L(e,t,n,r,s={}){return M(e,s,async()=>{let s={},o={};r&&("GET"===t?o=r:s={body:JSON.stringify(r)});let a=(0,i.xO)(Object.assign({key:e.config.apiKey},o)).slice(1),l=await e._getAdditionalHeaders();return l["Content-Type"]="application/json",e.languageCode&&(l["X-Firebase-Locale"]=e.languageCode),R.fetch()(F(e,e.config.apiHost,n,a),Object.assign({method:t,headers:l,referrerPolicy:"no-referrer"},s))})}async function M(e,t,n){e._canInitEmulator=!1;let r=Object.assign(Object.assign({},D),t);try{let s=new U(e),o=await Promise.race([n(),s.promise]);s.clearNetworkTimeout();let a=await o.json();if("needConfirmation"in a)throw V(e,"account-exists-with-different-credential",a);if(o.ok&&!("errorMessage"in a))return a;{let l=o.ok?a.errorMessage:a.error.message,[u,c]=l.split(" : ");if("FEDERATED_USER_ID_ALREADY_LINKED"===u)throw V(e,"credential-already-in-use",a);if("EMAIL_EXISTS"===u)throw V(e,"email-already-in-use",a);if("USER_DISABLED"===u)throw V(e,"user-disabled",a);let h=r[u]||u.toLowerCase().replace(/[_\s]+/g,"-");if(c)throw v(e,h,c);g(e,h)}}catch(d){if(d instanceof i.ZR)throw d;g(e,"network-request-failed")}}async function j(e,t,n,r,i={}){let s=await L(e,t,n,r,i);return"mfaPendingCredential"in s&&g(e,"multi-factor-auth-required",{_serverResponse:s}),s}function F(e,t,n,r){let i=`${t}${n}?${r}`;return e.config.emulator?A(e.config,i):`${e.config.apiScheme}://${i}`}class U{constructor(e){this.auth=e,this.timer=null,this.promise=new Promise((e,t)=>{this.timer=setTimeout(()=>t(y(this.auth,"network-request-failed")),O.get())})}clearNetworkTimeout(){clearTimeout(this.timer)}}function V(e,t,n){let r={appName:e.name};n.email&&(r.email=n.email),n.phoneNumber&&(r.phoneNumber=n.phoneNumber);let i=y(e,t,r);return i.customData._tokenResponse=n,i}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function q(e,t){return L(e,"POST","/v1/accounts:delete",t)}async function B(e,t){return L(e,"POST","/v1/accounts:update",t)}async function $(e,t){return L(e,"POST","/v1/accounts:lookup",t)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function z(e){if(e)try{let t=new Date(Number(e));if(!isNaN(t.getTime()))return t.toUTCString()}catch(n){}}async function G(e,t=!1){let n=(0,i.m9)(e),r=await n.getIdToken(t),s=H(r);b(s&&s.exp&&s.auth_time&&s.iat,n.auth,"internal-error");let o="object"==typeof s.firebase?s.firebase:void 0,a=null==o?void 0:o.sign_in_provider;return{claims:s,token:r,authTime:z(W(s.auth_time)),issuedAtTime:z(W(s.iat)),expirationTime:z(W(s.exp)),signInProvider:a||null,signInSecondFactor:(null==o?void 0:o.sign_in_second_factor)||null}}function W(e){return 1e3*Number(e)}function H(e){let[t,n,r]=e.split(".");if(void 0===t||void 0===n||void 0===r)return m("JWT malformed, contained fewer than 3 sections"),null;try{let s=(0,i.tV)(n);if(!s)return m("Failed to decode base64 JWT payload"),null;return JSON.parse(s)}catch(o){return m("Caught error parsing JWT payload as JSON",null==o?void 0:o.toString()),null}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function K(e,t,n=!1){if(n)return t;try{return await t}catch(r){throw r instanceof i.ZR&&function({code:e}){return"auth/user-disabled"===e||"auth/user-token-expired"===e}(r)&&e.auth.currentUser===e&&await e.auth.signOut(),r}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class Q{constructor(e){this.user=e,this.isRunning=!1,this.timerId=null,this.errorBackoff=3e4}_start(){this.isRunning||(this.isRunning=!0,this.schedule())}_stop(){this.isRunning&&(this.isRunning=!1,null!==this.timerId&&clearTimeout(this.timerId))}getInterval(e){var t;if(e){let n=this.errorBackoff;return this.errorBackoff=Math.min(2*this.errorBackoff,96e4),n}{this.errorBackoff=3e4;let r=null!==(t=this.user.stsTokenManager.expirationTime)&&void 0!==t?t:0,i=r-Date.now()-3e5;return Math.max(0,i)}}schedule(e=!1){if(!this.isRunning)return;let t=this.getInterval(e);this.timerId=setTimeout(async()=>{await this.iteration()},t)}async iteration(){try{await this.user.getIdToken(!0)}catch(e){(null==e?void 0:e.code)==="auth/network-request-failed"&&this.schedule(!0);return}this.schedule()}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class Y{constructor(e,t){this.createdAt=e,this.lastLoginAt=t,this._initializeTime()}_initializeTime(){this.lastSignInTime=z(this.lastLoginAt),this.creationTime=z(this.createdAt)}_copy(e){this.createdAt=e.createdAt,this.lastLoginAt=e.lastLoginAt,this._initializeTime()}toJSON(){return{createdAt:this.createdAt,lastLoginAt:this.lastLoginAt}}}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function X(e){var t;let n=e.auth,r=await e.getIdToken(),i=await K(e,$(n,{idToken:r}));b(null==i?void 0:i.users.length,n,"internal-error");let s=i.users[0];e._notifyReloadListener(s);let o=(null===(t=s.providerUserInfo)||void 0===t?void 0:t.length)?s.providerUserInfo.map(e=>{var{providerId:t}=e,n=a(e,["providerId"]);return{providerId:t,uid:n.rawId||"",displayName:n.displayName||null,email:n.email||null,phoneNumber:n.phoneNumber||null,photoURL:n.photoUrl||null}}):[],l=function(e,t){let n=e.filter(e=>!t.some(t=>t.providerId===e.providerId));return[...n,...t]}(e.providerData,o),u=e.isAnonymous,c=!(e.email&&s.passwordHash)&&!(null==l?void 0:l.length),h={uid:s.localId,displayName:s.displayName||null,photoURL:s.photoUrl||null,email:s.email||null,emailVerified:s.emailVerified||!1,phoneNumber:s.phoneNumber||null,tenantId:s.tenantId||null,providerData:l,metadata:new Y(s.createdAt,s.lastLoginAt),isAnonymous:!!u&&c};Object.assign(e,h)}async function J(e){let t=(0,i.m9)(e);await X(t),await t.auth._persistUserIfCurrent(t),t.auth._notifyListenersIfCurrent(t)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function Z(e,t){let n=await M(e,{},async()=>{let n=(0,i.xO)({grant_type:"refresh_token",refresh_token:t}).slice(1),{tokenApiHost:r,apiKey:s}=e.config,o=F(e,r,"/v1/token",`key=${s}`),a=await e._getAdditionalHeaders();return a["Content-Type"]="application/x-www-form-urlencoded",R.fetch()(o,{method:"POST",headers:a,body:n})});return{accessToken:n.access_token,expiresIn:n.expires_in,refreshToken:n.refresh_token}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class ee{constructor(){this.refreshToken=null,this.accessToken=null,this.expirationTime=null}get isExpired(){return!this.expirationTime||Date.now()>this.expirationTime-3e4}updateFromServerResponse(e){b(e.idToken,"internal-error"),b(void 0!==e.idToken,"internal-error"),b(void 0!==e.refreshToken,"internal-error");let t="expiresIn"in e&&void 0!==e.expiresIn?Number(e.expiresIn):function(e){let t=H(e);return b(t,"internal-error"),b(void 0!==t.exp,"internal-error"),b(void 0!==t.iat,"internal-error"),Number(t.exp)-Number(t.iat)}(e.idToken);this.updateTokensAndExpiration(e.idToken,e.refreshToken,t)}async getToken(e,t=!1){return(b(!this.accessToken||this.refreshToken,e,"user-token-expired"),t||!this.accessToken||this.isExpired)?this.refreshToken?(await this.refresh(e,this.refreshToken),this.accessToken):null:this.accessToken}clearRefreshToken(){this.refreshToken=null}async refresh(e,t){let{accessToken:n,refreshToken:r,expiresIn:i}=await Z(e,t);this.updateTokensAndExpiration(n,r,Number(i))}updateTokensAndExpiration(e,t,n){this.refreshToken=t||null,this.accessToken=e||null,this.expirationTime=Date.now()+1e3*n}static fromJSON(e,t){let{refreshToken:n,accessToken:r,expirationTime:i}=t,s=new ee;return n&&(b("string"==typeof n,"internal-error",{appName:e}),s.refreshToken=n),r&&(b("string"==typeof r,"internal-error",{appName:e}),s.accessToken=r),i&&(b("number"==typeof i,"internal-error",{appName:e}),s.expirationTime=i),s}toJSON(){return{refreshToken:this.refreshToken,accessToken:this.accessToken,expirationTime:this.expirationTime}}_assign(e){this.accessToken=e.accessToken,this.refreshToken=e.refreshToken,this.expirationTime=e.expirationTime}_clone(){return Object.assign(new ee,this.toJSON())}_performRefresh(){return I("not implemented")}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function et(e,t){b("string"==typeof e||void 0===e,"internal-error",{appName:t})}class en{constructor(e){var{uid:t,auth:n,stsTokenManager:r}=e,i=a(e,["uid","auth","stsTokenManager"]);this.providerId="firebase",this.proactiveRefresh=new Q(this),this.reloadUserInfo=null,this.reloadListener=null,this.uid=t,this.auth=n,this.stsTokenManager=r,this.accessToken=r.accessToken,this.displayName=i.displayName||null,this.email=i.email||null,this.emailVerified=i.emailVerified||!1,this.phoneNumber=i.phoneNumber||null,this.photoURL=i.photoURL||null,this.isAnonymous=i.isAnonymous||!1,this.tenantId=i.tenantId||null,this.providerData=i.providerData?[...i.providerData]:[],this.metadata=new Y(i.createdAt||void 0,i.lastLoginAt||void 0)}async getIdToken(e){let t=await K(this,this.stsTokenManager.getToken(this.auth,e));return b(t,this.auth,"internal-error"),this.accessToken!==t&&(this.accessToken=t,await this.auth._persistUserIfCurrent(this),this.auth._notifyListenersIfCurrent(this)),t}getIdTokenResult(e){return G(this,e)}reload(){return J(this)}_assign(e){this!==e&&(b(this.uid===e.uid,this.auth,"internal-error"),this.displayName=e.displayName,this.photoURL=e.photoURL,this.email=e.email,this.emailVerified=e.emailVerified,this.phoneNumber=e.phoneNumber,this.isAnonymous=e.isAnonymous,this.tenantId=e.tenantId,this.providerData=e.providerData.map(e=>Object.assign({},e)),this.metadata._copy(e.metadata),this.stsTokenManager._assign(e.stsTokenManager))}_clone(e){return new en(Object.assign(Object.assign({},this),{auth:e,stsTokenManager:this.stsTokenManager._clone()}))}_onReload(e){b(!this.reloadListener,this.auth,"internal-error"),this.reloadListener=e,this.reloadUserInfo&&(this._notifyReloadListener(this.reloadUserInfo),this.reloadUserInfo=null)}_notifyReloadListener(e){this.reloadListener?this.reloadListener(e):this.reloadUserInfo=e}_startProactiveRefresh(){this.proactiveRefresh._start()}_stopProactiveRefresh(){this.proactiveRefresh._stop()}async _updateTokensIfNecessary(e,t=!1){let n=!1;e.idToken&&e.idToken!==this.stsTokenManager.accessToken&&(this.stsTokenManager.updateFromServerResponse(e),n=!0),t&&await X(this),await this.auth._persistUserIfCurrent(this),n&&this.auth._notifyListenersIfCurrent(this)}async delete(){let e=await this.getIdToken();return await K(this,q(this.auth,{idToken:e})),this.stsTokenManager.clearRefreshToken(),this.auth.signOut()}toJSON(){return Object.assign(Object.assign({uid:this.uid,email:this.email||void 0,emailVerified:this.emailVerified,displayName:this.displayName||void 0,isAnonymous:this.isAnonymous,photoURL:this.photoURL||void 0,phoneNumber:this.phoneNumber||void 0,tenantId:this.tenantId||void 0,providerData:this.providerData.map(e=>Object.assign({},e)),stsTokenManager:this.stsTokenManager.toJSON(),_redirectEventId:this._redirectEventId},this.metadata.toJSON()),{apiKey:this.auth.config.apiKey,appName:this.auth.name})}get refreshToken(){return this.stsTokenManager.refreshToken||""}static _fromJSON(e,t){var n,r,i,s,o,a,l,u;let c=null!==(n=t.displayName)&&void 0!==n?n:void 0,h=null!==(r=t.email)&&void 0!==r?r:void 0,d=null!==(i=t.phoneNumber)&&void 0!==i?i:void 0,f=null!==(s=t.photoURL)&&void 0!==s?s:void 0,p=null!==(o=t.tenantId)&&void 0!==o?o:void 0,m=null!==(a=t._redirectEventId)&&void 0!==a?a:void 0,g=null!==(l=t.createdAt)&&void 0!==l?l:void 0,y=null!==(u=t.lastLoginAt)&&void 0!==u?u:void 0,{uid:v,emailVerified:_,isAnonymous:w,providerData:I,stsTokenManager:T}=t;b(v&&T,e,"internal-error");let E=ee.fromJSON(this.name,T);b("string"==typeof v,e,"internal-error"),et(c,e.name),et(h,e.name),b("boolean"==typeof _,e,"internal-error"),b("boolean"==typeof w,e,"internal-error"),et(d,e.name),et(f,e.name),et(p,e.name),et(m,e.name),et(g,e.name),et(y,e.name);let S=new en({uid:v,auth:e,email:h,emailVerified:_,displayName:c,isAnonymous:w,photoURL:f,phoneNumber:d,tenantId:p,stsTokenManager:E,createdAt:g,lastLoginAt:y});return I&&Array.isArray(I)&&(S.providerData=I.map(e=>Object.assign({},e))),m&&(S._redirectEventId=m),S}static async _fromIdTokenResponse(e,t,n=!1){let r=new ee;r.updateFromServerResponse(t);let i=new en({uid:t.localId,auth:e,stsTokenManager:r,isAnonymous:n});return await X(i),i}}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class er{constructor(){this.type="NONE",this.storage={}}async _isAvailable(){return!0}async _set(e,t){this.storage[e]=t}async _get(e){let t=this.storage[e];return void 0===t?null:t}async _remove(e){delete this.storage[e]}_addListener(e,t){}_removeListener(e,t){}}er.type="NONE";let ei=er;/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function es(e,t,n){return`firebase:${e}:${t}:${n}`}class eo{constructor(e,t,n){this.persistence=e,this.auth=t,this.userKey=n;let{config:r,name:i}=this.auth;this.fullUserKey=es(this.userKey,r.apiKey,i),this.fullPersistenceKey=es("persistence",r.apiKey,i),this.boundEventHandler=t._onStorageEvent.bind(t),this.persistence._addListener(this.fullUserKey,this.boundEventHandler)}setCurrentUser(e){return this.persistence._set(this.fullUserKey,e.toJSON())}async getCurrentUser(){let e=await this.persistence._get(this.fullUserKey);return e?en._fromJSON(this.auth,e):null}removeCurrentUser(){return this.persistence._remove(this.fullUserKey)}savePersistenceForRedirect(){return this.persistence._set(this.fullPersistenceKey,this.persistence.type)}async setPersistence(e){if(this.persistence===e)return;let t=await this.getCurrentUser();if(await this.removeCurrentUser(),this.persistence=e,t)return this.setCurrentUser(t)}delete(){this.persistence._removeListener(this.fullUserKey,this.boundEventHandler)}static async create(e,t,n="authUser"){if(!t.length)return new eo(S(ei),e,n);let r=(await Promise.all(t.map(async e=>{if(await e._isAvailable())return e}))).filter(e=>e),i=r[0]||S(ei),s=es(n,e.config.apiKey,e.name),o=null;for(let a of t)try{let l=await a._get(s);if(l){let u=en._fromJSON(e,l);a!==i&&(o=u),i=a;break}}catch(c){}let h=r.filter(e=>e._shouldAllowMigration);return i._shouldAllowMigration&&h.length&&(i=h[0],o&&await i._set(s,o.toJSON()),await Promise.all(t.map(async e=>{if(e!==i)try{await e._remove(s)}catch(t){}}))),new eo(i,e,n)}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function ea(e){let t=e.toLowerCase();if(t.includes("opera/")||t.includes("opr/")||t.includes("opios/"))return"Opera";if(eh(t))return"IEMobile";if(t.includes("msie")||t.includes("trident/"))return"IE";{if(t.includes("edge/"))return"Edge";if(el(t))return"Firefox";if(t.includes("silk/"))return"Silk";if(ef(t))return"Blackberry";if(ep(t))return"Webos";if(eu(t))return"Safari";if((t.includes("chrome/")||ec(t))&&!t.includes("edge/"))return"Chrome";if(ed(t))return"Android";let n=e.match(/([a-zA-Z\d\.]+)\/[a-zA-Z\d\.]*$/);if((null==n?void 0:n.length)===2)return n[1]}return"Other"}function el(e=(0,i.z$)()){return/firefox\//i.test(e)}function eu(e=(0,i.z$)()){let t=e.toLowerCase();return t.includes("safari/")&&!t.includes("chrome/")&&!t.includes("crios/")&&!t.includes("android")}function ec(e=(0,i.z$)()){return/crios\//i.test(e)}function eh(e=(0,i.z$)()){return/iemobile/i.test(e)}function ed(e=(0,i.z$)()){return/android/i.test(e)}function ef(e=(0,i.z$)()){return/blackberry/i.test(e)}function ep(e=(0,i.z$)()){return/webos/i.test(e)}function em(e=(0,i.z$)()){return/iphone|ipad|ipod/i.test(e)||/macintosh/i.test(e)&&/mobile/i.test(e)}function eg(e=(0,i.z$)()){return/(iPad|iPhone|iPod).*OS 7_\d/i.test(e)||/(iPad|iPhone|iPod).*OS 8_\d/i.test(e)}function ey(e=(0,i.z$)()){return em(e)||ed(e)||ep(e)||ef(e)||/windows phone/i.test(e)||eh(e)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function ev(e,t=[]){let n;switch(e){case"Browser":n=ea((0,i.z$)());break;case"Worker":n=`${ea((0,i.z$)())}-${e}`;break;default:n=e}let r=t.length?t.join(","):"FirebaseCore-web";return`${n}/JsCore/${s.SDK_VERSION}/${r}`}/**
 * @license
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class e_{constructor(e){this.auth=e,this.queue=[]}pushCallback(e,t){let n=t=>new Promise((n,r)=>{try{let i=e(t);n(i)}catch(s){r(s)}});n.onAbort=t,this.queue.push(n);let r=this.queue.length-1;return()=>{this.queue[r]=()=>Promise.resolve()}}async runMiddleware(e){if(this.auth.currentUser===e)return;let t=[];try{for(let n of this.queue)await n(e),n.onAbort&&t.push(n.onAbort)}catch(s){for(let r of(t.reverse(),t))try{r()}catch(i){}throw this.auth._errorFactory.create("login-blocked",{originalMessage:null==s?void 0:s.message})}}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class ew{constructor(e,t,n){this.app=e,this.heartbeatServiceProvider=t,this.config=n,this.currentUser=null,this.emulatorConfig=null,this.operations=Promise.resolve(),this.authStateSubscription=new eI(this),this.idTokenSubscription=new eI(this),this.beforeStateQueue=new e_(this),this.redirectUser=null,this.isProactiveRefreshEnabled=!1,this._canInitEmulator=!0,this._isInitialized=!1,this._deleted=!1,this._initializationPromise=null,this._popupRedirectResolver=null,this._errorFactory=f,this.lastNotifiedUid=void 0,this.languageCode=null,this.tenantId=null,this.settings={appVerificationDisabledForTesting:!1},this.frameworks=[],this.name=e.name,this.clientVersion=n.sdkClientVersion}_initializeWithPersistence(e,t){return t&&(this._popupRedirectResolver=S(t)),this._initializationPromise=this.queue(async()=>{var n,r;if(!this._deleted&&(this.persistenceManager=await eo.create(this,e),!this._deleted)){if(null===(n=this._popupRedirectResolver)||void 0===n?void 0:n._shouldInitProactively)try{await this._popupRedirectResolver._initialize(this)}catch(i){}await this.initializeCurrentUser(t),this.lastNotifiedUid=(null===(r=this.currentUser)||void 0===r?void 0:r.uid)||null,this._deleted||(this._isInitialized=!0)}}),this._initializationPromise}async _onStorageEvent(){if(this._deleted)return;let e=await this.assertedPersistence.getCurrentUser();if(this.currentUser||e){if(this.currentUser&&e&&this.currentUser.uid===e.uid){this._currentUser._assign(e),await this.currentUser.getIdToken();return}await this._updateCurrentUser(e,!0)}}async initializeCurrentUser(e){var t;let n=await this.assertedPersistence.getCurrentUser(),r=n,i=!1;if(e&&this.config.authDomain){await this.getOrInitRedirectPersistenceManager();let s=null===(t=this.redirectUser)||void 0===t?void 0:t._redirectEventId,o=null==r?void 0:r._redirectEventId,a=await this.tryRedirectSignIn(e);(!s||s===o)&&(null==a?void 0:a.user)&&(r=a.user,i=!0)}if(!r)return this.directlySetCurrentUser(null);if(!r._redirectEventId){if(i)try{await this.beforeStateQueue.runMiddleware(r)}catch(l){r=n,this._popupRedirectResolver._overrideRedirectResult(this,()=>Promise.reject(l))}return r?this.reloadAndSetCurrentUserOrClear(r):this.directlySetCurrentUser(null)}return(b(this._popupRedirectResolver,this,"argument-error"),await this.getOrInitRedirectPersistenceManager(),this.redirectUser&&this.redirectUser._redirectEventId===r._redirectEventId)?this.directlySetCurrentUser(r):this.reloadAndSetCurrentUserOrClear(r)}async tryRedirectSignIn(e){let t=null;try{t=await this._popupRedirectResolver._completeRedirectFn(this,e,!0)}catch(n){await this._setRedirectUser(null)}return t}async reloadAndSetCurrentUserOrClear(e){try{await X(e)}catch(t){if((null==t?void 0:t.code)!=="auth/network-request-failed")return this.directlySetCurrentUser(null)}return this.directlySetCurrentUser(e)}useDeviceLanguage(){this.languageCode=function(){if("undefined"==typeof navigator)return null;let e=navigator;return e.languages&&e.languages[0]||e.language||null}()}async _delete(){this._deleted=!0}async updateCurrentUser(e){let t=e?(0,i.m9)(e):null;return t&&b(t.auth.config.apiKey===this.config.apiKey,this,"invalid-user-token"),this._updateCurrentUser(t&&t._clone(this))}async _updateCurrentUser(e,t=!1){if(!this._deleted)return e&&b(this.tenantId===e.tenantId,this,"tenant-id-mismatch"),t||await this.beforeStateQueue.runMiddleware(e),this.queue(async()=>{await this.directlySetCurrentUser(e),this.notifyAuthListeners()})}async signOut(){return await this.beforeStateQueue.runMiddleware(null),(this.redirectPersistenceManager||this._popupRedirectResolver)&&await this._setRedirectUser(null),this._updateCurrentUser(null,!0)}setPersistence(e){return this.queue(async()=>{await this.assertedPersistence.setPersistence(S(e))})}_getPersistence(){return this.assertedPersistence.persistence.type}_updateErrorMap(e){this._errorFactory=new i.LL("auth","Firebase",e())}onAuthStateChanged(e,t,n){return this.registerStateListener(this.authStateSubscription,e,t,n)}beforeAuthStateChanged(e,t){return this.beforeStateQueue.pushCallback(e,t)}onIdTokenChanged(e,t,n){return this.registerStateListener(this.idTokenSubscription,e,t,n)}toJSON(){var e;return{apiKey:this.config.apiKey,authDomain:this.config.authDomain,appName:this.name,currentUser:null===(e=this._currentUser)||void 0===e?void 0:e.toJSON()}}async _setRedirectUser(e,t){let n=await this.getOrInitRedirectPersistenceManager(t);return null===e?n.removeCurrentUser():n.setCurrentUser(e)}async getOrInitRedirectPersistenceManager(e){if(!this.redirectPersistenceManager){let t=e&&S(e)||this._popupRedirectResolver;b(t,this,"argument-error"),this.redirectPersistenceManager=await eo.create(this,[S(t._redirectPersistence)],"redirectUser"),this.redirectUser=await this.redirectPersistenceManager.getCurrentUser()}return this.redirectPersistenceManager}async _redirectUserForId(e){var t,n;return(this._isInitialized&&await this.queue(async()=>{}),(null===(t=this._currentUser)||void 0===t?void 0:t._redirectEventId)===e)?this._currentUser:(null===(n=this.redirectUser)||void 0===n?void 0:n._redirectEventId)===e?this.redirectUser:null}async _persistUserIfCurrent(e){if(e===this.currentUser)return this.queue(async()=>this.directlySetCurrentUser(e))}_notifyListenersIfCurrent(e){e===this.currentUser&&this.notifyAuthListeners()}_key(){return`${this.config.authDomain}:${this.config.apiKey}:${this.name}`}_startProactiveRefresh(){this.isProactiveRefreshEnabled=!0,this.currentUser&&this._currentUser._startProactiveRefresh()}_stopProactiveRefresh(){this.isProactiveRefreshEnabled=!1,this.currentUser&&this._currentUser._stopProactiveRefresh()}get _currentUser(){return this.currentUser}notifyAuthListeners(){var e,t;if(!this._isInitialized)return;this.idTokenSubscription.next(this.currentUser);let n=null!==(t=null===(e=this.currentUser)||void 0===e?void 0:e.uid)&&void 0!==t?t:null;this.lastNotifiedUid!==n&&(this.lastNotifiedUid=n,this.authStateSubscription.next(this.currentUser))}registerStateListener(e,t,n,r){if(this._deleted)return()=>{};let i="function"==typeof t?t:t.next.bind(t),s=this._isInitialized?Promise.resolve():this._initializationPromise;return(b(s,this,"internal-error"),s.then(()=>i(this.currentUser)),"function"==typeof t)?e.addObserver(t,n,r):e.addObserver(t)}async directlySetCurrentUser(e){this.currentUser&&this.currentUser!==e&&this._currentUser._stopProactiveRefresh(),e&&this.isProactiveRefreshEnabled&&e._startProactiveRefresh(),this.currentUser=e,e?await this.assertedPersistence.setCurrentUser(e):await this.assertedPersistence.removeCurrentUser()}queue(e){return this.operations=this.operations.then(e,e),this.operations}get assertedPersistence(){return b(this.persistenceManager,this,"internal-error"),this.persistenceManager}_logFramework(e){!e||this.frameworks.includes(e)||(this.frameworks.push(e),this.frameworks.sort(),this.clientVersion=ev(this.config.clientPlatform,this._getFrameworks()))}_getFrameworks(){return this.frameworks}async _getAdditionalHeaders(){var e;let t={"X-Client-Version":this.clientVersion};this.app.options.appId&&(t["X-Firebase-gmpid"]=this.app.options.appId);let n=await (null===(e=this.heartbeatServiceProvider.getImmediate({optional:!0}))||void 0===e?void 0:e.getHeartbeatsHeader());return n&&(t["X-Firebase-Client"]=n),t}}function eb(e){return(0,i.m9)(e)}class eI{constructor(e){this.auth=e,this.observer=null,this.addObserver=(0,i.ne)(e=>this.observer=e)}get next(){return b(this.observer,this.auth,"internal-error"),this.observer.next.bind(this.observer)}}function eT(e,t,n){let r=eb(e);b(r._canInitEmulator,r,"emulator-config-failed"),b(/^https?:\/\//.test(t),r,"invalid-emulator-scheme");let i=!!(null==n?void 0:n.disableWarnings),s=eE(t),{host:o,port:a}=function(e){let t=eE(e),n=/(\/\/)?([^?#/]+)/.exec(e.substr(t.length));if(!n)return{host:"",port:null};let r=n[2].split("@").pop()||"",i=/^(\[[^\]]+\])(:|$)/.exec(r);if(i){let s=i[1];return{host:s,port:eS(r.substr(s.length+1))}}{let[o,a]=r.split(":");return{host:o,port:eS(a)}}}(t),l=null===a?"":`:${a}`;r.config.emulator={url:`${s}//${o}${l}/`},r.settings.appVerificationDisabledForTesting=!0,r.emulatorConfig=Object.freeze({host:o,port:a,protocol:s.replace(":",""),options:Object.freeze({disableWarnings:i})}),i||function(){function e(){let e=document.createElement("p"),t=e.style;e.innerText="Running in emulator mode. Do not use with production credentials.",t.position="fixed",t.width="100%",t.backgroundColor="#ffffff",t.border=".1em solid #000000",t.color="#b50000",t.bottom="0px",t.left="0px",t.margin="0px",t.zIndex="10000",t.textAlign="center",e.classList.add("firebase-emulator-warning"),document.body.appendChild(e)}"undefined"!=typeof console&&"function"==typeof console.info&&console.info("WARNING: You are using the Auth Emulator, which is intended for local testing only.  Do not use with production credentials."),"undefined"!=typeof window&&"undefined"!=typeof document&&("loading"===document.readyState?window.addEventListener("DOMContentLoaded",e):e())}()}function eE(e){let t=e.indexOf(":");return t<0?"":e.substr(0,t+1)}function eS(e){if(!e)return null;let t=Number(e);return isNaN(t)?null:t}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class ek{constructor(e,t){this.providerId=e,this.signInMethod=t}toJSON(){return I("not implemented")}_getIdTokenResponse(e){return I("not implemented")}_linkToIdToken(e,t){return I("not implemented")}_getReauthenticationResolver(e){return I("not implemented")}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function ex(e,t){return L(e,"POST","/v1/accounts:resetPassword",P(e,t))}async function eC(e,t){return L(e,"POST","/v1/accounts:update",t)}async function eN(e,t){return L(e,"POST","/v1/accounts:update",P(e,t))}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function eA(e,t){return j(e,"POST","/v1/accounts:signInWithPassword",P(e,t))}async function eR(e,t){return L(e,"POST","/v1/accounts:sendOobCode",P(e,t))}async function eD(e,t){return eR(e,t)}async function eO(e,t){return eR(e,t)}async function eP(e,t){return eR(e,t)}async function eL(e,t){return eR(e,t)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function eM(e,t){return j(e,"POST","/v1/accounts:signInWithEmailLink",P(e,t))}async function ej(e,t){return j(e,"POST","/v1/accounts:signInWithEmailLink",P(e,t))}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class eF extends ek{constructor(e,t,n,r=null){super("password",n),this._email=e,this._password=t,this._tenantId=r}static _fromEmailAndPassword(e,t){return new eF(e,t,"password")}static _fromEmailAndCode(e,t,n=null){return new eF(e,t,"emailLink",n)}toJSON(){return{email:this._email,password:this._password,signInMethod:this.signInMethod,tenantId:this._tenantId}}static fromJSON(e){let t="string"==typeof e?JSON.parse(e):e;if((null==t?void 0:t.email)&&(null==t?void 0:t.password)){if("password"===t.signInMethod)return this._fromEmailAndPassword(t.email,t.password);if("emailLink"===t.signInMethod)return this._fromEmailAndCode(t.email,t.password,t.tenantId)}return null}async _getIdTokenResponse(e){switch(this.signInMethod){case"password":return eA(e,{returnSecureToken:!0,email:this._email,password:this._password});case"emailLink":return eM(e,{email:this._email,oobCode:this._password});default:g(e,"internal-error")}}async _linkToIdToken(e,t){switch(this.signInMethod){case"password":return eC(e,{idToken:t,returnSecureToken:!0,email:this._email,password:this._password});case"emailLink":return ej(e,{idToken:t,email:this._email,oobCode:this._password});default:g(e,"internal-error")}}_getReauthenticationResolver(e){return this._getIdTokenResponse(e)}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function eU(e,t){return j(e,"POST","/v1/accounts:signInWithIdp",P(e,t))}class eV extends ek{constructor(){super(...arguments),this.pendingToken=null}static _fromParams(e){let t=new eV(e.providerId,e.signInMethod);return e.idToken||e.accessToken?(e.idToken&&(t.idToken=e.idToken),e.accessToken&&(t.accessToken=e.accessToken),e.nonce&&!e.pendingToken&&(t.nonce=e.nonce),e.pendingToken&&(t.pendingToken=e.pendingToken)):e.oauthToken&&e.oauthTokenSecret?(t.accessToken=e.oauthToken,t.secret=e.oauthTokenSecret):g("argument-error"),t}toJSON(){return{idToken:this.idToken,accessToken:this.accessToken,secret:this.secret,nonce:this.nonce,pendingToken:this.pendingToken,providerId:this.providerId,signInMethod:this.signInMethod}}static fromJSON(e){let t="string"==typeof e?JSON.parse(e):e,{providerId:n,signInMethod:r}=t,i=a(t,["providerId","signInMethod"]);if(!n||!r)return null;let s=new eV(n,r);return s.idToken=i.idToken||void 0,s.accessToken=i.accessToken||void 0,s.secret=i.secret,s.nonce=i.nonce,s.pendingToken=i.pendingToken||null,s}_getIdTokenResponse(e){let t=this.buildRequest();return eU(e,t)}_linkToIdToken(e,t){let n=this.buildRequest();return n.idToken=t,eU(e,n)}_getReauthenticationResolver(e){let t=this.buildRequest();return t.autoCreate=!1,eU(e,t)}buildRequest(){let e={requestUri:"http://localhost",returnSecureToken:!0};if(this.pendingToken)e.pendingToken=this.pendingToken;else{let t={};this.idToken&&(t.id_token=this.idToken),this.accessToken&&(t.access_token=this.accessToken),this.secret&&(t.oauth_token_secret=this.secret),t.providerId=this.providerId,this.nonce&&!this.pendingToken&&(t.nonce=this.nonce),e.postBody=(0,i.xO)(t)}return e}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function eq(e,t){return L(e,"POST","/v1/accounts:sendVerificationCode",P(e,t))}async function eB(e,t){return j(e,"POST","/v1/accounts:signInWithPhoneNumber",P(e,t))}async function e$(e,t){let n=await j(e,"POST","/v1/accounts:signInWithPhoneNumber",P(e,t));if(n.temporaryProof)throw V(e,"account-exists-with-different-credential",n);return n}let ez={USER_NOT_FOUND:"user-not-found"};async function eG(e,t){let n=Object.assign(Object.assign({},t),{operation:"REAUTH"});return j(e,"POST","/v1/accounts:signInWithPhoneNumber",P(e,n),ez)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class eW extends ek{constructor(e){super("phone","phone"),this.params=e}static _fromVerification(e,t){return new eW({verificationId:e,verificationCode:t})}static _fromTokenResponse(e,t){return new eW({phoneNumber:e,temporaryProof:t})}_getIdTokenResponse(e){return eB(e,this._makeVerificationRequest())}_linkToIdToken(e,t){return e$(e,Object.assign({idToken:t},this._makeVerificationRequest()))}_getReauthenticationResolver(e){return eG(e,this._makeVerificationRequest())}_makeVerificationRequest(){let{temporaryProof:e,phoneNumber:t,verificationId:n,verificationCode:r}=this.params;return e&&t?{temporaryProof:e,phoneNumber:t}:{sessionInfo:n,code:r}}toJSON(){let e={providerId:this.providerId};return this.params.phoneNumber&&(e.phoneNumber=this.params.phoneNumber),this.params.temporaryProof&&(e.temporaryProof=this.params.temporaryProof),this.params.verificationCode&&(e.verificationCode=this.params.verificationCode),this.params.verificationId&&(e.verificationId=this.params.verificationId),e}static fromJSON(e){"string"==typeof e&&(e=JSON.parse(e));let{verificationId:t,verificationCode:n,phoneNumber:r,temporaryProof:i}=e;return n||t||r||i?new eW({verificationId:t,verificationCode:n,phoneNumber:r,temporaryProof:i}):null}}class eH{constructor(e){var t,n,r,s,o,a;let l=(0,i.zd)((0,i.pd)(e)),u=null!==(t=l.apiKey)&&void 0!==t?t:null,c=null!==(n=l.oobCode)&&void 0!==n?n:null,h=/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function(e){switch(e){case"recoverEmail":return"RECOVER_EMAIL";case"resetPassword":return"PASSWORD_RESET";case"signIn":return"EMAIL_SIGNIN";case"verifyEmail":return"VERIFY_EMAIL";case"verifyAndChangeEmail":return"VERIFY_AND_CHANGE_EMAIL";case"revertSecondFactorAddition":return"REVERT_SECOND_FACTOR_ADDITION";default:return null}}(null!==(r=l.mode)&&void 0!==r?r:null);b(u&&c&&h,"argument-error"),this.apiKey=u,this.operation=h,this.code=c,this.continueUrl=null!==(s=l.continueUrl)&&void 0!==s?s:null,this.languageCode=null!==(o=l.languageCode)&&void 0!==o?o:null,this.tenantId=null!==(a=l.tenantId)&&void 0!==a?a:null}static parseLink(e){let t=function(e){let t=(0,i.zd)((0,i.pd)(e)).link,n=t?(0,i.zd)((0,i.pd)(t)).deep_link_id:null,r=(0,i.zd)((0,i.pd)(e)).deep_link_id,s=r?(0,i.zd)((0,i.pd)(r)).link:null;return s||r||n||t||e}(e);try{return new eH(t)}catch(n){return null}}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class eK{constructor(){this.providerId=eK.PROVIDER_ID}static credential(e,t){return eF._fromEmailAndPassword(e,t)}static credentialWithLink(e,t){let n=eH.parseLink(t);return b(n,"argument-error"),eF._fromEmailAndCode(e,n.code,n.tenantId)}}eK.PROVIDER_ID="password",eK.EMAIL_PASSWORD_SIGN_IN_METHOD="password",eK.EMAIL_LINK_SIGN_IN_METHOD="emailLink";/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class eQ{constructor(e){this.providerId=e,this.defaultLanguageCode=null,this.customParameters={}}setDefaultLanguage(e){this.defaultLanguageCode=e}setCustomParameters(e){return this.customParameters=e,this}getCustomParameters(){return this.customParameters}}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class eY extends eQ{constructor(){super(...arguments),this.scopes=[]}addScope(e){return this.scopes.includes(e)||this.scopes.push(e),this}getScopes(){return[...this.scopes]}}class eX extends eY{static credentialFromJSON(e){let t="string"==typeof e?JSON.parse(e):e;return b("providerId"in t&&"signInMethod"in t,"argument-error"),eV._fromParams(t)}credential(e){return this._credential(Object.assign(Object.assign({},e),{nonce:e.rawNonce}))}_credential(e){return b(e.idToken||e.accessToken,"argument-error"),eV._fromParams(Object.assign(Object.assign({},e),{providerId:this.providerId,signInMethod:this.providerId}))}static credentialFromResult(e){return eX.oauthCredentialFromTaggedObject(e)}static credentialFromError(e){return eX.oauthCredentialFromTaggedObject(e.customData||{})}static oauthCredentialFromTaggedObject({_tokenResponse:e}){if(!e)return null;let{oauthIdToken:t,oauthAccessToken:n,oauthTokenSecret:r,pendingToken:i,nonce:s,providerId:o}=e;if(!n&&!r&&!t&&!i||!o)return null;try{return new eX(o)._credential({idToken:t,accessToken:n,nonce:s,pendingToken:i})}catch(a){return null}}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class eJ extends eY{constructor(){super("facebook.com")}static credential(e){return eV._fromParams({providerId:eJ.PROVIDER_ID,signInMethod:eJ.FACEBOOK_SIGN_IN_METHOD,accessToken:e})}static credentialFromResult(e){return eJ.credentialFromTaggedObject(e)}static credentialFromError(e){return eJ.credentialFromTaggedObject(e.customData||{})}static credentialFromTaggedObject({_tokenResponse:e}){if(!e||!("oauthAccessToken"in e)||!e.oauthAccessToken)return null;try{return eJ.credential(e.oauthAccessToken)}catch(t){return null}}}eJ.FACEBOOK_SIGN_IN_METHOD="facebook.com",eJ.PROVIDER_ID="facebook.com";/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class eZ extends eY{constructor(){super("google.com"),this.addScope("profile")}static credential(e,t){return eV._fromParams({providerId:eZ.PROVIDER_ID,signInMethod:eZ.GOOGLE_SIGN_IN_METHOD,idToken:e,accessToken:t})}static credentialFromResult(e){return eZ.credentialFromTaggedObject(e)}static credentialFromError(e){return eZ.credentialFromTaggedObject(e.customData||{})}static credentialFromTaggedObject({_tokenResponse:e}){if(!e)return null;let{oauthIdToken:t,oauthAccessToken:n}=e;if(!t&&!n)return null;try{return eZ.credential(t,n)}catch(r){return null}}}eZ.GOOGLE_SIGN_IN_METHOD="google.com",eZ.PROVIDER_ID="google.com";/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class e0 extends eY{constructor(){super("github.com")}static credential(e){return eV._fromParams({providerId:e0.PROVIDER_ID,signInMethod:e0.GITHUB_SIGN_IN_METHOD,accessToken:e})}static credentialFromResult(e){return e0.credentialFromTaggedObject(e)}static credentialFromError(e){return e0.credentialFromTaggedObject(e.customData||{})}static credentialFromTaggedObject({_tokenResponse:e}){if(!e||!("oauthAccessToken"in e)||!e.oauthAccessToken)return null;try{return e0.credential(e.oauthAccessToken)}catch(t){return null}}}e0.GITHUB_SIGN_IN_METHOD="github.com",e0.PROVIDER_ID="github.com";class e1 extends ek{constructor(e,t){super(e,e),this.pendingToken=t}_getIdTokenResponse(e){let t=this.buildRequest();return eU(e,t)}_linkToIdToken(e,t){let n=this.buildRequest();return n.idToken=t,eU(e,n)}_getReauthenticationResolver(e){let t=this.buildRequest();return t.autoCreate=!1,eU(e,t)}toJSON(){return{signInMethod:this.signInMethod,providerId:this.providerId,pendingToken:this.pendingToken}}static fromJSON(e){let t="string"==typeof e?JSON.parse(e):e,{providerId:n,signInMethod:r,pendingToken:i}=t;return n&&r&&i&&n===r?new e1(n,i):null}static _create(e,t){return new e1(e,t)}buildRequest(){return{requestUri:"http://localhost",returnSecureToken:!0,pendingToken:this.pendingToken}}}class e2 extends eQ{constructor(e){b(e.startsWith("saml."),"argument-error"),super(e)}static credentialFromResult(e){return e2.samlCredentialFromTaggedObject(e)}static credentialFromError(e){return e2.samlCredentialFromTaggedObject(e.customData||{})}static credentialFromJSON(e){let t=e1.fromJSON(e);return b(t,"argument-error"),t}static samlCredentialFromTaggedObject({_tokenResponse:e}){if(!e)return null;let{pendingToken:t,providerId:n}=e;if(!t||!n)return null;try{return e1._create(n,t)}catch(r){return null}}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class e3 extends eY{constructor(){super("twitter.com")}static credential(e,t){return eV._fromParams({providerId:e3.PROVIDER_ID,signInMethod:e3.TWITTER_SIGN_IN_METHOD,oauthToken:e,oauthTokenSecret:t})}static credentialFromResult(e){return e3.credentialFromTaggedObject(e)}static credentialFromError(e){return e3.credentialFromTaggedObject(e.customData||{})}static credentialFromTaggedObject({_tokenResponse:e}){if(!e)return null;let{oauthAccessToken:t,oauthTokenSecret:n}=e;if(!t||!n)return null;try{return e3.credential(t,n)}catch(r){return null}}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function e4(e,t){return j(e,"POST","/v1/accounts:signUp",P(e,t))}e3.TWITTER_SIGN_IN_METHOD="twitter.com",e3.PROVIDER_ID="twitter.com";/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class e6{constructor(e){this.user=e.user,this.providerId=e.providerId,this._tokenResponse=e._tokenResponse,this.operationType=e.operationType}static async _fromIdTokenResponse(e,t,n,r=!1){let i=await en._fromIdTokenResponse(e,n,r),s=e5(n),o=new e6({user:i,providerId:s,_tokenResponse:n,operationType:t});return o}static async _forOperation(e,t,n){await e._updateTokensIfNecessary(n,!0);let r=e5(n);return new e6({user:e,providerId:r,_tokenResponse:n,operationType:t})}}function e5(e){return e.providerId?e.providerId:"phoneNumber"in e?"phone":null}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function e8(e){var t;let n=eb(e);if(await n._initializationPromise,null===(t=n.currentUser)||void 0===t?void 0:t.isAnonymous)return new e6({user:n.currentUser,providerId:null,operationType:"signIn"});let r=await e4(n,{returnSecureToken:!0}),i=await e6._fromIdTokenResponse(n,"signIn",r,!0);return await n._updateCurrentUser(i.user),i}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class e9 extends i.ZR{constructor(e,t,n,r){var i;super(t.code,t.message),this.operationType=n,this.user=r,Object.setPrototypeOf(this,e9.prototype),this.customData={appName:e.name,tenantId:null!==(i=e.tenantId)&&void 0!==i?i:void 0,_serverResponse:t.customData._serverResponse,operationType:n}}static _fromErrorAndOperation(e,t,n,r){return new e9(e,t,n,r)}}function e7(e,t,n,r){let i="reauthenticate"===t?n._getReauthenticationResolver(e):n._getIdTokenResponse(e);return i.catch(n=>{if("auth/multi-factor-auth-required"===n.code)throw e9._fromErrorAndOperation(e,n,t,r);throw n})}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function te(e){return new Set(e.map(({providerId:e})=>e).filter(e=>!!e))}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function tt(e,t){let n=(0,i.m9)(e);await tr(!0,n,t);let{providerUserInfo:r}=await B(n.auth,{idToken:await n.getIdToken(),deleteProvider:[t]}),s=te(r||[]);return n.providerData=n.providerData.filter(e=>s.has(e.providerId)),s.has("phone")||(n.phoneNumber=null),await n.auth._persistUserIfCurrent(n),n}async function tn(e,t,n=!1){let r=await K(e,t._linkToIdToken(e.auth,await e.getIdToken()),n);return e6._forOperation(e,"link",r)}async function tr(e,t,n){await X(t);let r=te(t.providerData);b(r.has(n)===e,t.auth,!1===e?"provider-already-linked":"no-such-provider")}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function ti(e,t,n=!1){let{auth:r}=e,i="reauthenticate";try{let s=await K(e,e7(r,i,t,e),n);b(s.idToken,r,"internal-error");let o=H(s.idToken);b(o,r,"internal-error");let{sub:a}=o;return b(e.uid===a,r,"user-mismatch"),e6._forOperation(e,i,s)}catch(l){throw(null==l?void 0:l.code)==="auth/user-not-found"&&g(r,"user-mismatch"),l}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function ts(e,t,n=!1){let r="signIn",i=await e7(e,r,t),s=await e6._fromIdTokenResponse(e,r,i);return n||await e._updateCurrentUser(s.user),s}async function to(e,t){return ts(eb(e),t)}async function ta(e,t){let n=(0,i.m9)(e);return await tr(!1,n,t.providerId),tn(n,t)}async function tl(e,t){return ti((0,i.m9)(e),t)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function tu(e,t){return j(e,"POST","/v1/accounts:signInWithCustomToken",P(e,t))}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function tc(e,t){let n=eb(e),r=await tu(n,{token:t,returnSecureToken:!0}),i=await e6._fromIdTokenResponse(n,"signIn",r);return await n._updateCurrentUser(i.user),i}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class th{constructor(e,t){this.factorId=e,this.uid=t.mfaEnrollmentId,this.enrollmentTime=new Date(t.enrolledAt).toUTCString(),this.displayName=t.displayName}static _fromServerResponse(e,t){return"phoneInfo"in t?td._fromServerResponse(e,t):g(e,"internal-error")}}class td extends th{constructor(e){super("phone",e),this.phoneNumber=e.phoneInfo}static _fromServerResponse(e,t){return new td(t)}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function tf(e,t,n){var r;b((null===(r=n.url)||void 0===r?void 0:r.length)>0,e,"invalid-continue-uri"),b(void 0===n.dynamicLinkDomain||n.dynamicLinkDomain.length>0,e,"invalid-dynamic-link-domain"),t.continueUrl=n.url,t.dynamicLinkDomain=n.dynamicLinkDomain,t.canHandleCodeInApp=n.handleCodeInApp,n.iOS&&(b(n.iOS.bundleId.length>0,e,"missing-ios-bundle-id"),t.iOSBundleId=n.iOS.bundleId),n.android&&(b(n.android.packageName.length>0,e,"missing-android-pkg-name"),t.androidInstallApp=n.android.installApp,t.androidMinimumVersionCode=n.android.minimumVersion,t.androidPackageName=n.android.packageName)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function tp(e,t,n){let r=(0,i.m9)(e),s={requestType:"PASSWORD_RESET",email:t};n&&tf(r,s,n),await eO(r,s)}async function tm(e,t,n){await ex((0,i.m9)(e),{oobCode:t,newPassword:n})}async function tg(e,t){await eN((0,i.m9)(e),{oobCode:t})}async function ty(e,t){let n=(0,i.m9)(e),r=await ex(n,{oobCode:t}),s=r.requestType;switch(b(s,n,"internal-error"),s){case"EMAIL_SIGNIN":break;case"VERIFY_AND_CHANGE_EMAIL":b(r.newEmail,n,"internal-error");break;case"REVERT_SECOND_FACTOR_ADDITION":b(r.mfaInfo,n,"internal-error");default:b(r.email,n,"internal-error")}let o=null;return r.mfaInfo&&(o=th._fromServerResponse(eb(n),r.mfaInfo)),{data:{email:("VERIFY_AND_CHANGE_EMAIL"===r.requestType?r.newEmail:r.email)||null,previousEmail:("VERIFY_AND_CHANGE_EMAIL"===r.requestType?r.email:r.newEmail)||null,multiFactorInfo:o},operation:s}}async function tv(e,t){let{data:n}=await ty((0,i.m9)(e),t);return n.email}async function t_(e,t,n){let r=eb(e),i=await e4(r,{returnSecureToken:!0,email:t,password:n}),s=await e6._fromIdTokenResponse(r,"signIn",i);return await r._updateCurrentUser(s.user),s}function tw(e,t,n){return to((0,i.m9)(e),eK.credential(t,n))}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function tb(e,t,n){let r=(0,i.m9)(e),s={requestType:"EMAIL_SIGNIN",email:t};b(n.handleCodeInApp,r,"argument-error"),n&&tf(r,s,n),await eP(r,s)}function tI(e,t){let n=eH.parseLink(t);return(null==n?void 0:n.operation)==="EMAIL_SIGNIN"}async function tT(e,t,n){let r=(0,i.m9)(e),s=eK.credentialWithLink(t,n||k());return b(s._tenantId===(r.tenantId||null),r,"tenant-id-mismatch"),to(r,s)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function tE(e,t){return L(e,"POST","/v1/accounts:createAuthUri",P(e,t))}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function tS(e,t){let n=x()?k():"http://localhost",{signinMethods:r}=await tE((0,i.m9)(e),{identifier:t,continueUri:n});return r||[]}async function tk(e,t){let n=(0,i.m9)(e),r=await e.getIdToken(),s={requestType:"VERIFY_EMAIL",idToken:r};t&&tf(n.auth,s,t);let{email:o}=await eD(n.auth,s);o!==e.email&&await e.reload()}async function tx(e,t,n){let r=(0,i.m9)(e),s=await e.getIdToken(),o={requestType:"VERIFY_AND_CHANGE_EMAIL",idToken:s,newEmail:t};n&&tf(r.auth,o,n);let{email:a}=await eL(r.auth,o);a!==e.email&&await e.reload()}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function tC(e,t){return L(e,"POST","/v1/accounts:update",t)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function tN(e,{displayName:t,photoURL:n}){if(void 0===t&&void 0===n)return;let r=(0,i.m9)(e),s=await r.getIdToken(),o=await K(r,tC(r.auth,{idToken:s,displayName:t,photoUrl:n,returnSecureToken:!0}));r.displayName=o.displayName||null,r.photoURL=o.photoUrl||null;let a=r.providerData.find(({providerId:e})=>"password"===e);a&&(a.displayName=r.displayName,a.photoURL=r.photoURL),await r._updateTokensIfNecessary(o)}function tA(e,t){return tD((0,i.m9)(e),t,null)}function tR(e,t){return tD((0,i.m9)(e),null,t)}async function tD(e,t,n){let{auth:r}=e,i=await e.getIdToken(),s={idToken:i,returnSecureToken:!0};t&&(s.email=t),n&&(s.password=n);let o=await K(e,eC(r,s));await e._updateTokensIfNecessary(o,!0)}class tO{constructor(e,t,n={}){this.isNewUser=e,this.providerId=t,this.profile=n}}class tP extends tO{constructor(e,t,n,r){super(e,t,n),this.username=r}}class tL extends tO{constructor(e,t){super(e,"facebook.com",t)}}class tM extends tP{constructor(e,t){super(e,"github.com",t,"string"==typeof(null==t?void 0:t.login)?null==t?void 0:t.login:null)}}class tj extends tO{constructor(e,t){super(e,"google.com",t)}}class tF extends tP{constructor(e,t,n){super(e,"twitter.com",t,n)}}function tU(e){let{user:t,_tokenResponse:n}=e;return t.isAnonymous&&!n?{providerId:null,isNewUser:!1,profile:null}:/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function(e){var t,n;if(!e)return null;let{providerId:r}=e,i=e.rawUserInfo?JSON.parse(e.rawUserInfo):{},s=e.isNewUser||"identitytoolkit#SignupNewUserResponse"===e.kind;if(!r&&(null==e?void 0:e.idToken)){let o=null===(n=null===(t=H(e.idToken))||void 0===t?void 0:t.firebase)||void 0===n?void 0:n.sign_in_provider;if(o)return new tO(s,"anonymous"!==o&&"custom"!==o?o:null)}if(!r)return null;switch(r){case"facebook.com":return new tL(s,i);case"github.com":return new tM(s,i);case"google.com":return new tj(s,i);case"twitter.com":return new tF(s,i,e.screenName||null);case"custom":case"anonymous":return new tO(s,null);default:return new tO(s,r,i)}}(n)}function tV(e,t,n,r){return(0,i.m9)(e).onAuthStateChanged(t,n,r)}class tq{constructor(e,t,n){this.type=e,this.credential=t,this.auth=n}static _fromIdtoken(e,t){return new tq("enroll",e,t)}static _fromMfaPendingCredential(e){return new tq("signin",e)}toJSON(){let e="enroll"===this.type?"idToken":"pendingCredential";return{multiFactorSession:{[e]:this.credential}}}static fromJSON(e){var t,n;if(null==e?void 0:e.multiFactorSession){if(null===(t=e.multiFactorSession)||void 0===t?void 0:t.pendingCredential)return tq._fromMfaPendingCredential(e.multiFactorSession.pendingCredential);if(null===(n=e.multiFactorSession)||void 0===n?void 0:n.idToken)return tq._fromIdtoken(e.multiFactorSession.idToken)}return null}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class tB{constructor(e,t,n){this.session=e,this.hints=t,this.signInResolver=n}static _fromError(e,t){let n=eb(e),r=t.customData._serverResponse,i=(r.mfaInfo||[]).map(e=>th._fromServerResponse(n,e));b(r.mfaPendingCredential,n,"internal-error");let s=tq._fromMfaPendingCredential(r.mfaPendingCredential);return new tB(s,i,async e=>{let i=await e._process(n,s);delete r.mfaInfo,delete r.mfaPendingCredential;let o=Object.assign(Object.assign({},r),{idToken:i.idToken,refreshToken:i.refreshToken});switch(t.operationType){case"signIn":let a=await e6._fromIdTokenResponse(n,t.operationType,o);return await n._updateCurrentUser(a.user),a;case"reauthenticate":return b(t.user,n,"internal-error"),e6._forOperation(t.user,t.operationType,o);default:g(n,"internal-error")}})}async resolveSignIn(e){return this.signInResolver(e)}}function t$(e,t){var n;let r=(0,i.m9)(e);return b(t.customData.operationType,r,"argument-error"),b(null===(n=t.customData._serverResponse)||void 0===n?void 0:n.mfaPendingCredential,r,"argument-error"),tB._fromError(r,t)}class tz{constructor(e){this.user=e,this.enrolledFactors=[],e._onReload(t=>{t.mfaInfo&&(this.enrolledFactors=t.mfaInfo.map(t=>th._fromServerResponse(e.auth,t)))})}static _fromUser(e){return new tz(e)}async getSession(){return tq._fromIdtoken(await this.user.getIdToken(),this.user.auth)}async enroll(e,t){let n=await this.getSession(),r=await K(this.user,e._process(this.user.auth,n,t));return await this.user._updateTokensIfNecessary(r),this.user.reload()}async unenroll(e){var t;let n="string"==typeof e?e:e.uid,r=await this.user.getIdToken(),i=await K(this.user,L(t=this.user.auth,"POST","/v2/accounts/mfaEnrollment:withdraw",P(t,{idToken:r,mfaEnrollmentId:n})));this.enrolledFactors=this.enrolledFactors.filter(({uid:e})=>e!==n),await this.user._updateTokensIfNecessary(i);try{await this.user.reload()}catch(s){if((null==s?void 0:s.code)!=="auth/user-token-expired")throw s}}}let tG=new WeakMap;function tW(e){let t=(0,i.m9)(e);return tG.has(t)||tG.set(t,tz._fromUser(t)),tG.get(t)}let tH="__sak";/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class tK{constructor(e,t){this.storageRetriever=e,this.type=t}_isAvailable(){try{if(!this.storage)return Promise.resolve(!1);return this.storage.setItem(tH,"1"),this.storage.removeItem(tH),Promise.resolve(!0)}catch(e){return Promise.resolve(!1)}}_set(e,t){return this.storage.setItem(e,JSON.stringify(t)),Promise.resolve()}_get(e){let t=this.storage.getItem(e);return Promise.resolve(t?JSON.parse(t):null)}_remove(e){return this.storage.removeItem(e),Promise.resolve()}get storage(){return this.storageRetriever()}}class tQ extends tK{constructor(){super(()=>window.localStorage,"LOCAL"),this.boundEventHandler=(e,t)=>this.onStorageEvent(e,t),this.listeners={},this.localCache={},this.pollTimer=null,this.safariLocalStorageNotSynced=/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function(){let e=(0,i.z$)();return eu(e)||em(e)}()&&function(){try{return!!(window&&window!==window.top)}catch(e){return!1}}(),this.fallbackToPolling=ey(),this._shouldAllowMigration=!0}forAllChangedKeys(e){for(let t of Object.keys(this.listeners)){let n=this.storage.getItem(t),r=this.localCache[t];n!==r&&e(t,r,n)}}onStorageEvent(e,t=!1){if(!e.key){this.forAllChangedKeys((e,t,n)=>{this.notifyListeners(e,n)});return}let n=e.key;if(t?this.detachListener():this.stopPolling(),this.safariLocalStorageNotSynced){let r=this.storage.getItem(n);if(e.newValue!==r)null!==e.newValue?this.storage.setItem(n,e.newValue):this.storage.removeItem(n);else if(this.localCache[n]===e.newValue&&!t)return}let s=()=>{let e=this.storage.getItem(n);(t||this.localCache[n]!==e)&&this.notifyListeners(n,e)},o=this.storage.getItem(n);(0,i.w1)()&&10===document.documentMode&&o!==e.newValue&&e.newValue!==e.oldValue?setTimeout(s,10):s()}notifyListeners(e,t){this.localCache[e]=t;let n=this.listeners[e];if(n)for(let r of Array.from(n))r(t?JSON.parse(t):t)}startPolling(){this.stopPolling(),this.pollTimer=setInterval(()=>{this.forAllChangedKeys((e,t,n)=>{this.onStorageEvent(new StorageEvent("storage",{key:e,oldValue:t,newValue:n}),!0)})},1e3)}stopPolling(){this.pollTimer&&(clearInterval(this.pollTimer),this.pollTimer=null)}attachListener(){window.addEventListener("storage",this.boundEventHandler)}detachListener(){window.removeEventListener("storage",this.boundEventHandler)}_addListener(e,t){0===Object.keys(this.listeners).length&&(this.fallbackToPolling?this.startPolling():this.attachListener()),this.listeners[e]||(this.listeners[e]=new Set,this.localCache[e]=this.storage.getItem(e)),this.listeners[e].add(t)}_removeListener(e,t){this.listeners[e]&&(this.listeners[e].delete(t),0===this.listeners[e].size&&delete this.listeners[e]),0===Object.keys(this.listeners).length&&(this.detachListener(),this.stopPolling())}async _set(e,t){await super._set(e,t),this.localCache[e]=JSON.stringify(t)}async _get(e){let t=await super._get(e);return this.localCache[e]=JSON.stringify(t),t}async _remove(e){await super._remove(e),delete this.localCache[e]}}tQ.type="LOCAL";let tY=tQ;/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class tX extends tK{constructor(){super(()=>window.sessionStorage,"SESSION")}_addListener(e,t){}_removeListener(e,t){}}tX.type="SESSION";let tJ=tX;/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class tZ{constructor(e){this.eventTarget=e,this.handlersMap={},this.boundEventHandler=this.handleEvent.bind(this)}static _getInstance(e){let t=this.receivers.find(t=>t.isListeningto(e));if(t)return t;let n=new tZ(e);return this.receivers.push(n),n}isListeningto(e){return this.eventTarget===e}async handleEvent(e){let{eventId:t,eventType:n,data:r}=e.data,i=this.handlersMap[n];if(!(null==i?void 0:i.size))return;e.ports[0].postMessage({status:"ack",eventId:t,eventType:n});let s=Array.from(i).map(async t=>t(e.origin,r)),o=await Promise.all(s.map(async e=>{try{let t=await e;return{fulfilled:!0,value:t}}catch(n){return{fulfilled:!1,reason:n}}}));e.ports[0].postMessage({status:"done",eventId:t,eventType:n,response:o})}_subscribe(e,t){0===Object.keys(this.handlersMap).length&&this.eventTarget.addEventListener("message",this.boundEventHandler),this.handlersMap[e]||(this.handlersMap[e]=new Set),this.handlersMap[e].add(t)}_unsubscribe(e,t){this.handlersMap[e]&&t&&this.handlersMap[e].delete(t),t&&0!==this.handlersMap[e].size||delete this.handlersMap[e],0===Object.keys(this.handlersMap).length&&this.eventTarget.removeEventListener("message",this.boundEventHandler)}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function t0(e="",t=10){let n="";for(let r=0;r<t;r++)n+=Math.floor(10*Math.random());return e+n}tZ.receivers=[];/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class t1{constructor(e){this.target=e,this.handlers=new Set}removeMessageHandler(e){e.messageChannel&&(e.messageChannel.port1.removeEventListener("message",e.onMessage),e.messageChannel.port1.close()),this.handlers.delete(e)}async _send(e,t,n=50){let r,i;let s="undefined"!=typeof MessageChannel?new MessageChannel:null;if(!s)throw Error("connection_unavailable");return new Promise((o,a)=>{let l=t0("",20);s.port1.start();let u=setTimeout(()=>{a(Error("unsupported_event"))},n);i={messageChannel:s,onMessage(e){if(e.data.eventId===l)switch(e.data.status){case"ack":clearTimeout(u),r=setTimeout(()=>{a(Error("timeout"))},3e3);break;case"done":clearTimeout(r),o(e.data.response);break;default:clearTimeout(u),clearTimeout(r),a(Error("invalid_response"))}}},this.handlers.add(i),s.port1.addEventListener("message",i.onMessage),this.target.postMessage({eventType:e,eventId:l,data:t},[s.port2])}).finally(()=>{i&&this.removeMessageHandler(i)})}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function t2(){return window}/**
 * @license
 * Copyright 2020 Google LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function t3(){return void 0!==t2().WorkerGlobalScope&&"function"==typeof t2().importScripts}async function t4(){if(!(null==navigator?void 0:navigator.serviceWorker))return null;try{let e=await navigator.serviceWorker.ready;return e.active}catch(t){return null}}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let t6="firebaseLocalStorageDb",t5="firebaseLocalStorage",t8="fbase_key";class t9{constructor(e){this.request=e}toPromise(){return new Promise((e,t)=>{this.request.addEventListener("success",()=>{e(this.request.result)}),this.request.addEventListener("error",()=>{t(this.request.error)})})}}function t7(e,t){return e.transaction([t5],t?"readwrite":"readonly").objectStore(t5)}function ne(){let e=indexedDB.open(t6,1);return new Promise((t,n)=>{e.addEventListener("error",()=>{n(e.error)}),e.addEventListener("upgradeneeded",()=>{let t=e.result;try{t.createObjectStore(t5,{keyPath:t8})}catch(r){n(r)}}),e.addEventListener("success",async()=>{let n=e.result;n.objectStoreNames.contains(t5)?t(n):(n.close(),await function(){let e=indexedDB.deleteDatabase(t6);return new t9(e).toPromise()}(),t(await ne()))})})}async function nt(e,t,n){let r=t7(e,!0).put({[t8]:t,value:n});return new t9(r).toPromise()}async function nn(e,t){let n=t7(e,!1).get(t),r=await new t9(n).toPromise();return void 0===r?null:r.value}function nr(e,t){let n=t7(e,!0).delete(t);return new t9(n).toPromise()}class ni{constructor(){this.type="LOCAL",this._shouldAllowMigration=!0,this.listeners={},this.localCache={},this.pollTimer=null,this.pendingWrites=0,this.receiver=null,this.sender=null,this.serviceWorkerReceiverAvailable=!1,this.activeServiceWorker=null,this._workerInitializationPromise=this.initializeServiceWorkerMessaging().then(()=>{},()=>{})}async _openDb(){return this.db||(this.db=await ne()),this.db}async _withRetries(e){let t=0;for(;;)try{let n=await this._openDb();return await e(n)}catch(r){if(t++>3)throw r;this.db&&(this.db.close(),this.db=void 0)}}async initializeServiceWorkerMessaging(){return t3()?this.initializeReceiver():this.initializeSender()}async initializeReceiver(){this.receiver=tZ._getInstance(t3()?self:null),this.receiver._subscribe("keyChanged",async(e,t)=>{let n=await this._poll();return{keyProcessed:n.includes(t.key)}}),this.receiver._subscribe("ping",async(e,t)=>["keyChanged"])}async initializeSender(){var e,t;if(this.activeServiceWorker=await t4(),!this.activeServiceWorker)return;this.sender=new t1(this.activeServiceWorker);let n=await this.sender._send("ping",{},800);n&&(null===(e=n[0])||void 0===e?void 0:e.fulfilled)&&(null===(t=n[0])||void 0===t?void 0:t.value.includes("keyChanged"))&&(this.serviceWorkerReceiverAvailable=!0)}async notifyServiceWorker(e){var t;if(this.sender&&this.activeServiceWorker&&((null===(t=null==navigator?void 0:navigator.serviceWorker)||void 0===t?void 0:t.controller)||null)===this.activeServiceWorker)try{await this.sender._send("keyChanged",{key:e},this.serviceWorkerReceiverAvailable?800:50)}catch(n){}}async _isAvailable(){try{if(!indexedDB)return!1;let e=await ne();return await nt(e,tH,"1"),await nr(e,tH),!0}catch(t){}return!1}async _withPendingWrite(e){this.pendingWrites++;try{await e()}finally{this.pendingWrites--}}async _set(e,t){return this._withPendingWrite(async()=>(await this._withRetries(n=>nt(n,e,t)),this.localCache[e]=t,this.notifyServiceWorker(e)))}async _get(e){let t=await this._withRetries(t=>nn(t,e));return this.localCache[e]=t,t}async _remove(e){return this._withPendingWrite(async()=>(await this._withRetries(t=>nr(t,e)),delete this.localCache[e],this.notifyServiceWorker(e)))}async _poll(){let e=await this._withRetries(e=>{let t=t7(e,!1).getAll();return new t9(t).toPromise()});if(!e||0!==this.pendingWrites)return[];let t=[],n=new Set;for(let{fbase_key:r,value:i}of e)n.add(r),JSON.stringify(this.localCache[r])!==JSON.stringify(i)&&(this.notifyListeners(r,i),t.push(r));for(let s of Object.keys(this.localCache))this.localCache[s]&&!n.has(s)&&(this.notifyListeners(s,null),t.push(s));return t}notifyListeners(e,t){this.localCache[e]=t;let n=this.listeners[e];if(n)for(let r of Array.from(n))r(t)}startPolling(){this.stopPolling(),this.pollTimer=setInterval(async()=>this._poll(),800)}stopPolling(){this.pollTimer&&(clearInterval(this.pollTimer),this.pollTimer=null)}_addListener(e,t){0===Object.keys(this.listeners).length&&this.startPolling(),this.listeners[e]||(this.listeners[e]=new Set,this._get(e)),this.listeners[e].add(t)}_removeListener(e,t){this.listeners[e]&&(this.listeners[e].delete(t),0===this.listeners[e].size&&delete this.listeners[e]),0===Object.keys(this.listeners).length&&this.stopPolling()}}ni.type="LOCAL";let ns=ni;/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function no(e){return(await L(e,"GET","/v1/recaptchaParams")).recaptchaSiteKey||""}function na(e){return new Promise((t,n)=>{var r,i;let s=document.createElement("script");s.setAttribute("src",e),s.onload=t,s.onerror=e=>{let t=y("internal-error");t.customData=e,n(t)},s.type="text/javascript",s.charset="UTF-8",(null!==(i=null===(r=document.getElementsByTagName("head"))||void 0===r?void 0:r[0])&&void 0!==i?i:document).appendChild(s)})}function nl(e){return`__${e}${Math.floor(1e6*Math.random())}`}class nu{constructor(e){this.auth=e,this.counter=1e12,this._widgets=new Map}render(e,t){let n=this.counter;return this._widgets.set(n,new nc(e,this.auth.name,t||{})),this.counter++,n}reset(e){var t;let n=e||1e12;null===(t=this._widgets.get(n))||void 0===t||t.delete(),this._widgets.delete(n)}getResponse(e){var t;return(null===(t=this._widgets.get(e||1e12))||void 0===t?void 0:t.getResponse())||""}async execute(e){var t;return null===(t=this._widgets.get(e||1e12))||void 0===t||t.execute(),""}}class nc{constructor(e,t,n){this.params=n,this.timerId=null,this.deleted=!1,this.responseToken=null,this.clickHandler=()=>{this.execute()};let r="string"==typeof e?document.getElementById(e):e;b(r,"argument-error",{appName:t}),this.container=r,this.isVisible="invisible"!==this.params.size,this.isVisible?this.execute():this.container.addEventListener("click",this.clickHandler)}getResponse(){return this.checkIfDeleted(),this.responseToken}delete(){this.checkIfDeleted(),this.deleted=!0,this.timerId&&(clearTimeout(this.timerId),this.timerId=null),this.container.removeEventListener("click",this.clickHandler)}execute(){this.checkIfDeleted(),this.timerId||(this.timerId=window.setTimeout(()=>{this.responseToken=function(e){let t=[],n="1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";for(let r=0;r<50;r++)t.push(n.charAt(Math.floor(Math.random()*n.length)));return t.join("")}(0);let{callback:e,"expired-callback":t}=this.params;if(e)try{e(this.responseToken)}catch(n){}this.timerId=window.setTimeout(()=>{if(this.timerId=null,this.responseToken=null,t)try{t()}catch(e){}this.isVisible&&this.execute()},6e4)},500))}checkIfDeleted(){if(this.deleted)throw Error("reCAPTCHA mock was already deleted!")}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let nh=nl("rcb"),nd=new N(3e4,6e4);class nf{constructor(){var e;this.hostLanguage="",this.counter=0,this.librarySeparatelyLoaded=!!(null===(e=t2().grecaptcha)||void 0===e?void 0:e.render)}load(e,t=""){return(b(t.length<=6&&/^\s*[a-zA-Z0-9\-]*\s*$/.test(t),e,"argument-error"),this.shouldResolveImmediately(t))?Promise.resolve(t2().grecaptcha):new Promise((n,r)=>{let s=t2().setTimeout(()=>{r(y(e,"network-request-failed"))},nd.get());t2()[nh]=()=>{t2().clearTimeout(s),delete t2()[nh];let i=t2().grecaptcha;if(!i){r(y(e,"internal-error"));return}let o=i.render;i.render=(e,t)=>{let n=o(e,t);return this.counter++,n},this.hostLanguage=t,n(i)};let o=`https://www.google.com/recaptcha/api.js??${(0,i.xO)({onload:nh,render:"explicit",hl:t})}`;na(o).catch(()=>{clearTimeout(s),r(y(e,"internal-error"))})})}clearedOneInstance(){this.counter--}shouldResolveImmediately(e){var t;return!!(null===(t=t2().grecaptcha)||void 0===t?void 0:t.render)&&(e===this.hostLanguage||this.counter>0||this.librarySeparatelyLoaded)}}class np{async load(e){return new nu(e)}clearedOneInstance(){}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let nm="recaptcha",ng={theme:"light",type:"image"};class ny{constructor(e,t=Object.assign({},ng),n){this.parameters=t,this.type=nm,this.destroyed=!1,this.widgetId=null,this.tokenChangeListeners=new Set,this.renderPromise=null,this.recaptcha=null,this.auth=eb(n),this.isInvisible="invisible"===this.parameters.size,b("undefined"!=typeof document,this.auth,"operation-not-supported-in-this-environment");let r="string"==typeof e?document.getElementById(e):e;b(r,this.auth,"argument-error"),this.container=r,this.parameters.callback=this.makeTokenCallback(this.parameters.callback),this._recaptchaLoader=this.auth.settings.appVerificationDisabledForTesting?new np:new nf,this.validateStartingState()}async verify(){this.assertNotDestroyed();let e=await this.render(),t=this.getAssertedRecaptcha(),n=t.getResponse(e);return n||new Promise(n=>{let r=e=>{e&&(this.tokenChangeListeners.delete(r),n(e))};this.tokenChangeListeners.add(r),this.isInvisible&&t.execute(e)})}render(){try{this.assertNotDestroyed()}catch(e){return Promise.reject(e)}return this.renderPromise||(this.renderPromise=this.makeRenderPromise().catch(e=>{throw this.renderPromise=null,e})),this.renderPromise}_reset(){this.assertNotDestroyed(),null!==this.widgetId&&this.getAssertedRecaptcha().reset(this.widgetId)}clear(){this.assertNotDestroyed(),this.destroyed=!0,this._recaptchaLoader.clearedOneInstance(),this.isInvisible||this.container.childNodes.forEach(e=>{this.container.removeChild(e)})}validateStartingState(){b(!this.parameters.sitekey,this.auth,"argument-error"),b(this.isInvisible||!this.container.hasChildNodes(),this.auth,"argument-error"),b("undefined"!=typeof document,this.auth,"operation-not-supported-in-this-environment")}makeTokenCallback(e){return t=>{if(this.tokenChangeListeners.forEach(e=>e(t)),"function"==typeof e)e(t);else if("string"==typeof e){let n=t2()[e];"function"==typeof n&&n(t)}}}assertNotDestroyed(){b(!this.destroyed,this.auth,"internal-error")}async makeRenderPromise(){if(await this.init(),!this.widgetId){let e=this.container;if(!this.isInvisible){let t=document.createElement("div");e.appendChild(t),e=t}this.widgetId=this.getAssertedRecaptcha().render(e,this.parameters)}return this.widgetId}async init(){let e;b(x()&&!t3(),this.auth,"internal-error"),await (e=null,new Promise(t=>{if("complete"===document.readyState){t();return}e=()=>t(),window.addEventListener("load",e)}).catch(t=>{throw e&&window.removeEventListener("load",e),t})),this.recaptcha=await this._recaptchaLoader.load(this.auth,this.auth.languageCode||void 0);let t=await no(this.auth);b(t,this.auth,"internal-error"),this.parameters.sitekey=t}getAssertedRecaptcha(){return b(this.recaptcha,this.auth,"internal-error"),this.recaptcha}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class nv{constructor(e,t){this.verificationId=e,this.onConfirmation=t}confirm(e){let t=eW._fromVerification(this.verificationId,e);return this.onConfirmation(t)}}async function n_(e,t,n){let r=eb(e),s=await nI(r,t,(0,i.m9)(n));return new nv(s,e=>to(r,e))}async function nw(e,t,n){let r=(0,i.m9)(e);await tr(!1,r,"phone");let s=await nI(r.auth,t,(0,i.m9)(n));return new nv(s,e=>ta(r,e))}async function nb(e,t,n){let r=(0,i.m9)(e),s=await nI(r.auth,t,(0,i.m9)(n));return new nv(s,e=>tl(r,e))}async function nI(e,t,n){var r,i,s;let o=await n.verify();try{let a;if(b("string"==typeof o,e,"argument-error"),b(n.type===nm,e,"argument-error"),a="string"==typeof t?{phoneNumber:t}:t,"session"in a){let l=a.session;if("phoneNumber"in a){b("enroll"===l.type,e,"internal-error");let u=await (i={idToken:l.credential,phoneEnrollmentInfo:{phoneNumber:a.phoneNumber,recaptchaToken:o}},L(e,"POST","/v2/accounts/mfaEnrollment:start",P(e,i)));return u.phoneSessionInfo.sessionInfo}{b("signin"===l.type,e,"internal-error");let c=(null===(r=a.multiFactorHint)||void 0===r?void 0:r.uid)||a.multiFactorUid;b(c,e,"missing-multi-factor-info");let h=await (s={mfaPendingCredential:l.credential,mfaEnrollmentId:c,phoneSignInInfo:{recaptchaToken:o}},L(e,"POST","/v2/accounts/mfaSignIn:start",P(e,s)));return h.phoneResponseInfo.sessionInfo}}{let{sessionInfo:d}=await eq(e,{phoneNumber:a.phoneNumber,recaptchaToken:o});return d}}finally{n._reset()}}async function nT(e,t){await tn((0,i.m9)(e),t)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class nE{constructor(e){this.providerId=nE.PROVIDER_ID,this.auth=eb(e)}verifyPhoneNumber(e,t){return nI(this.auth,e,(0,i.m9)(t))}static credential(e,t){return eW._fromVerification(e,t)}static credentialFromResult(e){return nE.credentialFromTaggedObject(e)}static credentialFromError(e){return nE.credentialFromTaggedObject(e.customData||{})}static credentialFromTaggedObject({_tokenResponse:e}){if(!e)return null;let{phoneNumber:t,temporaryProof:n}=e;return t&&n?eW._fromTokenResponse(t,n):null}}/**
 * @license
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function nS(e,t){return t?S(t):(b(e._popupRedirectResolver,e,"argument-error"),e._popupRedirectResolver)}nE.PROVIDER_ID="phone",nE.PHONE_SIGN_IN_METHOD="phone";/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class nk extends ek{constructor(e){super("custom","custom"),this.params=e}_getIdTokenResponse(e){return eU(e,this._buildIdpRequest())}_linkToIdToken(e,t){return eU(e,this._buildIdpRequest(t))}_getReauthenticationResolver(e){return eU(e,this._buildIdpRequest())}_buildIdpRequest(e){let t={requestUri:this.params.requestUri,sessionId:this.params.sessionId,postBody:this.params.postBody,tenantId:this.params.tenantId,pendingToken:this.params.pendingToken,returnSecureToken:!0,returnIdpCredential:!0};return e&&(t.idToken=e),t}}function nx(e){return ts(e.auth,new nk(e),e.bypassAuthState)}function nC(e){let{auth:t,user:n}=e;return b(n,t,"internal-error"),ti(n,new nk(e),e.bypassAuthState)}async function nN(e){let{auth:t,user:n}=e;return b(n,t,"internal-error"),tn(n,new nk(e),e.bypassAuthState)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class nA{constructor(e,t,n,r,i=!1){this.auth=e,this.resolver=n,this.user=r,this.bypassAuthState=i,this.pendingPromise=null,this.eventManager=null,this.filter=Array.isArray(t)?t:[t]}execute(){return new Promise(async(e,t)=>{this.pendingPromise={resolve:e,reject:t};try{this.eventManager=await this.resolver._initialize(this.auth),await this.onExecution(),this.eventManager.registerConsumer(this)}catch(n){this.reject(n)}})}async onAuthEvent(e){let{urlResponse:t,sessionId:n,postBody:r,tenantId:i,error:s,type:o}=e;if(s){this.reject(s);return}let a={auth:this.auth,requestUri:t,sessionId:n,tenantId:i||void 0,postBody:r||void 0,user:this.user,bypassAuthState:this.bypassAuthState};try{this.resolve(await this.getIdpTask(o)(a))}catch(l){this.reject(l)}}onError(e){this.reject(e)}getIdpTask(e){switch(e){case"signInViaPopup":case"signInViaRedirect":return nx;case"linkViaPopup":case"linkViaRedirect":return nN;case"reauthViaPopup":case"reauthViaRedirect":return nC;default:g(this.auth,"internal-error")}}resolve(e){T(this.pendingPromise,"Pending promise was never set"),this.pendingPromise.resolve(e),this.unregisterAndCleanUp()}reject(e){T(this.pendingPromise,"Pending promise was never set"),this.pendingPromise.reject(e),this.unregisterAndCleanUp()}unregisterAndCleanUp(){this.eventManager&&this.eventManager.unregisterConsumer(this),this.pendingPromise=null,this.cleanUp()}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let nR=new N(2e3,1e4);async function nD(e,t,n){let r=eb(e);_(e,t,eQ);let i=nS(r,n),s=new nL(r,"signInViaPopup",t,i);return s.executeNotNull()}async function nO(e,t,n){let r=(0,i.m9)(e);_(r.auth,t,eQ);let s=nS(r.auth,n),o=new nL(r.auth,"reauthViaPopup",t,s,r);return o.executeNotNull()}async function nP(e,t,n){let r=(0,i.m9)(e);_(r.auth,t,eQ);let s=nS(r.auth,n),o=new nL(r.auth,"linkViaPopup",t,s,r);return o.executeNotNull()}class nL extends nA{constructor(e,t,n,r,i){super(e,t,r,i),this.provider=n,this.authWindow=null,this.pollId=null,nL.currentPopupAction&&nL.currentPopupAction.cancel(),nL.currentPopupAction=this}async executeNotNull(){let e=await this.execute();return b(e,this.auth,"internal-error"),e}async onExecution(){T(1===this.filter.length,"Popup operations only handle one event");let e=t0();this.authWindow=await this.resolver._openPopup(this.auth,this.provider,this.filter[0],e),this.authWindow.associatedEvent=e,this.resolver._originValidation(this.auth).catch(e=>{this.reject(e)}),this.resolver._isIframeWebStorageSupported(this.auth,e=>{e||this.reject(y(this.auth,"web-storage-unsupported"))}),this.pollUserCancellation()}get eventId(){var e;return(null===(e=this.authWindow)||void 0===e?void 0:e.associatedEvent)||null}cancel(){this.reject(y(this.auth,"cancelled-popup-request"))}cleanUp(){this.authWindow&&this.authWindow.close(),this.pollId&&window.clearTimeout(this.pollId),this.authWindow=null,this.pollId=null,nL.currentPopupAction=null}pollUserCancellation(){let e=()=>{var t,n;if(null===(n=null===(t=this.authWindow)||void 0===t?void 0:t.window)||void 0===n?void 0:n.closed){this.pollId=window.setTimeout(()=>{this.pollId=null,this.reject(y(this.auth,"popup-closed-by-user"))},2e3);return}this.pollId=window.setTimeout(e,nR.get())};e()}}nL.currentPopupAction=null;let nM=new Map;class nj extends nA{constructor(e,t,n=!1){super(e,["signInViaRedirect","linkViaRedirect","reauthViaRedirect","unknown"],t,void 0,n),this.eventId=null}async execute(){let e=nM.get(this.auth._key());if(!e){try{let t=await nF(this.resolver,this.auth),n=t?await super.execute():null;e=()=>Promise.resolve(n)}catch(r){e=()=>Promise.reject(r)}nM.set(this.auth._key(),e)}return this.bypassAuthState||nM.set(this.auth._key(),()=>Promise.resolve(null)),e()}async onAuthEvent(e){if("signInViaRedirect"===e.type)return super.onAuthEvent(e);if("unknown"===e.type){this.resolve(null);return}if(e.eventId){let t=await this.auth._redirectUserForId(e.eventId);if(t)return this.user=t,super.onAuthEvent(e);this.resolve(null)}}async onExecution(){}cleanUp(){}}async function nF(e,t){let n=n$(t),r=nB(e);if(!await r._isAvailable())return!1;let i=await r._get(n)==="true";return await r._remove(n),i}async function nU(e,t){return nB(e)._set(n$(t),"true")}function nV(){nM.clear()}function nq(e,t){nM.set(e._key(),t)}function nB(e){return S(e._redirectPersistence)}function n$(e){return es("pendingRedirect",e.config.apiKey,e.name)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function nz(e,t,n){return nG(e,t,n)}async function nG(e,t,n){let r=eb(e);_(e,t,eQ);let i=nS(r,n);return await nU(i,r),i._openRedirect(r,t,"signInViaRedirect")}function nW(e,t,n){return nH(e,t,n)}async function nH(e,t,n){let r=(0,i.m9)(e);_(r.auth,t,eQ);let s=nS(r.auth,n);await nU(s,r.auth);let o=await nJ(r);return s._openRedirect(r.auth,t,"reauthViaRedirect",o)}function nK(e,t,n){return nQ(e,t,n)}async function nQ(e,t,n){let r=(0,i.m9)(e);_(r.auth,t,eQ);let s=nS(r.auth,n);await tr(!1,r,t.providerId),await nU(s,r.auth);let o=await nJ(r);return s._openRedirect(r.auth,t,"linkViaRedirect",o)}async function nY(e,t){return await eb(e)._initializationPromise,nX(e,t,!1)}async function nX(e,t,n=!1){let r=eb(e),i=nS(r,t),s=new nj(r,i,n),o=await s.execute();return o&&!n&&(delete o.user._redirectEventId,await r._persistUserIfCurrent(o.user),await r._setRedirectUser(null,t)),o}async function nJ(e){let t=t0(`${e.uid}:::`);return e._redirectEventId=t,await e.auth._setRedirectUser(e),await e.auth._persistUserIfCurrent(e),t}class nZ{constructor(e){this.auth=e,this.cachedEventUids=new Set,this.consumers=new Set,this.queuedRedirectEvent=null,this.hasHandledPotentialRedirect=!1,this.lastProcessedEventTime=Date.now()}registerConsumer(e){this.consumers.add(e),this.queuedRedirectEvent&&this.isEventForConsumer(this.queuedRedirectEvent,e)&&(this.sendToConsumer(this.queuedRedirectEvent,e),this.saveEventToCache(this.queuedRedirectEvent),this.queuedRedirectEvent=null)}unregisterConsumer(e){this.consumers.delete(e)}onEvent(e){if(this.hasEventBeenHandled(e))return!1;let t=!1;return this.consumers.forEach(n=>{this.isEventForConsumer(e,n)&&(t=!0,this.sendToConsumer(e,n),this.saveEventToCache(e))}),this.hasHandledPotentialRedirect||!function(e){switch(e.type){case"signInViaRedirect":case"linkViaRedirect":case"reauthViaRedirect":return!0;case"unknown":return n1(e);default:return!1}}(e)||(this.hasHandledPotentialRedirect=!0,t||(this.queuedRedirectEvent=e,t=!0)),t}sendToConsumer(e,t){var n;if(e.error&&!n1(e)){let r=(null===(n=e.error.code)||void 0===n?void 0:n.split("auth/")[1])||"internal-error";t.onError(y(this.auth,r))}else t.onAuthEvent(e)}isEventForConsumer(e,t){let n=null===t.eventId||!!e.eventId&&e.eventId===t.eventId;return t.filter.includes(e.type)&&n}hasEventBeenHandled(e){return Date.now()-this.lastProcessedEventTime>=6e5&&this.cachedEventUids.clear(),this.cachedEventUids.has(n0(e))}saveEventToCache(e){this.cachedEventUids.add(n0(e)),this.lastProcessedEventTime=Date.now()}}function n0(e){return[e.type,e.eventId,e.sessionId,e.tenantId].filter(e=>e).join("-")}function n1({type:e,error:t}){return"unknown"===e&&(null==t?void 0:t.code)==="auth/no-auth-event"}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function n2(e,t={}){return L(e,"GET","/v1/projects",t)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let n3=/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/,n4=/^https?/;async function n6(e){if(e.config.emulator)return;let{authorizedDomains:t}=await n2(e);for(let n of t)try{if(function(e){let t=k(),{protocol:n,hostname:r}=new URL(t);if(e.startsWith("chrome-extension://")){let i=new URL(e);return""===i.hostname&&""===r?"chrome-extension:"===n&&e.replace("chrome-extension://","")===t.replace("chrome-extension://",""):"chrome-extension:"===n&&i.hostname===r}if(!n4.test(n))return!1;if(n3.test(e))return r===e;let s=e.replace(/\./g,"\\."),o=RegExp("^(.+\\."+s+"|"+s+")$","i");return o.test(r)}(n))return}catch(r){}g(e,"unauthorized-domain")}/**
 * @license
 * Copyright 2020 Google LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let n5=new N(3e4,6e4);function n8(){let e=t2().___jsl;if(null==e?void 0:e.H){for(let t of Object.keys(e.H))if(e.H[t].r=e.H[t].r||[],e.H[t].L=e.H[t].L||[],e.H[t].r=[...e.H[t].L],e.CP)for(let n=0;n<e.CP.length;n++)e.CP[n]=null}}let n9=null,n7=new N(5e3,15e3),re={style:{position:"absolute",top:"-100px",width:"1px",height:"1px"},"aria-hidden":"true",tabindex:"-1"},rt=new Map([["identitytoolkit.googleapis.com","p"],["staging-identitytoolkit.sandbox.googleapis.com","s"],["test-identitytoolkit.sandbox.googleapis.com","t"]]);async function rn(e){let t=await (n9=n9||new Promise((t,n)=>{var r,i,s;function o(){n8(),gapi.load("gapi.iframes",{callback:()=>{t(gapi.iframes.getContext())},ontimeout:()=>{n8(),n(y(e,"network-request-failed"))},timeout:n5.get()})}if(null===(i=null===(r=t2().gapi)||void 0===r?void 0:r.iframes)||void 0===i?void 0:i.Iframe)t(gapi.iframes.getContext());else if(null===(s=t2().gapi)||void 0===s?void 0:s.load)o();else{let a=nl("iframefcb");return t2()[a]=()=>{gapi.load?o():n(y(e,"network-request-failed"))},na(`https://apis.google.com/js/api.js?onload=${a}`).catch(e=>n(e))}}).catch(e=>{throw n9=null,e})),n=t2().gapi;return b(n,e,"internal-error"),t.open({where:document.body,url:function(e){let t=e.config;b(t.authDomain,e,"auth-domain-config-required");let n=t.emulator?A(t,"emulator/auth/iframe"):`https://${e.config.authDomain}/__/auth/iframe`,r={apiKey:t.apiKey,appName:e.name,v:s.SDK_VERSION},o=rt.get(e.config.apiHost);o&&(r.eid=o);let a=e._getFrameworks();return a.length&&(r.fw=a.join(",")),`${n}?${(0,i.xO)(r).slice(1)}`}(e),messageHandlersFilter:n.iframes.CROSS_ORIGIN_IFRAMES_FILTER,attributes:re,dontclear:!0},t=>new Promise(async(n,r)=>{await t.restyle({setHideOnLeave:!1});let i=y(e,"network-request-failed"),s=t2().setTimeout(()=>{r(i)},n7.get());function o(){t2().clearTimeout(s),n(t)}t.ping(o).then(o,()=>{r(i)})}))}/**
 * @license
 * Copyright 2020 Google LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let rr={location:"yes",resizable:"yes",statusbar:"yes",toolbar:"no"};class ri{constructor(e){this.window=e,this.associatedEvent=null}close(){if(this.window)try{this.window.close()}catch(e){}}}function rs(e,t,n,r,o,a){b(e.config.authDomain,e,"auth-domain-config-required"),b(e.config.apiKey,e,"invalid-api-key");let l={apiKey:e.config.apiKey,appName:e.name,authType:n,redirectUrl:r,v:s.SDK_VERSION,eventId:o};if(t instanceof eQ)for(let[u,c]of(t.setDefaultLanguage(e.languageCode),l.providerId=t.providerId||"",(0,i.xb)(t.getCustomParameters())||(l.customParameters=JSON.stringify(t.getCustomParameters())),Object.entries(a||{})))l[u]=c;if(t instanceof eY){let h=t.getScopes().filter(e=>""!==e);h.length>0&&(l.scopes=h.join(","))}e.tenantId&&(l.tid=e.tenantId);let d=l;for(let f of Object.keys(d))void 0===d[f]&&delete d[f];return`${function({config:e}){return e.emulator?A(e,"emulator/auth/handler"):`https://${e.authDomain}/__/auth/handler`}(e)}?${(0,i.xO)(d).slice(1)}`}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let ro="webStorageSupport",ra=class{constructor(){this.eventManagers={},this.iframes={},this.originValidationPromises={},this._redirectPersistence=tJ,this._completeRedirectFn=nX,this._overrideRedirectResult=nq}async _openPopup(e,t,n,r){var s;T(null===(s=this.eventManagers[e._key()])||void 0===s?void 0:s.manager,"_initialize() not called before _openPopup()");let o=rs(e,t,n,k(),r);return function(e,t,n,r=500,s=600){let o=Math.max((window.screen.availHeight-s)/2,0).toString(),a=Math.max((window.screen.availWidth-r)/2,0).toString(),l="",u=Object.assign(Object.assign({},rr),{width:r.toString(),height:s.toString(),top:o,left:a}),c=(0,i.z$)().toLowerCase();n&&(l=ec(c)?"_blank":n),el(c)&&(t=t||"http://localhost",u.scrollbars="yes");let h=Object.entries(u).reduce((e,[t,n])=>`${e}${t}=${n},`,"");if(function(e=(0,i.z$)()){var t;return em(e)&&!!(null===(t=window.navigator)||void 0===t?void 0:t.standalone)}(c)&&"_self"!==l)return function(e,t){let n=document.createElement("a");n.href=e,n.target=t;let r=document.createEvent("MouseEvent");r.initMouseEvent("click",!0,!0,window,1,0,0,0,0,!1,!1,!1,!1,1,null),n.dispatchEvent(r)}(t||"",l),new ri(null);let d=window.open(t||"",l,h);b(d,e,"popup-blocked");try{d.focus()}catch(f){}return new ri(d)}(e,o,t0())}async _openRedirect(e,t,n,r){var i;return await this._originValidation(e),i=rs(e,t,n,k(),r),t2().location.href=i,new Promise(()=>{})}_initialize(e){let t=e._key();if(this.eventManagers[t]){let{manager:n,promise:r}=this.eventManagers[t];return n?Promise.resolve(n):(T(r,"If manager is not set, promise should be"),r)}let i=this.initAndGetManager(e);return this.eventManagers[t]={promise:i},i.catch(()=>{delete this.eventManagers[t]}),i}async initAndGetManager(e){let t=await rn(e),n=new nZ(e);return t.register("authEvent",t=>{b(null==t?void 0:t.authEvent,e,"invalid-auth-event");let r=n.onEvent(t.authEvent);return{status:r?"ACK":"ERROR"}},gapi.iframes.CROSS_ORIGIN_IFRAMES_FILTER),this.eventManagers[e._key()]={manager:n},this.iframes[e._key()]=t,n}_isIframeWebStorageSupported(e,t){let n=this.iframes[e._key()];n.send(ro,{type:ro},n=>{var r;let i=null===(r=null==n?void 0:n[0])||void 0===r?void 0:r[ro];void 0!==i&&t(!!i),g(e,"internal-error")},gapi.iframes.CROSS_ORIGIN_IFRAMES_FILTER)}_originValidation(e){let t=e._key();return this.originValidationPromises[t]||(this.originValidationPromises[t]=n6(e)),this.originValidationPromises[t]}get _shouldInitProactively(){return ey()||eu()||em()}};class rl{constructor(e){this.factorId=e}_process(e,t,n){switch(t.type){case"enroll":return this._finalizeEnroll(e,t.credential,n);case"signin":return this._finalizeSignIn(e,t.credential);default:return I("unexpected MultiFactorSessionType")}}}class ru extends rl{constructor(e){super("phone"),this.credential=e}static _fromCredential(e){return new ru(e)}_finalizeEnroll(e,t,n){return L(e,"POST","/v2/accounts/mfaEnrollment:finalize",P(e,{idToken:t,displayName:n,phoneVerificationInfo:this.credential._makeVerificationRequest()}))}_finalizeSignIn(e,t){return L(e,"POST","/v2/accounts/mfaSignIn:finalize",P(e,{mfaPendingCredential:t,phoneVerificationInfo:this.credential._makeVerificationRequest()}))}}class rc{constructor(){}static assertion(e){return ru._fromCredential(e)}}rc.FACTOR_ID="phone";var rh="@firebase/auth",rd="0.20.10";/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class rf{constructor(e){this.auth=e,this.internalListeners=new Map}getUid(){var e;return this.assertAuthConfigured(),(null===(e=this.auth.currentUser)||void 0===e?void 0:e.uid)||null}async getToken(e){if(this.assertAuthConfigured(),await this.auth._initializationPromise,!this.auth.currentUser)return null;let t=await this.auth.currentUser.getIdToken(e);return{accessToken:t}}addAuthTokenListener(e){if(this.assertAuthConfigured(),this.internalListeners.has(e))return;let t=this.auth.onIdTokenChanged(t=>{e((null==t?void 0:t.stsTokenManager.accessToken)||null)});this.internalListeners.set(e,t),this.updateProactiveRefresh()}removeAuthTokenListener(e){this.assertAuthConfigured();let t=this.internalListeners.get(e);t&&(this.internalListeners.delete(e),t(),this.updateProactiveRefresh())}assertAuthConfigured(){b(this.auth._initializationPromise,"dependent-sdk-initialized-before-auth")}updateProactiveRefresh(){this.internalListeners.size>0?this.auth._startProactiveRefresh():this.auth._stopProactiveRefresh()}}(0,i.Pz)("authIdTokenMaxAge"),r="Browser",(0,s._registerComponent)(new l.wA("auth",(e,{options:t})=>{let n=e.getProvider("app").getImmediate(),i=e.getProvider("heartbeat"),{apiKey:s,authDomain:o}=n.options;return((e,n)=>{b(s&&!s.includes(":"),"invalid-api-key",{appName:e.name}),b(!(null==o?void 0:o.includes(":")),"argument-error",{appName:e.name});let i={apiKey:s,authDomain:o,clientPlatform:r,apiHost:"identitytoolkit.googleapis.com",tokenApiHost:"securetoken.googleapis.com",apiScheme:"https",sdkClientVersion:ev(r)},a=new ew(e,n,i);return function(e,t){let n=(null==t?void 0:t.persistence)||[],r=(Array.isArray(n)?n:[n]).map(S);(null==t?void 0:t.errorMap)&&e._updateErrorMap(t.errorMap),e._initializeWithPersistence(r,null==t?void 0:t.popupRedirectResolver)}(a,t),a})(n,i)},"PUBLIC").setInstantiationMode("EXPLICIT").setInstanceCreatedCallback((e,t,n)=>{let r=e.getProvider("auth-internal");r.initialize()})),(0,s._registerComponent)(new l.wA("auth-internal",e=>{let t=eb(e.getProvider("auth").getImmediate());return new rf(t)},"PRIVATE").setInstantiationMode("EXPLICIT")),(0,s.registerVersion)(rh,rd,/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function(e){switch(e){case"Node":return"node";case"ReactNative":return"rn";case"Worker":return"webworker";case"Cordova":return"cordova";default:return}}(r)),(0,s.registerVersion)(rh,rd,"esm2017")},4444:function(e,t,n){"use strict";n.d(t,{BH:function(){return P},DV:function(){return G},G6:function(){return T},GJ:function(){return $},L:function(){return h},LL:function(){return j},P0:function(){return R},Pz:function(){return O},Sg:function(){return L},UG:function(){return y},UI:function(){return H},US:function(){return u},Wl:function(){return V},Yr:function(){return I},ZB:function(){return p},ZR:function(){return M},aH:function(){return D},b$:function(){return w},cI:function(){return U},dS:function(){return er},eu:function(){return S},g5:function(){return o},gK:function(){return en},gQ:function(){return J},h$:function(){return c},hl:function(){return E},hu:function(){return s},jU:function(){return v},m9:function(){return es},ne:function(){return Z},p$:function(){return f},pd:function(){return X},r3:function(){return z},ru:function(){return _},tV:function(){return d},uI:function(){return g},ug:function(){return ei},vZ:function(){return function e(t,n){if(t===n)return!0;let r=Object.keys(t),i=Object.keys(n);for(let s of r){if(!i.includes(s))return!1;let o=t[s],a=n[s];if(K(o)&&K(a)){if(!e(o,a))return!1}else if(o!==a)return!1}for(let l of i)if(!r.includes(l))return!1;return!0}},w1:function(){return b},w9:function(){return B},xO:function(){return Q},xb:function(){return W},z$:function(){return m},zd:function(){return Y}});var r=n(3454);/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let i={NODE_CLIENT:!1,NODE_ADMIN:!1,SDK_VERSION:"${JSCORE_VERSION}"},s=function(e,t){if(!e)throw o(t)},o=function(e){return Error("Firebase Database ("+i.SDK_VERSION+") INTERNAL ASSERT FAILED: "+e)},a=function(e){let t=[],n=0;for(let r=0;r<e.length;r++){let i=e.charCodeAt(r);i<128?t[n++]=i:i<2048?(t[n++]=i>>6|192,t[n++]=63&i|128):(64512&i)==55296&&r+1<e.length&&(64512&e.charCodeAt(r+1))==56320?(i=65536+((1023&i)<<10)+(1023&e.charCodeAt(++r)),t[n++]=i>>18|240,t[n++]=i>>12&63|128,t[n++]=i>>6&63|128,t[n++]=63&i|128):(t[n++]=i>>12|224,t[n++]=i>>6&63|128,t[n++]=63&i|128)}return t},l=function(e){let t=[],n=0,r=0;for(;n<e.length;){let i=e[n++];if(i<128)t[r++]=String.fromCharCode(i);else if(i>191&&i<224){let s=e[n++];t[r++]=String.fromCharCode((31&i)<<6|63&s)}else if(i>239&&i<365){let o=e[n++],a=e[n++],l=e[n++],u=((7&i)<<18|(63&o)<<12|(63&a)<<6|63&l)-65536;t[r++]=String.fromCharCode(55296+(u>>10)),t[r++]=String.fromCharCode(56320+(1023&u))}else{let c=e[n++],h=e[n++];t[r++]=String.fromCharCode((15&i)<<12|(63&c)<<6|63&h)}}return t.join("")},u={byteToCharMap_:null,charToByteMap_:null,byteToCharMapWebSafe_:null,charToByteMapWebSafe_:null,ENCODED_VALS_BASE:"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",get ENCODED_VALS(){return this.ENCODED_VALS_BASE+"+/="},get ENCODED_VALS_WEBSAFE(){return this.ENCODED_VALS_BASE+"-_."},HAS_NATIVE_SUPPORT:"function"==typeof atob,encodeByteArray(e,t){if(!Array.isArray(e))throw Error("encodeByteArray takes an array as a parameter");this.init_();let n=t?this.byteToCharMapWebSafe_:this.byteToCharMap_,r=[];for(let i=0;i<e.length;i+=3){let s=e[i],o=i+1<e.length,a=o?e[i+1]:0,l=i+2<e.length,u=l?e[i+2]:0,c=s>>2,h=(3&s)<<4|a>>4,d=(15&a)<<2|u>>6,f=63&u;l||(f=64,o||(d=64)),r.push(n[c],n[h],n[d],n[f])}return r.join("")},encodeString(e,t){return this.HAS_NATIVE_SUPPORT&&!t?btoa(e):this.encodeByteArray(a(e),t)},decodeString(e,t){return this.HAS_NATIVE_SUPPORT&&!t?atob(e):l(this.decodeStringToByteArray(e,t))},decodeStringToByteArray(e,t){this.init_();let n=t?this.charToByteMapWebSafe_:this.charToByteMap_,r=[];for(let i=0;i<e.length;){let s=n[e.charAt(i++)],o=i<e.length,a=o?n[e.charAt(i)]:0;++i;let l=i<e.length,u=l?n[e.charAt(i)]:64;++i;let c=i<e.length,h=c?n[e.charAt(i)]:64;if(++i,null==s||null==a||null==u||null==h)throw Error();let d=s<<2|a>>4;if(r.push(d),64!==u){let f=a<<4&240|u>>2;if(r.push(f),64!==h){let p=u<<6&192|h;r.push(p)}}}return r},init_(){if(!this.byteToCharMap_){this.byteToCharMap_={},this.charToByteMap_={},this.byteToCharMapWebSafe_={},this.charToByteMapWebSafe_={};for(let e=0;e<this.ENCODED_VALS.length;e++)this.byteToCharMap_[e]=this.ENCODED_VALS.charAt(e),this.charToByteMap_[this.byteToCharMap_[e]]=e,this.byteToCharMapWebSafe_[e]=this.ENCODED_VALS_WEBSAFE.charAt(e),this.charToByteMapWebSafe_[this.byteToCharMapWebSafe_[e]]=e,e>=this.ENCODED_VALS_BASE.length&&(this.charToByteMap_[this.ENCODED_VALS_WEBSAFE.charAt(e)]=e,this.charToByteMapWebSafe_[this.ENCODED_VALS.charAt(e)]=e)}}},c=function(e){let t=a(e);return u.encodeByteArray(t,!0)},h=function(e){return c(e).replace(/\./g,"")},d=function(e){try{return u.decodeString(e,!0)}catch(t){console.error("base64Decode failed: ",t)}return null};/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function f(e){return p(void 0,e)}function p(e,t){if(!(t instanceof Object))return t;switch(t.constructor){case Date:return new Date(t.getTime());case Object:void 0===e&&(e={});break;case Array:e=[];break;default:return t}for(let n in t)t.hasOwnProperty(n)&&"__proto__"!==n&&(e[n]=p(e[n],t[n]));return e}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function m(){return"undefined"!=typeof navigator&&"string"==typeof navigator.userAgent?navigator.userAgent:""}function g(){return"undefined"!=typeof window&&!!(window.cordova||window.phonegap||window.PhoneGap)&&/ios|iphone|ipod|ipad|android|blackberry|iemobile/i.test(m())}function y(){try{return"[object process]"===Object.prototype.toString.call(n.g.process)}catch(e){return!1}}function v(){return"object"==typeof self&&self.self===self}function _(){let e="object"==typeof chrome?chrome.runtime:"object"==typeof browser?browser.runtime:void 0;return"object"==typeof e&&void 0!==e.id}function w(){return"object"==typeof navigator&&"ReactNative"===navigator.product}function b(){let e=m();return e.indexOf("MSIE ")>=0||e.indexOf("Trident/")>=0}function I(){return!0===i.NODE_CLIENT||!0===i.NODE_ADMIN}function T(){return!y()&&navigator.userAgent.includes("Safari")&&!navigator.userAgent.includes("Chrome")}function E(){return"object"==typeof indexedDB}function S(){return new Promise((e,t)=>{try{let n=!0,r="validate-browser-context-for-indexeddb-analytics-module",i=self.indexedDB.open(r);i.onsuccess=()=>{i.result.close(),n||self.indexedDB.deleteDatabase(r),e(!0)},i.onupgradeneeded=()=>{n=!1},i.onerror=()=>{var e;t((null===(e=i.error)||void 0===e?void 0:e.message)||"")}}catch(s){t(s)}})}/**
 * @license
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let k=()=>(function(){if("undefined"!=typeof self)return self;if("undefined"!=typeof window)return window;if(void 0!==n.g)return n.g;throw Error("Unable to locate global object.")})().__FIREBASE_DEFAULTS__,x=()=>{if(void 0===r||void 0===r.env)return;let e=r.env.__FIREBASE_DEFAULTS__;if(e)return JSON.parse(e)},C=()=>{let e;if("undefined"==typeof document)return;try{e=document.cookie.match(/__FIREBASE_DEFAULTS__=([^;]+)/)}catch(t){return}let n=e&&d(e[1]);return n&&JSON.parse(n)},N=()=>{try{return k()||x()||C()}catch(e){console.info(`Unable to get __FIREBASE_DEFAULTS__ due to: ${e}`);return}},A=e=>{var t,n;return null===(n=null===(t=N())||void 0===t?void 0:t.emulatorHosts)||void 0===n?void 0:n[e]},R=e=>{let t=A(e);if(!t)return;let n=t.lastIndexOf(":");if(n<=0||n+1===t.length)throw Error(`Invalid host ${t} with no separate hostname and port!`);let r=parseInt(t.substring(n+1),10);return"["===t[0]?[t.substring(1,n-1),r]:[t.substring(0,n),r]},D=()=>{var e;return null===(e=N())||void 0===e?void 0:e.config},O=e=>{var t;return null===(t=N())||void 0===t?void 0:t[`_${e}`]};/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class P{constructor(){this.reject=()=>{},this.resolve=()=>{},this.promise=new Promise((e,t)=>{this.resolve=e,this.reject=t})}wrapCallback(e){return(t,n)=>{t?this.reject(t):this.resolve(n),"function"==typeof e&&(this.promise.catch(()=>{}),1===e.length?e(t):e(t,n))}}}/**
 * @license
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function L(e,t){if(e.uid)throw Error('The "uid" field is no longer supported by mockUserToken. Please use "sub" instead for Firebase Auth User ID.');let n=t||"demo-project",r=e.iat||0,i=e.sub||e.user_id;if(!i)throw Error("mockUserToken must contain 'sub' or 'user_id' field!");let s=Object.assign({iss:`https://securetoken.google.com/${n}`,aud:n,iat:r,exp:r+3600,auth_time:r,sub:i,user_id:i,firebase:{sign_in_provider:"custom",identities:{}}},e);return[h(JSON.stringify({alg:"none",type:"JWT"})),h(JSON.stringify(s)),""].join(".")}class M extends Error{constructor(e,t,n){super(t),this.code=e,this.customData=n,this.name="FirebaseError",Object.setPrototypeOf(this,M.prototype),Error.captureStackTrace&&Error.captureStackTrace(this,j.prototype.create)}}class j{constructor(e,t,n){this.service=e,this.serviceName=t,this.errors=n}create(e,...t){let n=t[0]||{},r=`${this.service}/${e}`,i=this.errors[e],s=i?i.replace(F,(e,t)=>{let r=n[t];return null!=r?String(r):`<${t}?>`}):"Error",o=`${this.serviceName}: ${s} (${r}).`,a=new M(r,o,n);return a}}let F=/\{\$([^}]+)}/g;/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function U(e){return JSON.parse(e)}function V(e){return JSON.stringify(e)}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let q=function(e){let t={},n={},r={},i="";try{let s=e.split(".");t=U(d(s[0])||""),n=U(d(s[1])||""),i=s[2],r=n.d||{},delete n.d}catch(o){}return{header:t,claims:n,data:r,signature:i}},B=function(e){let t=q(e),n=t.claims;return!!n&&"object"==typeof n&&n.hasOwnProperty("iat")},$=function(e){let t=q(e).claims;return"object"==typeof t&&!0===t.admin};/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function z(e,t){return Object.prototype.hasOwnProperty.call(e,t)}function G(e,t){return Object.prototype.hasOwnProperty.call(e,t)?e[t]:void 0}function W(e){for(let t in e)if(Object.prototype.hasOwnProperty.call(e,t))return!1;return!0}function H(e,t,n){let r={};for(let i in e)Object.prototype.hasOwnProperty.call(e,i)&&(r[i]=t.call(n,e[i],i,e));return r}function K(e){return null!==e&&"object"==typeof e}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function Q(e){let t=[];for(let[n,r]of Object.entries(e))Array.isArray(r)?r.forEach(e=>{t.push(encodeURIComponent(n)+"="+encodeURIComponent(e))}):t.push(encodeURIComponent(n)+"="+encodeURIComponent(r));return t.length?"&"+t.join("&"):""}function Y(e){let t={},n=e.replace(/^\?/,"").split("&");return n.forEach(e=>{if(e){let[n,r]=e.split("=");t[decodeURIComponent(n)]=decodeURIComponent(r)}}),t}function X(e){let t=e.indexOf("?");if(!t)return"";let n=e.indexOf("#",t);return e.substring(t,n>0?n:void 0)}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class J{constructor(){this.chain_=[],this.buf_=[],this.W_=[],this.pad_=[],this.inbuf_=0,this.total_=0,this.blockSize=64,this.pad_[0]=128;for(let e=1;e<this.blockSize;++e)this.pad_[e]=0;this.reset()}reset(){this.chain_[0]=1732584193,this.chain_[1]=4023233417,this.chain_[2]=2562383102,this.chain_[3]=271733878,this.chain_[4]=3285377520,this.inbuf_=0,this.total_=0}compress_(e,t){let n,r;t||(t=0);let i=this.W_;if("string"==typeof e)for(let s=0;s<16;s++)i[s]=e.charCodeAt(t)<<24|e.charCodeAt(t+1)<<16|e.charCodeAt(t+2)<<8|e.charCodeAt(t+3),t+=4;else for(let o=0;o<16;o++)i[o]=e[t]<<24|e[t+1]<<16|e[t+2]<<8|e[t+3],t+=4;for(let a=16;a<80;a++){let l=i[a-3]^i[a-8]^i[a-14]^i[a-16];i[a]=(l<<1|l>>>31)&4294967295}let u=this.chain_[0],c=this.chain_[1],h=this.chain_[2],d=this.chain_[3],f=this.chain_[4];for(let p=0;p<80;p++){p<40?p<20?(n=d^c&(h^d),r=1518500249):(n=c^h^d,r=1859775393):p<60?(n=c&h|d&(c|h),r=2400959708):(n=c^h^d,r=3395469782);let m=(u<<5|u>>>27)+n+f+r+i[p]&4294967295;f=d,d=h,h=(c<<30|c>>>2)&4294967295,c=u,u=m}this.chain_[0]=this.chain_[0]+u&4294967295,this.chain_[1]=this.chain_[1]+c&4294967295,this.chain_[2]=this.chain_[2]+h&4294967295,this.chain_[3]=this.chain_[3]+d&4294967295,this.chain_[4]=this.chain_[4]+f&4294967295}update(e,t){if(null==e)return;void 0===t&&(t=e.length);let n=t-this.blockSize,r=0,i=this.buf_,s=this.inbuf_;for(;r<t;){if(0===s)for(;r<=n;)this.compress_(e,r),r+=this.blockSize;if("string"==typeof e){for(;r<t;)if(i[s]=e.charCodeAt(r),++s,++r,s===this.blockSize){this.compress_(i),s=0;break}}else for(;r<t;)if(i[s]=e[r],++s,++r,s===this.blockSize){this.compress_(i),s=0;break}}this.inbuf_=s,this.total_+=t}digest(){let e=[],t=8*this.total_;this.inbuf_<56?this.update(this.pad_,56-this.inbuf_):this.update(this.pad_,this.blockSize-(this.inbuf_-56));for(let n=this.blockSize-1;n>=56;n--)this.buf_[n]=255&t,t/=256;this.compress_(this.buf_);let r=0;for(let i=0;i<5;i++)for(let s=24;s>=0;s-=8)e[r]=this.chain_[i]>>s&255,++r;return e}}function Z(e,t){let n=new ee(e,t);return n.subscribe.bind(n)}class ee{constructor(e,t){this.observers=[],this.unsubscribes=[],this.observerCount=0,this.task=Promise.resolve(),this.finalized=!1,this.onNoObservers=t,this.task.then(()=>{e(this)}).catch(e=>{this.error(e)})}next(e){this.forEachObserver(t=>{t.next(e)})}error(e){this.forEachObserver(t=>{t.error(e)}),this.close(e)}complete(){this.forEachObserver(e=>{e.complete()}),this.close()}subscribe(e,t,n){let r;if(void 0===e&&void 0===t&&void 0===n)throw Error("Missing Observer.");void 0===(r=!function(e,t){if("object"!=typeof e||null===e)return!1;for(let n of t)if(n in e&&"function"==typeof e[n])return!0;return!1}(e,["next","error","complete"])?{next:e,error:t,complete:n}:e).next&&(r.next=et),void 0===r.error&&(r.error=et),void 0===r.complete&&(r.complete=et);let i=this.unsubscribeOne.bind(this,this.observers.length);return this.finalized&&this.task.then(()=>{try{this.finalError?r.error(this.finalError):r.complete()}catch(e){}}),this.observers.push(r),i}unsubscribeOne(e){void 0!==this.observers&&void 0!==this.observers[e]&&(delete this.observers[e],this.observerCount-=1,0===this.observerCount&&void 0!==this.onNoObservers&&this.onNoObservers(this))}forEachObserver(e){if(!this.finalized)for(let t=0;t<this.observers.length;t++)this.sendOne(t,e)}sendOne(e,t){this.task.then(()=>{if(void 0!==this.observers&&void 0!==this.observers[e])try{t(this.observers[e])}catch(n){"undefined"!=typeof console&&console.error&&console.error(n)}})}close(e){this.finalized||(this.finalized=!0,void 0!==e&&(this.finalError=e),this.task.then(()=>{this.observers=void 0,this.onNoObservers=void 0}))}}function et(){}function en(e,t){return`${e} failed: ${t} argument `}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let er=function(e){let t=[],n=0;for(let r=0;r<e.length;r++){let i=e.charCodeAt(r);if(i>=55296&&i<=56319){let o=i-55296;s(++r<e.length,"Surrogate pair missing trail surrogate.");let a=e.charCodeAt(r)-56320;i=65536+(o<<10)+a}i<128?t[n++]=i:i<2048?(t[n++]=i>>6|192,t[n++]=63&i|128):i<65536?(t[n++]=i>>12|224,t[n++]=i>>6&63|128,t[n++]=63&i|128):(t[n++]=i>>18|240,t[n++]=i>>12&63|128,t[n++]=i>>6&63|128,t[n++]=63&i|128)}return t},ei=function(e){let t=0;for(let n=0;n<e.length;n++){let r=e.charCodeAt(n);r<128?t++:r<2048?t+=2:r>=55296&&r<=56319?(t+=4,n++):t+=3}return t};/**
 * @license
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function es(e){return e&&e._delegate?e._delegate:e}},4184:function(e,t){var n;/*!
	Copyright (c) 2018 Jed Watson.
	Licensed under the MIT License (MIT), see
	http://jedwatson.github.io/classnames
*/!function(){"use strict";var r={}.hasOwnProperty;function i(){for(var e=[],t=0;t<arguments.length;t++){var n=arguments[t];if(n){var s=typeof n;if("string"===s||"number"===s)e.push(n);else if(Array.isArray(n)){if(n.length){var o=i.apply(null,n);o&&e.push(o)}}else if("object"===s){if(n.toString!==Object.prototype.toString&&!n.toString.toString().includes("[native code]")){e.push(n.toString());continue}for(var a in n)r.call(n,a)&&n[a]&&e.push(a)}}}return e.join(" ")}e.exports?(i.default=i,e.exports=i):void 0!==(n=(function(){return i}).apply(t,[]))&&(e.exports=n)}()},2175:function(e,t,n){"use strict";n.d(t,{Bc:function(){return nT},gN:function(){return ng},l0:function(){return ny},J9:function(){return nd}});var r,i,s,o,a,l,u=n(7294),c=n(9590),h=n.n(c),d=function(e){var t;return!!e&&"object"==typeof e&&"[object RegExp]"!==(t=Object.prototype.toString.call(e))&&"[object Date]"!==t&&e.$$typeof!==f},f="function"==typeof Symbol&&Symbol.for?Symbol.for("react.element"):60103;function p(e,t){return!1!==t.clone&&t.isMergeableObject(e)?g(Array.isArray(e)?[]:{},e,t):e}function m(e,t,n){return e.concat(t).map(function(e){return p(e,n)})}function g(e,t,n){(n=n||{}).arrayMerge=n.arrayMerge||m,n.isMergeableObject=n.isMergeableObject||d;var r,i,s=Array.isArray(t);return s!==Array.isArray(e)?p(t,n):s?n.arrayMerge(e,t,n):(i={},(r=n).isMergeableObject(e)&&Object.keys(e).forEach(function(t){i[t]=p(e[t],r)}),Object.keys(t).forEach(function(n){r.isMergeableObject(t[n])&&e[n]?i[n]=g(e[n],t[n],r):i[n]=p(t[n],r)}),i)}g.all=function(e,t){if(!Array.isArray(e))throw Error("first argument should be an array");return e.reduce(function(e,n){return g(e,n,t)},{})};var y=g,v="object"==typeof global&&global&&global.Object===Object&&global,_="object"==typeof self&&self&&self.Object===Object&&self,w=v||_||Function("return this")(),b=w.Symbol,I=Object.prototype,T=I.hasOwnProperty,E=I.toString,S=b?b.toStringTag:void 0,k=function(e){var t=T.call(e,S),n=e[S];try{e[S]=void 0;var r=!0}catch(i){}var s=E.call(e);return r&&(t?e[S]=n:delete e[S]),s},x=Object.prototype.toString,C=b?b.toStringTag:void 0,N=function(e){return null==e?void 0===e?"[object Undefined]":"[object Null]":C&&C in Object(e)?k(e):x.call(e)},A=function(e,t){return function(n){return e(t(n))}},R=A(Object.getPrototypeOf,Object),D=function(e){return null!=e&&"object"==typeof e},O=Object.prototype,P=Function.prototype.toString,L=O.hasOwnProperty,M=P.call(Object),j=function(e){if(!D(e)||"[object Object]"!=N(e))return!1;var t=R(e);if(null===t)return!0;var n=L.call(t,"constructor")&&t.constructor;return"function"==typeof n&&n instanceof n&&P.call(n)==M},F=function(e,t){return e===t||e!=e&&t!=t},U=function(e,t){for(var n=e.length;n--;)if(F(e[n][0],t))return n;return -1},V=Array.prototype.splice;function q(e){var t=-1,n=null==e?0:e.length;for(this.clear();++t<n;){var r=e[t];this.set(r[0],r[1])}}q.prototype.clear=function(){this.__data__=[],this.size=0},q.prototype.delete=function(e){var t=this.__data__,n=U(t,e);return!(n<0)&&(n==t.length-1?t.pop():V.call(t,n,1),--this.size,!0)},q.prototype.get=function(e){var t=this.__data__,n=U(t,e);return n<0?void 0:t[n][1]},q.prototype.has=function(e){return U(this.__data__,e)>-1},q.prototype.set=function(e,t){var n=this.__data__,r=U(n,e);return r<0?(++this.size,n.push([e,t])):n[r][1]=t,this};var B=function(e){var t=typeof e;return null!=e&&("object"==t||"function"==t)},$=function(e){if(!B(e))return!1;var t=N(e);return"[object Function]"==t||"[object GeneratorFunction]"==t||"[object AsyncFunction]"==t||"[object Proxy]"==t},z=w["__core-js_shared__"],G=(r=/[^.]+$/.exec(z&&z.keys&&z.keys.IE_PROTO||""))?"Symbol(src)_1."+r:"",W=Function.prototype.toString,H=function(e){if(null!=e){try{return W.call(e)}catch(t){}try{return e+""}catch(n){}}return""},K=/^\[object .+?Constructor\]$/,Q=Object.prototype,Y=Function.prototype.toString,X=Q.hasOwnProperty,J=RegExp("^"+Y.call(X).replace(/[\\^$.*+?()[\]{}|]/g,"\\$&").replace(/hasOwnProperty|(function).*?(?=\\\()| for .+?(?=\\\])/g,"$1.*?")+"$"),Z=function(e,t){var n,r=null==e?void 0:e[t];return B(n=r)&&(!G||!(G in n))&&($(n)?J:K).test(H(n))?r:void 0},ee=Z(w,"Map"),et=Z(Object,"create"),en=Object.prototype.hasOwnProperty,er=Object.prototype.hasOwnProperty;function ei(e){var t=-1,n=null==e?0:e.length;for(this.clear();++t<n;){var r=e[t];this.set(r[0],r[1])}}ei.prototype.clear=function(){this.__data__=et?et(null):{},this.size=0},ei.prototype.delete=function(e){var t=this.has(e)&&delete this.__data__[e];return this.size-=t?1:0,t},ei.prototype.get=function(e){var t=this.__data__;if(et){var n=t[e];return"__lodash_hash_undefined__"===n?void 0:n}return en.call(t,e)?t[e]:void 0},ei.prototype.has=function(e){var t=this.__data__;return et?void 0!==t[e]:er.call(t,e)},ei.prototype.set=function(e,t){var n=this.__data__;return this.size+=this.has(e)?0:1,n[e]=et&&void 0===t?"__lodash_hash_undefined__":t,this};var es=function(e){var t=typeof e;return"string"==t||"number"==t||"symbol"==t||"boolean"==t?"__proto__"!==e:null===e},eo=function(e,t){var n=e.__data__;return es(t)?n["string"==typeof t?"string":"hash"]:n.map};function ea(e){var t=-1,n=null==e?0:e.length;for(this.clear();++t<n;){var r=e[t];this.set(r[0],r[1])}}function el(e){var t=this.__data__=new q(e);this.size=t.size}ea.prototype.clear=function(){this.size=0,this.__data__={hash:new ei,map:new(ee||q),string:new ei}},ea.prototype.delete=function(e){var t=eo(this,e).delete(e);return this.size-=t?1:0,t},ea.prototype.get=function(e){return eo(this,e).get(e)},ea.prototype.has=function(e){return eo(this,e).has(e)},ea.prototype.set=function(e,t){var n=eo(this,e),r=n.size;return n.set(e,t),this.size+=n.size==r?0:1,this},el.prototype.clear=function(){this.__data__=new q,this.size=0},el.prototype.delete=function(e){var t=this.__data__,n=t.delete(e);return this.size=t.size,n},el.prototype.get=function(e){return this.__data__.get(e)},el.prototype.has=function(e){return this.__data__.has(e)},el.prototype.set=function(e,t){var n=this.__data__;if(n instanceof q){var r=n.__data__;if(!ee||r.length<199)return r.push([e,t]),this.size=++n.size,this;n=this.__data__=new ea(r)}return n.set(e,t),this.size=n.size,this};var eu=function(e,t){for(var n=-1,r=null==e?0:e.length;++n<r&&!1!==t(e[n],n,e););return e},ec=function(){try{var e=Z(Object,"defineProperty");return e({},"",{}),e}catch(t){}}(),eh=function(e,t,n){"__proto__"==t&&ec?ec(e,t,{configurable:!0,enumerable:!0,value:n,writable:!0}):e[t]=n},ed=Object.prototype.hasOwnProperty,ef=function(e,t,n){var r=e[t];ed.call(e,t)&&F(r,n)&&(void 0!==n||t in e)||eh(e,t,n)},ep=function(e,t,n,r){var i=!n;n||(n={});for(var s=-1,o=t.length;++s<o;){var a=t[s],l=r?r(n[a],e[a],a,n,e):void 0;void 0===l&&(l=e[a]),i?eh(n,a,l):ef(n,a,l)}return n},em=function(e,t){for(var n=-1,r=Array(e);++n<e;)r[n]=t(n);return r},eg=function(e){return D(e)&&"[object Arguments]"==N(e)},ey=Object.prototype,ev=ey.hasOwnProperty,e_=ey.propertyIsEnumerable,ew=eg(function(){return arguments}())?eg:function(e){return D(e)&&ev.call(e,"callee")&&!e_.call(e,"callee")},eb=Array.isArray,eI="object"==typeof exports&&exports&&!exports.nodeType&&exports,eT=eI&&"object"==typeof module&&module&&!module.nodeType&&module,eE=eT&&eT.exports===eI?w.Buffer:void 0,eS=(eE?eE.isBuffer:void 0)||function(){return!1},ek=/^(?:0|[1-9]\d*)$/,ex=function(e,t){var n=typeof e;return!!(t=null==t?9007199254740991:t)&&("number"==n||"symbol"!=n&&ek.test(e))&&e>-1&&e%1==0&&e<t},eC=function(e){return"number"==typeof e&&e>-1&&e%1==0&&e<=9007199254740991},eN={};eN["[object Float32Array]"]=eN["[object Float64Array]"]=eN["[object Int8Array]"]=eN["[object Int16Array]"]=eN["[object Int32Array]"]=eN["[object Uint8Array]"]=eN["[object Uint8ClampedArray]"]=eN["[object Uint16Array]"]=eN["[object Uint32Array]"]=!0,eN["[object Arguments]"]=eN["[object Array]"]=eN["[object ArrayBuffer]"]=eN["[object Boolean]"]=eN["[object DataView]"]=eN["[object Date]"]=eN["[object Error]"]=eN["[object Function]"]=eN["[object Map]"]=eN["[object Number]"]=eN["[object Object]"]=eN["[object RegExp]"]=eN["[object Set]"]=eN["[object String]"]=eN["[object WeakMap]"]=!1;var eA=function(e){return function(t){return e(t)}},eR="object"==typeof exports&&exports&&!exports.nodeType&&exports,eD=eR&&"object"==typeof module&&module&&!module.nodeType&&module,eO=eD&&eD.exports===eR&&v.process,eP=function(){try{var e=eD&&eD.require&&eD.require("util").types;if(e)return e;return eO&&eO.binding&&eO.binding("util")}catch(t){}}(),eL=eP&&eP.isTypedArray,eM=eL?eA(eL):function(e){return D(e)&&eC(e.length)&&!!eN[N(e)]},ej=Object.prototype.hasOwnProperty,eF=function(e,t){var n=eb(e),r=!n&&ew(e),i=!n&&!r&&eS(e),s=!n&&!r&&!i&&eM(e),o=n||r||i||s,a=o?em(e.length,String):[],l=a.length;for(var u in e)(t||ej.call(e,u))&&!(o&&("length"==u||i&&("offset"==u||"parent"==u)||s&&("buffer"==u||"byteLength"==u||"byteOffset"==u)||ex(u,l)))&&a.push(u);return a},eU=Object.prototype,eV=function(e){var t=e&&e.constructor,n="function"==typeof t&&t.prototype||eU;return e===n},eq=A(Object.keys,Object),eB=Object.prototype.hasOwnProperty,e$=function(e){if(!eV(e))return eq(e);var t=[];for(var n in Object(e))eB.call(e,n)&&"constructor"!=n&&t.push(n);return t},ez=function(e){return null!=e&&eC(e.length)&&!$(e)},eG=function(e){return ez(e)?eF(e):e$(e)},eW=function(e){var t=[];if(null!=e)for(var n in Object(e))t.push(n);return t},eH=Object.prototype.hasOwnProperty,eK=function(e){if(!B(e))return eW(e);var t=eV(e),n=[];for(var r in e)"constructor"==r&&(t||!eH.call(e,r))||n.push(r);return n},eQ=function(e){return ez(e)?eF(e,!0):eK(e)},eY="object"==typeof exports&&exports&&!exports.nodeType&&exports,eX=eY&&"object"==typeof module&&module&&!module.nodeType&&module,eJ=eX&&eX.exports===eY?w.Buffer:void 0,eZ=eJ?eJ.allocUnsafe:void 0,e0=function(e,t){if(t)return e.slice();var n=e.length,r=eZ?eZ(n):new e.constructor(n);return e.copy(r),r},e1=function(e,t){var n=-1,r=e.length;for(t||(t=Array(r));++n<r;)t[n]=e[n];return t},e2=function(e,t){for(var n=-1,r=null==e?0:e.length,i=0,s=[];++n<r;){var o=e[n];t(o,n,e)&&(s[i++]=o)}return s},e3=function(){return[]},e4=Object.prototype.propertyIsEnumerable,e6=Object.getOwnPropertySymbols,e5=e6?function(e){return null==e?[]:e2(e6(e=Object(e)),function(t){return e4.call(e,t)})}:e3,e8=function(e,t){for(var n=-1,r=t.length,i=e.length;++n<r;)e[i+n]=t[n];return e},e9=Object.getOwnPropertySymbols?function(e){for(var t=[];e;)e8(t,e5(e)),e=R(e);return t}:e3,e7=function(e,t,n){var r=t(e);return eb(e)?r:e8(r,n(e))},te=function(e){return e7(e,eG,e5)},tt=function(e){return e7(e,eQ,e9)},tn=Z(w,"DataView"),tr=Z(w,"Promise"),ti=Z(w,"Set"),ts=Z(w,"WeakMap"),to="[object Map]",ta="[object Promise]",tl="[object Set]",tu="[object WeakMap]",tc="[object DataView]",th=H(tn),td=H(ee),tf=H(tr),tp=H(ti),tm=H(ts),tg=N;(tn&&tg(new tn(new ArrayBuffer(1)))!=tc||ee&&tg(new ee)!=to||tr&&tg(tr.resolve())!=ta||ti&&tg(new ti)!=tl||ts&&tg(new ts)!=tu)&&(tg=function(e){var t=N(e),n="[object Object]"==t?e.constructor:void 0,r=n?H(n):"";if(r)switch(r){case th:return tc;case td:return to;case tf:return ta;case tp:return tl;case tm:return tu}return t});var ty=tg,tv=Object.prototype.hasOwnProperty,t_=function(e){var t=e.length,n=new e.constructor(t);return t&&"string"==typeof e[0]&&tv.call(e,"index")&&(n.index=e.index,n.input=e.input),n},tw=w.Uint8Array,tb=function(e){var t=new e.constructor(e.byteLength);return new tw(t).set(new tw(e)),t},tI=function(e,t){var n=t?tb(e.buffer):e.buffer;return new e.constructor(n,e.byteOffset,e.byteLength)},tT=/\w*$/,tE=function(e){var t=new e.constructor(e.source,tT.exec(e));return t.lastIndex=e.lastIndex,t},tS=b?b.prototype:void 0,tk=tS?tS.valueOf:void 0,tx=function(e,t){var n=t?tb(e.buffer):e.buffer;return new e.constructor(n,e.byteOffset,e.length)},tC=function(e,t,n){var r=e.constructor;switch(t){case"[object ArrayBuffer]":return tb(e);case"[object Boolean]":case"[object Date]":return new r(+e);case"[object DataView]":return tI(e,n);case"[object Float32Array]":case"[object Float64Array]":case"[object Int8Array]":case"[object Int16Array]":case"[object Int32Array]":case"[object Uint8Array]":case"[object Uint8ClampedArray]":case"[object Uint16Array]":case"[object Uint32Array]":return tx(e,n);case"[object Map]":case"[object Set]":return new r;case"[object Number]":case"[object String]":return new r(e);case"[object RegExp]":return tE(e);case"[object Symbol]":return tk?Object(tk.call(e)):{}}},tN=Object.create,tA=function(){function e(){}return function(t){if(!B(t))return{};if(tN)return tN(t);e.prototype=t;var n=new e;return e.prototype=void 0,n}}(),tR=eP&&eP.isMap,tD=tR?eA(tR):function(e){return D(e)&&"[object Map]"==ty(e)},tO=eP&&eP.isSet,tP=tO?eA(tO):function(e){return D(e)&&"[object Set]"==ty(e)},tL="[object Arguments]",tM="[object Function]",tj="[object Object]",tF={};tF[tL]=tF["[object Array]"]=tF["[object ArrayBuffer]"]=tF["[object DataView]"]=tF["[object Boolean]"]=tF["[object Date]"]=tF["[object Float32Array]"]=tF["[object Float64Array]"]=tF["[object Int8Array]"]=tF["[object Int16Array]"]=tF["[object Int32Array]"]=tF["[object Map]"]=tF["[object Number]"]=tF[tj]=tF["[object RegExp]"]=tF["[object Set]"]=tF["[object String]"]=tF["[object Symbol]"]=tF["[object Uint8Array]"]=tF["[object Uint8ClampedArray]"]=tF["[object Uint16Array]"]=tF["[object Uint32Array]"]=!0,tF["[object Error]"]=tF[tM]=tF["[object WeakMap]"]=!1;var tU=function e(t,n,r,i,s,o){var a,l=1&n,u=2&n;if(r&&(a=s?r(t,i,s,o):r(t)),void 0!==a)return a;if(!B(t))return t;var c=eb(t);if(c){if(a=t_(t),!l)return e1(t,a)}else{var h,d,f,p,m=ty(t),g=m==tM||"[object GeneratorFunction]"==m;if(eS(t))return e0(t,l);if(m==tj||m==tL||g&&!s){if(a=u||g?{}:"function"!=typeof t.constructor||eV(t)?{}:tA(R(t)),!l)return u?(d=(h=a)&&ep(t,eQ(t),h),ep(t,e9(t),d)):(p=(f=a)&&ep(t,eG(t),f),ep(t,e5(t),p))}else{if(!tF[m])return s?t:{};a=tC(t,m,l)}}o||(o=new el);var y=o.get(t);if(y)return y;o.set(t,a),tP(t)?t.forEach(function(i){a.add(e(i,n,r,i,t,o))}):tD(t)&&t.forEach(function(i,s){a.set(s,e(i,n,r,s,t,o))});var v=c?void 0:(4&n?u?tt:te:u?eQ:eG)(t);return eu(v||t,function(i,s){v&&(i=t[s=i]),ef(a,s,e(i,n,r,s,t,o))}),a},tV=function(e){return tU(e,4)},tq=function(e,t){for(var n=-1,r=null==e?0:e.length,i=Array(r);++n<r;)i[n]=t(e[n],n,e);return i},tB=function(e){return"symbol"==typeof e||D(e)&&"[object Symbol]"==N(e)};function t$(e,t){if("function"!=typeof e||null!=t&&"function"!=typeof t)throw TypeError("Expected a function");var n=function(){var r=arguments,i=t?t.apply(this,r):r[0],s=n.cache;if(s.has(i))return s.get(i);var o=e.apply(this,r);return n.cache=s.set(i,o)||s,o};return n.cache=new(t$.Cache||ea),n}t$.Cache=ea;var tz=/[^.[\]]+|\[(?:(-?\d+(?:\.\d+)?)|(["'])((?:(?!\2)[^\\]|\\.)*?)\2)\]|(?=(?:\.|\[\])(?:\.|\[\]|$))/g,tG=/\\(\\)?/g,tW=(s=(i=t$(function(e){var t=[];return 46===e.charCodeAt(0)&&t.push(""),e.replace(tz,function(e,n,r,i){t.push(r?i.replace(tG,"$1"):n||e)}),t},function(e){return 500===s.size&&s.clear(),e})).cache,i),tH=1/0,tK=function(e){if("string"==typeof e||tB(e))return e;var t=e+"";return"0"==t&&1/e==-tH?"-0":t},tQ=1/0,tY=b?b.prototype:void 0,tX=tY?tY.toString:void 0,tJ=function e(t){if("string"==typeof t)return t;if(eb(t))return tq(t,e)+"";if(tB(t))return tX?tX.call(t):"";var n=t+"";return"0"==n&&1/t==-tQ?"-0":n},tZ=function(e){return eb(e)?tq(e,tK):tB(e)?[e]:e1(tW(null==e?"":tJ(e)))},t0=function(e,t){},t1=n(8679),t2=n.n(t1);function t3(){return(t3=Object.assign||function(e){for(var t=1;t<arguments.length;t++){var n=arguments[t];for(var r in n)Object.prototype.hasOwnProperty.call(n,r)&&(e[r]=n[r])}return e}).apply(this,arguments)}function t4(e,t){e.prototype=Object.create(t.prototype),e.prototype.constructor=e,e.__proto__=t}function t6(e,t){if(null==e)return{};var n,r,i={},s=Object.keys(e);for(r=0;r<s.length;r++)n=s[r],t.indexOf(n)>=0||(i[n]=e[n]);return i}function t5(e){if(void 0===e)throw ReferenceError("this hasn't been initialised - super() hasn't been called");return e}var t8=function(e){return Array.isArray(e)&&0===e.length},t9=function(e){return"function"==typeof e},t7=function(e){return null!==e&&"object"==typeof e},ne=function(e){return"[object String]"===Object.prototype.toString.call(e)},nt=function(e){return 0===u.Children.count(e)},nn=function(e){return t7(e)&&t9(e.then)};function nr(e,t,n,r){void 0===r&&(r=0);for(var i=tZ(t);e&&r<i.length;)e=e[i[r++]];return void 0===e?n:e}function ni(e,t,n){for(var r=tV(e),i=r,s=0,o=tZ(t);s<o.length-1;s++){var a=o[s],l=nr(e,o.slice(0,s+1));if(l&&(t7(l)||Array.isArray(l)))i=i[a]=tV(l);else{var u=o[s+1];i=i[a]=String(Math.floor(Number(u)))===u&&Number(u)>=0?[]:{}}}return(0===s?e:i)[o[s]]===n?e:(void 0===n?delete i[o[s]]:i[o[s]]=n,0===s&&void 0===n&&delete r[o[s]],r)}var ns=(0,u.createContext)(void 0);ns.displayName="FormikContext";var no=ns.Provider,na=ns.Consumer;function nl(){var e=(0,u.useContext)(ns);return e||t0(!1),e}function nu(e,t){switch(t.type){case"SET_VALUES":return t3({},e,{values:t.payload});case"SET_TOUCHED":return t3({},e,{touched:t.payload});case"SET_ERRORS":if(h()(e.errors,t.payload))return e;return t3({},e,{errors:t.payload});case"SET_STATUS":return t3({},e,{status:t.payload});case"SET_ISSUBMITTING":return t3({},e,{isSubmitting:t.payload});case"SET_ISVALIDATING":return t3({},e,{isValidating:t.payload});case"SET_FIELD_VALUE":return t3({},e,{values:ni(e.values,t.payload.field,t.payload.value)});case"SET_FIELD_TOUCHED":return t3({},e,{touched:ni(e.touched,t.payload.field,t.payload.value)});case"SET_FIELD_ERROR":return t3({},e,{errors:ni(e.errors,t.payload.field,t.payload.value)});case"RESET_FORM":return t3({},e,t.payload);case"SET_FORMIK_STATE":return t.payload(e);case"SUBMIT_ATTEMPT":return t3({},e,{touched:function e(t,n,r,i){void 0===r&&(r=new WeakMap),void 0===i&&(i={});for(var s=0,o=Object.keys(t);s<o.length;s++){var a=o[s],l=t[a];t7(l)?r.get(l)||(r.set(l,!0),i[a]=Array.isArray(l)?[]:{},e(l,n,r,i[a])):i[a]=n}return i}(e.values,!0),isSubmitting:!0,submitCount:e.submitCount+1});case"SUBMIT_FAILURE":case"SUBMIT_SUCCESS":return t3({},e,{isSubmitting:!1});default:return e}}var nc={},nh={};function nd(e){var t,n,r,i,s,o,a,l,c,d,f,p,m,g,v,_,w,b,I,T,E,S,k,x,C,N,A,R,D,O,P,L,M,F,U,V,q,B,$,z,G,W,H,K,Q,Y,X,J,Z,ee,et,en,er,ei=(n=void 0===(t=e.validateOnChange)||t,i=void 0===(r=e.validateOnBlur)||r,o=void 0!==(s=e.validateOnMount)&&s,a=e.isInitialValid,c=void 0!==(l=e.enableReinitialize)&&l,f=t3({validateOnChange:n,validateOnBlur:i,validateOnMount:o,onSubmit:d=e.onSubmit},t6(e,["validateOnChange","validateOnBlur","validateOnMount","isInitialValid","enableReinitialize","onSubmit"])),p=(0,u.useRef)(f.initialValues),m=(0,u.useRef)(f.initialErrors||nc),g=(0,u.useRef)(f.initialTouched||nh),v=(0,u.useRef)(f.initialStatus),_=(0,u.useRef)(!1),w=(0,u.useRef)({}),(0,u.useEffect)(function(){return _.current=!0,function(){_.current=!1}},[]),I=(b=(0,u.useReducer)(nu,{values:f.initialValues,errors:f.initialErrors||nc,touched:f.initialTouched||nh,status:f.initialStatus,isSubmitting:!1,isValidating:!1,submitCount:0}))[0],T=b[1],E=(0,u.useCallback)(function(e,t){return new Promise(function(n,r){var i=f.validate(e,t);null==i?n(nc):nn(i)?i.then(function(e){n(e||nc)},function(e){r(e)}):n(i)})},[f.validate]),S=(0,u.useCallback)(function(e,t){var n,r,i,s=f.validationSchema,o=t9(s)?s(t):s,a=t&&o.validateAt?o.validateAt(t,e):(void 0===n&&(n=!1),void 0===r&&(r={}),i=function e(t){var n=Array.isArray(t)?[]:{};for(var r in t)if(Object.prototype.hasOwnProperty.call(t,r)){var i=String(r);!0===Array.isArray(t[i])?n[i]=t[i].map(function(t){return!0===Array.isArray(t)||j(t)?e(t):""!==t?t:void 0}):j(t[i])?n[i]=e(t[i]):n[i]=""!==t[i]?t[i]:void 0}return n}(e),o[n?"validateSync":"validate"](i,{abortEarly:!1,context:r}));return new Promise(function(e,t){a.then(function(){e(nc)},function(n){"ValidationError"===n.name?e(function(e){var t={};if(e.inner){if(0===e.inner.length)return ni(t,e.path,e.message);for(var n=e.inner,r=Array.isArray(n),i=0,n=r?n:n[Symbol.iterator]();;){if(r){if(i>=n.length)break;s=n[i++]}else{if((i=n.next()).done)break;s=i.value}var s,o=s;nr(t,o.path)||(t=ni(t,o.path,o.message))}}return t}(n)):t(n)})})},[f.validationSchema]),k=(0,u.useCallback)(function(e,t){return new Promise(function(n){return n(w.current[e].validate(t))})},[]),x=(0,u.useCallback)(function(e){var t=Object.keys(w.current).filter(function(e){return t9(w.current[e].validate)});return Promise.all(t.length>0?t.map(function(t){return k(t,nr(e,t))}):[Promise.resolve("DO_NOT_DELETE_YOU_WILL_BE_FIRED")]).then(function(e){return e.reduce(function(e,n,r){return"DO_NOT_DELETE_YOU_WILL_BE_FIRED"===n||n&&(e=ni(e,t[r],n)),e},{})})},[k]),C=(0,u.useCallback)(function(e){return Promise.all([x(e),f.validationSchema?S(e):{},f.validate?E(e):{}]).then(function(e){var t=e[0],n=e[1],r=e[2];return y.all([t,n,r],{arrayMerge:nf})})},[f.validate,f.validationSchema,x,E,S]),N=nm(function(e){return void 0===e&&(e=I.values),T({type:"SET_ISVALIDATING",payload:!0}),C(e).then(function(e){return _.current&&(T({type:"SET_ISVALIDATING",payload:!1}),T({type:"SET_ERRORS",payload:e})),e})}),(0,u.useEffect)(function(){o&&!0===_.current&&h()(p.current,f.initialValues)&&N(p.current)},[o,N]),A=(0,u.useCallback)(function(e){var t=e&&e.values?e.values:p.current,n=e&&e.errors?e.errors:m.current?m.current:f.initialErrors||{},r=e&&e.touched?e.touched:g.current?g.current:f.initialTouched||{},i=e&&e.status?e.status:v.current?v.current:f.initialStatus;p.current=t,m.current=n,g.current=r,v.current=i;var s=function(){T({type:"RESET_FORM",payload:{isSubmitting:!!e&&!!e.isSubmitting,errors:n,touched:r,status:i,values:t,isValidating:!!e&&!!e.isValidating,submitCount:e&&e.submitCount&&"number"==typeof e.submitCount?e.submitCount:0}})};if(f.onReset){var o=f.onReset(I.values,Y);nn(o)?o.then(s):s()}else s()},[f.initialErrors,f.initialStatus,f.initialTouched]),(0,u.useEffect)(function(){!0===_.current&&!h()(p.current,f.initialValues)&&(c&&(p.current=f.initialValues,A()),o&&N(p.current))},[c,f.initialValues,A,o,N]),(0,u.useEffect)(function(){c&&!0===_.current&&!h()(m.current,f.initialErrors)&&(m.current=f.initialErrors||nc,T({type:"SET_ERRORS",payload:f.initialErrors||nc}))},[c,f.initialErrors]),(0,u.useEffect)(function(){c&&!0===_.current&&!h()(g.current,f.initialTouched)&&(g.current=f.initialTouched||nh,T({type:"SET_TOUCHED",payload:f.initialTouched||nh}))},[c,f.initialTouched]),(0,u.useEffect)(function(){c&&!0===_.current&&!h()(v.current,f.initialStatus)&&(v.current=f.initialStatus,T({type:"SET_STATUS",payload:f.initialStatus}))},[c,f.initialStatus,f.initialTouched]),R=nm(function(e){if(w.current[e]&&t9(w.current[e].validate)){var t=nr(I.values,e),n=w.current[e].validate(t);return nn(n)?(T({type:"SET_ISVALIDATING",payload:!0}),n.then(function(e){return e}).then(function(t){T({type:"SET_FIELD_ERROR",payload:{field:e,value:t}}),T({type:"SET_ISVALIDATING",payload:!1})})):(T({type:"SET_FIELD_ERROR",payload:{field:e,value:n}}),Promise.resolve(n))}return f.validationSchema?(T({type:"SET_ISVALIDATING",payload:!0}),S(I.values,e).then(function(e){return e}).then(function(t){T({type:"SET_FIELD_ERROR",payload:{field:e,value:t[e]}}),T({type:"SET_ISVALIDATING",payload:!1})})):Promise.resolve()}),D=(0,u.useCallback)(function(e,t){var n=t.validate;w.current[e]={validate:n}},[]),O=(0,u.useCallback)(function(e){delete w.current[e]},[]),P=nm(function(e,t){return T({type:"SET_TOUCHED",payload:e}),(void 0===t?i:t)?N(I.values):Promise.resolve()}),L=(0,u.useCallback)(function(e){T({type:"SET_ERRORS",payload:e})},[]),M=nm(function(e,t){var r=t9(e)?e(I.values):e;return T({type:"SET_VALUES",payload:r}),(void 0===t?n:t)?N(r):Promise.resolve()}),F=(0,u.useCallback)(function(e,t){T({type:"SET_FIELD_ERROR",payload:{field:e,value:t}})},[]),U=nm(function(e,t,r){return T({type:"SET_FIELD_VALUE",payload:{field:e,value:t}}),(void 0===r?n:r)?N(ni(I.values,e,t)):Promise.resolve()}),V=(0,u.useCallback)(function(e,t){var n,r=t,i=e;if(!ne(e)){e.persist&&e.persist();var s=e.target?e.target:e.currentTarget,o=s.type,a=s.name,l=s.id,u=s.value,c=s.checked,h=(s.outerHTML,s.options),d=s.multiple;r=t||a||l,i=/number|range/.test(o)?isNaN(n=parseFloat(u))?"":n:/checkbox/.test(o)?function(e,t,n){if("boolean"==typeof e)return Boolean(t);var r=[],i=!1,s=-1;if(Array.isArray(e))r=e,i=(s=e.indexOf(n))>=0;else if(!n||"true"==n||"false"==n)return Boolean(t);return t&&n&&!i?r.concat(n):i?r.slice(0,s).concat(r.slice(s+1)):r}(nr(I.values,r),c,u):h&&d?Array.from(h).filter(function(e){return e.selected}).map(function(e){return e.value}):u}r&&U(r,i)},[U,I.values]),q=nm(function(e){if(ne(e))return function(t){return V(t,e)};V(e)}),B=nm(function(e,t,n){return void 0===t&&(t=!0),T({type:"SET_FIELD_TOUCHED",payload:{field:e,value:t}}),(void 0===n?i:n)?N(I.values):Promise.resolve()}),$=(0,u.useCallback)(function(e,t){e.persist&&e.persist();var n=e.target,r=n.name,i=n.id;n.outerHTML,B(t||r||i,!0)},[B]),z=nm(function(e){if(ne(e))return function(t){return $(t,e)};$(e)}),G=(0,u.useCallback)(function(e){t9(e)?T({type:"SET_FORMIK_STATE",payload:e}):T({type:"SET_FORMIK_STATE",payload:function(){return e}})},[]),W=(0,u.useCallback)(function(e){T({type:"SET_STATUS",payload:e})},[]),H=(0,u.useCallback)(function(e){T({type:"SET_ISSUBMITTING",payload:e})},[]),K=nm(function(){return T({type:"SUBMIT_ATTEMPT"}),N().then(function(e){var t,n=e instanceof Error;if(!n&&0===Object.keys(e).length){try{if(t=X(),void 0===t)return}catch(r){throw r}return Promise.resolve(t).then(function(e){return _.current&&T({type:"SUBMIT_SUCCESS"}),e}).catch(function(e){if(_.current)throw T({type:"SUBMIT_FAILURE"}),e})}if(_.current&&(T({type:"SUBMIT_FAILURE"}),n))throw e})}),Q=nm(function(e){e&&e.preventDefault&&t9(e.preventDefault)&&e.preventDefault(),e&&e.stopPropagation&&t9(e.stopPropagation)&&e.stopPropagation(),K().catch(function(e){console.warn("Warning: An unhandled error was caught from submitForm()",e)})}),Y={resetForm:A,validateForm:N,validateField:R,setErrors:L,setFieldError:F,setFieldTouched:B,setFieldValue:U,setStatus:W,setSubmitting:H,setTouched:P,setValues:M,setFormikState:G,submitForm:K},X=nm(function(){return d(I.values,Y)}),J=nm(function(e){e&&e.preventDefault&&t9(e.preventDefault)&&e.preventDefault(),e&&e.stopPropagation&&t9(e.stopPropagation)&&e.stopPropagation(),A()}),Z=(0,u.useCallback)(function(e){return{value:nr(I.values,e),error:nr(I.errors,e),touched:!!nr(I.touched,e),initialValue:nr(p.current,e),initialTouched:!!nr(g.current,e),initialError:nr(m.current,e)}},[I.errors,I.touched,I.values]),ee=(0,u.useCallback)(function(e){return{setValue:function(t,n){return U(e,t,n)},setTouched:function(t,n){return B(e,t,n)},setError:function(t){return F(e,t)}}},[U,B,F]),et=(0,u.useCallback)(function(e){var t=t7(e),n=t?e.name:e,r=nr(I.values,n),i={name:n,value:r,onChange:q,onBlur:z};if(t){var s=e.type,o=e.value,a=e.as,l=e.multiple;"checkbox"===s?void 0===o?i.checked=!!r:(i.checked=!!(Array.isArray(r)&&~r.indexOf(o)),i.value=o):"radio"===s?(i.checked=r===o,i.value=o):"select"===a&&l&&(i.value=i.value||[],i.multiple=!0)}return i},[z,q,I.values]),en=(0,u.useMemo)(function(){return!h()(p.current,I.values)},[p.current,I.values]),er=(0,u.useMemo)(function(){return void 0!==a?en?I.errors&&0===Object.keys(I.errors).length:!1!==a&&t9(a)?a(f):a:I.errors&&0===Object.keys(I.errors).length},[a,en,I.errors,f]),t3({},I,{initialValues:p.current,initialErrors:m.current,initialTouched:g.current,initialStatus:v.current,handleBlur:z,handleChange:q,handleReset:J,handleSubmit:Q,resetForm:A,setErrors:L,setFormikState:G,setFieldTouched:B,setFieldValue:U,setFieldError:F,setStatus:W,setSubmitting:H,setTouched:P,setValues:M,submitForm:K,validateForm:N,validateField:R,isValid:er,dirty:en,unregisterField:O,registerField:D,getFieldProps:et,getFieldMeta:Z,getFieldHelpers:ee,validateOnBlur:i,validateOnChange:n,validateOnMount:o})),es=e.component,eo=e.children,ea=e.render,el=e.innerRef;return(0,u.useImperativeHandle)(el,function(){return ei}),(0,u.createElement)(no,{value:ei},es?(0,u.createElement)(es,ei):ea?ea(ei):eo?t9(eo)?eo(ei):nt(eo)?null:u.Children.only(eo):null)}function nf(e,t,n){var r=e.slice();return t.forEach(function(t,i){if(void 0===r[i]){var s=!1!==n.clone&&n.isMergeableObject(t);r[i]=s?y(Array.isArray(t)?[]:{},t,n):t}else n.isMergeableObject(t)?r[i]=y(e[i],t,n):-1===e.indexOf(t)&&r.push(t)}),r}var np="undefined"!=typeof window&&void 0!==window.document&&void 0!==window.document.createElement?u.useLayoutEffect:u.useEffect;function nm(e){var t=(0,u.useRef)(e);return np(function(){t.current=e}),(0,u.useCallback)(function(){for(var e=arguments.length,n=Array(e),r=0;r<e;r++)n[r]=arguments[r];return t.current.apply(void 0,n)},[])}function ng(e){var t=e.validate,n=e.name,r=e.render,i=e.children,s=e.as,o=e.component,a=t6(e,["validate","name","render","children","as","component"]),l=t6(nl(),["validate","validationSchema"]),c=l.registerField,h=l.unregisterField;(0,u.useEffect)(function(){return c(n,{validate:t}),function(){h(n)}},[c,h,n,t]);var d=l.getFieldProps(t3({name:n},a)),f=l.getFieldMeta(n),p={field:d,form:l};if(r)return r(t3({},p,{meta:f}));if(t9(i))return i(t3({},p,{meta:f}));if(o){if("string"==typeof o){var m=a.innerRef,g=t6(a,["innerRef"]);return(0,u.createElement)(o,t3({ref:m},d,g),i)}return(0,u.createElement)(o,t3({field:d,form:l},a),i)}var y=s||"input";if("string"==typeof y){var v=a.innerRef,_=t6(a,["innerRef"]);return(0,u.createElement)(y,t3({ref:v},d,_),i)}return(0,u.createElement)(y,t3({},d,a),i)}var ny=(0,u.forwardRef)(function(e,t){var n=e.action,r=t6(e,["action"]),i=nl(),s=i.handleReset,o=i.handleSubmit;return(0,u.createElement)("form",Object.assign({onSubmit:o,ref:t,onReset:s,action:null!=n?n:"#"},r))});ny.displayName="Form";var nv=function(e,t,n){var r=nI(e),i=r[t];return r.splice(t,1),r.splice(n,0,i),r},n_=function(e,t,n){var r=nI(e),i=r[t];return r[t]=r[n],r[n]=i,r},nw=function(e,t,n){var r=nI(e);return r.splice(t,0,n),r},nb=function(e,t,n){var r=nI(e);return r[t]=n,r},nI=function(e){if(!e)return[];if(Array.isArray(e))return[].concat(e);var t=Object.keys(e).map(function(e){return parseInt(e)}).reduce(function(e,t){return t>e?t:e},0);return Array.from(t3({},e,{length:t+1}))};(function(e){function t(t){var n;return(n=e.call(this,t)||this).updateArrayField=function(e,t,r){var i=n.props,s=i.name;(0,i.formik.setFormikState)(function(n){var i=ni(n.values,s,e(nr(n.values,s))),o=r?("function"==typeof r?r:e)(nr(n.errors,s)):void 0,a=t?("function"==typeof t?t:e)(nr(n.touched,s)):void 0;return t8(o)&&(o=void 0),t8(a)&&(a=void 0),t3({},n,{values:i,errors:r?ni(n.errors,s,o):n.errors,touched:t?ni(n.touched,s,a):n.touched})})},n.push=function(e){return n.updateArrayField(function(t){return[].concat(nI(t),[tU(e,5)])},!1,!1)},n.handlePush=function(e){return function(){return n.push(e)}},n.swap=function(e,t){return n.updateArrayField(function(n){return n_(n,e,t)},!0,!0)},n.handleSwap=function(e,t){return function(){return n.swap(e,t)}},n.move=function(e,t){return n.updateArrayField(function(n){return nv(n,e,t)},!0,!0)},n.handleMove=function(e,t){return function(){return n.move(e,t)}},n.insert=function(e,t){return n.updateArrayField(function(n){return nw(n,e,t)},function(t){return nw(t,e,null)},function(t){return nw(t,e,null)})},n.handleInsert=function(e,t){return function(){return n.insert(e,t)}},n.replace=function(e,t){return n.updateArrayField(function(n){return nb(n,e,t)},!1,!1)},n.handleReplace=function(e,t){return function(){return n.replace(e,t)}},n.unshift=function(e){var t=-1;return n.updateArrayField(function(n){var r=n?[e].concat(n):[e];return t<0&&(t=r.length),r},function(e){var n=e?[null].concat(e):[null];return t<0&&(t=n.length),n},function(e){var n=e?[null].concat(e):[null];return t<0&&(t=n.length),n}),t},n.handleUnshift=function(e){return function(){return n.unshift(e)}},n.handleRemove=function(e){return function(){return n.remove(e)}},n.handlePop=function(){return function(){return n.pop()}},n.remove=n.remove.bind(t5(n)),n.pop=n.pop.bind(t5(n)),n}t4(t,e);var n=t.prototype;return n.componentDidUpdate=function(e){this.props.validateOnChange&&this.props.formik.validateOnChange&&!h()(nr(e.formik.values,e.name),nr(this.props.formik.values,this.props.name))&&this.props.formik.validateForm(this.props.formik.values)},n.remove=function(e){var t;return this.updateArrayField(function(n){var r=n?nI(n):[];return t||(t=r[e]),t9(r.splice)&&r.splice(e,1),r},!0,!0),t},n.pop=function(){var e;return this.updateArrayField(function(t){return e||(e=t&&t.pop&&t.pop()),t},!0,!0),e},n.render=function(){var e={push:this.push,pop:this.pop,swap:this.swap,move:this.move,insert:this.insert,replace:this.replace,unshift:this.unshift,remove:this.remove,handlePush:this.handlePush,handlePop:this.handlePop,handleSwap:this.handleSwap,handleMove:this.handleMove,handleInsert:this.handleInsert,handleReplace:this.handleReplace,handleUnshift:this.handleUnshift,handleRemove:this.handleRemove},t=this.props,n=t.component,r=t.render,i=t.children,s=t.name,o=t3({},e,{form:t6(t.formik,["validate","validationSchema"]),name:s});return n?(0,u.createElement)(n,o):r?r(o):i?"function"==typeof i?i(o):nt(i)?null:u.Children.only(i):null},t})(u.Component).defaultProps={validateOnChange:!0};var nT=(o=function(e){function t(){return e.apply(this,arguments)||this}t4(t,e);var n=t.prototype;return n.shouldComponentUpdate=function(e){return nr(this.props.formik.errors,this.props.name)!==nr(e.formik.errors,this.props.name)||nr(this.props.formik.touched,this.props.name)!==nr(e.formik.touched,this.props.name)||Object.keys(this.props).length!==Object.keys(e).length},n.render=function(){var e=this.props,t=e.component,n=e.formik,r=e.render,i=e.children,s=e.name,o=t6(e,["component","formik","render","children","name"]),a=nr(n.touched,s),l=nr(n.errors,s);return a&&l?r?t9(r)?r(l):null:i?t9(i)?i(l):null:t?(0,u.createElement)(t,o,l):l:null},t}(u.Component),a=function(e){return(0,u.createElement)(na,null,function(t){return t||t0(!1),(0,u.createElement)(o,Object.assign({},e,{formik:t}))})},l=o.displayName||o.name||o.constructor&&o.constructor.name||"Component",a.WrappedComponent=o,a.displayName="FormikConnect("+l+")",t2()(a,o));u.Component},8679:function(e,t,n){"use strict";var r=n(9864),i={childContextTypes:!0,contextType:!0,contextTypes:!0,defaultProps:!0,displayName:!0,getDefaultProps:!0,getDerivedStateFromError:!0,getDerivedStateFromProps:!0,mixins:!0,propTypes:!0,type:!0},s={name:!0,length:!0,prototype:!0,caller:!0,callee:!0,arguments:!0,arity:!0},o={$$typeof:!0,compare:!0,defaultProps:!0,displayName:!0,propTypes:!0,type:!0},a={};function l(e){return r.isMemo(e)?o:a[e.$$typeof]||i}a[r.ForwardRef]={$$typeof:!0,render:!0,defaultProps:!0,displayName:!0,propTypes:!0},a[r.Memo]=o;var u=Object.defineProperty,c=Object.getOwnPropertyNames,h=Object.getOwnPropertySymbols,d=Object.getOwnPropertyDescriptor,f=Object.getPrototypeOf,p=Object.prototype;e.exports=function e(t,n,r){if("string"!=typeof n){if(p){var i=f(n);i&&i!==p&&e(t,i,r)}var o=c(n);h&&(o=o.concat(h(n)));for(var a=l(t),m=l(n),g=0;g<o.length;++g){var y=o[g];if(!s[y]&&!(r&&r[y])&&!(m&&m[y])&&!(a&&a[y])){var v=d(n,y);try{u(t,y,v)}catch(_){}}}}return t}},3454:function(e,t,n){"use strict";var r,i;e.exports=(null==(r=n.g.process)?void 0:r.env)&&"object"==typeof(null==(i=n.g.process)?void 0:i.env)?n.g.process:n(7663)},1118:function(e,t,n){(window.__NEXT_P=window.__NEXT_P||[]).push(["/_app",function(){return n(1669)}])},4536:function(e,t,n){"use strict";n.d(t,{Z:function(){return H}});var r=n(5893),i=n(7294);n(6762);var s=n(3935),o=n(4184),a=n.n(o),l=!1;if("undefined"!=typeof window){var u={get passive(){l=!0;return}};window.addEventListener("testPassive",null,u),window.removeEventListener("testPassive",null,u)}var c="undefined"!=typeof window&&window.navigator&&window.navigator.platform&&(/iP(ad|hone|od)/.test(window.navigator.platform)||"MacIntel"===window.navigator.platform&&window.navigator.maxTouchPoints>1),h=[],d=!1,f=-1,p=void 0,m=void 0,g=function(e){return h.some(function(t){return!!(t.options.allowTouchMove&&t.options.allowTouchMove(e))})},y=function(e){var t=e||window.event;return!!g(t.target)||t.touches.length>1||(t.preventDefault&&t.preventDefault(),!1)},v=function(e){if(void 0===m){var t=!!e&&!0===e.reserveScrollBarGap,n=window.innerWidth-document.documentElement.clientWidth;t&&n>0&&(m=document.body.style.paddingRight,document.body.style.paddingRight=n+"px")}void 0===p&&(p=document.body.style.overflow,document.body.style.overflow="hidden")},_=function(){void 0!==m&&(document.body.style.paddingRight=m,m=void 0),void 0!==p&&(document.body.style.overflow=p,p=void 0)},w=function(e,t){var n=e.targetTouches[0].clientY-f;return!g(e.target)&&(t&&0===t.scrollTop&&n>0?y(e):t&&t.scrollHeight-t.scrollTop<=t.clientHeight&&n<0?y(e):(e.stopPropagation(),!0))},b=function(e,t){if(!e){console.error("disableBodyScroll unsuccessful - targetElement must be provided when calling disableBodyScroll on IOS devices.");return}!h.some(function(t){return t.targetElement===e})&&(h=[].concat(function(e){if(!Array.isArray(e))return Array.from(e);for(var t=0,n=Array(e.length);t<e.length;t++)n[t]=e[t];return n}(h),[{targetElement:e,options:t||{}}]),c?(e.ontouchstart=function(e){1===e.targetTouches.length&&(f=e.targetTouches[0].clientY)},e.ontouchmove=function(t){1===t.targetTouches.length&&w(t,e)},d||(document.addEventListener("touchmove",y,l?{passive:!1}:void 0),d=!0)):v(t))},I=function(e){if(!e){console.error("enableBodyScroll unsuccessful - targetElement must be provided when calling enableBodyScroll on IOS devices.");return}h=h.filter(function(t){return t.targetElement!==e}),c?(e.ontouchstart=null,e.ontouchmove=null,d&&0===h.length&&(document.removeEventListener("touchmove",y,l?{passive:!1}:void 0),d=!1)):h.length||_()};function T(){return(T=Object.assign||function(e){for(var t=1;t<arguments.length;t++){var n=arguments[t];for(var r in n)Object.prototype.hasOwnProperty.call(n,r)&&(e[r]=n[r])}return e}).apply(this,arguments)}n(3454);var E=function(e){var t=e.classes,n=e.classNames,r=e.styles,s=e.id,o=e.closeIcon,l=e.onClick;return i.createElement("button",{id:s,className:a()(t.closeButton,null==n?void 0:n.closeButton),style:null==r?void 0:r.closeButton,onClick:l,"data-testid":"close-button"},o||i.createElement("svg",{className:null==n?void 0:n.closeIcon,style:null==r?void 0:r.closeIcon,width:28,height:28,viewBox:"0 0 36 36","data-testid":"close-icon"},i.createElement("path",{d:"M28.5 9.62L26.38 7.5 18 15.88 9.62 7.5 7.5 9.62 15.88 18 7.5 26.38l2.12 2.12L18 20.12l8.38 8.38 2.12-2.12L20.12 18z"})))},S="undefined"!=typeof window,k=["input","select","textarea","a[href]","button","[tabindex]","audio[controls]","video[controls]",'[contenteditable]:not([contenteditable="false"])'];function x(e){for(var t=document.activeElement,n=e.querySelectorAll(k.join(",")),r=[],i=0;i<n.length;i++){var s=n[i];(t===s||!s.disabled&&function(e){var t=parseInt(e.getAttribute("tabindex"),10);return isNaN(t)?e.getAttribute("contentEditable")?0:e.tabIndex:t}(s)>-1&&!(null===s.offsetParent||"hidden"===getComputedStyle(s).visibility)&&function(e){if("INPUT"!==e.tagName||"radio"!==e.type||!e.name)return!0;var t=(e.form||e.ownerDocument).querySelectorAll('input[type="radio"][name="'+e.name+'"]'),n=function(e,t){for(var n=0;n<e.length;n++)if(e[n].checked&&e[n].form===t)return e[n]}(t,e.form);return n===e||void 0===n&&t[0]===e}(s))&&r.push(s)}return r}var C=function(e){var t=e.container,n=e.initialFocusRef,r=(0,i.useRef)();return(0,i.useEffect)(function(){var e=function(e){(null==t?void 0:t.current)&&function(e,t){if(e&&"Tab"===e.key&&t&&t.contains&&t.contains(e.target)){var n=x(t),r=n[0],i=n[n.length-1];e.shiftKey&&e.target===r?(i.focus(),e.preventDefault()):e.shiftKey||e.target!==i||(r.focus(),e.preventDefault())}}(e,t.current)};if(S&&document.addEventListener("keydown",e),S&&(null==t?void 0:t.current)){var i=function(){-1!==k.findIndex(function(e){var t;return null==(t=document.activeElement)?void 0:t.matches(e)})&&(r.current=document.activeElement)};if(n)i(),requestAnimationFrame(function(){var e;null==(e=n.current)||e.focus()});else{var s=x(t.current);s[0]&&(i(),s[0].focus())}}return function(){if(S){var t;document.removeEventListener("keydown",e),null==(t=r.current)||t.focus()}}},[t,n]),null},N=[],A={add:function(e){N.push(e)},remove:function(e){N=N.filter(function(t){return t!==e})},isTopModal:function(e){return!!N.length&&N[N.length-1]===e}},R=function(e,t,n,r,s){var o=(0,i.useRef)(null);(0,i.useEffect)(function(){return t&&e.current&&r&&(o.current=e.current,b(e.current,{reserveScrollBarGap:s})),function(){o.current&&(I(o.current),o.current=null)}},[t,n,e,r,s])},D={root:"react-responsive-modal-root",overlay:"react-responsive-modal-overlay",overlayAnimationIn:"react-responsive-modal-overlay-in",overlayAnimationOut:"react-responsive-modal-overlay-out",modalContainer:"react-responsive-modal-container",modalContainerCenter:"react-responsive-modal-containerCenter",modal:"react-responsive-modal-modal",modalAnimationIn:"react-responsive-modal-modal-in",modalAnimationOut:"react-responsive-modal-modal-out",closeButton:"react-responsive-modal-closeButton"},O=i.forwardRef(function(e,t){var n,r,o,l,u=e.open,c=e.center,h=e.blockScroll,d=e.closeOnEsc,f=void 0===d||d,p=e.closeOnOverlayClick,m=void 0===p||p,g=e.container,y=e.showCloseIcon,v=e.closeIconId,_=e.closeIcon,w=e.focusTrapped,b=e.initialFocusRef,I=e.animationDuration,k=void 0===I?300:I,x=e.classNames,N=e.styles,O=e.role,P=e.ariaDescribedby,L=e.ariaLabelledby,M=e.containerId,j=e.modalId,F=e.onClose,U=e.onEscKeyDown,V=e.onOverlayClick,q=e.onAnimationEnd,B=e.children,$=e.reserveScrollBarGap,z=function(e,t={isStateful:!0}){let n=function(e=null){let[t,n]=i.useState(e),{current:r}=i.useRef({current:t});return Object.defineProperty(r,"current",{get:()=>t,set:e=>{Object.is(t,e)||(t=e,n(e))}}),r}(null),r=(0,i.useRef)(null),s=t.isStateful?n:r;return i.useEffect(()=>{e&&("function"==typeof e?e(s.current):e.current=s.current)}),s}(t),G=(0,i.useRef)(null),W=(0,i.useRef)(null),H=(0,i.useRef)(null);null===H.current&&S&&(H.current=document.createElement("div"));var K=(0,i.useState)(!1),Q=K[0],Y=K[1];(0,i.useEffect)(function(){return u&&A.add(G),function(){A.remove(G)}},[u,G]),R(G,u,Q,void 0===h||h,$);var X=function(){!H.current||g||document.body.contains(H.current)||document.body.appendChild(H.current),document.addEventListener("keydown",Z)},J=function(){H.current&&!g&&document.body.contains(H.current)&&document.body.removeChild(H.current),document.removeEventListener("keydown",Z)},Z=function(e){27===e.keyCode&&A.isTopModal(G)&&(null==U||U(e),f&&F())};(0,i.useEffect)(function(){return function(){Q&&J()}},[Q]),(0,i.useEffect)(function(){u&&!Q&&(Y(!0),X())},[u]);var ee=function(){W.current=!1},et=g||H.current,en=u?null!=(n=null==x?void 0:x.overlayAnimationIn)?n:D.overlayAnimationIn:null!=(r=null==x?void 0:x.overlayAnimationOut)?r:D.overlayAnimationOut,er=u?null!=(o=null==x?void 0:x.modalAnimationIn)?o:D.modalAnimationIn:null!=(l=null==x?void 0:x.modalAnimationOut)?l:D.modalAnimationOut;return Q&&et?s.createPortal(i.createElement("div",{className:a()(D.root,null==x?void 0:x.root),style:null==N?void 0:N.root,"data-testid":"root"},i.createElement("div",{className:a()(D.overlay,null==x?void 0:x.overlay),"data-testid":"overlay","aria-hidden":!0,style:T({animation:en+" "+k+"ms"},null==N?void 0:N.overlay)}),i.createElement("div",{ref:G,id:M,className:a()(D.modalContainer,c&&D.modalContainerCenter,null==x?void 0:x.modalContainer),style:null==N?void 0:N.modalContainer,"data-testid":"modal-container",onClick:function(e){if(null===W.current&&(W.current=!0),!W.current){W.current=null;return}null==V||V(e),m&&F(),W.current=null}},i.createElement("div",{ref:z,className:a()(D.modal,null==x?void 0:x.modal),style:T({animation:er+" "+k+"ms"},null==N?void 0:N.modal),onMouseDown:ee,onMouseUp:ee,onClick:ee,onAnimationEnd:function(){u||Y(!1),null==q||q()},id:j,role:void 0===O?"dialog":O,"aria-modal":"true","aria-labelledby":L,"aria-describedby":P,"data-testid":"modal",tabIndex:-1},(void 0===w||w)&&i.createElement(C,{container:z,initialFocusRef:void 0===b?void 0:b}),B,(void 0===y||y)&&i.createElement(E,{classes:D,classNames:x,styles:N,closeIcon:_,onClick:F,id:v})))),et):null}),P=n(2175),L=n(6501),M=n(8104);n(6310);var j=n(8059);function F(e){let{eventData:t,categoryTest:n}=e;return"hackathon"===n?(0,r.jsx)(V,{eventData:t}):"internship"==n?(0,r.jsx)(q,{eventData:t}):"grants"==n?(0,r.jsx)(B,{eventData:t}):"conferences"==n?(0,r.jsx)($,{eventData:t}):void 0}let U=e=>{let{eventData:t}=e;return(0,r.jsx)(P.J9,{initialValues:{category:"Hackathon"},onSubmit:e=>{e()},children:e=>(0,r.jsxs)("div",{children:[(0,r.jsxs)("div",{className:"multiOption",children:[(0,r.jsx)("div",{id:"my-radio-group",children:"Category"}),(0,r.jsxs)("div",{role:"group","aria-labelledby":"my-radio-group",className:"optionDiv",children:[(0,r.jsxs)("label",{children:[(0,r.jsx)(P.gN,{type:"radio",name:"category",value:"Hackathon"}),"Hackathon"]}),(0,r.jsxs)("label",{children:[(0,r.jsx)(P.gN,{type:"radio",name:"category",value:"Internship"}),"Internship"]}),(0,r.jsxs)("label",{children:[(0,r.jsx)(P.gN,{type:"radio",name:"category",value:"Grants"}),"Grants"]}),(0,r.jsxs)("label",{children:[(0,r.jsx)(P.gN,{type:"radio",name:"category",value:"Conferences"}),"Conferences"]})]})]}),"Hackathon"==e.values.category&&(0,r.jsx)(V,{eventData:null}),"Internship"==e.values.category&&(0,r.jsx)(q,{eventData:null}),"Grants"==e.values.category&&(0,r.jsx)(B,{eventData:null}),"Conferences"==e.values.category&&(0,r.jsx)($,{eventData:null})]})})};function V(e){let{eventData:t}=e,{user:n,username:s}=(0,i.useContext)(j.S);return null==t?(0,r.jsx)(P.J9,{initialValues:{eventN:"",link:"",appS:"",appE:"",eventS:"",eventE:"",postedBy:"",filters:""},onSubmit:async e=>{e.postedBy=s,L.ZP.loading("Adding ".concat(e.eventN," for the community")),await z("add","Hackathon",e,n)},children:e=>{let{isSubmitting:t}=e;return(0,r.jsxs)(P.l0,{children:[(0,r.jsxs)("div",{children:[(0,r.jsx)("label",{htmlFor:"eventN",children:"Hackathon"}),(0,r.jsx)(P.gN,{name:"eventN",placeholder:"Hackathon",validate:e=>{if(!e)return"Title is required"}}),(0,r.jsx)(P.Bc,{name:"eventN"})]}),(0,r.jsxs)("div",{children:[(0,r.jsx)("label",{htmlFor:"link",children:"Link"}),(0,r.jsx)(P.gN,{name:"link",placeholder:"HackthonURL",validate:e=>{if(!e)return"Link is required"}}),(0,r.jsx)(P.Bc,{name:"link"})]}),(0,r.jsxs)("div",{className:"multiOption",children:[(0,r.jsx)("div",{id:"my-radio-group",children:"Filters"}),(0,r.jsxs)("div",{role:"group","aria-labelledby":"my-radio-group",className:"optionDiv",children:[(0,r.jsxs)("label",{children:[(0,r.jsx)(P.gN,{type:"radio",name:"filters",value:"onsite"}),"Onsite"]}),(0,r.jsxs)("label",{children:[(0,r.jsx)(P.gN,{type:"radio",name:"filters",value:"remote"}),"Remote"]}),(0,r.jsxs)("label",{children:[(0,r.jsx)(P.gN,{type:"radio",name:"filters",value:"hybrid"}),"Hybrid"]})]})]}),(0,r.jsxs)("div",{children:[(0,r.jsx)("label",{htmlFor:"appS",children:"Application Starts"}),(0,r.jsx)(P.gN,{name:"appS",type:"date",validate:e=>{if(!e)return"Application Start Date is required"}}),(0,r.jsx)(P.Bc,{name:"appS"})]}),(0,r.jsxs)("div",{children:[(0,r.jsx)("label",{htmlFor:"appE",children:"Application Ends"}),(0,r.jsx)(P.gN,{name:"appE",type:"date",validate:e=>{if(!e)return"Application End Date is required"}}),(0,r.jsx)(P.Bc,{name:"appE"})]}),(0,r.jsxs)("div",{children:[(0,r.jsx)("label",{htmlFor:"eventS",children:"Hackathon Beings"}),(0,r.jsx)(P.gN,{name:"eventS",type:"date"}),(0,r.jsx)(P.Bc,{name:"eventS"})]}),(0,r.jsxs)("div",{children:[(0,r.jsx)("label",{htmlFor:"eventE",children:"Hackathon Ends"}),(0,r.jsx)(P.gN,{name:"eventE",type:"date"})]}),(0,r.jsx)("button",{type:"submit",disabled:t,children:"Submit"}),(0,r.jsx)(L.x7,{})]})}}):(0,r.jsx)(P.J9,{initialValues:{eventN:t.eventN,link:t.link,appS:t.appS,appE:t.appE,eventS:t.eventS,eventE:t.eventE,filters:t.filters,postedBy:t.postedBy},onSubmit:async e=>{L.ZP.loading("Updating ".concat(e.eventN," for the community")),e.calID=t.calID?t.calID:"",e.discordMessageID=t.discordMessageID?t.discordMessageID:"",await z("edit","Hackathon",e,n,t.id)},children:e=>{let{isSubmitting:t}=e;return(0,r.jsxs)(P.l0,{children:[(0,r.jsxs)("div",{children:[(0,r.jsx)("label",{htmlFor:"eventN",children:"Hackathon"}),(0,r.jsx)(P.gN,{name:"eventN",placeholder:"Title",validate:e=>{if(!e)return"Hackathon Title is required"}}),(0,r.jsx)(P.Bc,{name:"eventN"})]}),(0,r.jsxs)("div",{children:[(0,r.jsx)("label",{htmlFor:"link",children:"Link"}),(0,r.jsx)(P.gN,{name:"link",placeholder:"Hackathon URL",validate:e=>{if(!e)return"Hackathon URL is required"}}),(0,r.jsx)(P.Bc,{name:"link"})]}),(0,r.jsxs)("div",{className:"multiOption",children:[(0,r.jsx)("div",{id:"my-radio-group",children:"Filters"}),(0,r.jsxs)("div",{role:"group","aria-labelledby":"my-radio-group",className:"optionDiv",children:[(0,r.jsxs)("label",{children:[(0,r.jsx)(P.gN,{type:"radio",name:"filters",value:"onsite"}),"Onsite"]}),(0,r.jsxs)("label",{children:[(0,r.jsx)(P.gN,{type:"radio",name:"filters",value:"remote"}),"Remote"]}),(0,r.jsxs)("label",{children:[(0,r.jsx)(P.gN,{type:"radio",name:"filters",value:"hybrid"}),"Hybrid"]})]})]}),(0,r.jsx)("label",{htmlFor:"appS",children:"Registration Begins"}),(0,r.jsx)(P.gN,{name:"appS",type:"date",validate:e=>{if(!e)return"Application Start date is required"}}),(0,r.jsx)("label",{htmlFor:"appE",children:"Registration Ends"}),(0,r.jsx)(P.gN,{name:"appE",type:"date",validate:e=>{if(!e)return"Application End date is required"}}),(0,r.jsx)("label",{htmlFor:"eventS",children:"Conference Beings"}),(0,r.jsx)(P.gN,{name:"eventS",type:"date"}),(0,r.jsx)("label",{htmlFor:"eventE",children:"Conference Ends"}),(0,r.jsx)(P.gN,{name:"eventE",type:"date"}),(0,r.jsx)("button",{type:"submit",disabled:t,children:"Submit"}),(0,r.jsx)(L.x7,{})]})}})}function q(e){let{eventData:t}=e,{user:n,username:s}=(0,i.useContext)(j.S);return null==t?(0,r.jsx)(P.J9,{initialValues:{eventN:"",link:"",appS:"",appE:"",eventS:"",eventE:"",filters:"",postedBy:""},onSubmit:async e=>{e.postedBy=s,L.ZP.loading("Adding ".concat(e.eventN," for the community")),await z("add","Internship",e,n)},children:e=>{let{isSubmitting:t}=e;return(0,r.jsxs)(P.l0,{children:[(0,r.jsxs)("div",{children:[(0,r.jsx)("label",{htmlFor:"eventN",children:"Company"}),(0,r.jsx)(P.gN,{name:"eventN",placeholder:"Internship",validate:e=>{if(!e)return"Internship Title is required"}}),(0,r.jsx)(P.Bc,{name:"eventN"})]}),(0,r.jsxs)("div",{children:[(0,r.jsx)("label",{htmlFor:"link",children:"Link"}),(0,r.jsx)(P.gN,{name:"link",placeholder:"Link to application",validate:e=>{if(!e)return"Internship URL is required"}}),(0,r.jsx)(P.Bc,{name:"link"})]}),(0,r.jsxs)("div",{className:"multiOption",children:[(0,r.jsx)("div",{id:"my-radio-group",children:"Type"}),(0,r.jsxs)("div",{role:"group","aria-labelledby":"my-radio-group",className:"optionDiv",children:[(0,r.jsxs)("label",{children:[(0,r.jsx)(P.gN,{type:"radio",name:"filters",value:"remote"}),"Onsite"]}),(0,r.jsxs)("label",{children:[(0,r.jsx)(P.gN,{type:"radio",name:"filters",value:"remote"}),"Remote"]}),(0,r.jsxs)("label",{children:[(0,r.jsx)(P.gN,{type:"radio",name:"filters",value:"hybrid"}),"Hybrid"]})]})]}),(0,r.jsxs)("div",{children:[(0,r.jsxs)("div",{children:[(0,r.jsx)("label",{htmlFor:"appS",children:"Application Starts"}),(0,r.jsx)(P.gN,{name:"appS",type:"date",validate:e=>{if(!e)return"Application Start date is required"}}),(0,r.jsx)(P.Bc,{name:"appS"})]}),(0,r.jsxs)("div",{children:[(0,r.jsx)("label",{htmlFor:"appE",children:"Application Ends"}),(0,r.jsx)(P.gN,{name:"appE",type:"date",validate:e=>{if(!e)return"Application End date is required"}})]})]}),(0,r.jsxs)("div",{children:[(0,r.jsxs)("div",{children:[(0,r.jsx)("label",{htmlFor:"eventS",children:"Internship Beings"}),(0,r.jsx)(P.gN,{name:"eventS",type:"date"}),(0,r.jsx)(P.Bc,{name:"eventS"})]}),(0,r.jsxs)("div",{children:[(0,r.jsx)("label",{htmlFor:"eventE",children:"Internship Ends"}),(0,r.jsx)(P.gN,{name:"eventE",type:"date"})]})]}),(0,r.jsx)("button",{type:"submit",disabled:t,children:"Submit"}),(0,r.jsx)(L.x7,{})]})}}):(0,r.jsx)(P.J9,{initialValues:{eventN:t.eventN,link:t.link,appS:t.appS,appE:t.appE,eventS:t.eventS,eventE:t.eventE,filters:t.filters,postedBy:t.postedBy},onSubmit:async e=>{e.postedBy=s,e.calID=t.calID?t.calID:"",L.ZP.loading("Adding ".concat(e.eventN," for the community")),await z("edit","Grants",e,n)},children:e=>{let{isSubmitting:t}=e;return(0,r.jsxs)(P.l0,{children:[(0,r.jsx)("label",{htmlFor:"eventN",children:"Company"}),(0,r.jsx)(P.gN,{name:"eventN",placeholder:"",validate:e=>{if(!e)return"Company title is required"}}),(0,r.jsx)("label",{htmlFor:"link",children:"Link"}),(0,r.jsx)(P.gN,{name:"link",placeholder:"hackHar.com",validate:e=>{if(!e)return"Internship application URL is required"}}),(0,r.jsx)("div",{id:"my-radio-group",children:"Picked"}),(0,r.jsxs)("div",{role:"group","aria-labelledby":"my-radio-group",children:[(0,r.jsxs)("label",{children:[(0,r.jsx)(P.gN,{type:"radio",name:"filters",value:"onsite"}),"Onsite"]}),(0,r.jsxs)("label",{children:[(0,r.jsx)(P.gN,{type:"radio",name:"filters",value:"remote"}),"Remote"]}),(0,r.jsxs)("label",{children:[(0,r.jsx)(P.gN,{type:"radio",name:"filters",value:"hybrid"}),"Hybrid"]})]}),(0,r.jsx)("label",{htmlFor:"appS",children:"Application Starts"}),(0,r.jsx)(P.gN,{name:"appS",type:"date",validate:e=>{if(!e)return"Application Start date is required"}}),(0,r.jsx)("label",{htmlFor:"appE",children:"Application Ends"}),(0,r.jsx)(P.gN,{name:"appE",type:"date",validate:e=>{if(!e)return"Application End date is required"}}),(0,r.jsx)("label",{htmlFor:"eventS",children:"Hackathon Beings"}),(0,r.jsx)(P.gN,{name:"eventS",type:"date"}),(0,r.jsx)("label",{htmlFor:"eventE",children:"Hackathon Ends"}),(0,r.jsx)(P.gN,{name:"eventE",type:"date"}),(0,r.jsx)("button",{type:"submit",disabled:t,children:"Submit"}),(0,r.jsx)(L.x7,{})]})}})}function B(e){let{eventData:t}=e,{user:n,username:s}=(0,i.useContext)(j.S);return null==t?(0,r.jsx)(P.J9,{initialValues:{eventN:"",link:"",appS:"",appE:"",filters:"",postedBy:""},onSubmit:async e=>{e.postedBy=s,L.ZP.loading("Adding ".concat(e.eventN," for the community")),await z("add","Grants",e,n)},children:e=>{let{isSubmitting:t}=e;return(0,r.jsxs)(P.l0,{children:[(0,r.jsxs)("div",{children:[(0,r.jsx)("label",{htmlFor:"eventN",children:"Company"}),(0,r.jsx)(P.gN,{name:"eventN",placeholder:"Grant Title",validate:e=>{if(!e)return"Title is required"}}),(0,r.jsx)(P.Bc,{name:"eventN"})]}),(0,r.jsxs)("div",{children:[(0,r.jsx)("label",{htmlFor:"link",children:"Link"}),(0,r.jsx)(P.gN,{name:"link",placeholder:"Application link",validate:e=>{if(!e)return"Link to application is required"}}),(0,r.jsx)(P.Bc,{name:"link"})]}),(0,r.jsxs)("div",{className:"multiOption",children:[(0,r.jsx)("div",{id:"my-radio-group",children:"Type"}),(0,r.jsxs)("div",{role:"group","aria-labelledby":"my-radio-group",className:"optionDiv",children:[(0,r.jsxs)("label",{children:[(0,r.jsx)(P.gN,{type:"radio",name:"filters",value:"travel"}),"Travel"]}),(0,r.jsxs)("label",{children:[(0,r.jsx)(P.gN,{type:"radio",name:"filters",value:"course"}),"Course"]}),(0,r.jsxs)("label",{children:[(0,r.jsx)(P.gN,{type:"radio",name:"filters",value:"conference"}),"Conference"]})]})]}),(0,r.jsxs)("div",{children:[(0,r.jsxs)("div",{children:[(0,r.jsx)("label",{htmlFor:"appS",children:"Application Starts"}),(0,r.jsx)(P.gN,{name:"appS",type:"date",validate:e=>{if(!e)return"Application Start date is required"}}),(0,r.jsx)(P.Bc,{name:"appS"})]}),(0,r.jsxs)("div",{children:[(0,r.jsx)("label",{htmlFor:"appE",children:"Application Ends"}),(0,r.jsx)(P.gN,{name:"appE",type:"date",validate:e=>{if(!e)return"Application End date is required"}})]})]}),(0,r.jsx)("button",{type:"submit",disabled:t,children:"Submit"}),(0,r.jsx)(L.x7,{})]})}}):(0,r.jsx)(P.J9,{initialValues:{eventN:t.eventN,link:t.link,appS:t.appS,appE:t.appE,filters:t.filters,postedBy:t.postedBy},onSubmit:async e=>{e.postedBy=s,e.calID=t.calID?t.calID:"",L.ZP.loading("Adding ".concat(e.eventN," for the community")),await z("edit","Grants",e,n)},children:e=>{let{isSubmitting:t}=e;return(0,r.jsxs)(P.l0,{children:[(0,r.jsx)("label",{htmlFor:"eventN",children:"Grant"}),(0,r.jsx)(P.gN,{name:"eventN",placeholder:"",validate:e=>{if(!e)return"Grant title is required"}}),(0,r.jsx)("label",{htmlFor:"link",children:"Link"}),(0,r.jsx)(P.gN,{name:"link",placeholder:"hackHar.com",validate:e=>{if(!e)return"Grant application url is required"}}),(0,r.jsx)("div",{id:"my-radio-group",children:"Picked"}),(0,r.jsxs)("div",{role:"group","aria-labelledby":"my-radio-group",children:[(0,r.jsxs)("label",{children:[(0,r.jsx)(P.gN,{type:"radio",name:"filters",value:"travel"}),"Travel"]}),(0,r.jsxs)("label",{children:[(0,r.jsx)(P.gN,{type:"radio",name:"filters",value:"course"}),"Course"]}),(0,r.jsxs)("label",{children:[(0,r.jsx)(P.gN,{type:"radio",name:"filters",value:"conference"}),"Conference"]})]}),(0,r.jsx)("label",{htmlFor:"appS",children:"Application Starts"}),(0,r.jsx)(P.gN,{name:"appS",type:"date",validate:e=>{if(!e)return"Application Start date is required"}}),(0,r.jsx)("label",{htmlFor:"appE",children:"Application Ends"}),(0,r.jsx)(P.gN,{name:"appE",type:"date",validate:e=>{if(!e)return"Application End date is required"}}),(0,r.jsx)("button",{type:"submit",disabled:t,children:"Submit"}),(0,r.jsx)(L.x7,{})]})}})}function $(e){let{eventData:t}=e,{user:n,username:s}=(0,i.useContext)(j.S);return null==t?(0,r.jsx)(P.J9,{initialValues:{eventN:"",link:"",appS:"",appE:"",eventS:"",eventE:"",filters:"",postedBy:""},onSubmit:async e=>{e.postedBy=s,L.ZP.loading("Adding ".concat(e.eventN," for the community")),await z("add","Conferences",e,n)},children:e=>{let{isSubmitting:t}=e;return(0,r.jsxs)(P.l0,{children:[(0,r.jsxs)("div",{children:[(0,r.jsx)("label",{htmlFor:"eventN",children:"Conference Title"}),(0,r.jsx)(P.gN,{name:"eventN",placeholder:"Title",validate:e=>{if(!e)return"Conference Title is required"}}),(0,r.jsx)(P.Bc,{name:"eventN"})]}),(0,r.jsxs)("div",{children:[(0,r.jsx)("label",{htmlFor:"link",children:"Link"}),(0,r.jsx)(P.gN,{name:"link",placeholder:"Conference URL",validate:e=>{if(!e)return"Conference url is required"}}),(0,r.jsx)(P.Bc,{name:"link"})]}),(0,r.jsxs)("div",{className:"multiOption",children:[(0,r.jsx)("div",{id:"my-radio-group",children:"Picked "}),(0,r.jsxs)("div",{role:"group","aria-labelledby":"my-radio-group",className:"optionDiv",children:[(0,r.jsxs)("label",{children:[(0,r.jsx)(P.gN,{type:"radio",name:"filters",value:"design"}),"Design"]}),(0,r.jsxs)("label",{children:[(0,r.jsx)(P.gN,{type:"radio",name:"filters",value:"launch event"}),"Launch Event"]})]})]}),(0,r.jsxs)("div",{children:[(0,r.jsx)("label",{htmlFor:"appS",children:"Registration Starts"}),(0,r.jsx)(P.gN,{name:"appS",type:"date",validate:e=>{if(!e)return"Registration Start date is required"}}),(0,r.jsx)(P.Bc,{name:"appS"})]}),(0,r.jsxs)("div",{children:[(0,r.jsx)("label",{htmlFor:"appE",children:"Registration Ends"}),(0,r.jsx)(P.gN,{name:"appE",type:"date",validate:e=>{if(!e)return"Registration End date is required"}})]}),(0,r.jsxs)("div",{children:[(0,r.jsx)("label",{htmlFor:"eventS",children:"Conference Beings"}),(0,r.jsx)(P.gN,{name:"eventS",type:"date"}),(0,r.jsx)(P.Bc,{name:"eventS"})]}),(0,r.jsxs)("div",{children:[(0,r.jsx)("label",{htmlFor:"eventE",children:"Conference Ends"}),(0,r.jsx)(P.gN,{name:"eventE",type:"date"})]}),(0,r.jsx)("button",{type:"submit",disabled:t,children:"Submit"}),(0,r.jsx)(L.x7,{})]})}}):(0,r.jsx)(P.J9,{initialValues:{eventN:t.eventN,link:t.link,appS:t.appS,appE:t.appE,eventS:t.eventS,eventE:t.eventE,filters:t.filters,postedBy:t.postedBy},onSubmit:async e=>{e.postedBy=s,e.calID=t.calID?t.calID:"",L.ZP.loading("Adding ".concat(e.eventN," for the community")),await z("edit","Conferences",e,n)},children:e=>{let{isSubmitting:t}=e;return(0,r.jsxs)(P.l0,{children:[(0,r.jsxs)("div",{children:[(0,r.jsx)("label",{htmlFor:"eventN",children:"Conference Title"}),(0,r.jsx)(P.gN,{name:"eventN",placeholder:"Title",validate:e=>{if(!e)return"Conference Title is required"}}),(0,r.jsx)(P.Bc,{name:"eventN"})]}),(0,r.jsxs)("div",{children:[(0,r.jsx)("label",{htmlFor:"link",children:"Link"}),(0,r.jsx)(P.gN,{name:"link",placeholder:"Conference URL",validate:e=>{if(!e)return"Conference URL is required"}}),(0,r.jsx)(P.Bc,{name:"link"})]}),(0,r.jsx)("div",{id:"my-radio-group",children:"Picked"}),(0,r.jsxs)("div",{role:"group","aria-labelledby":"my-radio-group",children:[(0,r.jsxs)("label",{children:[(0,r.jsx)(P.gN,{type:"radio",name:"filters",value:"design"}),"Design"]}),(0,r.jsxs)("label",{children:[(0,r.jsx)(P.gN,{type:"radio",name:"filters",value:"launch event"}),"Launch Event"]})]}),(0,r.jsx)("label",{htmlFor:"appS",children:"Registration Begins"}),(0,r.jsx)(P.gN,{name:"appS",type:"date",validate:e=>{if(!e)return"Application Start date is required"}}),(0,r.jsx)("label",{htmlFor:"appE",children:"Registration Ends"}),(0,r.jsx)(P.gN,{name:"appE",type:"date",validate:e=>{if(!e)return"Application End date is required"}}),(0,r.jsx)("label",{htmlFor:"eventS",children:"Conference Beings"}),(0,r.jsx)(P.gN,{name:"eventS",type:"date"}),(0,r.jsx)("label",{htmlFor:"eventE",children:"Conference Ends"}),(0,r.jsx)(P.gN,{name:"eventE",type:"date"}),(0,r.jsx)("button",{type:"submit",disabled:t,children:"Submit"}),(0,r.jsx)(L.x7,{})]})}})}async function z(e,t,n,r,i){L.ZP.promise(fetch("/api/".concat(e,"/"),{method:"POST",headers:{Authorization:"".concat(r.accessToken),category:t,firestoreid:i||"","Content-Type":"application/json"},body:JSON.stringify(n)}).then(e=>{e.ok?(L.ZP.dismiss(),L.ZP.success("".concat(n.eventN," Added")),L.ZP.success("Thanks for your contribution ".concat(n.postedBy))):401==e.status?(L.ZP.dismiss(),L.ZP.success("".concat(n.eventN," Updated"))):(L.ZP.dismiss(),L.ZP.error("Error occurred while adding ".concat(n.eventN)))}))}var G=n(24),W=n(1163);function H(e){let{eventData:t}=e,{user:n,username:s}=(0,i.useContext)(j.S),o=(0,W.useRouter)(),[a,l]=(0,i.useState)(!1),u=()=>{if(s)l(!0);else{o.push("/enter");return}},c=()=>l(!1),[h]=(0,G.KO)(M.m9);return null!=t?(0,r.jsxs)("div",{children:[(0,r.jsx)("button",{onClick:u,children:"Update "+t.eventN}),(0,r.jsx)(O,{open:a,onClose:c,center:!0,children:(0,r.jsx)(F,{eventData:t,categoryTest:h})})]}):(0,r.jsxs)("div",{children:[(0,r.jsx)("button",{onClick:u,children:"Add Opp"}),(0,r.jsx)(O,{open:a,onClose:c,center:!0,children:(0,r.jsx)(U,{eventData:t})})]})}},8104:function(e,t,n){"use strict";n.d(t,{Tq:function(){return o},m9:function(){return s}});var r=n(24);let i=(0,r.cn)("hello");(0,r.cn)(e=>e(i),(e,t,n)=>t(i,n));let s=(0,r.cn)("hackathon");(0,r.cn)(e=>e(i),(e,t,n)=>t(i,n));let o=(0,r.cn)("all");(0,r.cn)(e=>e(i),(e,t,n)=>t(i,n))},8059:function(e,t,n){"use strict";n.d(t,{S:function(){return i}});var r=n(7294);let i=(0,r.createContext)({user:null,username:null})},3963:function(e,t,n){"use strict";let r,i,s,o,a,l,u,c,h,d,f;n.d(t,{mC:function(){return g0},I8:function(){return gY},RZ:function(){return gJ},qV:function(){return gX},tO:function(){return gZ}});var p,m,g,y,v,_,w,b,I,T,E,S=n(4444),k=n(8463),x=n(5816),C=n(3333);/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class N{constructor(e,t){this._delegate=e,this.firebase=t,(0,x._addComponent)(e,new k.wA("app-compat",()=>this,"PUBLIC")),this.container=e.container}get automaticDataCollectionEnabled(){return this._delegate.automaticDataCollectionEnabled}set automaticDataCollectionEnabled(e){this._delegate.automaticDataCollectionEnabled=e}get name(){return this._delegate.name}get options(){return this._delegate.options}delete(){return new Promise(e=>{this._delegate.checkDestroyed(),e()}).then(()=>(this.firebase.INTERNAL.removeApp(this.name),(0,x.deleteApp)(this._delegate)))}_getService(e,t=x._DEFAULT_ENTRY_NAME){var n;this._delegate.checkDestroyed();let r=this._delegate.container.getProvider(e);return r.isInitialized()||(null===(n=r.getComponent())||void 0===n?void 0:n.instantiationMode)!=="EXPLICIT"||r.initialize(),r.getImmediate({identifier:t})}_removeServiceInstance(e,t=x._DEFAULT_ENTRY_NAME){this._delegate.container.getProvider(e).clearInstance(t)}_addComponent(e){(0,x._addComponent)(this._delegate,e)}_addOrOverwriteComponent(e){(0,x._addOrOverwriteComponent)(this._delegate,e)}toJSON(){return{name:this.name,automaticDataCollectionEnabled:this.automaticDataCollectionEnabled,options:this.options}}}let A=new S.LL("app-compat","Firebase",{"no-app":"No Firebase App '{$appName}' has been created - call Firebase App.initializeApp()","invalid-app-argument":"firebase.{$appName}() takes either no argument or a Firebase App instance."}),R=/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function e(){let t=/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function(e){let t={},n={__esModule:!0,initializeApp:function(r,i={}){let s=x.initializeApp(r,i);if((0,S.r3)(t,s.name))return t[s.name];let o=new e(s,n);return t[s.name]=o,o},app:r,registerVersion:x.registerVersion,setLogLevel:x.setLogLevel,onLog:x.onLog,apps:null,SDK_VERSION:x.SDK_VERSION,INTERNAL:{registerComponent:function(t){let i=t.name,s=i.replace("-compat","");if(x._registerComponent(t)&&"PUBLIC"===t.type){let o=(e=r())=>{if("function"!=typeof e[s])throw A.create("invalid-app-argument",{appName:i});return e[s]()};void 0!==t.serviceProps&&(0,S.ZB)(o,t.serviceProps),n[s]=o,e.prototype[s]=function(...e){let n=this._getService.bind(this,i);return n.apply(this,t.multipleInstances?e:[])}}return"PUBLIC"===t.type?n[s]:null},removeApp:function(e){delete t[e]},useAsService:function(e,t){return"serverAuth"===t?null:t},modularAPIs:x}};function r(e){if(e=e||x._DEFAULT_ENTRY_NAME,!(0,S.r3)(t,e))throw A.create("no-app",{appName:e});return t[e]}return n.default=n,Object.defineProperty(n,"apps",{get:function(){return Object.keys(t).map(e=>t[e])}}),r.App=e,n}(N);return t.INTERNAL=Object.assign(Object.assign({},t.INTERNAL),{createFirebaseNamespace:e,extendNamespace:function(e){(0,S.ZB)(t,e)},createSubscribe:S.ne,ErrorFactory:S.LL,deepExtend:S.ZB}),t}(),D=new C.Yd("@firebase/app-compat");/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */if((0,S.jU)()&&void 0!==self.firebase){D.warn(`
    Warning: Firebase is already defined in the global scope. Please make sure
    Firebase library is only loaded once.
  `);let O=self.firebase.SDK_VERSION;O&&O.indexOf("LITE")>=0&&D.warn(`
    Warning: You are trying to load Firebase while using Firebase Performance standalone script.
    You should load Firebase Performance with this instance of Firebase to avoid loading duplicate code.
    `)}(0,x.registerVersion)("@firebase/app-compat","0.1.37",void 0),/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */R.registerVersion("firebase","9.12.1","app-compat");var P=n(6660);/**
 * @license
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function L(){return window}async function M(e,t,n){var r;let{BuildInfo:i}=L();(0,P.aq)(t.sessionId,"AuthEvent did not contain a session ID");let s=await U(t.sessionId),o={};return(0,P.ar)()?o.ibi=i.packageName:(0,P.as)()?o.apn=i.packageName:(0,P.at)(e,"operation-not-supported-in-this-environment"),i.displayName&&(o.appDisplayName=i.displayName),o.sessionId=s,(0,P.au)(e,n,t.type,void 0,null!==(r=t.eventId)&&void 0!==r?r:void 0,o)}async function j(e){let{BuildInfo:t}=L(),n={};(0,P.ar)()?n.iosBundleId=t.packageName:(0,P.as)()?n.androidPackageName=t.packageName:(0,P.at)(e,"operation-not-supported-in-this-environment"),await (0,P.av)(e,n)}async function F(e,t,n){let{cordova:r}=L(),i=()=>{};try{await new Promise((s,o)=>{let a=null;function l(){var e;s();let t=null===(e=r.plugins.browsertab)||void 0===e?void 0:e.close;"function"==typeof t&&t(),"function"==typeof(null==n?void 0:n.close)&&n.close()}function u(){a||(a=window.setTimeout(()=>{o((0,P.aw)(e,"redirect-cancelled-by-user"))},2e3))}function c(){(null==document?void 0:document.visibilityState)==="visible"&&u()}t.addPassiveListener(l),document.addEventListener("resume",u,!1),(0,P.as)()&&document.addEventListener("visibilitychange",c,!1),i=()=>{t.removePassiveListener(l),document.removeEventListener("resume",u,!1),document.removeEventListener("visibilitychange",c,!1),a&&window.clearTimeout(a)}})}finally{i()}}async function U(e){let t=function(e){if((0,P.aq)(/[0-9a-zA-Z]+/.test(e),"Can only convert alpha-numeric strings"),"undefined"!=typeof TextEncoder)return new TextEncoder().encode(e);let t=new ArrayBuffer(e.length),n=new Uint8Array(t);for(let r=0;r<e.length;r++)n[r]=e.charCodeAt(r);return n}(e),n=await crypto.subtle.digest("SHA-256",t),r=Array.from(new Uint8Array(n));return r.map(e=>e.toString(16).padStart(2,"0")).join("")}class V extends P.aA{constructor(){super(...arguments),this.passiveListeners=new Set,this.initPromise=new Promise(e=>{this.resolveInialized=e})}addPassiveListener(e){this.passiveListeners.add(e)}removePassiveListener(e){this.passiveListeners.delete(e)}resetRedirect(){this.queuedRedirectEvent=null,this.hasHandledPotentialRedirect=!1}onEvent(e){return this.resolveInialized(),this.passiveListeners.forEach(t=>t(e)),super.onEvent(e)}async initialized(){await this.initPromise}}async function q(e){let t=await B()._get($(e));return t&&await B()._remove($(e)),t}function B(){return(0,P.ay)(P.b)}function $(e){return(0,P.az)("authEvent",e.config.apiKey,e.name)}function z(e){if(!(null==e?void 0:e.includes("?")))return{};let[t,...n]=e.split("?");return(0,S.zd)(n.join("?"))}let G=class{constructor(){this._redirectPersistence=P.a,this._shouldInitProactively=!0,this.eventManagers=new Map,this.originValidationPromises={},this._completeRedirectFn=P.aB,this._overrideRedirectResult=P.aC}async _initialize(e){let t=e._key(),n=this.eventManagers.get(t);return n||(n=new V(e),this.eventManagers.set(t,n),this.attachCallbackListeners(e,n)),n}_openPopup(e){(0,P.at)(e,"operation-not-supported-in-this-environment")}async _openRedirect(e,t,n,r){!function(e){var t,n,r,i,s,o,a,l,u,c;let h=L();(0,P.ax)("function"==typeof(null===(t=null==h?void 0:h.universalLinks)||void 0===t?void 0:t.subscribe),e,"invalid-cordova-configuration",{missingPlugin:"cordova-universal-links-plugin-fix"}),(0,P.ax)(void 0!==(null===(n=null==h?void 0:h.BuildInfo)||void 0===n?void 0:n.packageName),e,"invalid-cordova-configuration",{missingPlugin:"cordova-plugin-buildInfo"}),(0,P.ax)("function"==typeof(null===(s=null===(i=null===(r=null==h?void 0:h.cordova)||void 0===r?void 0:r.plugins)||void 0===i?void 0:i.browsertab)||void 0===s?void 0:s.openUrl),e,"invalid-cordova-configuration",{missingPlugin:"cordova-plugin-browsertab"}),(0,P.ax)("function"==typeof(null===(l=null===(a=null===(o=null==h?void 0:h.cordova)||void 0===o?void 0:o.plugins)||void 0===a?void 0:a.browsertab)||void 0===l?void 0:l.isAvailable),e,"invalid-cordova-configuration",{missingPlugin:"cordova-plugin-browsertab"}),(0,P.ax)("function"==typeof(null===(c=null===(u=null==h?void 0:h.cordova)||void 0===u?void 0:u.InAppBrowser)||void 0===c?void 0:c.open),e,"invalid-cordova-configuration",{missingPlugin:"cordova-plugin-inappbrowser"})}(e);let i=await this._initialize(e);await i.initialized(),i.resetRedirect(),(0,P.aD)(),await this._originValidation(e);let s=function(e,t,n=null){return{type:t,eventId:n,urlResponse:null,sessionId:function(){let e=[],t="1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";for(let n=0;n<20;n++){let r=Math.floor(Math.random()*t.length);e.push(t.charAt(r))}return e.join("")}(),postBody:null,tenantId:e.tenantId,error:(0,P.aw)(e,"no-auth-event")}}(e,n,r);await B()._set($(e),s);let o=await M(e,s,t),a=await function(e){let{cordova:t}=L();return new Promise(n=>{t.plugins.browsertab.isAvailable(r=>{let i=null;r?t.plugins.browsertab.openUrl(e):i=t.InAppBrowser.open(e,(0,P.ap)()?"_blank":"_system","location=yes"),n(i)})})}(o);return F(e,i,a)}_isIframeWebStorageSupported(e,t){throw Error("Method not implemented.")}_originValidation(e){let t=e._key();return this.originValidationPromises[t]||(this.originValidationPromises[t]=j(e)),this.originValidationPromises[t]}attachCallbackListeners(e,t){let{universalLinks:n,handleOpenURL:r,BuildInfo:i}=L(),s=setTimeout(async()=>{await q(e),t.onEvent(W())},500),o=async n=>{clearTimeout(s);let r=await q(e),i=null;r&&(null==n?void 0:n.url)&&(i=function(e,t){var n,r;let i=function(e){let t=z(e),n=t.link?decodeURIComponent(t.link):void 0,r=z(n).link,i=t.deep_link_id?decodeURIComponent(t.deep_link_id):void 0,s=z(i).link;return s||i||r||n||e}(t);if(i.includes("/__/auth/callback")){let s=z(i),o=s.firebaseError?function(e){try{return JSON.parse(e)}catch(t){return null}}(decodeURIComponent(s.firebaseError)):null,a=null===(r=null===(n=null==o?void 0:o.code)||void 0===n?void 0:n.split("auth/"))||void 0===r?void 0:r[1],l=a?(0,P.aw)(a):null;return l?{type:e.type,eventId:e.eventId,tenantId:e.tenantId,error:l,urlResponse:null,sessionId:null,postBody:null}:{type:e.type,eventId:e.eventId,tenantId:e.tenantId,sessionId:e.sessionId,urlResponse:i,postBody:null}}return null}(r,n.url)),t.onEvent(i||W())};void 0!==n&&"function"==typeof n.subscribe&&n.subscribe(null,o);let a=`${i.packageName.toLowerCase()}://`;L().handleOpenURL=async e=>{if(e.toLowerCase().startsWith(a)&&o({url:e}),"function"==typeof r)try{r(e)}catch(t){console.error(t)}}}};function W(){return{type:"unknown",eventId:null,sessionId:null,urlResponse:null,postBody:null,tenantId:null,error:(0,P.aw)("no-auth-event")}}function H(){var e;return(null===(e=null==self?void 0:self.location)||void 0===e?void 0:e.protocol)||null}function K(e=(0,S.z$)()){return!!(("file:"===H()||"ionic:"===H()||"capacitor:"===H())&&e.toLowerCase().match(/iphone|ipad|ipod|android/))}function Q(){try{let e=self.localStorage,t=P.aI();if(e){if(e.setItem(t,"1"),e.removeItem(t),function(e=(0,S.z$)()){return(0,S.w1)()&&(null==document?void 0:document.documentMode)===11||function(e=(0,S.z$)()){return/Edge\/\d+/.test(e)}(e)}())return(0,S.hl)();return!0}}catch(n){return Y()&&(0,S.hl)()}return!1}function Y(){return void 0!==n.g&&"WorkerGlobalScope"in n.g&&"importScripts"in n.g}function X(){return("http:"===H()||"https:"===H()||(0,S.ru)()||K())&&!((0,S.b$)()||(0,S.UG)())&&Q()&&!Y()}function J(){return K()&&"undefined"!=typeof document}async function Z(){return!!J()&&new Promise(e=>{let t=setTimeout(()=>{e(!1)},1e3);document.addEventListener("deviceready",()=>{clearTimeout(t),e(!0)})})}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let ee={LOCAL:"local",NONE:"none",SESSION:"session"},et=P.ax,en="persistence";async function er(e){await e._initializationPromise;let t=ei(),n=P.az(en,e.config.apiKey,e.name);t&&t.setItem(n,e._getPersistence())}function ei(){var e;try{return(null===(e="undefined"!=typeof window?window:null)||void 0===e?void 0:e.sessionStorage)||null}catch(t){return null}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let es=P.ax;class eo{constructor(){this.browserResolver=P.ay(P.k),this.cordovaResolver=P.ay(G),this.underlyingResolver=null,this._redirectPersistence=P.a,this._completeRedirectFn=P.aB,this._overrideRedirectResult=P.aC}async _initialize(e){return await this.selectUnderlyingResolver(),this.assertedUnderlyingResolver._initialize(e)}async _openPopup(e,t,n,r){return await this.selectUnderlyingResolver(),this.assertedUnderlyingResolver._openPopup(e,t,n,r)}async _openRedirect(e,t,n,r){return await this.selectUnderlyingResolver(),this.assertedUnderlyingResolver._openRedirect(e,t,n,r)}_isIframeWebStorageSupported(e,t){this.assertedUnderlyingResolver._isIframeWebStorageSupported(e,t)}_originValidation(e){return this.assertedUnderlyingResolver._originValidation(e)}get _shouldInitProactively(){return J()||this.browserResolver._shouldInitProactively}get assertedUnderlyingResolver(){return es(this.underlyingResolver,"internal-error"),this.underlyingResolver}async selectUnderlyingResolver(){if(this.underlyingResolver)return;let e=await Z();this.underlyingResolver=e?this.cordovaResolver:this.browserResolver}}function ea(e){let t;let{_tokenResponse:n}=e instanceof S.ZR?e.customData:e;if(!n)return null;if(!(e instanceof S.ZR)&&"temporaryProof"in n&&"phoneNumber"in n)return P.P.credentialFromResult(e);let r=n.providerId;if(!r||r===P.o.PASSWORD)return null;switch(r){case P.o.GOOGLE:t=P.Q;break;case P.o.FACEBOOK:t=P.N;break;case P.o.GITHUB:t=P.T;break;case P.o.TWITTER:t=P.W;break;default:let{oauthIdToken:i,oauthAccessToken:s,oauthTokenSecret:o,pendingToken:a,nonce:l}=n;if(!s&&!o&&!i&&!a)return null;if(a){if(r.startsWith("saml."))return P.aL._create(r,a);return P.J._fromParams({providerId:r,signInMethod:r,pendingToken:a,idToken:i,accessToken:s})}return new P.U(r).credential({idToken:i,accessToken:s,rawNonce:l})}return e instanceof S.ZR?t.credentialFromError(e):t.credentialFromResult(e)}function el(e,t){return t.catch(t=>{throw t instanceof S.ZR&&function(e,t){var n;let r=null===(n=t.customData)||void 0===n?void 0:n._tokenResponse;if((null==t?void 0:t.code)==="auth/multi-factor-auth-required"){let i=t;i.resolver=new ec(e,P.an(e,t))}else if(r){let s=ea(t),o=t;s&&(o.credential=s,o.tenantId=r.tenantId||void 0,o.email=r.email||void 0,o.phoneNumber=r.phoneNumber||void 0)}}(e,t),t}).then(e=>{let t=e.operationType,n=e.user;return{operationType:t,credential:ea(e),additionalUserInfo:P.al(e),user:eh.getOrCreate(n)}})}async function eu(e,t){let n=await t;return{verificationId:n.verificationId,confirm:t=>el(e,n.confirm(t))}}class ec{constructor(e,t){this.resolver=t,this.auth=e.wrapped()}get session(){return this.resolver.session}get hints(){return this.resolver.hints}resolveSignIn(e){return el(this.auth.unwrap(),this.resolver.resolveSignIn(e))}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class eh{constructor(e){this._delegate=e,this.multiFactor=P.ao(e)}static getOrCreate(e){return eh.USER_MAP.has(e)||eh.USER_MAP.set(e,new eh(e)),eh.USER_MAP.get(e)}delete(){return this._delegate.delete()}reload(){return this._delegate.reload()}toJSON(){return this._delegate.toJSON()}getIdTokenResult(e){return this._delegate.getIdTokenResult(e)}getIdToken(e){return this._delegate.getIdToken(e)}linkAndRetrieveDataWithCredential(e){return this.linkWithCredential(e)}async linkWithCredential(e){return el(this.auth,P.Z(this._delegate,e))}async linkWithPhoneNumber(e,t){return eu(this.auth,P.l(this._delegate,e,t))}async linkWithPopup(e){return el(this.auth,P.d(this._delegate,e,eo))}async linkWithRedirect(e){return await er(P.aE(this.auth)),P.g(this._delegate,e,eo)}reauthenticateAndRetrieveDataWithCredential(e){return this.reauthenticateWithCredential(e)}async reauthenticateWithCredential(e){return el(this.auth,P._(this._delegate,e))}reauthenticateWithPhoneNumber(e,t){return eu(this.auth,P.r(this._delegate,e,t))}reauthenticateWithPopup(e){return el(this.auth,P.e(this._delegate,e,eo))}async reauthenticateWithRedirect(e){return await er(P.aE(this.auth)),P.h(this._delegate,e,eo)}sendEmailVerification(e){return P.ab(this._delegate,e)}async unlink(e){return await P.ak(this._delegate,e),this}updateEmail(e){return P.ag(this._delegate,e)}updatePassword(e){return P.ah(this._delegate,e)}updatePhoneNumber(e){return P.u(this._delegate,e)}updateProfile(e){return P.af(this._delegate,e)}verifyBeforeUpdateEmail(e,t){return P.ac(this._delegate,e,t)}get emailVerified(){return this._delegate.emailVerified}get isAnonymous(){return this._delegate.isAnonymous}get metadata(){return this._delegate.metadata}get phoneNumber(){return this._delegate.phoneNumber}get providerData(){return this._delegate.providerData}get refreshToken(){return this._delegate.refreshToken}get tenantId(){return this._delegate.tenantId}get displayName(){return this._delegate.displayName}get email(){return this._delegate.email}get photoURL(){return this._delegate.photoURL}get providerId(){return this._delegate.providerId}get uid(){return this._delegate.uid}get auth(){return this._delegate.auth}}eh.USER_MAP=new WeakMap;/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let ed=P.ax;class ef{constructor(e,t){if(this.app=e,t.isInitialized()){this._delegate=t.getImmediate(),this.linkUnderlyingAuth();return}let{apiKey:n}=e.options;ed(n,"invalid-api-key",{appName:e.name}),ed(n,"invalid-api-key",{appName:e.name});let r="undefined"!=typeof window?eo:void 0;this._delegate=t.initialize({options:{persistence:function(e,t){let n=function(e,t){let n=ei();if(!n)return[];let r=P.az(en,e,t),i=n.getItem(r);switch(i){case ee.NONE:return[P.L];case ee.LOCAL:return[P.i,P.a];case ee.SESSION:return[P.a];default:return[]}}(e,t);if("undefined"==typeof self||n.includes(P.i)||n.push(P.i),"undefined"!=typeof window)for(let r of[P.b,P.a])n.includes(r)||n.push(r);return n.includes(P.L)||n.push(P.L),n}(n,e.name),popupRedirectResolver:r}}),this._delegate._updateErrorMap(P.B),this.linkUnderlyingAuth()}get emulatorConfig(){return this._delegate.emulatorConfig}get currentUser(){return this._delegate.currentUser?eh.getOrCreate(this._delegate.currentUser):null}get languageCode(){return this._delegate.languageCode}set languageCode(e){this._delegate.languageCode=e}get settings(){return this._delegate.settings}get tenantId(){return this._delegate.tenantId}set tenantId(e){this._delegate.tenantId=e}useDeviceLanguage(){this._delegate.useDeviceLanguage()}signOut(){return this._delegate.signOut()}useEmulator(e,t){P.G(this._delegate,e,t)}applyActionCode(e){return P.a2(this._delegate,e)}checkActionCode(e){return P.a3(this._delegate,e)}confirmPasswordReset(e,t){return P.a1(this._delegate,e,t)}async createUserWithEmailAndPassword(e,t){return el(this._delegate,P.a5(this._delegate,e,t))}fetchProvidersForEmail(e){return this.fetchSignInMethodsForEmail(e)}fetchSignInMethodsForEmail(e){return P.aa(this._delegate,e)}isSignInWithEmailLink(e){return P.a8(this._delegate,e)}async getRedirectResult(){ed(X(),this._delegate,"operation-not-supported-in-this-environment");let e=await P.j(this._delegate,eo);return e?el(this._delegate,Promise.resolve(e)):{credential:null,user:null}}addFrameworkForLogging(e){!/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function(e,t){(0,P.aE)(e)._logFramework(t)}(this._delegate,e)}onAuthStateChanged(e,t,n){let{next:r,error:i,complete:s}=ep(e,t,n);return this._delegate.onAuthStateChanged(r,i,s)}onIdTokenChanged(e,t,n){let{next:r,error:i,complete:s}=ep(e,t,n);return this._delegate.onIdTokenChanged(r,i,s)}sendSignInLinkToEmail(e,t){return P.a7(this._delegate,e,t)}sendPasswordResetEmail(e,t){return P.a0(this._delegate,e,t||void 0)}async setPersistence(e){let t;switch(!function(e,t){if(et(Object.values(ee).includes(t),e,"invalid-persistence-type"),(0,S.b$)()){et(t!==ee.SESSION,e,"unsupported-persistence-type");return}if((0,S.UG)()){et(t===ee.NONE,e,"unsupported-persistence-type");return}if(Y()){et(t===ee.NONE||t===ee.LOCAL&&(0,S.hl)(),e,"unsupported-persistence-type");return}et(t===ee.NONE||Q(),e,"unsupported-persistence-type")}(this._delegate,e),e){case ee.SESSION:t=P.a;break;case ee.LOCAL:let n=await P.ay(P.i)._isAvailable();t=n?P.i:P.b;break;case ee.NONE:t=P.L;break;default:return P.at("argument-error",{appName:this._delegate.name})}return this._delegate.setPersistence(t)}signInAndRetrieveDataWithCredential(e){return this.signInWithCredential(e)}signInAnonymously(){return el(this._delegate,P.X(this._delegate))}signInWithCredential(e){return el(this._delegate,P.Y(this._delegate,e))}signInWithCustomToken(e){return el(this._delegate,P.$(this._delegate,e))}signInWithEmailAndPassword(e,t){return el(this._delegate,P.a6(this._delegate,e,t))}signInWithEmailLink(e,t){return el(this._delegate,P.a9(this._delegate,e,t))}signInWithPhoneNumber(e,t){return eu(this._delegate,P.s(this._delegate,e,t))}async signInWithPopup(e){return ed(X(),this._delegate,"operation-not-supported-in-this-environment"),el(this._delegate,P.c(this._delegate,e,eo))}async signInWithRedirect(e){return ed(X(),this._delegate,"operation-not-supported-in-this-environment"),await er(this._delegate),P.f(this._delegate,e,eo)}updateCurrentUser(e){return this._delegate.updateCurrentUser(e)}verifyPasswordResetCode(e){return P.a4(this._delegate,e)}unwrap(){return this._delegate}_delete(){return this._delegate._delete()}linkUnderlyingAuth(){this._delegate.wrapped=()=>this}}function ep(e,t,n){let r=e;"function"!=typeof e&&({next:r,error:t,complete:n}=e);let i=r,s=e=>i(e&&eh.getOrCreate(e));return{next:s,error:t,complete:n}}ef.Persistence=ee;/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class em{constructor(){this.providerId="phone",this._delegate=new P.P(R.auth().unwrap())}static credential(e,t){return P.P.credential(e,t)}verifyPhoneNumber(e,t){return this._delegate.verifyPhoneNumber(e,t)}unwrap(){return this._delegate}}em.PHONE_SIGN_IN_METHOD=P.P.PHONE_SIGN_IN_METHOD,em.PROVIDER_ID=P.P.PROVIDER_ID;/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let eg=P.ax;R.INTERNAL.registerComponent(new k.wA("auth-compat",e=>{let t=e.getProvider("app-compat").getImmediate(),n=e.getProvider("auth");return new ef(t,n)},"PUBLIC").setServiceProps({ActionCodeInfo:{Operation:{EMAIL_SIGNIN:P.A.EMAIL_SIGNIN,PASSWORD_RESET:P.A.PASSWORD_RESET,RECOVER_EMAIL:P.A.RECOVER_EMAIL,REVERT_SECOND_FACTOR_ADDITION:P.A.REVERT_SECOND_FACTOR_ADDITION,VERIFY_AND_CHANGE_EMAIL:P.A.VERIFY_AND_CHANGE_EMAIL,VERIFY_EMAIL:P.A.VERIFY_EMAIL}},EmailAuthProvider:P.M,FacebookAuthProvider:P.N,GithubAuthProvider:P.T,GoogleAuthProvider:P.Q,OAuthProvider:P.U,SAMLAuthProvider:P.V,PhoneAuthProvider:em,PhoneMultiFactorGenerator:P.m,RecaptchaVerifier:class{constructor(e,t,n=R.app()){var r;eg(null===(r=n.options)||void 0===r?void 0:r.apiKey,"invalid-api-key",{appName:n.name}),this._delegate=new P.R(e,t,n.auth()),this.type=this._delegate.type}clear(){this._delegate.clear()}render(){return this._delegate.render()}verify(){return this._delegate.verify()}},TwitterAuthProvider:P.W,Auth:ef,AuthCredential:P.H,Error:S.ZR}).setInstantiationMode("LAZY").setMultipleInstances(!1)),R.registerVersion("@firebase/auth-compat","0.2.23");var ey,ev="undefined"!=typeof globalThis?globalThis:"undefined"!=typeof window?window:void 0!==n.g?n.g:"undefined"!=typeof self?self:{},e_={},ew=ew||{},eb=ev||self;function eI(){}function eT(e){var t=typeof e;return"array"==(t="object"!=t?t:e?Array.isArray(e)?"array":t:"null")||"object"==t&&"number"==typeof e.length}function eE(e){var t=typeof e;return"object"==t&&null!=e||"function"==t}function eS(e,t,n){return e.call.apply(e.bind,arguments)}function ek(e,t,n){if(!e)throw Error();if(2<arguments.length){var r=Array.prototype.slice.call(arguments,2);return function(){var n=Array.prototype.slice.call(arguments);return Array.prototype.unshift.apply(n,r),e.apply(t,n)}}return function(){return e.apply(t,arguments)}}function ex(e,t,n){return(ex=Function.prototype.bind&&-1!=Function.prototype.bind.toString().indexOf("native code")?eS:ek).apply(null,arguments)}function eC(e,t){var n=Array.prototype.slice.call(arguments,1);return function(){var t=n.slice();return t.push.apply(t,arguments),e.apply(this,t)}}function eN(e,t){function n(){}n.prototype=t.prototype,e.X=t.prototype,e.prototype=new n,e.prototype.constructor=e,e.Wb=function(e,n,r){for(var i=Array(arguments.length-2),s=2;s<arguments.length;s++)i[s-2]=arguments[s];return t.prototype[n].apply(e,i)}}function eA(){this.s=this.s,this.o=this.o}eA.prototype.s=!1,eA.prototype.na=function(){this.s||(this.s=!0,this.M())},eA.prototype.M=function(){if(this.o)for(;this.o.length;)this.o.shift()()};let eR=Array.prototype.indexOf?function(e,t){return Array.prototype.indexOf.call(e,t,void 0)}:function(e,t){if("string"==typeof e)return"string"!=typeof t||1!=t.length?-1:e.indexOf(t,0);for(let n=0;n<e.length;n++)if(n in e&&e[n]===t)return n;return -1};function eD(e){let t=e.length;if(0<t){let n=Array(t);for(let r=0;r<t;r++)n[r]=e[r];return n}return[]}function eO(e,t){for(let n=1;n<arguments.length;n++){let r=arguments[n];if(eT(r)){let i=e.length||0,s=r.length||0;e.length=i+s;for(let o=0;o<s;o++)e[i+o]=r[o]}else e.push(r)}}function eP(e,t){this.type=e,this.g=this.target=t,this.defaultPrevented=!1}eP.prototype.h=function(){this.defaultPrevented=!0};var eL=function(){if(!eb.addEventListener||!Object.defineProperty)return!1;var e=!1,t=Object.defineProperty({},"passive",{get:function(){e=!0}});try{eb.addEventListener("test",eI,t),eb.removeEventListener("test",eI,t)}catch(n){}return e}();function eM(e){return/^[\s\xa0]*$/.test(e)}var ej=String.prototype.trim?function(e){return e.trim()}:function(e){return/^[\s\xa0]*([\s\S]*?)[\s\xa0]*$/.exec(e)[1]};function eF(e,t){return e<t?-1:e>t?1:0}function eU(){var e=eb.navigator;return e&&(e=e.userAgent)?e:""}function eV(e){return -1!=eU().indexOf(e)}function eq(e){return eq[" "](e),e}eq[" "]=eI;var eB=eV("Opera"),e$=eV("Trident")||eV("MSIE"),ez=eV("Edge"),eG=ez||e$,eW=eV("Gecko")&&!(-1!=eU().toLowerCase().indexOf("webkit")&&!eV("Edge"))&&!(eV("Trident")||eV("MSIE"))&&!eV("Edge"),eH=-1!=eU().toLowerCase().indexOf("webkit")&&!eV("Edge");function eK(){var e=eb.document;return e?e.documentMode:void 0}e:{var eQ,eY="",eX=(eQ=eU(),eW?/rv:([^\);]+)(\)|;)/.exec(eQ):ez?/Edge\/([\d\.]+)/.exec(eQ):e$?/\b(?:MSIE|rv)[: ]([^\);]+)(\)|;)/.exec(eQ):eH?/WebKit\/(\S+)/.exec(eQ):eB?/(?:Version)[ \/]?(\S+)/.exec(eQ):void 0);if(eX&&(eY=eX?eX[1]:""),e$){var eJ=eK();if(null!=eJ&&eJ>parseFloat(eY)){y=String(eJ);break e}}y=eY}var eZ={},e0=eb.document&&e$&&(eK()||parseInt(y,10))||void 0;function e1(e,t){if(eP.call(this,e?e.type:""),this.relatedTarget=this.g=this.target=null,this.button=this.screenY=this.screenX=this.clientY=this.clientX=0,this.key="",this.metaKey=this.shiftKey=this.altKey=this.ctrlKey=!1,this.state=null,this.pointerId=0,this.pointerType="",this.i=null,e){var n=this.type=e.type,r=e.changedTouches&&e.changedTouches.length?e.changedTouches[0]:null;if(this.target=e.target||e.srcElement,this.g=t,t=e.relatedTarget){if(eW){e:{try{eq(t.nodeName);var i=!0;break e}catch(s){}i=!1}i||(t=null)}}else"mouseover"==n?t=e.fromElement:"mouseout"==n&&(t=e.toElement);this.relatedTarget=t,r?(this.clientX=void 0!==r.clientX?r.clientX:r.pageX,this.clientY=void 0!==r.clientY?r.clientY:r.pageY,this.screenX=r.screenX||0,this.screenY=r.screenY||0):(this.clientX=void 0!==e.clientX?e.clientX:e.pageX,this.clientY=void 0!==e.clientY?e.clientY:e.pageY,this.screenX=e.screenX||0,this.screenY=e.screenY||0),this.button=e.button,this.key=e.key||"",this.ctrlKey=e.ctrlKey,this.altKey=e.altKey,this.shiftKey=e.shiftKey,this.metaKey=e.metaKey,this.pointerId=e.pointerId||0,this.pointerType="string"==typeof e.pointerType?e.pointerType:e2[e.pointerType]||"",this.state=e.state,this.i=e,e.defaultPrevented&&e1.X.h.call(this)}}eN(e1,eP);var e2={2:"touch",3:"pen",4:"mouse"};e1.prototype.h=function(){e1.X.h.call(this);var e=this.i;e.preventDefault?e.preventDefault():e.returnValue=!1};var e3="closure_listenable_"+(1e6*Math.random()|0),e4=0;function e6(e,t,n,r,i){this.listener=e,this.proxy=null,this.src=t,this.type=n,this.capture=!!r,this.ha=i,this.key=++e4,this.ba=this.ea=!1}function e5(e){e.ba=!0,e.listener=null,e.proxy=null,e.src=null,e.ha=null}function e8(e,t,n){for(let r in e)t.call(n,e[r],r,e)}function e9(e){let t={};for(let n in e)t[n]=e[n];return t}let e7="constructor hasOwnProperty isPrototypeOf propertyIsEnumerable toLocaleString toString valueOf".split(" ");function te(e,t){let n,r;for(let i=1;i<arguments.length;i++){for(n in r=arguments[i])e[n]=r[n];for(let s=0;s<e7.length;s++)n=e7[s],Object.prototype.hasOwnProperty.call(r,n)&&(e[n]=r[n])}}function tt(e){this.src=e,this.g={},this.h=0}function tn(e,t){var n=t.type;if(n in e.g){var r,i=e.g[n],s=eR(i,t);(r=0<=s)&&Array.prototype.splice.call(i,s,1),r&&(e5(t),0==e.g[n].length&&(delete e.g[n],e.h--))}}function tr(e,t,n,r){for(var i=0;i<e.length;++i){var s=e[i];if(!s.ba&&s.listener==t&&!!n==s.capture&&s.ha==r)return i}return -1}tt.prototype.add=function(e,t,n,r,i){var s=e.toString();(e=this.g[s])||(e=this.g[s]=[],this.h++);var o=tr(e,t,r,i);return -1<o?(t=e[o],n||(t.ea=!1)):((t=new e6(t,this.src,s,!!r,i)).ea=n,e.push(t)),t};var ti="closure_lm_"+(1e6*Math.random()|0),ts={};function to(e,t,n,r,i,s){if(!t)throw Error("Invalid event type");var o=eE(i)?!!i.capture:!!i,a=tc(e);if(a||(e[ti]=a=new tt(e)),(n=a.add(t,n,r,o,s)).proxy)return n;if(r=function e(t){return tu.call(e.src,e.listener,t)},n.proxy=r,r.src=e,r.listener=n,e.addEventListener)eL||(i=o),void 0===i&&(i=!1),e.addEventListener(t.toString(),r,i);else if(e.attachEvent)e.attachEvent(tl(t.toString()),r);else if(e.addListener&&e.removeListener)e.addListener(r);else throw Error("addEventListener and attachEvent are unavailable.");return n}function ta(e){if("number"!=typeof e&&e&&!e.ba){var t=e.src;if(t&&t[e3])tn(t.i,e);else{var n=e.type,r=e.proxy;t.removeEventListener?t.removeEventListener(n,r,e.capture):t.detachEvent?t.detachEvent(tl(n),r):t.addListener&&t.removeListener&&t.removeListener(r),(n=tc(t))?(tn(n,e),0==n.h&&(n.src=null,t[ti]=null)):e5(e)}}}function tl(e){return e in ts?ts[e]:ts[e]="on"+e}function tu(e,t){if(e.ba)e=!0;else{t=new e1(t,this);var n=e.listener,r=e.ha||e.src;e.ea&&ta(e),e=n.call(r,t)}return e}function tc(e){return(e=e[ti])instanceof tt?e:null}var th="__closure_events_fn_"+(1e9*Math.random()>>>0);function td(e){return"function"==typeof e?e:(e[th]||(e[th]=function(t){return e.handleEvent(t)}),e[th])}function tf(){eA.call(this),this.i=new tt(this),this.P=this,this.I=null}function tp(e,t){var n,r=e.I;if(r)for(n=[];r;r=r.I)n.push(r);if(e=e.P,r=t.type||t,"string"==typeof t)t=new eP(t,e);else if(t instanceof eP)t.target=t.target||e;else{var i=t;te(t=new eP(r,e),i)}if(i=!0,n)for(var s=n.length-1;0<=s;s--){var o=t.g=n[s];i=tm(o,r,!0,t)&&i}if(i=tm(o=t.g=e,r,!0,t)&&i,i=tm(o,r,!1,t)&&i,n)for(s=0;s<n.length;s++)i=tm(o=t.g=n[s],r,!1,t)&&i}function tm(e,t,n,r){if(!(t=e.i.g[String(t)]))return!0;t=t.concat();for(var i=!0,s=0;s<t.length;++s){var o=t[s];if(o&&!o.ba&&o.capture==n){var a=o.listener,l=o.ha||o.src;o.ea&&tn(e.i,o),i=!1!==a.call(l,r)&&i}}return i&&!r.defaultPrevented}eN(tf,eA),tf.prototype[e3]=!0,tf.prototype.removeEventListener=function(e,t,n,r){!function e(t,n,r,i,s){if(Array.isArray(n))for(var o=0;o<n.length;o++)e(t,n[o],r,i,s);else(i=eE(i)?!!i.capture:!!i,r=td(r),t&&t[e3])?(t=t.i,(n=String(n).toString())in t.g&&-1<(r=tr(o=t.g[n],r,i,s))&&(e5(o[r]),Array.prototype.splice.call(o,r,1),0==o.length&&(delete t.g[n],t.h--))):t&&(t=tc(t))&&(n=t.g[n.toString()],t=-1,n&&(t=tr(n,r,i,s)),(r=-1<t?n[t]:null)&&ta(r))}(this,e,t,n,r)},tf.prototype.M=function(){if(tf.X.M.call(this),this.i){var e,t=this.i;for(e in t.g){for(var n=t.g[e],r=0;r<n.length;r++)e5(n[r]);delete t.g[e],t.h--}}this.I=null},tf.prototype.N=function(e,t,n,r){return this.i.add(String(e),t,!1,n,r)},tf.prototype.O=function(e,t,n,r){return this.i.add(String(e),t,!0,n,r)};var tg=eb.JSON.stringify,ty=new class{constructor(e,t){this.i=e,this.j=t,this.h=0,this.g=null}get(){let e;return 0<this.h?(this.h--,e=this.g,this.g=e.next,e.next=null):e=this.i(),e}}(()=>new tv,e=>e.reset());class tv{constructor(){this.next=this.g=this.h=null}set(e,t){this.h=e,this.g=t,this.next=null}reset(){this.next=this.g=this.h=null}}function t_(e,t){var n;_||(n=eb.Promise.resolve(void 0),_=function(){n.then(tI)}),tw||(_(),tw=!0),tb.add(e,t)}var tw=!1,tb=new class{constructor(){this.h=this.g=null}add(e,t){let n=ty.get();n.set(e,t),this.h?this.h.next=n:this.g=n,this.h=n}};function tI(){let e;for(;e=null,(n=tb).g&&(e=n.g,n.g=n.g.next,n.g||(n.h=null),e.next=null),r=e;){try{r.h.call(r.g)}catch(t){!function(e){eb.setTimeout(()=>{throw e},0)}(t)}var n,r,i=ty;i.j(r),100>i.h&&(i.h++,r.next=i.g,i.g=r)}tw=!1}function tT(e,t){tf.call(this),this.h=e||1,this.g=t||eb,this.j=ex(this.lb,this),this.l=Date.now()}function tE(e){e.ca=!1,e.R&&(e.g.clearTimeout(e.R),e.R=null)}function tS(e,t,n){if("function"==typeof e)n&&(e=ex(e,n));else if(e&&"function"==typeof e.handleEvent)e=ex(e.handleEvent,e);else throw Error("Invalid listener argument");return 2147483647<Number(t)?-1:eb.setTimeout(e,t||0)}eN(tT,tf),(ey=tT.prototype).ca=!1,ey.R=null,ey.lb=function(){if(this.ca){var e=Date.now()-this.l;0<e&&e<.8*this.h?this.R=this.g.setTimeout(this.j,this.h-e):(this.R&&(this.g.clearTimeout(this.R),this.R=null),tp(this,"tick"),this.ca&&(tE(this),this.start()))}},ey.start=function(){this.ca=!0,this.R||(this.R=this.g.setTimeout(this.j,this.h),this.l=Date.now())},ey.M=function(){tT.X.M.call(this),tE(this),delete this.g};class tk extends eA{constructor(e,t){super(),this.m=e,this.j=t,this.h=null,this.i=!1,this.g=null}l(e){this.h=arguments,this.g?this.i=!0:function e(t){t.g=tS(()=>{t.g=null,t.i&&(t.i=!1,e(t))},t.j);let n=t.h;t.h=null,t.m.apply(null,n)}(this)}M(){super.M(),this.g&&(eb.clearTimeout(this.g),this.g=null,this.i=!1,this.h=null)}}function tx(e){eA.call(this),this.h=e,this.g={}}eN(tx,eA);var tC=[];function tN(e,t,n,r){Array.isArray(n)||(n&&(tC[0]=n.toString()),n=tC);for(var i=0;i<n.length;i++){var s=function e(t,n,r,i,s){if(i&&i.once)return function e(t,n,r,i,s){if(Array.isArray(n)){for(var o=0;o<n.length;o++)e(t,n[o],r,i,s);return null}return r=td(r),t&&t[e3]?t.O(n,r,eE(i)?!!i.capture:!!i,s):to(t,n,r,!0,i,s)}(t,n,r,i,s);if(Array.isArray(n)){for(var o=0;o<n.length;o++)e(t,n[o],r,i,s);return null}return r=td(r),t&&t[e3]?t.N(n,r,eE(i)?!!i.capture:!!i,s):to(t,n,r,!1,i,s)}(t,n[i],r||e.handleEvent,!1,e.h||e);if(!s)break;e.g[s.key]=s}}function tA(e){e8(e.g,function(e,t){this.g.hasOwnProperty(t)&&ta(e)},e),e.g={}}function tR(){this.g=!0}function tD(e,t,n,r){e.info(function(){return"XMLHTTP TEXT ("+t+"): "+function(e,t){if(!e.g)return t;if(!t)return null;try{var n=JSON.parse(t);if(n){for(e=0;e<n.length;e++)if(Array.isArray(n[e])){var r=n[e];if(!(2>r.length)){var i=r[1];if(Array.isArray(i)&&!(1>i.length)){var s=i[0];if("noop"!=s&&"stop"!=s&&"close"!=s)for(var o=1;o<i.length;o++)i[o]=""}}}}return tg(n)}catch(a){return t}}(e,n)+(r?" "+r:"")})}tx.prototype.M=function(){tx.X.M.call(this),tA(this)},tx.prototype.handleEvent=function(){throw Error("EventHandler.handleEvent not implemented")},tR.prototype.Aa=function(){this.g=!1},tR.prototype.info=function(){};var tO={},tP=null;function tL(){return tP=tP||new tf}function tM(e){eP.call(this,tO.Pa,e)}function tj(e){let t=tL();tp(t,new tM(t,e))}function tF(e,t){eP.call(this,tO.STAT_EVENT,e),this.stat=t}function tU(e){let t=tL();tp(t,new tF(t,e))}function tV(e,t){eP.call(this,tO.Qa,e),this.size=t}function tq(e,t){if("function"!=typeof e)throw Error("Fn must not be null and must be a function");return eb.setTimeout(function(){e()},t)}tO.Pa="serverreachability",eN(tM,eP),tO.STAT_EVENT="statevent",eN(tF,eP),tO.Qa="timingevent",eN(tV,eP);var tB={NO_ERROR:0,mb:1,zb:2,yb:3,tb:4,xb:5,Ab:6,Ma:7,TIMEOUT:8,Db:9},t$={rb:"complete",Nb:"success",Na:"error",Ma:"abort",Fb:"ready",Gb:"readystatechange",TIMEOUT:"timeout",Bb:"incrementaldata",Eb:"progress",ub:"downloadprogress",Vb:"uploadprogress"};function tz(){}function tG(e){return e.h||(e.h=e.i())}function tW(){}tz.prototype.h=null;var tH={OPEN:"a",qb:"b",Na:"c",Cb:"d"};function tK(){eP.call(this,"d")}function tQ(){eP.call(this,"c")}function tY(){}function tX(e,t,n,r){this.l=e,this.j=t,this.m=n,this.U=r||1,this.S=new tx(this),this.O=tZ,e=eG?125:void 0,this.T=new tT(e),this.H=null,this.i=!1,this.s=this.A=this.v=this.K=this.F=this.V=this.B=null,this.D=[],this.g=null,this.C=0,this.o=this.u=null,this.Y=-1,this.I=!1,this.N=0,this.L=null,this.$=this.J=this.Z=this.P=!1,this.h=new tJ}function tJ(){this.i=null,this.g="",this.h=!1}eN(tK,eP),eN(tQ,eP),eN(tY,tz),tY.prototype.g=function(){return new XMLHttpRequest},tY.prototype.i=function(){return{}},w=new tY;var tZ=45e3,t0={},t1={};function t2(e,t,n){e.K=1,e.v=nc(ns(t)),e.s=n,e.P=!0,t3(e,null)}function t3(e,t){e.F=Date.now(),t5(e),e.A=ns(e.v);var n=e.A,r=e.U;Array.isArray(r)||(r=[String(r)]),nT(n.i,"t",r),e.C=0,n=e.l.H,e.h=new tJ,e.g=rd(e.l,n?t:null,!e.s),0<e.N&&(e.L=new tk(ex(e.La,e,e.g),e.N)),tN(e.S,e.g,"readystatechange",e.ib),t=e.H?e9(e.H):{},e.s?(e.u||(e.u="POST"),t["Content-Type"]="application/x-www-form-urlencoded",e.g.da(e.A,e.u,e.s,t)):(e.u="GET",e.g.da(e.A,e.u,null,t)),tj(1),function(e,t,n,r,i,s){e.info(function(){if(e.g){if(s)for(var o="",a=s.split("&"),l=0;l<a.length;l++){var u=a[l].split("=");if(1<u.length){var c=u[0];u=u[1];var h=c.split("_");o=2<=h.length&&"type"==h[1]?o+(c+"=")+u+"&":o+(c+"=redacted&")}}else o=null}else o=s;return"XMLHTTP REQ ("+r+") [attempt "+i+"]: "+t+"\n"+n+"\n"+o})}(e.j,e.u,e.A,e.m,e.U,e.s)}function t4(e){return!!e.g&&"GET"==e.u&&2!=e.K&&e.l.Da}function t6(e,t,n){let r=!0,i;for(;!e.I&&e.C<n.length;)if((i=function(e,t){var n=e.C,r=t.indexOf("\n",n);return -1==r?t1:isNaN(n=Number(t.substring(n,r)))?t0:(r+=1)+n>t.length?t1:(t=t.substr(r,n),e.C=r+n,t)}(e,n))==t1){4==t&&(e.o=4,tU(14),r=!1),tD(e.j,e.m,null,"[Incomplete Response]");break}else if(i==t0){e.o=4,tU(15),tD(e.j,e.m,n,"[Invalid Chunk]"),r=!1;break}else tD(e.j,e.m,i,null),nt(e,i);t4(e)&&i!=t1&&i!=t0&&(e.h.g="",e.C=0),4!=t||0!=n.length||e.h.h||(e.o=1,tU(16),r=!1),e.i=e.i&&r,r?0<n.length&&!e.$&&(e.$=!0,(t=e.l).g==e&&t.$&&!t.K&&(t.j.info("Great, no buffering proxy detected. Bytes received: "+n.length),ri(t),t.K=!0,tU(11))):(tD(e.j,e.m,n,"[Invalid Chunked Response]"),ne(e),t7(e))}function t5(e){e.V=Date.now()+e.O,t8(e,e.O)}function t8(e,t){if(null!=e.B)throw Error("WatchDog timer not null");e.B=tq(ex(e.gb,e),t)}function t9(e){e.B&&(eb.clearTimeout(e.B),e.B=null)}function t7(e){0==e.l.G||e.I||ra(e.l,e)}function ne(e){t9(e);var t=e.L;t&&"function"==typeof t.na&&t.na(),e.L=null,tE(e.T),tA(e.S),e.g&&(t=e.g,e.g=null,t.abort(),t.na())}function nt(e,t){try{var n=e.l;if(0!=n.G&&(n.g==e||nA(n.h,e))){if(!e.J&&nA(n.h,e)&&3==n.G){try{var r=n.Fa.g.parse(t)}catch(i){r=null}if(Array.isArray(r)&&3==r.length){var s=r;if(0==s[0]){e:if(!n.u){if(n.g){if(n.g.F+3e3<e.F)ro(n),n5(n);else break e}rr(n),tU(18)}}else n.Ba=s[1],0<n.Ba-n.T&&37500>s[2]&&n.L&&0==n.A&&!n.v&&(n.v=tq(ex(n.cb,n),6e3));if(1>=nN(n.h)&&n.ja){try{n.ja()}catch(o){}n.ja=void 0}}else ru(n,11)}else if((e.J||n.g==e)&&ro(n),!eM(t))for(s=n.Fa.g.parse(t),t=0;t<s.length;t++){let a=s[t];if(n.T=a[0],a=a[1],2==n.G){if("c"==a[0]){n.I=a[1],n.ka=a[2];let l=a[3];null!=l&&(n.ma=l,n.j.info("VER="+n.ma));let u=a[4];null!=u&&(n.Ca=u,n.j.info("SVER="+n.Ca));let c=a[5];null!=c&&"number"==typeof c&&0<c&&(r=1.5*c,n.J=r,n.j.info("backChannelRequestTimeoutMs_="+r)),r=n;let h=e.g;if(h){let d=h.g?h.g.getResponseHeader("X-Client-Wire-Protocol"):null;if(d){var f=r.h;f.g||-1==d.indexOf("spdy")&&-1==d.indexOf("quic")&&-1==d.indexOf("h2")||(f.j=f.l,f.g=new Set,f.h&&(nR(f,f.h),f.h=null))}if(r.D){let p=h.g?h.g.getResponseHeader("X-HTTP-Session-Id"):null;p&&(r.za=p,nu(r.F,r.D,p))}}if(n.G=3,n.l&&n.l.xa(),n.$&&(n.P=Date.now()-e.F,n.j.info("Handshake RTT: "+n.P+"ms")),(r=n).sa=rh(r,r.H?r.ka:null,r.V),e.J){nD(r.h,e);var m=r.J;m&&e.setTimeout(m),e.B&&(t9(e),t5(e)),r.g=e}else rn(r);0<n.i.length&&n9(n)}else"stop"!=a[0]&&"close"!=a[0]||ru(n,7)}else 3==n.G&&("stop"==a[0]||"close"==a[0]?"stop"==a[0]?ru(n,7):n6(n):"noop"!=a[0]&&n.l&&n.l.wa(a),n.A=0)}}tj(4)}catch(g){}}function nn(e,t){if(e.forEach&&"function"==typeof e.forEach)e.forEach(t,void 0);else if(eT(e)||"string"==typeof e)Array.prototype.forEach.call(e,t,void 0);else for(var n=function(e){if(e.oa&&"function"==typeof e.oa)return e.oa();if(!e.W||"function"!=typeof e.W){if("undefined"!=typeof Map&&e instanceof Map)return Array.from(e.keys());if(!("undefined"!=typeof Set&&e instanceof Set)){if(eT(e)||"string"==typeof e){var t=[];e=e.length;for(var n=0;n<e;n++)t.push(n);return t}for(let r in t=[],n=0,e)t[n++]=r;return t}}}(e),r=function(e){if(e.W&&"function"==typeof e.W)return e.W();if("undefined"!=typeof Map&&e instanceof Map||"undefined"!=typeof Set&&e instanceof Set)return Array.from(e.values());if("string"==typeof e)return e.split("");if(eT(e)){for(var t=[],n=e.length,r=0;r<n;r++)t.push(e[r]);return t}for(r in t=[],n=0,e)t[n++]=e[r];return t}(e),i=r.length,s=0;s<i;s++)t.call(void 0,r[s],n&&n[s],e)}(ey=tX.prototype).setTimeout=function(e){this.O=e},ey.ib=function(e){e=e.target;let t=this.L;t&&3==nZ(e)?t.l():this.La(e)},ey.La=function(e){try{if(e==this.g)e:{let t=nZ(this.g);var n=this.g.Ea();let r=this.g.aa();if(!(3>t)&&(3!=t||eG||this.g&&(this.h.h||this.g.fa()||n0(this.g)))){this.I||4!=t||7==n||(8==n||0>=r?tj(3):tj(2)),t9(this);var i=this.g.aa();this.Y=i;t:if(t4(this)){var s=n0(this.g);e="";var o=s.length,a=4==nZ(this.g);if(!this.h.i){if("undefined"==typeof TextDecoder){ne(this),t7(this);var l="";break t}this.h.i=new eb.TextDecoder}for(n=0;n<o;n++)this.h.h=!0,e+=this.h.i.decode(s[n],{stream:a&&n==o-1});s.splice(0,o),this.h.g+=e,this.C=0,l=this.h.g}else l=this.g.fa();if(this.i=200==i,function(e,t,n,r,i,s,o){e.info(function(){return"XMLHTTP RESP ("+r+") [ attempt "+i+"]: "+t+"\n"+n+"\n"+s+" "+o})}(this.j,this.u,this.A,this.m,this.U,t,i),this.i){if(this.Z&&!this.J){t:{if(this.g){var u,c=this.g;if((u=c.g?c.g.getResponseHeader("X-HTTP-Initial-Response"):null)&&!eM(u)){var h=u;break t}}h=null}if(i=h)tD(this.j,this.m,i,"Initial handshake response via X-HTTP-Initial-Response"),this.J=!0,nt(this,i);else{this.i=!1,this.o=3,tU(12),ne(this),t7(this);break e}}this.P?(t6(this,t,l),eG&&this.i&&3==t&&(tN(this.S,this.T,"tick",this.hb),this.T.start())):(tD(this.j,this.m,l,null),nt(this,l)),4==t&&ne(this),this.i&&!this.I&&(4==t?ra(this.l,this):(this.i=!1,t5(this)))}else 400==i&&0<l.indexOf("Unknown SID")?(this.o=3,tU(12)):(this.o=0,tU(13)),ne(this),t7(this)}}}catch(d){}finally{}},ey.hb=function(){if(this.g){var e=nZ(this.g),t=this.g.fa();this.C<t.length&&(t9(this),t6(this,e,t),this.i&&4!=e&&t5(this))}},ey.cancel=function(){this.I=!0,ne(this)},ey.gb=function(){this.B=null;let e=Date.now();0<=e-this.V?(function(e,t){e.info(function(){return"TIMEOUT: "+t})}(this.j,this.A),2!=this.K&&(tj(3),tU(17)),ne(this),this.o=2,t7(this)):t8(this,this.V-e)};var nr=RegExp("^(?:([^:/?#.]+):)?(?://(?:([^\\\\/?#]*)@)?([^\\\\/?#]*?)(?::([0-9]+))?(?=[\\\\/?#]|$))?([^?#]+)?(?:\\?([^#]*))?(?:#([\\s\\S]*))?$");function ni(e,t){if(this.g=this.s=this.j="",this.m=null,this.o=this.l="",this.h=!1,e instanceof ni){this.h=void 0!==t?t:e.h,no(this,e.j),this.s=e.s,this.g=e.g,na(this,e.m),this.l=e.l,t=e.i;var n=new n_;n.i=t.i,t.g&&(n.g=new Map(t.g),n.h=t.h),nl(this,n),this.o=e.o}else e&&(n=String(e).match(nr))?(this.h=!!t,no(this,n[1]||"",!0),this.s=nh(n[2]||""),this.g=nh(n[3]||"",!0),na(this,n[4]),this.l=nh(n[5]||"",!0),nl(this,n[6]||"",!0),this.o=nh(n[7]||"")):(this.h=!!t,this.i=new n_(null,this.h))}function ns(e){return new ni(e)}function no(e,t,n){e.j=n?nh(t,!0):t,e.j&&(e.j=e.j.replace(/:$/,""))}function na(e,t){if(t){if(isNaN(t=Number(t))||0>t)throw Error("Bad port number "+t);e.m=t}else e.m=null}function nl(e,t,n){var r,i;t instanceof n_?(e.i=t,r=e.i,(i=e.h)&&!r.j&&(nw(r),r.i=null,r.g.forEach(function(e,t){var n=t.toLowerCase();t!=n&&(nb(this,t),nT(this,n,e))},r)),r.j=i):(n||(t=nd(t,ny)),e.i=new n_(t,e.h))}function nu(e,t,n){e.i.set(t,n)}function nc(e){return nu(e,"zx",Math.floor(2147483648*Math.random()).toString(36)+Math.abs(Math.floor(2147483648*Math.random())^Date.now()).toString(36)),e}function nh(e,t){return e?t?decodeURI(e.replace(/%25/g,"%2525")):decodeURIComponent(e):""}function nd(e,t,n){return"string"==typeof e?(e=encodeURI(e).replace(t,nf),n&&(e=e.replace(/%25([0-9a-fA-F]{2})/g,"%$1")),e):null}function nf(e){return"%"+((e=e.charCodeAt(0))>>4&15).toString(16)+(15&e).toString(16)}ni.prototype.toString=function(){var e=[],t=this.j;t&&e.push(nd(t,np,!0),":");var n=this.g;return(n||"file"==t)&&(e.push("//"),(t=this.s)&&e.push(nd(t,np,!0),"@"),e.push(encodeURIComponent(String(n)).replace(/%25([0-9a-fA-F]{2})/g,"%$1")),null!=(n=this.m)&&e.push(":",String(n))),(n=this.l)&&(this.g&&"/"!=n.charAt(0)&&e.push("/"),e.push(nd(n,"/"==n.charAt(0)?ng:nm,!0))),(n=this.i.toString())&&e.push("?",n),(n=this.o)&&e.push("#",nd(n,nv)),e.join("")};var np=/[#\/\?@]/g,nm=/[#\?:]/g,ng=/[#\?]/g,ny=/[#\?@]/g,nv=/#/g;function n_(e,t){this.h=this.g=null,this.i=e||null,this.j=!!t}function nw(e){e.g||(e.g=new Map,e.h=0,e.i&&function(e,t){if(e){e=e.split("&");for(var n=0;n<e.length;n++){var r=e[n].indexOf("="),i=null;if(0<=r){var s=e[n].substring(0,r);i=e[n].substring(r+1)}else s=e[n];t(s,i?decodeURIComponent(i.replace(/\+/g," ")):"")}}}(e.i,function(t,n){e.add(decodeURIComponent(t.replace(/\+/g," ")),n)}))}function nb(e,t){nw(e),t=nE(e,t),e.g.has(t)&&(e.i=null,e.h-=e.g.get(t).length,e.g.delete(t))}function nI(e,t){return nw(e),t=nE(e,t),e.g.has(t)}function nT(e,t,n){nb(e,t),0<n.length&&(e.i=null,e.g.set(nE(e,t),eD(n)),e.h+=n.length)}function nE(e,t){return t=String(t),e.j&&(t=t.toLowerCase()),t}(ey=n_.prototype).add=function(e,t){nw(this),this.i=null,e=nE(this,e);var n=this.g.get(e);return n||this.g.set(e,n=[]),n.push(t),this.h+=1,this},ey.forEach=function(e,t){nw(this),this.g.forEach(function(n,r){n.forEach(function(n){e.call(t,n,r,this)},this)},this)},ey.oa=function(){nw(this);let e=Array.from(this.g.values()),t=Array.from(this.g.keys()),n=[];for(let r=0;r<t.length;r++){let i=e[r];for(let s=0;s<i.length;s++)n.push(t[r])}return n},ey.W=function(e){nw(this);let t=[];if("string"==typeof e)nI(this,e)&&(t=t.concat(this.g.get(nE(this,e))));else{e=Array.from(this.g.values());for(let n=0;n<e.length;n++)t=t.concat(e[n])}return t},ey.set=function(e,t){return nw(this),this.i=null,nI(this,e=nE(this,e))&&(this.h-=this.g.get(e).length),this.g.set(e,[t]),this.h+=1,this},ey.get=function(e,t){return e&&0<(e=this.W(e)).length?String(e[0]):t},ey.toString=function(){if(this.i)return this.i;if(!this.g)return"";let e=[],t=Array.from(this.g.keys());for(var n=0;n<t.length;n++){var r=t[n];let i=encodeURIComponent(String(r)),s=this.W(r);for(r=0;r<s.length;r++){var o=i;""!==s[r]&&(o+="="+encodeURIComponent(String(s[r]))),e.push(o)}}return this.i=e.join("&")};var nS=class{constructor(e,t){this.h=e,this.g=t}};function nk(e){this.l=e||nx,e=eb.PerformanceNavigationTiming?0<(e=eb.performance.getEntriesByType("navigation")).length&&("hq"==e[0].nextHopProtocol||"h2"==e[0].nextHopProtocol):!!(eb.g&&eb.g.Ga&&eb.g.Ga()&&eb.g.Ga().$b),this.j=e?this.l:1,this.g=null,1<this.j&&(this.g=new Set),this.h=null,this.i=[]}var nx=10;function nC(e){return!!e.h||!!e.g&&e.g.size>=e.j}function nN(e){return e.h?1:e.g?e.g.size:0}function nA(e,t){return e.h?e.h==t:!!e.g&&e.g.has(t)}function nR(e,t){e.g?e.g.add(t):e.h=t}function nD(e,t){e.h&&e.h==t?e.h=null:e.g&&e.g.has(t)&&e.g.delete(t)}function nO(e){if(null!=e.h)return e.i.concat(e.h.D);if(null!=e.g&&0!==e.g.size){let t=e.i;for(let n of e.g.values())t=t.concat(n.D);return t}return eD(e.i)}function nP(){}function nL(){this.g=new nP}function nM(e,t,n,r,i){try{t.onload=null,t.onerror=null,t.onabort=null,t.ontimeout=null,i(r)}catch(s){}}function nj(e){this.l=e.ac||null,this.j=e.jb||!1}function nF(e,t){tf.call(this),this.D=e,this.u=t,this.m=void 0,this.readyState=nU,this.status=0,this.responseType=this.responseText=this.response=this.statusText="",this.onreadystatechange=null,this.v=new Headers,this.h=null,this.C="GET",this.B="",this.g=!1,this.A=this.j=this.l=null}nk.prototype.cancel=function(){if(this.i=nO(this),this.h)this.h.cancel(),this.h=null;else if(this.g&&0!==this.g.size){for(let e of this.g.values())e.cancel();this.g.clear()}},nP.prototype.stringify=function(e){return eb.JSON.stringify(e,void 0)},nP.prototype.parse=function(e){return eb.JSON.parse(e,void 0)},eN(nj,tz),nj.prototype.g=function(){return new nF(this.l,this.j)},nj.prototype.i=(p={},function(){return p}),eN(nF,tf);var nU=0;function nV(e){e.j.read().then(e.Ta.bind(e)).catch(e.ga.bind(e))}function nq(e){e.readyState=4,e.l=null,e.j=null,e.A=null,nB(e)}function nB(e){e.onreadystatechange&&e.onreadystatechange.call(e)}(ey=nF.prototype).open=function(e,t){if(this.readyState!=nU)throw this.abort(),Error("Error reopening a connection");this.C=e,this.B=t,this.readyState=1,nB(this)},ey.send=function(e){if(1!=this.readyState)throw this.abort(),Error("need to call open() first. ");this.g=!0;let t={headers:this.v,method:this.C,credentials:this.m,cache:void 0};e&&(t.body=e),(this.D||eb).fetch(new Request(this.B,t)).then(this.Wa.bind(this),this.ga.bind(this))},ey.abort=function(){this.response=this.responseText="",this.v=new Headers,this.status=0,this.j&&this.j.cancel("Request was aborted.").catch(()=>{}),1<=this.readyState&&this.g&&4!=this.readyState&&(this.g=!1,nq(this)),this.readyState=nU},ey.Wa=function(e){if(this.g&&(this.l=e,this.h||(this.status=this.l.status,this.statusText=this.l.statusText,this.h=e.headers,this.readyState=2,nB(this)),this.g&&(this.readyState=3,nB(this),this.g))){if("arraybuffer"===this.responseType)e.arrayBuffer().then(this.Ua.bind(this),this.ga.bind(this));else if(void 0!==eb.ReadableStream&&"body"in e){if(this.j=e.body.getReader(),this.u){if(this.responseType)throw Error('responseType must be empty for "streamBinaryChunks" mode responses.');this.response=[]}else this.response=this.responseText="",this.A=new TextDecoder;nV(this)}else e.text().then(this.Va.bind(this),this.ga.bind(this))}},ey.Ta=function(e){if(this.g){if(this.u&&e.value)this.response.push(e.value);else if(!this.u){var t=e.value?e.value:new Uint8Array(0);(t=this.A.decode(t,{stream:!e.done}))&&(this.response=this.responseText+=t)}e.done?nq(this):nB(this),3==this.readyState&&nV(this)}},ey.Va=function(e){this.g&&(this.response=this.responseText=e,nq(this))},ey.Ua=function(e){this.g&&(this.response=e,nq(this))},ey.ga=function(){this.g&&nq(this)},ey.setRequestHeader=function(e,t){this.v.append(e,t)},ey.getResponseHeader=function(e){return this.h&&this.h.get(e.toLowerCase())||""},ey.getAllResponseHeaders=function(){if(!this.h)return"";let e=[],t=this.h.entries();for(var n=t.next();!n.done;)e.push((n=n.value)[0]+": "+n[1]),n=t.next();return e.join("\r\n")},Object.defineProperty(nF.prototype,"withCredentials",{get:function(){return"include"===this.m},set:function(e){this.m=e?"include":"same-origin"}});var n$=eb.JSON.parse;function nz(e){tf.call(this),this.headers=new Map,this.u=e||null,this.h=!1,this.C=this.g=null,this.H="",this.m=0,this.j="",this.l=this.F=this.v=this.D=!1,this.B=0,this.A=null,this.J=nG,this.K=this.L=!1}eN(nz,tf);var nG="",nW=/^https?$/i,nH=["POST","PUT"];function nK(e,t){e.h=!1,e.g&&(e.l=!0,e.g.abort(),e.l=!1),e.j=t,e.m=5,nQ(e),nX(e)}function nQ(e){e.D||(e.D=!0,tp(e,"complete"),tp(e,"error"))}function nY(e){if(e.h&&void 0!==ew&&(!e.C[1]||4!=nZ(e)||2!=e.aa())){if(e.v&&4==nZ(e))tS(e.Ha,0,e);else if(tp(e,"readystatechange"),4==nZ(e)){e.h=!1;try{let t=e.aa();e:switch(t){case 200:case 201:case 202:case 204:case 206:case 304:case 1223:var n,r,i=!0;break e;default:i=!1}if(!(n=i)){if(r=0===t){var s=String(e.H).match(nr)[1]||null;if(!s&&eb.self&&eb.self.location){var o=eb.self.location.protocol;s=o.substr(0,o.length-1)}r=!nW.test(s?s.toLowerCase():"")}n=r}if(n)tp(e,"complete"),tp(e,"success");else{e.m=6;try{var a=2<nZ(e)?e.g.statusText:""}catch(l){a=""}e.j=a+" ["+e.aa()+"]",nQ(e)}}finally{nX(e)}}}}function nX(e,t){if(e.g){nJ(e);let n=e.g,r=e.C[0]?eI:null;e.g=null,e.C=null,t||tp(e,"ready");try{n.onreadystatechange=r}catch(i){}}}function nJ(e){e.g&&e.K&&(e.g.ontimeout=null),e.A&&(eb.clearTimeout(e.A),e.A=null)}function nZ(e){return e.g?e.g.readyState:0}function n0(e){try{if(!e.g)return null;if("response"in e.g)return e.g.response;switch(e.J){case nG:case"text":return e.g.responseText;case"arraybuffer":if("mozResponseArrayBuffer"in e.g)return e.g.mozResponseArrayBuffer}return null}catch(t){return null}}function n1(e){let t="";return e8(e,function(e,n){t+=n+":"+e+"\r\n"}),t}function n2(e,t,n){e:{for(r in n){var r=!1;break e}r=!0}r||(n=n1(n),"string"==typeof e?null!=n&&encodeURIComponent(String(n)):nu(e,t,n))}function n3(e,t,n){return n&&n.internalChannelParams&&n.internalChannelParams[e]||t}function n4(e){this.Ca=0,this.i=[],this.j=new tR,this.ka=this.sa=this.F=this.V=this.g=this.za=this.D=this.ia=this.o=this.S=this.s=null,this.ab=this.U=0,this.Za=n3("failFast",!1,e),this.L=this.v=this.u=this.m=this.l=null,this.Y=!0,this.pa=this.Ba=this.T=-1,this.Z=this.A=this.C=0,this.Xa=n3("baseRetryDelayMs",5e3,e),this.bb=n3("retryDelaySeedMs",1e4,e),this.$a=n3("forwardChannelMaxRetries",2,e),this.ta=n3("forwardChannelRequestTimeoutMs",2e4,e),this.ra=e&&e.xmlHttpFactory||void 0,this.Da=e&&e.Zb||!1,this.J=void 0,this.H=e&&e.supportsCrossDomainXhr||!1,this.I="",this.h=new nk(e&&e.concurrentRequestLimit),this.Fa=new nL,this.O=e&&e.fastHandshake||!1,this.N=e&&e.encodeInitMessageHeaders||!1,this.O&&this.N&&(this.N=!1),this.Ya=e&&e.Xb||!1,e&&e.Aa&&this.j.Aa(),e&&e.forceLongPolling&&(this.Y=!1),this.$=!this.O&&this.Y&&e&&e.detectBufferingProxy||!1,this.ja=void 0,this.P=0,this.K=!1,this.la=this.B=null}function n6(e){if(n8(e),3==e.G){var t=e.U++,n=ns(e.F);nu(n,"SID",e.I),nu(n,"RID",t),nu(n,"TYPE","terminate"),re(e,n),(t=new tX(e,e.j,t,void 0)).K=2,t.v=nc(ns(n)),n=!1,eb.navigator&&eb.navigator.sendBeacon&&(n=eb.navigator.sendBeacon(t.v.toString(),"")),!n&&eb.Image&&((new Image).src=t.v,n=!0),n||(t.g=rd(t.l,null),t.g.da(t.v)),t.F=Date.now(),t5(t)}rc(e)}function n5(e){e.g&&(ri(e),e.g.cancel(),e.g=null)}function n8(e){n5(e),e.u&&(eb.clearTimeout(e.u),e.u=null),ro(e),e.h.cancel(),e.m&&("number"==typeof e.m&&eb.clearTimeout(e.m),e.m=null)}function n9(e){nC(e.h)||e.m||(e.m=!0,t_(e.Ja,e),e.C=0)}function n7(e,t){var n;n=t?t.m:e.U++;let r=ns(e.F);nu(r,"SID",e.I),nu(r,"RID",n),nu(r,"AID",e.T),re(e,r),e.o&&e.s&&n2(r,e.o,e.s),n=new tX(e,e.j,n,e.C+1),null===e.o&&(n.H=e.s),t&&(e.i=t.D.concat(e.i)),t=rt(e,n,1e3),n.setTimeout(Math.round(.5*e.ta)+Math.round(.5*e.ta*Math.random())),nR(e.h,n),t2(n,r,t)}function re(e,t){e.ia&&e8(e.ia,function(e,n){nu(t,n,e)}),e.l&&nn({},function(e,n){nu(t,n,e)})}function rt(e,t,n){n=Math.min(e.i.length,n);var r=e.l?ex(e.l.Ra,e.l,e):null;e:{var i=e.i;let s=-1;for(;;){let o=["count="+n];-1==s?0<n?(s=i[0].h,o.push("ofs="+s)):s=0:o.push("ofs="+s);let a=!0;for(let l=0;l<n;l++){let u=i[l].h,c=i[l].g;if(0>(u-=s))s=Math.max(0,i[l].h-100),a=!1;else try{!function(e,t,n){let r=n||"";try{nn(e,function(e,n){let i=e;eE(e)&&(i=tg(e)),t.push(r+n+"="+encodeURIComponent(i))})}catch(i){throw t.push(r+"type="+encodeURIComponent("_badmap")),i}}(c,o,"req"+u+"_")}catch(h){r&&r(c)}}if(a){r=o.join("&");break e}}}return e=e.i.splice(0,n),t.D=e,r}function rn(e){e.g||e.u||(e.Z=1,t_(e.Ia,e),e.A=0)}function rr(e){return!e.g&&!e.u&&!(3<=e.A)&&(e.Z++,e.u=tq(ex(e.Ia,e),rl(e,e.A)),e.A++,!0)}function ri(e){null!=e.B&&(eb.clearTimeout(e.B),e.B=null)}function rs(e){e.g=new tX(e,e.j,"rpc",e.Z),null===e.o&&(e.g.H=e.s),e.g.N=0;var t=ns(e.sa);nu(t,"RID","rpc"),nu(t,"SID",e.I),nu(t,"CI",e.L?"0":"1"),nu(t,"AID",e.T),nu(t,"TYPE","xmlhttp"),re(e,t),e.o&&e.s&&n2(t,e.o,e.s),e.J&&e.g.setTimeout(e.J);var n=e.g;e=e.ka,n.K=1,n.v=nc(ns(t)),n.s=null,n.P=!0,t3(n,e)}function ro(e){null!=e.v&&(eb.clearTimeout(e.v),e.v=null)}function ra(e,t){var n=null;if(e.g==t){ro(e),ri(e),e.g=null;var r=2}else{if(!nA(e.h,t))return;n=t.D,nD(e.h,t),r=1}if(0!=e.G){if(e.pa=t.Y,t.i){if(1==r){n=t.s?t.s.length:0,t=Date.now()-t.F;var i,s,o=e.C;tp(r=tL(),new tV(r,n,t,o)),n9(e)}else rn(e)}else if(3==(o=t.o)||0==o&&0<e.pa||!(1==r&&(i=e,s=t,!(nN(i.h)>=i.h.j-(i.m?1:0))&&(i.m?(i.i=s.D.concat(i.i),!0):1!=i.G&&2!=i.G&&!(i.C>=(i.Za?0:i.$a))&&(i.m=tq(ex(i.Ja,i,s),rl(i,i.C)),i.C++,!0)))||2==r&&rr(e)))switch(n&&0<n.length&&((t=e.h).i=t.i.concat(n)),o){case 1:ru(e,5);break;case 4:ru(e,10);break;case 3:ru(e,6);break;default:ru(e,2)}}}function rl(e,t){let n=e.Xa+Math.floor(Math.random()*e.bb);return e.l||(n*=2),n*t}function ru(e,t){if(e.j.info("Error code "+t),2==t){var n=null;e.l&&(n=null);var r=ex(e.kb,e);n||(n=new ni("//www.google.com/images/cleardot.gif"),eb.location&&"http"==eb.location.protocol||no(n,"https"),nc(n)),function(e,t){let n=new tR;if(eb.Image){let r=new Image;r.onload=eC(nM,n,r,"TestLoadImage: loaded",!0,t),r.onerror=eC(nM,n,r,"TestLoadImage: error",!1,t),r.onabort=eC(nM,n,r,"TestLoadImage: abort",!1,t),r.ontimeout=eC(nM,n,r,"TestLoadImage: timeout",!1,t),eb.setTimeout(function(){r.ontimeout&&r.ontimeout()},1e4),r.src=e}else t(!1)}(n.toString(),r)}else tU(2);e.G=0,e.l&&e.l.va(t),rc(e),n8(e)}function rc(e){if(e.G=0,e.la=[],e.l){let t=nO(e.h);(0!=t.length||0!=e.i.length)&&(eO(e.la,t),eO(e.la,e.i),e.h.i.length=0,eD(e.i),e.i.length=0),e.l.ua()}}function rh(e,t,n){var r=n instanceof ni?ns(n):new ni(n,void 0);if(""!=r.g)t&&(r.g=t+"."+r.g),na(r,r.m);else{var i=eb.location;r=i.protocol,t=t?t+"."+i.hostname:i.hostname,i=+i.port;var s=new ni(null,void 0);r&&no(s,r),t&&(s.g=t),i&&na(s,i),n&&(s.l=n),r=s}return n=e.D,t=e.za,n&&t&&nu(r,n,t),nu(r,"VER",e.ma),re(e,r),r}function rd(e,t,n){if(t&&!e.H)throw Error("Can't create secondary domain capable XhrIo object.");return(t=new nz(n&&e.Da&&!e.ra?new nj({jb:!0}):e.ra)).Ka(e.H),t}function rf(){}function rp(){if(e$&&!(10<=Number(e0)))throw Error("Environmental error: no available transport.")}function rm(e,t){tf.call(this),this.g=new n4(t),this.l=e,this.h=t&&t.messageUrlParams||null,e=t&&t.messageHeaders||null,t&&t.clientProtocolHeaderRequired&&(e?e["X-Client-Protocol"]="webchannel":e={"X-Client-Protocol":"webchannel"}),this.g.s=e,e=t&&t.initMessageHeaders||null,t&&t.messageContentType&&(e?e["X-WebChannel-Content-Type"]=t.messageContentType:e={"X-WebChannel-Content-Type":t.messageContentType}),t&&t.ya&&(e?e["X-WebChannel-Client-Profile"]=t.ya:e={"X-WebChannel-Client-Profile":t.ya}),this.g.S=e,(e=t&&t.Yb)&&!eM(e)&&(this.g.o=e),this.A=t&&t.supportsCrossDomainXhr||!1,this.v=t&&t.sendRawJson||!1,(t=t&&t.httpSessionIdParam)&&!eM(t)&&(this.g.D=t,null!==(e=this.h)&&t in e&&t in(e=this.h)&&delete e[t]),this.j=new rv(this)}function rg(e){tK.call(this);var t=e.__sm__;if(t){e:{for(let n in t){e=n;break e}e=void 0}(this.i=e)&&(e=this.i,t=null!==t&&e in t?t[e]:void 0),this.data=t}else this.data=e}function ry(){tQ.call(this),this.status=1}function rv(e){this.g=e}(ey=nz.prototype).Ka=function(e){this.L=e},ey.da=function(e,t,n,r){if(this.g)throw Error("[goog.net.XhrIo] Object is active with another request="+this.H+"; newUri="+e);t=t?t.toUpperCase():"GET",this.H=e,this.j="",this.m=0,this.D=!1,this.h=!0,this.g=this.u?this.u.g():w.g(),this.C=this.u?tG(this.u):tG(w),this.g.onreadystatechange=ex(this.Ha,this);try{this.F=!0,this.g.open(t,String(e),!0),this.F=!1}catch(i){nK(this,i);return}if(e=n||"",n=new Map(this.headers),r){if(Object.getPrototypeOf(r)===Object.prototype)for(var s in r)n.set(s,r[s]);else if("function"==typeof r.keys&&"function"==typeof r.get)for(let o of r.keys())n.set(o,r.get(o));else throw Error("Unknown input type for opt_headers: "+String(r))}for(let[a,l]of(r=Array.from(n.keys()).find(e=>"content-type"==e.toLowerCase()),s=eb.FormData&&e instanceof eb.FormData,!(0<=eR(nH,t))||r||s||n.set("Content-Type","application/x-www-form-urlencoded;charset=utf-8"),n))this.g.setRequestHeader(a,l);this.J&&(this.g.responseType=this.J),"withCredentials"in this.g&&this.g.withCredentials!==this.L&&(this.g.withCredentials=this.L);try{var u,c;nJ(this),0<this.B&&((this.K=(u=this.g,e$&&(c=eZ,Object.prototype.hasOwnProperty.call(c,9)?c[9]:c[9]=function(){let e=0,t=ej(String(y)).split("."),n=ej("9").split("."),r=Math.max(t.length,n.length);for(let i=0;0==e&&i<r;i++){var s=t[i]||"",o=n[i]||"";do{if(s=/(\d*)(\D*)(.*)/.exec(s)||["","","",""],o=/(\d*)(\D*)(.*)/.exec(o)||["","","",""],0==s[0].length&&0==o[0].length)break;e=eF(0==s[1].length?0:parseInt(s[1],10),0==o[1].length?0:parseInt(o[1],10))||eF(0==s[2].length,0==o[2].length)||eF(s[2],o[2]),s=s[3],o=o[3]}while(0==e)}return 0<=e}(9))&&"number"==typeof u.timeout&&void 0!==u.ontimeout))?(this.g.timeout=this.B,this.g.ontimeout=ex(this.qa,this)):this.A=tS(this.qa,this.B,this)),this.v=!0,this.g.send(e),this.v=!1}catch(h){nK(this,h)}},ey.qa=function(){void 0!==ew&&this.g&&(this.j="Timed out after "+this.B+"ms, aborting",this.m=8,tp(this,"timeout"),this.abort(8))},ey.abort=function(e){this.g&&this.h&&(this.h=!1,this.l=!0,this.g.abort(),this.l=!1,this.m=e||7,tp(this,"complete"),tp(this,"abort"),nX(this))},ey.M=function(){this.g&&(this.h&&(this.h=!1,this.l=!0,this.g.abort(),this.l=!1),nX(this,!0)),nz.X.M.call(this)},ey.Ha=function(){this.s||(this.F||this.v||this.l?nY(this):this.fb())},ey.fb=function(){nY(this)},ey.aa=function(){try{return 2<nZ(this)?this.g.status:-1}catch(e){return -1}},ey.fa=function(){try{return this.g?this.g.responseText:""}catch(e){return""}},ey.Sa=function(e){if(this.g){var t=this.g.responseText;return e&&0==t.indexOf(e)&&(t=t.substring(e.length)),n$(t)}},ey.Ea=function(){return this.m},ey.Oa=function(){return"string"==typeof this.j?this.j:String(this.j)},(ey=n4.prototype).ma=8,ey.G=1,ey.Ja=function(e){if(this.m){if(this.m=null,1==this.G){if(!e){this.U=Math.floor(1e5*Math.random()),e=this.U++;let t=new tX(this,this.j,e,void 0),n=this.s;if(this.S&&(n?te(n=e9(n),this.S):n=this.S),null!==this.o||this.N||(t.H=n,n=null),this.O)e:{for(var r=0,i=0;i<this.i.length;i++){t:{var s=this.i[i];if("__data__"in s.g&&"string"==typeof(s=s.g.__data__)){s=s.length;break t}s=void 0}if(void 0===s)break;if(4096<(r+=s)){r=i;break e}if(4096===r||i===this.i.length-1){r=i+1;break e}}r=1e3}else r=1e3;r=rt(this,t,r),nu(i=ns(this.F),"RID",e),nu(i,"CVER",22),this.D&&nu(i,"X-HTTP-Session-Id",this.D),re(this,i),n&&(this.N?r="headers="+encodeURIComponent(String(n1(n)))+"&"+r:this.o&&n2(i,this.o,n)),nR(this.h,t),this.Ya&&nu(i,"TYPE","init"),this.O?(nu(i,"$req",r),nu(i,"SID","null"),t.Z=!0,t2(t,i,null)):t2(t,i,r),this.G=2}}else 3==this.G&&(e?n7(this,e):0==this.i.length||nC(this.h)||n7(this))}},ey.Ia=function(){if(this.u=null,rs(this),this.$&&!(this.K||null==this.g||0>=this.P)){var e=2*this.P;this.j.info("BP detection timer enabled: "+e),this.B=tq(ex(this.eb,this),e)}},ey.eb=function(){this.B&&(this.B=null,this.j.info("BP detection timeout reached."),this.j.info("Buffering proxy detected and switch to long-polling!"),this.L=!1,this.K=!0,tU(10),n5(this),rs(this))},ey.cb=function(){null!=this.v&&(this.v=null,n5(this),rr(this),tU(19))},ey.kb=function(e){e?(this.j.info("Successfully pinged google.com"),tU(2)):(this.j.info("Failed to ping google.com"),tU(1))},(ey=rf.prototype).xa=function(){},ey.wa=function(){},ey.va=function(){},ey.ua=function(){},ey.Ra=function(){},rp.prototype.g=function(e,t){return new rm(e,t)},eN(rm,tf),rm.prototype.m=function(){this.g.l=this.j,this.A&&(this.g.H=!0);var e=this.g,t=this.l,n=this.h||void 0;tU(0),e.V=t,e.ia=n||{},e.L=e.Y,e.F=rh(e,null,e.V),n9(e)},rm.prototype.close=function(){n6(this.g)},rm.prototype.u=function(e){var t=this.g;if("string"==typeof e){var n={};n.__data__=e,e=n}else this.v&&((n={}).__data__=tg(e),e=n);t.i.push(new nS(t.ab++,e)),3==t.G&&n9(t)},rm.prototype.M=function(){this.g.l=null,delete this.j,n6(this.g),delete this.g,rm.X.M.call(this)},eN(rg,tK),eN(ry,tQ),eN(rv,rf),rv.prototype.xa=function(){tp(this.g,"a")},rv.prototype.wa=function(e){tp(this.g,new rg(e))},rv.prototype.va=function(e){tp(this.g,new ry(e))},rv.prototype.ua=function(){tp(this.g,"b")},rp.prototype.createWebChannel=rp.prototype.g,rm.prototype.send=rm.prototype.u,rm.prototype.open=rm.prototype.m,rm.prototype.close=rm.prototype.close,tB.NO_ERROR=0,tB.TIMEOUT=8,tB.HTTP_ERROR=6,t$.COMPLETE="complete",tW.EventType=tH,tH.OPEN="a",tH.CLOSE="b",tH.ERROR="c",tH.MESSAGE="d",tf.prototype.listen=tf.prototype.N,nz.prototype.listenOnce=nz.prototype.O,nz.prototype.getLastError=nz.prototype.Oa,nz.prototype.getLastErrorCode=nz.prototype.Ea,nz.prototype.getStatus=nz.prototype.aa,nz.prototype.getResponseJson=nz.prototype.Sa,nz.prototype.getResponseText=nz.prototype.fa,nz.prototype.send=nz.prototype.da,nz.prototype.setWithCredentials=nz.prototype.Ka;var r_=e_.createWebChannelTransport=function(){return new rp},rw=e_.getStatEventTarget=function(){return tL()},rb=e_.ErrorCode=tB,rI=e_.EventType=t$,rT=e_.Event=tO,rE=e_.Stat={sb:0,vb:1,wb:2,Pb:3,Ub:4,Rb:5,Sb:6,Qb:7,Ob:8,Tb:9,PROXY:10,NOPROXY:11,Mb:12,Ib:13,Jb:14,Hb:15,Kb:16,Lb:17,ob:18,nb:19,pb:20},rS=e_.FetchXmlHttpFactory=nj,rk=e_.WebChannel=tW,rx=e_.XhrIo=nz,rC=n(3454);let rN="@firebase/firestore";/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class rA{constructor(e){this.uid=e}isAuthenticated(){return null!=this.uid}toKey(){return this.isAuthenticated()?"uid:"+this.uid:"anonymous-user"}isEqual(e){return e.uid===this.uid}}rA.UNAUTHENTICATED=new rA(null),rA.GOOGLE_CREDENTIALS=new rA("google-credentials-uid"),rA.FIRST_PARTY=new rA("first-party-uid"),rA.MOCK_USER=new rA("mock-user");/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let rR="9.12.1",rD=new C.Yd("@firebase/firestore");function rO(){return rD.logLevel}function rP(e,...t){if(rD.logLevel<=C.in.DEBUG){let n=t.map(rj);rD.debug(`Firestore (${rR}): ${e}`,...n)}}function rL(e,...t){if(rD.logLevel<=C.in.ERROR){let n=t.map(rj);rD.error(`Firestore (${rR}): ${e}`,...n)}}function rM(e,...t){if(rD.logLevel<=C.in.WARN){let n=t.map(rj);rD.warn(`Firestore (${rR}): ${e}`,...n)}}function rj(e){if("string"==typeof e)return e;try{return JSON.stringify(e)}catch(t){return e}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function rF(e="Unexpected state"){let t=`FIRESTORE (${rR}) INTERNAL ASSERTION FAILED: `+e;throw rL(t),Error(t)}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let rU={OK:"ok",CANCELLED:"cancelled",UNKNOWN:"unknown",INVALID_ARGUMENT:"invalid-argument",DEADLINE_EXCEEDED:"deadline-exceeded",NOT_FOUND:"not-found",ALREADY_EXISTS:"already-exists",PERMISSION_DENIED:"permission-denied",UNAUTHENTICATED:"unauthenticated",RESOURCE_EXHAUSTED:"resource-exhausted",FAILED_PRECONDITION:"failed-precondition",ABORTED:"aborted",OUT_OF_RANGE:"out-of-range",UNIMPLEMENTED:"unimplemented",INTERNAL:"internal",UNAVAILABLE:"unavailable",DATA_LOSS:"data-loss"};class rV extends S.ZR{constructor(e,t){super(e,t),this.code=e,this.message=t,this.toString=()=>`${this.name}: [code=${this.code}]: ${this.message}`}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class rq{constructor(){this.promise=new Promise((e,t)=>{this.resolve=e,this.reject=t})}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class rB{constructor(e,t){this.user=t,this.type="OAuth",this.headers=new Map,this.headers.set("Authorization",`Bearer ${e}`)}}class r${getToken(){return Promise.resolve(null)}invalidateToken(){}start(e,t){e.enqueueRetryable(()=>t(rA.UNAUTHENTICATED))}shutdown(){}}class rz{constructor(e){this.token=e,this.changeListener=null}getToken(){return Promise.resolve(this.token)}invalidateToken(){}start(e,t){this.changeListener=t,e.enqueueRetryable(()=>t(this.token.user))}shutdown(){this.changeListener=null}}class rG{constructor(e){this.t=e,this.currentUser=rA.UNAUTHENTICATED,this.i=0,this.forceRefresh=!1,this.auth=null}start(e,t){let n=this.i,r=e=>this.i!==n?(n=this.i,t(e)):Promise.resolve(),i=new rq;this.o=()=>{this.i++,this.currentUser=this.u(),i.resolve(),i=new rq,e.enqueueRetryable(()=>r(this.currentUser))};let s=()=>{let t=i;e.enqueueRetryable(async()=>{await t.promise,await r(this.currentUser)})},o=e=>{rP("FirebaseAuthCredentialsProvider","Auth detected"),this.auth=e,this.auth.addAuthTokenListener(this.o),s()};this.t.onInit(e=>o(e)),setTimeout(()=>{if(!this.auth){let e=this.t.getImmediate({optional:!0});e?o(e):(rP("FirebaseAuthCredentialsProvider","Auth not yet detected"),i.resolve(),i=new rq)}},0),s()}getToken(){let e=this.i,t=this.forceRefresh;return this.forceRefresh=!1,this.auth?this.auth.getToken(t).then(t=>this.i!==e?(rP("FirebaseAuthCredentialsProvider","getToken aborted due to token change."),this.getToken()):t?("string"==typeof t.accessToken||rF(),new rB(t.accessToken,this.currentUser)):null):Promise.resolve(null)}invalidateToken(){this.forceRefresh=!0}shutdown(){this.auth&&this.auth.removeAuthTokenListener(this.o)}u(){let e=this.auth&&this.auth.getUid();return null===e||"string"==typeof e||rF(),new rA(e)}}class rW{constructor(e,t,n,r){this.h=e,this.l=t,this.m=n,this.g=r,this.type="FirstParty",this.user=rA.FIRST_PARTY,this.p=new Map}I(){return this.g?this.g():("object"==typeof this.h&&null!==this.h&&this.h.auth&&this.h.auth.getAuthHeaderValueForFirstParty||rF(),this.h.auth.getAuthHeaderValueForFirstParty([]))}get headers(){this.p.set("X-Goog-AuthUser",this.l);let e=this.I();return e&&this.p.set("Authorization",e),this.m&&this.p.set("X-Goog-Iam-Authorization-Token",this.m),this.p}}class rH{constructor(e,t,n,r){this.h=e,this.l=t,this.m=n,this.g=r}getToken(){return Promise.resolve(new rW(this.h,this.l,this.m,this.g))}start(e,t){e.enqueueRetryable(()=>t(rA.FIRST_PARTY))}shutdown(){}invalidateToken(){}}class rK{constructor(e){this.value=e,this.type="AppCheck",this.headers=new Map,e&&e.length>0&&this.headers.set("x-firebase-appcheck",this.value)}}class rQ{constructor(e){this.T=e,this.forceRefresh=!1,this.appCheck=null,this.A=null}start(e,t){let n=e=>{null!=e.error&&rP("FirebaseAppCheckTokenProvider",`Error getting App Check token; using placeholder token instead. Error: ${e.error.message}`);let n=e.token!==this.A;return this.A=e.token,rP("FirebaseAppCheckTokenProvider",`Received ${n?"new":"existing"} token.`),n?t(e.token):Promise.resolve()};this.o=t=>{e.enqueueRetryable(()=>n(t))};let r=e=>{rP("FirebaseAppCheckTokenProvider","AppCheck detected"),this.appCheck=e,this.appCheck.addTokenListener(this.o)};this.T.onInit(e=>r(e)),setTimeout(()=>{if(!this.appCheck){let e=this.T.getImmediate({optional:!0});e?r(e):rP("FirebaseAppCheckTokenProvider","AppCheck not yet detected")}},0)}getToken(){let e=this.forceRefresh;return this.forceRefresh=!1,this.appCheck?this.appCheck.getToken(e).then(e=>e?("string"==typeof e.token||rF(),this.A=e.token,new rK(e.token)):null):Promise.resolve(null)}invalidateToken(){this.forceRefresh=!0}shutdown(){this.appCheck&&this.appCheck.removeTokenListener(this.o)}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class rY{static R(){let e="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",t=Math.floor(256/e.length)*e.length,n="";for(;n.length<20;){let r=/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function(e){let t="undefined"!=typeof self&&(self.crypto||self.msCrypto),n=new Uint8Array(e);if(t&&"function"==typeof t.getRandomValues)t.getRandomValues(n);else for(let r=0;r<e;r++)n[r]=Math.floor(256*Math.random());return n}(40);for(let i=0;i<r.length;++i)n.length<20&&r[i]<t&&(n+=e.charAt(r[i]%e.length))}return n}}function rX(e,t){return e<t?-1:e>t?1:0}function rJ(e,t,n){return e.length===t.length&&e.every((e,r)=>n(e,t[r]))}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class rZ{constructor(e,t){if(this.seconds=e,this.nanoseconds=t,t<0||t>=1e9)throw new rV(rU.INVALID_ARGUMENT,"Timestamp nanoseconds out of range: "+t);if(e<-62135596800||e>=253402300800)throw new rV(rU.INVALID_ARGUMENT,"Timestamp seconds out of range: "+e)}static now(){return rZ.fromMillis(Date.now())}static fromDate(e){return rZ.fromMillis(e.getTime())}static fromMillis(e){let t=Math.floor(e/1e3);return new rZ(t,Math.floor(1e6*(e-1e3*t)))}toDate(){return new Date(this.toMillis())}toMillis(){return 1e3*this.seconds+this.nanoseconds/1e6}_compareTo(e){return this.seconds===e.seconds?rX(this.nanoseconds,e.nanoseconds):rX(this.seconds,e.seconds)}isEqual(e){return e.seconds===this.seconds&&e.nanoseconds===this.nanoseconds}toString(){return"Timestamp(seconds="+this.seconds+", nanoseconds="+this.nanoseconds+")"}toJSON(){return{seconds:this.seconds,nanoseconds:this.nanoseconds}}valueOf(){let e=this.seconds- -62135596800;return String(e).padStart(12,"0")+"."+String(this.nanoseconds).padStart(9,"0")}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class r0{constructor(e){this.timestamp=e}static fromTimestamp(e){return new r0(e)}static min(){return new r0(new rZ(0,0))}static max(){return new r0(new rZ(253402300799,999999999))}compareTo(e){return this.timestamp._compareTo(e.timestamp)}isEqual(e){return this.timestamp.isEqual(e.timestamp)}toMicroseconds(){return 1e6*this.timestamp.seconds+this.timestamp.nanoseconds/1e3}toString(){return"SnapshotVersion("+this.timestamp.toString()+")"}toTimestamp(){return this.timestamp}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class r1{constructor(e,t,n){void 0===t?t=0:t>e.length&&rF(),void 0===n?n=e.length-t:n>e.length-t&&rF(),this.segments=e,this.offset=t,this.len=n}get length(){return this.len}isEqual(e){return 0===r1.comparator(this,e)}child(e){let t=this.segments.slice(this.offset,this.limit());return e instanceof r1?e.forEach(e=>{t.push(e)}):t.push(e),this.construct(t)}limit(){return this.offset+this.length}popFirst(e){return e=void 0===e?1:e,this.construct(this.segments,this.offset+e,this.length-e)}popLast(){return this.construct(this.segments,this.offset,this.length-1)}firstSegment(){return this.segments[this.offset]}lastSegment(){return this.get(this.length-1)}get(e){return this.segments[this.offset+e]}isEmpty(){return 0===this.length}isPrefixOf(e){if(e.length<this.length)return!1;for(let t=0;t<this.length;t++)if(this.get(t)!==e.get(t))return!1;return!0}isImmediateParentOf(e){if(this.length+1!==e.length)return!1;for(let t=0;t<this.length;t++)if(this.get(t)!==e.get(t))return!1;return!0}forEach(e){for(let t=this.offset,n=this.limit();t<n;t++)e(this.segments[t])}toArray(){return this.segments.slice(this.offset,this.limit())}static comparator(e,t){let n=Math.min(e.length,t.length);for(let r=0;r<n;r++){let i=e.get(r),s=t.get(r);if(i<s)return -1;if(i>s)return 1}return e.length<t.length?-1:e.length>t.length?1:0}}class r2 extends r1{construct(e,t,n){return new r2(e,t,n)}canonicalString(){return this.toArray().join("/")}toString(){return this.canonicalString()}static fromString(...e){let t=[];for(let n of e){if(n.indexOf("//")>=0)throw new rV(rU.INVALID_ARGUMENT,`Invalid segment (${n}). Paths must not contain // in them.`);t.push(...n.split("/").filter(e=>e.length>0))}return new r2(t)}static emptyPath(){return new r2([])}}let r3=/^[_a-zA-Z][_a-zA-Z0-9]*$/;class r4 extends r1{construct(e,t,n){return new r4(e,t,n)}static isValidIdentifier(e){return r3.test(e)}canonicalString(){return this.toArray().map(e=>(e=e.replace(/\\/g,"\\\\").replace(/`/g,"\\`"),r4.isValidIdentifier(e)||(e="`"+e+"`"),e)).join(".")}toString(){return this.canonicalString()}isKeyField(){return 1===this.length&&"__name__"===this.get(0)}static keyField(){return new r4(["__name__"])}static fromServerFormat(e){let t=[],n="",r=0,i=()=>{if(0===n.length)throw new rV(rU.INVALID_ARGUMENT,`Invalid field path (${e}). Paths must not be empty, begin with '.', end with '.', or contain '..'`);t.push(n),n=""},s=!1;for(;r<e.length;){let o=e[r];if("\\"===o){if(r+1===e.length)throw new rV(rU.INVALID_ARGUMENT,"Path has trailing escape character: "+e);let a=e[r+1];if("\\"!==a&&"."!==a&&"`"!==a)throw new rV(rU.INVALID_ARGUMENT,"Path has invalid escape sequence: "+e);n+=a,r+=2}else"`"===o?(s=!s,r++):"."!==o||s?(n+=o,r++):(i(),r++)}if(i(),s)throw new rV(rU.INVALID_ARGUMENT,"Unterminated ` in path: "+e);return new r4(t)}static emptyPath(){return new r4([])}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class r6{constructor(e){this.path=e}static fromPath(e){return new r6(r2.fromString(e))}static fromName(e){return new r6(r2.fromString(e).popFirst(5))}static empty(){return new r6(r2.emptyPath())}get collectionGroup(){return this.path.popLast().lastSegment()}hasCollectionId(e){return this.path.length>=2&&this.path.get(this.path.length-2)===e}getCollectionGroup(){return this.path.get(this.path.length-2)}getCollectionPath(){return this.path.popLast()}isEqual(e){return null!==e&&0===r2.comparator(this.path,e.path)}toString(){return this.path.toString()}static comparator(e,t){return r2.comparator(e.path,t.path)}static isDocumentKey(e){return e.length%2==0}static fromSegments(e){return new r6(new r2(e.slice()))}}/**
 * @license
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class r5{constructor(e,t,n,r){this.indexId=e,this.collectionGroup=t,this.fields=n,this.indexState=r}}function r8(e){return e.fields.find(e=>2===e.kind)}function r9(e){return e.fields.filter(e=>2!==e.kind)}r5.UNKNOWN_ID=-1;class r7{constructor(e,t){this.fieldPath=e,this.kind=t}}class ie{constructor(e,t){this.sequenceNumber=e,this.offset=t}static empty(){return new ie(0,ii.min())}}function it(e,t){let n=e.toTimestamp().seconds,r=e.toTimestamp().nanoseconds+1,i=r0.fromTimestamp(1e9===r?new rZ(n+1,0):new rZ(n,r));return new ii(i,r6.empty(),t)}function ir(e){return new ii(e.readTime,e.key,-1)}class ii{constructor(e,t,n){this.readTime=e,this.documentKey=t,this.largestBatchId=n}static min(){return new ii(r0.min(),r6.empty(),-1)}static max(){return new ii(r0.max(),r6.empty(),-1)}}function is(e,t){let n=e.readTime.compareTo(t.readTime);return 0!==n?n:0!==(n=r6.comparator(e.documentKey,t.documentKey))?n:rX(e.largestBatchId,t.largestBatchId)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let io="The current tab is not in the required state to perform this operation. It might be necessary to refresh the browser tab.";class ia{constructor(){this.onCommittedListeners=[]}addOnCommittedListener(e){this.onCommittedListeners.push(e)}raiseOnCommittedEvent(){this.onCommittedListeners.forEach(e=>e())}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function il(e){if(e.code!==rU.FAILED_PRECONDITION||e.message!==io)throw e;rP("LocalStore","Unexpectedly lost primary lease")}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class iu{constructor(e){this.nextCallback=null,this.catchCallback=null,this.result=void 0,this.error=void 0,this.isDone=!1,this.callbackAttached=!1,e(e=>{this.isDone=!0,this.result=e,this.nextCallback&&this.nextCallback(e)},e=>{this.isDone=!0,this.error=e,this.catchCallback&&this.catchCallback(e)})}catch(e){return this.next(void 0,e)}next(e,t){return this.callbackAttached&&rF(),this.callbackAttached=!0,this.isDone?this.error?this.wrapFailure(t,this.error):this.wrapSuccess(e,this.result):new iu((n,r)=>{this.nextCallback=t=>{this.wrapSuccess(e,t).next(n,r)},this.catchCallback=e=>{this.wrapFailure(t,e).next(n,r)}})}toPromise(){return new Promise((e,t)=>{this.next(e,t)})}wrapUserFunction(e){try{let t=e();return t instanceof iu?t:iu.resolve(t)}catch(n){return iu.reject(n)}}wrapSuccess(e,t){return e?this.wrapUserFunction(()=>e(t)):iu.resolve(t)}wrapFailure(e,t){return e?this.wrapUserFunction(()=>e(t)):iu.reject(t)}static resolve(e){return new iu((t,n)=>{t(e)})}static reject(e){return new iu((t,n)=>{n(e)})}static waitFor(e){return new iu((t,n)=>{let r=0,i=0,s=!1;e.forEach(e=>{++r,e.next(()=>{++i,s&&i===r&&t()},e=>n(e))}),s=!0,i===r&&t()})}static or(e){let t=iu.resolve(!1);for(let n of e)t=t.next(e=>e?iu.resolve(e):n());return t}static forEach(e,t){let n=[];return e.forEach((e,r)=>{n.push(t.call(this,e,r))}),this.waitFor(n)}static mapArray(e,t){return new iu((n,r)=>{let i=e.length,s=Array(i),o=0;for(let a=0;a<i;a++){let l=a;t(e[l]).next(e=>{s[l]=e,++o===i&&n(s)},e=>r(e))}})}static doWhile(e,t){return new iu((n,r)=>{let i=()=>{!0===e()?t().next(()=>{i()},r):n()};i()})}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class ic{constructor(e,t){this.action=e,this.transaction=t,this.aborted=!1,this.P=new rq,this.transaction.oncomplete=()=>{this.P.resolve()},this.transaction.onabort=()=>{t.error?this.P.reject(new ip(e,t.error)):this.P.resolve()},this.transaction.onerror=t=>{let n=i_(t.target.error);this.P.reject(new ip(e,n))}}static open(e,t,n,r){try{return new ic(t,e.transaction(r,n))}catch(i){throw new ip(t,i)}}get v(){return this.P.promise}abort(e){e&&this.P.reject(e),this.aborted||(rP("SimpleDb","Aborting transaction:",e?e.message:"Client-initiated abort"),this.aborted=!0,this.transaction.abort())}V(){let e=this.transaction;this.aborted||"function"!=typeof e.commit||e.commit()}store(e){let t=this.transaction.objectStore(e);return new ig(t)}}class ih{constructor(e,t,n){this.name=e,this.version=t,this.S=n,12.2===ih.D((0,S.z$)())&&rL("Firestore persistence suffers from a bug in iOS 12.2 Safari that may cause your app to stop working. See https://stackoverflow.com/q/56496296/110915 for details and a potential workaround.")}static delete(e){return rP("SimpleDb","Removing database:",e),iy(window.indexedDB.deleteDatabase(e)).toPromise()}static C(){if(!(0,S.hl)())return!1;if(ih.N())return!0;let e=(0,S.z$)(),t=ih.D(e),n=ih.k(e);return!(e.indexOf("MSIE ")>0||e.indexOf("Trident/")>0||e.indexOf("Edge/")>0||0<t&&t<10||0<n&&n<4.5)}static N(){var e;return void 0!==rC&&"YES"===(null===(e=rC.env)||void 0===e?void 0:e.O)}static M(e,t){return e.store(t)}static D(e){let t=e.match(/i(?:phone|pad|pod) os ([\d_]+)/i),n=t?t[1].split("_").slice(0,2).join("."):"-1";return Number(n)}static k(e){let t=e.match(/Android ([\d.]+)/i),n=t?t[1].split(".").slice(0,2).join("."):"-1";return Number(n)}async F(e){return this.db||(rP("SimpleDb","Opening database:",this.name),this.db=await new Promise((t,n)=>{let r=indexedDB.open(this.name,this.version);r.onsuccess=e=>{let n=e.target.result;t(n)},r.onblocked=()=>{n(new ip(e,"Cannot upgrade IndexedDB schema while another tab is open. Close all tabs that access Firestore and reload this page to proceed."))},r.onerror=t=>{let r=t.target.error;"VersionError"===r.name?n(new rV(rU.FAILED_PRECONDITION,"A newer version of the Firestore SDK was previously used and so the persisted data is not compatible with the version of the SDK you are now using. The SDK will operate with persistence disabled. If you need persistence, please re-upgrade to a newer version of the SDK or else clear the persisted IndexedDB data for your app to start fresh.")):"InvalidStateError"===r.name?n(new rV(rU.FAILED_PRECONDITION,"Unable to open an IndexedDB connection. This could be due to running in a private browsing session on a browser whose private browsing sessions do not support IndexedDB: "+r)):n(new ip(e,r))},r.onupgradeneeded=e=>{rP("SimpleDb",'Database "'+this.name+'" requires upgrade from version:',e.oldVersion);let t=e.target.result;this.S.$(t,r.transaction,e.oldVersion,this.version).next(()=>{rP("SimpleDb","Database upgrade to version "+this.version+" complete")})}})),this.B&&(this.db.onversionchange=e=>this.B(e)),this.db}L(e){this.B=e,this.db&&(this.db.onversionchange=t=>e(t))}async runTransaction(e,t,n,r){let i="readonly"===t,s=0;for(;;){++s;try{this.db=await this.F(e);let o=ic.open(this.db,e,i?"readonly":"readwrite",n),a=r(o).next(e=>(o.V(),e)).catch(e=>(o.abort(e),iu.reject(e))).toPromise();return a.catch(()=>{}),await o.v,a}catch(u){let l="FirebaseError"!==u.name&&s<3;if(rP("SimpleDb","Transaction failed with error:",u.message,"Retrying:",l),this.close(),!l)return Promise.reject(u)}}}close(){this.db&&this.db.close(),this.db=void 0}}class id{constructor(e){this.U=e,this.q=!1,this.K=null}get isDone(){return this.q}get G(){return this.K}set cursor(e){this.U=e}done(){this.q=!0}j(e){this.K=e}delete(){return iy(this.U.delete())}}class ip extends rV{constructor(e,t){super(rU.UNAVAILABLE,`IndexedDB transaction '${e}' failed: ${t}`),this.name="IndexedDbTransactionError"}}function im(e){return"IndexedDbTransactionError"===e.name}class ig{constructor(e){this.store=e}put(e,t){let n;return void 0!==t?(rP("SimpleDb","PUT",this.store.name,e,t),n=this.store.put(t,e)):(rP("SimpleDb","PUT",this.store.name,"<auto-key>",e),n=this.store.put(e)),iy(n)}add(e){return rP("SimpleDb","ADD",this.store.name,e,e),iy(this.store.add(e))}get(e){return iy(this.store.get(e)).next(t=>(void 0===t&&(t=null),rP("SimpleDb","GET",this.store.name,e,t),t))}delete(e){return rP("SimpleDb","DELETE",this.store.name,e),iy(this.store.delete(e))}count(){return rP("SimpleDb","COUNT",this.store.name),iy(this.store.count())}W(e,t){let n=this.options(e,t);if(n.index||"function"!=typeof this.store.getAll){let r=this.cursor(n),i=[];return this.H(r,(e,t)=>{i.push(t)}).next(()=>i)}{let s=this.store.getAll(n.range);return new iu((e,t)=>{s.onerror=e=>{t(e.target.error)},s.onsuccess=t=>{e(t.target.result)}})}}J(e,t){let n=this.store.getAll(e,null===t?void 0:t);return new iu((e,t)=>{n.onerror=e=>{t(e.target.error)},n.onsuccess=t=>{e(t.target.result)}})}Y(e,t){rP("SimpleDb","DELETE ALL",this.store.name);let n=this.options(e,t);n.X=!1;let r=this.cursor(n);return this.H(r,(e,t,n)=>n.delete())}Z(e,t){let n;t?n=e:(n={},t=e);let r=this.cursor(n);return this.H(r,t)}tt(e){let t=this.cursor({});return new iu((n,r)=>{t.onerror=e=>{let t=i_(e.target.error);r(t)},t.onsuccess=t=>{let r=t.target.result;r?e(r.primaryKey,r.value).next(e=>{e?r.continue():n()}):n()}})}H(e,t){let n=[];return new iu((r,i)=>{e.onerror=e=>{i(e.target.error)},e.onsuccess=e=>{let i=e.target.result;if(!i)return void r();let s=new id(i),o=t(i.primaryKey,i.value,s);if(o instanceof iu){let a=o.catch(e=>(s.done(),iu.reject(e)));n.push(a)}s.isDone?r():null===s.G?i.continue():i.continue(s.G)}}).next(()=>iu.waitFor(n))}options(e,t){let n;return void 0!==e&&("string"==typeof e?n=e:t=e),{index:n,range:t}}cursor(e){let t="next";if(e.reverse&&(t="prev"),e.index){let n=this.store.index(e.index);return e.X?n.openKeyCursor(e.range,t):n.openCursor(e.range,t)}return this.store.openCursor(e.range,t)}}function iy(e){return new iu((t,n)=>{e.onsuccess=e=>{let n=e.target.result;t(n)},e.onerror=e=>{let t=i_(e.target.error);n(t)}})}let iv=!1;function i_(e){let t=ih.D((0,S.z$)());if(t>=12.2&&t<13){let n="An internal error was encountered in the Indexed Database server";if(e.message.indexOf(n)>=0){let r=new rV("internal",`IOS_INDEXEDDB_BUG1: IndexedDb has thrown '${n}'. This is likely due to an unavoidable bug in iOS. See https://stackoverflow.com/q/56496296/110915 for details and a potential workaround.`);return iv||(iv=!0,setTimeout(()=>{throw r},0)),r}}return e}class iw{constructor(e,t){this.asyncQueue=e,this.et=t,this.task=null}start(){this.nt(15e3)}stop(){this.task&&(this.task.cancel(),this.task=null)}get started(){return null!==this.task}nt(e){rP("IndexBackiller",`Scheduled in ${e}ms`),this.task=this.asyncQueue.enqueueAfterDelay("index_backfill",e,async()=>{this.task=null;try{rP("IndexBackiller",`Documents written: ${await this.et.st()}`)}catch(e){im(e)?rP("IndexBackiller","Ignoring IndexedDB error during index backfill: ",e):await il(e)}await this.nt(6e4)})}}class ib{constructor(e,t){this.localStore=e,this.persistence=t}async st(e=50){return this.persistence.runTransaction("Backfill Indexes","readwrite-primary",t=>this.it(t,e))}it(e,t){let n=new Set,r=t,i=!0;return iu.doWhile(()=>!0===i&&r>0,()=>this.localStore.indexManager.getNextCollectionGroupToUpdate(e).next(t=>{if(null!==t&&!n.has(t))return rP("IndexBackiller",`Processing collection: ${t}`),this.rt(e,t,r).next(e=>{r-=e,n.add(t)});i=!1})).next(()=>t-r)}rt(e,t,n){return this.localStore.indexManager.getMinOffsetFromCollectionGroup(e,t).next(r=>this.localStore.localDocuments.getNextDocuments(e,t,r,n).next(n=>{let i=n.changes;return this.localStore.indexManager.updateIndexEntries(e,i).next(()=>this.ot(r,n)).next(n=>(rP("IndexBackiller",`Updating offset: ${n}`),this.localStore.indexManager.updateCollectionGroup(e,t,n))).next(()=>i.size)}))}ot(e,t){let n=e;return t.changes.forEach((e,t)=>{let r=ir(t);is(r,n)>0&&(n=r)}),new ii(n.readTime,n.documentKey,Math.max(t.batchId,e.largestBatchId))}}/**
 * @license
 * Copyright 2018 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class iI{constructor(e,t){this.previousValue=e,t&&(t.sequenceNumberHandler=e=>this.ut(e),this.ct=e=>t.writeSequenceNumber(e))}ut(e){return this.previousValue=Math.max(e,this.previousValue),this.previousValue}next(){let e=++this.previousValue;return this.ct&&this.ct(e),e}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function iT(e){let t=0;for(let n in e)Object.prototype.hasOwnProperty.call(e,n)&&t++;return t}function iE(e,t){for(let n in e)Object.prototype.hasOwnProperty.call(e,n)&&t(n,e[n])}function iS(e){for(let t in e)if(Object.prototype.hasOwnProperty.call(e,t))return!1;return!0}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */iI.at=-1;class ik{constructor(e,t){this.comparator=e,this.root=t||iC.EMPTY}insert(e,t){return new ik(this.comparator,this.root.insert(e,t,this.comparator).copy(null,null,iC.BLACK,null,null))}remove(e){return new ik(this.comparator,this.root.remove(e,this.comparator).copy(null,null,iC.BLACK,null,null))}get(e){let t=this.root;for(;!t.isEmpty();){let n=this.comparator(e,t.key);if(0===n)return t.value;n<0?t=t.left:n>0&&(t=t.right)}return null}indexOf(e){let t=0,n=this.root;for(;!n.isEmpty();){let r=this.comparator(e,n.key);if(0===r)return t+n.left.size;r<0?n=n.left:(t+=n.left.size+1,n=n.right)}return -1}isEmpty(){return this.root.isEmpty()}get size(){return this.root.size}minKey(){return this.root.minKey()}maxKey(){return this.root.maxKey()}inorderTraversal(e){return this.root.inorderTraversal(e)}forEach(e){this.inorderTraversal((t,n)=>(e(t,n),!1))}toString(){let e=[];return this.inorderTraversal((t,n)=>(e.push(`${t}:${n}`),!1)),`{${e.join(", ")}}`}reverseTraversal(e){return this.root.reverseTraversal(e)}getIterator(){return new ix(this.root,null,this.comparator,!1)}getIteratorFrom(e){return new ix(this.root,e,this.comparator,!1)}getReverseIterator(){return new ix(this.root,null,this.comparator,!0)}getReverseIteratorFrom(e){return new ix(this.root,e,this.comparator,!0)}}class ix{constructor(e,t,n,r){this.isReverse=r,this.nodeStack=[];let i=1;for(;!e.isEmpty();)if(i=t?n(e.key,t):1,t&&r&&(i*=-1),i<0)e=this.isReverse?e.left:e.right;else{if(0===i){this.nodeStack.push(e);break}this.nodeStack.push(e),e=this.isReverse?e.right:e.left}}getNext(){let e=this.nodeStack.pop(),t={key:e.key,value:e.value};if(this.isReverse)for(e=e.left;!e.isEmpty();)this.nodeStack.push(e),e=e.right;else for(e=e.right;!e.isEmpty();)this.nodeStack.push(e),e=e.left;return t}hasNext(){return this.nodeStack.length>0}peek(){if(0===this.nodeStack.length)return null;let e=this.nodeStack[this.nodeStack.length-1];return{key:e.key,value:e.value}}}class iC{constructor(e,t,n,r,i){this.key=e,this.value=t,this.color=null!=n?n:iC.RED,this.left=null!=r?r:iC.EMPTY,this.right=null!=i?i:iC.EMPTY,this.size=this.left.size+1+this.right.size}copy(e,t,n,r,i){return new iC(null!=e?e:this.key,null!=t?t:this.value,null!=n?n:this.color,null!=r?r:this.left,null!=i?i:this.right)}isEmpty(){return!1}inorderTraversal(e){return this.left.inorderTraversal(e)||e(this.key,this.value)||this.right.inorderTraversal(e)}reverseTraversal(e){return this.right.reverseTraversal(e)||e(this.key,this.value)||this.left.reverseTraversal(e)}min(){return this.left.isEmpty()?this:this.left.min()}minKey(){return this.min().key}maxKey(){return this.right.isEmpty()?this.key:this.right.maxKey()}insert(e,t,n){let r=this,i=n(e,r.key);return(r=i<0?r.copy(null,null,null,r.left.insert(e,t,n),null):0===i?r.copy(null,t,null,null,null):r.copy(null,null,null,null,r.right.insert(e,t,n))).fixUp()}removeMin(){if(this.left.isEmpty())return iC.EMPTY;let e=this;return e.left.isRed()||e.left.left.isRed()||(e=e.moveRedLeft()),(e=e.copy(null,null,null,e.left.removeMin(),null)).fixUp()}remove(e,t){let n,r=this;if(0>t(e,r.key))r.left.isEmpty()||r.left.isRed()||r.left.left.isRed()||(r=r.moveRedLeft()),r=r.copy(null,null,null,r.left.remove(e,t),null);else{if(r.left.isRed()&&(r=r.rotateRight()),r.right.isEmpty()||r.right.isRed()||r.right.left.isRed()||(r=r.moveRedRight()),0===t(e,r.key)){if(r.right.isEmpty())return iC.EMPTY;n=r.right.min(),r=r.copy(n.key,n.value,null,null,r.right.removeMin())}r=r.copy(null,null,null,null,r.right.remove(e,t))}return r.fixUp()}isRed(){return this.color}fixUp(){let e=this;return e.right.isRed()&&!e.left.isRed()&&(e=e.rotateLeft()),e.left.isRed()&&e.left.left.isRed()&&(e=e.rotateRight()),e.left.isRed()&&e.right.isRed()&&(e=e.colorFlip()),e}moveRedLeft(){let e=this.colorFlip();return e.right.left.isRed()&&(e=(e=(e=e.copy(null,null,null,null,e.right.rotateRight())).rotateLeft()).colorFlip()),e}moveRedRight(){let e=this.colorFlip();return e.left.left.isRed()&&(e=(e=e.rotateRight()).colorFlip()),e}rotateLeft(){let e=this.copy(null,null,iC.RED,null,this.right.left);return this.right.copy(null,null,this.color,e,null)}rotateRight(){let e=this.copy(null,null,iC.RED,this.left.right,null);return this.left.copy(null,null,this.color,null,e)}colorFlip(){let e=this.left.copy(null,null,!this.left.color,null,null),t=this.right.copy(null,null,!this.right.color,null,null);return this.copy(null,null,!this.color,e,t)}checkMaxDepth(){let e=this.check();return Math.pow(2,e)<=this.size+1}check(){if(this.isRed()&&this.left.isRed()||this.right.isRed())throw rF();let e=this.left.check();if(e!==this.right.check())throw rF();return e+(this.isRed()?0:1)}}iC.EMPTY=null,iC.RED=!0,iC.BLACK=!1,iC.EMPTY=new class{constructor(){this.size=0}get key(){throw rF()}get value(){throw rF()}get color(){throw rF()}get left(){throw rF()}get right(){throw rF()}copy(e,t,n,r,i){return this}insert(e,t,n){return new iC(e,t)}remove(e,t){return this}isEmpty(){return!0}inorderTraversal(e){return!1}reverseTraversal(e){return!1}minKey(){return null}maxKey(){return null}isRed(){return!1}checkMaxDepth(){return!0}check(){return 0}};/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class iN{constructor(e){this.comparator=e,this.data=new ik(this.comparator)}has(e){return null!==this.data.get(e)}first(){return this.data.minKey()}last(){return this.data.maxKey()}get size(){return this.data.size}indexOf(e){return this.data.indexOf(e)}forEach(e){this.data.inorderTraversal((t,n)=>(e(t),!1))}forEachInRange(e,t){let n=this.data.getIteratorFrom(e[0]);for(;n.hasNext();){let r=n.getNext();if(this.comparator(r.key,e[1])>=0)return;t(r.key)}}forEachWhile(e,t){let n;for(n=void 0!==t?this.data.getIteratorFrom(t):this.data.getIterator();n.hasNext();)if(!e(n.getNext().key))return}firstAfterOrEqual(e){let t=this.data.getIteratorFrom(e);return t.hasNext()?t.getNext().key:null}getIterator(){return new iA(this.data.getIterator())}getIteratorFrom(e){return new iA(this.data.getIteratorFrom(e))}add(e){return this.copy(this.data.remove(e).insert(e,!0))}delete(e){return this.has(e)?this.copy(this.data.remove(e)):this}isEmpty(){return this.data.isEmpty()}unionWith(e){let t=this;return t.size<e.size&&(t=e,e=this),e.forEach(e=>{t=t.add(e)}),t}isEqual(e){if(!(e instanceof iN)||this.size!==e.size)return!1;let t=this.data.getIterator(),n=e.data.getIterator();for(;t.hasNext();){let r=t.getNext().key,i=n.getNext().key;if(0!==this.comparator(r,i))return!1}return!0}toArray(){let e=[];return this.forEach(t=>{e.push(t)}),e}toString(){let e=[];return this.forEach(t=>e.push(t)),"SortedSet("+e.toString()+")"}copy(e){let t=new iN(this.comparator);return t.data=e,t}}class iA{constructor(e){this.iter=e}getNext(){return this.iter.getNext().key}hasNext(){return this.iter.hasNext()}}function iR(e){return e.hasNext()?e.getNext():void 0}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class iD{constructor(e){this.fields=e,e.sort(r4.comparator)}static empty(){return new iD([])}unionWith(e){let t=new iN(r4.comparator);for(let n of this.fields)t=t.add(n);for(let r of e)t=t.add(r);return new iD(t.toArray())}covers(e){for(let t of this.fields)if(t.isPrefixOf(e))return!0;return!1}isEqual(e){return rJ(this.fields,e.fields,(e,t)=>e.isEqual(t))}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class iO{constructor(e){this.binaryString=e}static fromBase64String(e){let t=atob(e);return new iO(t)}static fromUint8Array(e){let t=function(e){let t="";for(let n=0;n<e.length;++n)t+=String.fromCharCode(e[n]);return t}(e);return new iO(t)}[Symbol.iterator](){let e=0;return{next:()=>e<this.binaryString.length?{value:this.binaryString.charCodeAt(e++),done:!1}:{value:void 0,done:!0}}}toBase64(){return btoa(this.binaryString)}toUint8Array(){return function(e){let t=new Uint8Array(e.length);for(let n=0;n<e.length;n++)t[n]=e.charCodeAt(n);return t}(this.binaryString)}approximateByteSize(){return 2*this.binaryString.length}compareTo(e){return rX(this.binaryString,e.binaryString)}isEqual(e){return this.binaryString===e.binaryString}}iO.EMPTY_BYTE_STRING=new iO("");let iP=RegExp(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.(\d+))?Z$/);function iL(e){if(e||rF(),"string"==typeof e){let t=0,n=iP.exec(e);if(n||rF(),n[1]){let r=n[1];t=Number(r=(r+"000000000").substr(0,9))}let i=new Date(e);return{seconds:Math.floor(i.getTime()/1e3),nanos:t}}return{seconds:iM(e.seconds),nanos:iM(e.nanos)}}function iM(e){return"number"==typeof e?e:"string"==typeof e?Number(e):0}function ij(e){return"string"==typeof e?iO.fromBase64String(e):iO.fromUint8Array(e)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function iF(e){var t,n;return"server_timestamp"===(null===(n=((null===(t=null==e?void 0:e.mapValue)||void 0===t?void 0:t.fields)||{}).__type__)||void 0===n?void 0:n.stringValue)}function iU(e){let t=iL(e.mapValue.fields.__local_write_time__.timestampValue);return new rZ(t.seconds,t.nanos)}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class iV{constructor(e,t,n,r,i,s,o,a){this.databaseId=e,this.appId=t,this.persistenceKey=n,this.host=r,this.ssl=i,this.forceLongPolling=s,this.autoDetectLongPolling=o,this.useFetchStreams=a}}class iq{constructor(e,t){this.projectId=e,this.database=t||"(default)"}static empty(){return new iq("","")}get isDefaultDatabase(){return"(default)"===this.database}isEqual(e){return e instanceof iq&&e.projectId===this.projectId&&e.database===this.database}}function iB(e){return null==e}function i$(e){return 0===e&&1/e==-1/0}function iz(e){return"number"==typeof e&&Number.isInteger(e)&&!i$(e)&&e<=Number.MAX_SAFE_INTEGER&&e>=Number.MIN_SAFE_INTEGER}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let iG={mapValue:{fields:{__type__:{stringValue:"__max__"}}}},iW={nullValue:"NULL_VALUE"};function iH(e){return"nullValue"in e?0:"booleanValue"in e?1:"integerValue"in e||"doubleValue"in e?2:"timestampValue"in e?3:"stringValue"in e?5:"bytesValue"in e?6:"referenceValue"in e?7:"geoPointValue"in e?8:"arrayValue"in e?9:"mapValue"in e?iF(e)?4:i5(e)?9007199254740991:10:rF()}function iK(e,t){if(e===t)return!0;let n=iH(e);if(n!==iH(t))return!1;switch(n){case 0:case 9007199254740991:return!0;case 1:return e.booleanValue===t.booleanValue;case 4:return iU(e).isEqual(iU(t));case 3:return function(e,t){if("string"==typeof e.timestampValue&&"string"==typeof t.timestampValue&&e.timestampValue.length===t.timestampValue.length)return e.timestampValue===t.timestampValue;let n=iL(e.timestampValue),r=iL(t.timestampValue);return n.seconds===r.seconds&&n.nanos===r.nanos}(e,t);case 5:return e.stringValue===t.stringValue;case 6:return ij(e.bytesValue).isEqual(ij(t.bytesValue));case 7:return e.referenceValue===t.referenceValue;case 8:return iM(e.geoPointValue.latitude)===iM(t.geoPointValue.latitude)&&iM(e.geoPointValue.longitude)===iM(t.geoPointValue.longitude);case 2:return function(e,t){if("integerValue"in e&&"integerValue"in t)return iM(e.integerValue)===iM(t.integerValue);if("doubleValue"in e&&"doubleValue"in t){let n=iM(e.doubleValue),r=iM(t.doubleValue);return n===r?i$(n)===i$(r):isNaN(n)&&isNaN(r)}return!1}(e,t);case 9:return rJ(e.arrayValue.values||[],t.arrayValue.values||[],iK);case 10:return function(e,t){let n=e.mapValue.fields||{},r=t.mapValue.fields||{};if(iT(n)!==iT(r))return!1;for(let i in n)if(n.hasOwnProperty(i)&&(void 0===r[i]||!iK(n[i],r[i])))return!1;return!0}(e,t);default:return rF()}}function iQ(e,t){return void 0!==(e.values||[]).find(e=>iK(e,t))}function iY(e,t){if(e===t)return 0;let n=iH(e),r=iH(t);if(n!==r)return rX(n,r);switch(n){case 0:case 9007199254740991:return 0;case 1:return rX(e.booleanValue,t.booleanValue);case 2:return function(e,t){let n=iM(e.integerValue||e.doubleValue),r=iM(t.integerValue||t.doubleValue);return n<r?-1:n>r?1:n===r?0:isNaN(n)?isNaN(r)?0:-1:1}(e,t);case 3:return iX(e.timestampValue,t.timestampValue);case 4:return iX(iU(e),iU(t));case 5:return rX(e.stringValue,t.stringValue);case 6:return function(e,t){let n=ij(e),r=ij(t);return n.compareTo(r)}(e.bytesValue,t.bytesValue);case 7:return function(e,t){let n=e.split("/"),r=t.split("/");for(let i=0;i<n.length&&i<r.length;i++){let s=rX(n[i],r[i]);if(0!==s)return s}return rX(n.length,r.length)}(e.referenceValue,t.referenceValue);case 8:return function(e,t){let n=rX(iM(e.latitude),iM(t.latitude));return 0!==n?n:rX(iM(e.longitude),iM(t.longitude))}(e.geoPointValue,t.geoPointValue);case 9:return function(e,t){let n=e.values||[],r=t.values||[];for(let i=0;i<n.length&&i<r.length;++i){let s=iY(n[i],r[i]);if(s)return s}return rX(n.length,r.length)}(e.arrayValue,t.arrayValue);case 10:return function(e,t){if(e===iG.mapValue&&t===iG.mapValue)return 0;if(e===iG.mapValue)return 1;if(t===iG.mapValue)return -1;let n=e.fields||{},r=Object.keys(n),i=t.fields||{},s=Object.keys(i);r.sort(),s.sort();for(let o=0;o<r.length&&o<s.length;++o){let a=rX(r[o],s[o]);if(0!==a)return a;let l=iY(n[r[o]],i[s[o]]);if(0!==l)return l}return rX(r.length,s.length)}(e.mapValue,t.mapValue);default:throw rF()}}function iX(e,t){if("string"==typeof e&&"string"==typeof t&&e.length===t.length)return rX(e,t);let n=iL(e),r=iL(t),i=rX(n.seconds,r.seconds);return 0!==i?i:rX(n.nanos,r.nanos)}function iJ(e){var t,n;return"nullValue"in e?"null":"booleanValue"in e?""+e.booleanValue:"integerValue"in e?""+e.integerValue:"doubleValue"in e?""+e.doubleValue:"timestampValue"in e?function(e){let t=iL(e);return`time(${t.seconds},${t.nanos})`}(e.timestampValue):"stringValue"in e?e.stringValue:"bytesValue"in e?ij(e.bytesValue).toBase64():"referenceValue"in e?(n=e.referenceValue,r6.fromName(n).toString()):"geoPointValue"in e?`geo(${(t=e.geoPointValue).latitude},${t.longitude})`:"arrayValue"in e?function(e){let t="[",n=!0;for(let r of e.values||[])n?n=!1:t+=",",t+=iJ(r);return t+"]"}(e.arrayValue):"mapValue"in e?function(e){let t=Object.keys(e.fields||{}).sort(),n="{",r=!0;for(let i of t)r?r=!1:n+=",",n+=`${i}:${iJ(e.fields[i])}`;return n+"}"}(e.mapValue):rF()}function iZ(e,t){return{referenceValue:`projects/${e.projectId}/databases/${e.database}/documents/${t.path.canonicalString()}`}}function i0(e){return!!e&&"integerValue"in e}function i1(e){return!!e&&"arrayValue"in e}function i2(e){return!!e&&"nullValue"in e}function i3(e){return!!e&&"doubleValue"in e&&isNaN(Number(e.doubleValue))}function i4(e){return!!e&&"mapValue"in e}function i6(e){if(e.geoPointValue)return{geoPointValue:Object.assign({},e.geoPointValue)};if(e.timestampValue&&"object"==typeof e.timestampValue)return{timestampValue:Object.assign({},e.timestampValue)};if(e.mapValue){let t={mapValue:{fields:{}}};return iE(e.mapValue.fields,(e,n)=>t.mapValue.fields[e]=i6(n)),t}if(e.arrayValue){let n={arrayValue:{values:[]}};for(let r=0;r<(e.arrayValue.values||[]).length;++r)n.arrayValue.values[r]=i6(e.arrayValue.values[r]);return n}return Object.assign({},e)}function i5(e){return"__max__"===(((e.mapValue||{}).fields||{}).__type__||{}).stringValue}function i8(e,t){let n=iY(e.value,t.value);return 0!==n?n:e.inclusive&&!t.inclusive?-1:!e.inclusive&&t.inclusive?1:0}function i9(e,t){let n=iY(e.value,t.value);return 0!==n?n:e.inclusive&&!t.inclusive?1:!e.inclusive&&t.inclusive?-1:0}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class i7{constructor(e){this.value=e}static empty(){return new i7({mapValue:{}})}field(e){if(e.isEmpty())return this.value;{let t=this.value;for(let n=0;n<e.length-1;++n)if(!i4(t=(t.mapValue.fields||{})[e.get(n)]))return null;return(t=(t.mapValue.fields||{})[e.lastSegment()])||null}}set(e,t){this.getFieldsMap(e.popLast())[e.lastSegment()]=i6(t)}setAll(e){let t=r4.emptyPath(),n={},r=[];e.forEach((e,i)=>{if(!t.isImmediateParentOf(i)){let s=this.getFieldsMap(t);this.applyChanges(s,n,r),n={},r=[],t=i.popLast()}e?n[i.lastSegment()]=i6(e):r.push(i.lastSegment())});let i=this.getFieldsMap(t);this.applyChanges(i,n,r)}delete(e){let t=this.field(e.popLast());i4(t)&&t.mapValue.fields&&delete t.mapValue.fields[e.lastSegment()]}isEqual(e){return iK(this.value,e.value)}getFieldsMap(e){let t=this.value;t.mapValue.fields||(t.mapValue={fields:{}});for(let n=0;n<e.length;++n){let r=t.mapValue.fields[e.get(n)];i4(r)&&r.mapValue.fields||(r={mapValue:{fields:{}}},t.mapValue.fields[e.get(n)]=r),t=r}return t.mapValue.fields}applyChanges(e,t,n){for(let r of(iE(t,(t,n)=>e[t]=n),n))delete e[r]}clone(){return new i7(i6(this.value))}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class se{constructor(e,t,n,r,i,s){this.key=e,this.documentType=t,this.version=n,this.readTime=r,this.data=i,this.documentState=s}static newInvalidDocument(e){return new se(e,0,r0.min(),r0.min(),i7.empty(),0)}static newFoundDocument(e,t,n){return new se(e,1,t,r0.min(),n,0)}static newNoDocument(e,t){return new se(e,2,t,r0.min(),i7.empty(),0)}static newUnknownDocument(e,t){return new se(e,3,t,r0.min(),i7.empty(),2)}convertToFoundDocument(e,t){return this.version=e,this.documentType=1,this.data=t,this.documentState=0,this}convertToNoDocument(e){return this.version=e,this.documentType=2,this.data=i7.empty(),this.documentState=0,this}convertToUnknownDocument(e){return this.version=e,this.documentType=3,this.data=i7.empty(),this.documentState=2,this}setHasCommittedMutations(){return this.documentState=2,this}setHasLocalMutations(){return this.documentState=1,this.version=r0.min(),this}setReadTime(e){return this.readTime=e,this}get hasLocalMutations(){return 1===this.documentState}get hasCommittedMutations(){return 2===this.documentState}get hasPendingWrites(){return this.hasLocalMutations||this.hasCommittedMutations}isValidDocument(){return 0!==this.documentType}isFoundDocument(){return 1===this.documentType}isNoDocument(){return 2===this.documentType}isUnknownDocument(){return 3===this.documentType}isEqual(e){return e instanceof se&&this.key.isEqual(e.key)&&this.version.isEqual(e.version)&&this.documentType===e.documentType&&this.documentState===e.documentState&&this.data.isEqual(e.data)}mutableCopy(){return new se(this.key,this.documentType,this.version,this.readTime,this.data.clone(),this.documentState)}toString(){return`Document(${this.key}, ${this.version}, ${JSON.stringify(this.data.value)}, {documentType: ${this.documentType}}), {documentState: ${this.documentState}})`}}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class st{constructor(e,t=null,n=[],r=[],i=null,s=null,o=null){this.path=e,this.collectionGroup=t,this.orderBy=n,this.filters=r,this.limit=i,this.startAt=s,this.endAt=o,this.ht=null}}function sn(e,t=null,n=[],r=[],i=null,s=null,o=null){return new st(e,t,n,r,i,s,o)}function sr(e){let t=e;if(null===t.ht){let n=t.path.canonicalString();null!==t.collectionGroup&&(n+="|cg:"+t.collectionGroup),n+="|f:"+t.filters.map(e=>e.field.canonicalString()+e.op.toString()+iJ(e.value)).join(",")+"|ob:"+t.orderBy.map(e=>e.field.canonicalString()+e.dir).join(","),iB(t.limit)||(n+="|l:"+t.limit),t.startAt&&(n+="|lb:"+(t.startAt.inclusive?"b:":"a:")+t.startAt.position.map(e=>iJ(e)).join(",")),t.endAt&&(n+="|ub:"+(t.endAt.inclusive?"a:":"b:")+t.endAt.position.map(e=>iJ(e)).join(",")),t.ht=n}return t.ht}function si(e,t){var n,r,i,s;if(e.limit!==t.limit||e.orderBy.length!==t.orderBy.length)return!1;for(let o=0;o<e.orderBy.length;o++)if(i=e.orderBy[o],s=t.orderBy[o],!(i.dir===s.dir&&i.field.isEqual(s.field)))return!1;if(e.filters.length!==t.filters.length)return!1;for(let a=0;a<e.filters.length;a++)if(n=e.filters[a],r=t.filters[a],n.op!==r.op||!n.field.isEqual(r.field)||!iK(n.value,r.value))return!1;return e.collectionGroup===t.collectionGroup&&!!e.path.isEqual(t.path)&&!!sb(e.startAt,t.startAt)&&sb(e.endAt,t.endAt)}function ss(e){return r6.isDocumentKey(e.path)&&null===e.collectionGroup&&0===e.filters.length}function so(e,t){return e.filters.filter(e=>e instanceof su&&e.field.isEqual(t))}function sa(e,t,n){let r=iW,i=!0;for(let s of so(e,t)){let o=iW,a=!0;switch(s.op){case"<":case"<=":var l;o="nullValue"in(l=s.value)?iW:"booleanValue"in l?{booleanValue:!1}:"integerValue"in l||"doubleValue"in l?{doubleValue:NaN}:"timestampValue"in l?{timestampValue:{seconds:Number.MIN_SAFE_INTEGER}}:"stringValue"in l?{stringValue:""}:"bytesValue"in l?{bytesValue:""}:"referenceValue"in l?iZ(iq.empty(),r6.empty()):"geoPointValue"in l?{geoPointValue:{latitude:-90,longitude:-180}}:"arrayValue"in l?{arrayValue:{}}:"mapValue"in l?{mapValue:{}}:rF();break;case"==":case"in":case">=":o=s.value;break;case">":o=s.value,a=!1;break;case"!=":case"not-in":o=iW}0>i8({value:r,inclusive:i},{value:o,inclusive:a})&&(r=o,i=a)}if(null!==n){for(let u=0;u<e.orderBy.length;++u)if(e.orderBy[u].field.isEqual(t)){let c=n.position[u];0>i8({value:r,inclusive:i},{value:c,inclusive:n.inclusive})&&(r=c,i=n.inclusive);break}}return{value:r,inclusive:i}}function sl(e,t,n){let r=iG,i=!0;for(let s of so(e,t)){let o=iG,a=!0;switch(s.op){case">=":case">":var l;o="nullValue"in(l=s.value)?{booleanValue:!1}:"booleanValue"in l?{doubleValue:NaN}:"integerValue"in l||"doubleValue"in l?{timestampValue:{seconds:Number.MIN_SAFE_INTEGER}}:"timestampValue"in l?{stringValue:""}:"stringValue"in l?{bytesValue:""}:"bytesValue"in l?iZ(iq.empty(),r6.empty()):"referenceValue"in l?{geoPointValue:{latitude:-90,longitude:-180}}:"geoPointValue"in l?{arrayValue:{}}:"arrayValue"in l?{mapValue:{}}:"mapValue"in l?iG:rF(),a=!1;break;case"==":case"in":case"<=":o=s.value;break;case"<":o=s.value,a=!1;break;case"!=":case"not-in":o=iG}i9({value:r,inclusive:i},{value:o,inclusive:a})>0&&(r=o,i=a)}if(null!==n){for(let u=0;u<e.orderBy.length;++u)if(e.orderBy[u].field.isEqual(t)){let c=n.position[u];i9({value:r,inclusive:i},{value:c,inclusive:n.inclusive})>0&&(r=c,i=n.inclusive);break}}return{value:r,inclusive:i}}class su extends class{}{constructor(e,t,n){super(),this.field=e,this.op=t,this.value=n}static create(e,t,n){return e.isKeyField()?"in"===t||"not-in"===t?this.lt(e,t,n):new sc(e,t,n):"array-contains"===t?new sp(e,n):"in"===t?new sm(e,n):"not-in"===t?new sg(e,n):"array-contains-any"===t?new sy(e,n):new su(e,t,n)}static lt(e,t,n){return"in"===t?new sh(e,n):new sd(e,n)}matches(e){let t=e.data.field(this.field);return"!="===this.op?null!==t&&this.ft(iY(t,this.value)):null!==t&&iH(this.value)===iH(t)&&this.ft(iY(t,this.value))}ft(e){switch(this.op){case"<":return e<0;case"<=":return e<=0;case"==":return 0===e;case"!=":return 0!==e;case">":return e>0;case">=":return e>=0;default:return rF()}}dt(){return["<","<=",">",">=","!=","not-in"].indexOf(this.op)>=0}}class sc extends su{constructor(e,t,n){super(e,t,n),this.key=r6.fromName(n.referenceValue)}matches(e){let t=r6.comparator(e.key,this.key);return this.ft(t)}}class sh extends su{constructor(e,t){super(e,"in",t),this.keys=sf("in",t)}matches(e){return this.keys.some(t=>t.isEqual(e.key))}}class sd extends su{constructor(e,t){super(e,"not-in",t),this.keys=sf("not-in",t)}matches(e){return!this.keys.some(t=>t.isEqual(e.key))}}function sf(e,t){var n;return((null===(n=t.arrayValue)||void 0===n?void 0:n.values)||[]).map(e=>r6.fromName(e.referenceValue))}class sp extends su{constructor(e,t){super(e,"array-contains",t)}matches(e){let t=e.data.field(this.field);return i1(t)&&iQ(t.arrayValue,this.value)}}class sm extends su{constructor(e,t){super(e,"in",t)}matches(e){let t=e.data.field(this.field);return null!==t&&iQ(this.value.arrayValue,t)}}class sg extends su{constructor(e,t){super(e,"not-in",t)}matches(e){if(iQ(this.value.arrayValue,{nullValue:"NULL_VALUE"}))return!1;let t=e.data.field(this.field);return null!==t&&!iQ(this.value.arrayValue,t)}}class sy extends su{constructor(e,t){super(e,"array-contains-any",t)}matches(e){let t=e.data.field(this.field);return!(!i1(t)||!t.arrayValue.values)&&t.arrayValue.values.some(e=>iQ(this.value.arrayValue,e))}}class sv{constructor(e,t){this.position=e,this.inclusive=t}}class s_{constructor(e,t="asc"){this.field=e,this.dir=t}}function sw(e,t,n){let r=0;for(let i=0;i<e.position.length;i++){let s=t[i],o=e.position[i];if(r=s.field.isKeyField()?r6.comparator(r6.fromName(o.referenceValue),n.key):iY(o,n.data.field(s.field)),"desc"===s.dir&&(r*=-1),0!==r)break}return r}function sb(e,t){if(null===e)return null===t;if(null===t||e.inclusive!==t.inclusive||e.position.length!==t.position.length)return!1;for(let n=0;n<e.position.length;n++)if(!iK(e.position[n],t.position[n]))return!1;return!0}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class sI{constructor(e,t=null,n=[],r=[],i=null,s="F",o=null,a=null){this.path=e,this.collectionGroup=t,this.explicitOrderBy=n,this.filters=r,this.limit=i,this.limitType=s,this.startAt=o,this.endAt=a,this._t=null,this.wt=null,this.startAt,this.endAt}}function sT(e){return new sI(e)}function sE(e){return 0===e.filters.length&&null===e.limit&&null==e.startAt&&null==e.endAt&&(0===e.explicitOrderBy.length||1===e.explicitOrderBy.length&&e.explicitOrderBy[0].field.isKeyField())}function sS(e){return e.explicitOrderBy.length>0?e.explicitOrderBy[0].field:null}function sk(e){for(let t of e.filters)if(t.dt())return t.field;return null}function sx(e){return null!==e.collectionGroup}function sC(e){let t=e;if(null===t._t){t._t=[];let n=sk(t),r=sS(t);if(null!==n&&null===r)n.isKeyField()||t._t.push(new s_(n)),t._t.push(new s_(r4.keyField(),"asc"));else{let i=!1;for(let s of t.explicitOrderBy)t._t.push(s),s.field.isKeyField()&&(i=!0);if(!i){let o=t.explicitOrderBy.length>0?t.explicitOrderBy[t.explicitOrderBy.length-1].dir:"asc";t._t.push(new s_(r4.keyField(),o))}}}return t._t}function sN(e){let t=e;if(!t.wt){if("F"===t.limitType)t.wt=sn(t.path,t.collectionGroup,sC(t),t.filters,t.limit,t.startAt,t.endAt);else{let n=[];for(let r of sC(t)){let i="desc"===r.dir?"asc":"desc";n.push(new s_(r.field,i))}let s=t.endAt?new sv(t.endAt.position,t.endAt.inclusive):null,o=t.startAt?new sv(t.startAt.position,t.startAt.inclusive):null;t.wt=sn(t.path,t.collectionGroup,n,t.filters,t.limit,s,o)}}return t.wt}function sA(e,t,n){return new sI(e.path,e.collectionGroup,e.explicitOrderBy.slice(),e.filters.slice(),t,n,e.startAt,e.endAt)}function sR(e,t){return si(sN(e),sN(t))&&e.limitType===t.limitType}function sD(e){return`${sr(sN(e))}|lt:${e.limitType}`}function sO(e){var t;let n;return`Query(target=${n=(t=sN(e)).path.canonicalString(),null!==t.collectionGroup&&(n+=" collectionGroup="+t.collectionGroup),t.filters.length>0&&(n+=`, filters: [${t.filters.map(e=>`${e.field.canonicalString()} ${e.op} ${iJ(e.value)}`).join(", ")}]`),iB(t.limit)||(n+=", limit: "+t.limit),t.orderBy.length>0&&(n+=`, orderBy: [${t.orderBy.map(e=>`${e.field.canonicalString()} (${e.dir})`).join(", ")}]`),t.startAt&&(n+=", startAt: "+(t.startAt.inclusive?"b:":"a:")+t.startAt.position.map(e=>iJ(e)).join(",")),t.endAt&&(n+=", endAt: "+(t.endAt.inclusive?"a:":"b:")+t.endAt.position.map(e=>iJ(e)).join(",")),`Target(${n})`}; limitType=${e.limitType})`}function sP(e,t){return t.isFoundDocument()&&function(e,t){let n=t.key.path;return null!==e.collectionGroup?t.key.hasCollectionId(e.collectionGroup)&&e.path.isPrefixOf(n):r6.isDocumentKey(e.path)?e.path.isEqual(n):e.path.isImmediateParentOf(n)}(e,t)&&function(e,t){for(let n of e.explicitOrderBy)if(!n.field.isKeyField()&&null===t.data.field(n.field))return!1;return!0}(e,t)&&function(e,t){for(let n of e.filters)if(!n.matches(t))return!1;return!0}(e,t)&&(!e.startAt||!!function(e,t,n){let r=sw(e,t,n);return e.inclusive?r<=0:r<0}(e.startAt,sC(e),t))&&(!e.endAt||!!function(e,t,n){let r=sw(e,t,n);return e.inclusive?r>=0:r>0}(e.endAt,sC(e),t))}function sL(e){return e.collectionGroup||(e.path.length%2==1?e.path.lastSegment():e.path.get(e.path.length-2))}function sM(e){return(t,n)=>{let r=!1;for(let i of sC(e)){let s=function(e,t,n){let r=e.field.isKeyField()?r6.comparator(t.key,n.key):function(e,t,n){let r=t.data.field(e),i=n.data.field(e);return null!==r&&null!==i?iY(r,i):rF()}(e.field,t,n);switch(e.dir){case"asc":return r;case"desc":return -1*r;default:return rF()}}(i,t,n);if(0!==s)return s;r=r||i.field.isKeyField()}return 0}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function sj(e,t){if(e.gt){if(isNaN(t))return{doubleValue:"NaN"};if(t===1/0)return{doubleValue:"Infinity"};if(t===-1/0)return{doubleValue:"-Infinity"}}return{doubleValue:i$(t)?"-0":t}}function sF(e){return{integerValue:""+e}}function sU(e,t){return iz(t)?sF(t):sj(e,t)}/**
 * @license
 * Copyright 2018 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class sV{constructor(){this._=void 0}}function sq(e,t){return e instanceof sH?i0(t)||t&&"doubleValue"in t?t:{integerValue:0}:null}class sB extends sV{}class s$ extends sV{constructor(e){super(),this.elements=e}}function sz(e,t){let n=sQ(t);for(let r of e.elements)n.some(e=>iK(e,r))||n.push(r);return{arrayValue:{values:n}}}class sG extends sV{constructor(e){super(),this.elements=e}}function sW(e,t){let n=sQ(t);for(let r of e.elements)n=n.filter(e=>!iK(e,r));return{arrayValue:{values:n}}}class sH extends sV{constructor(e,t){super(),this.It=e,this.yt=t}}function sK(e){return iM(e.integerValue||e.doubleValue)}function sQ(e){return i1(e)&&e.arrayValue.values?e.arrayValue.values.slice():[]}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class sY{constructor(e,t){this.field=e,this.transform=t}}class sX{constructor(e,t){this.version=e,this.transformResults=t}}class sJ{constructor(e,t){this.updateTime=e,this.exists=t}static none(){return new sJ}static exists(e){return new sJ(void 0,e)}static updateTime(e){return new sJ(e)}get isNone(){return void 0===this.updateTime&&void 0===this.exists}isEqual(e){return this.exists===e.exists&&(this.updateTime?!!e.updateTime&&this.updateTime.isEqual(e.updateTime):!e.updateTime)}}function sZ(e,t){return void 0!==e.updateTime?t.isFoundDocument()&&t.version.isEqual(e.updateTime):void 0===e.exists||e.exists===t.isFoundDocument()}class s0{}function s1(e,t){if(!e.hasLocalMutations||t&&0===t.fields.length)return null;if(null===t)return e.isNoDocument()?new s7(e.key,sJ.none()):new s4(e.key,e.data,sJ.none());{let n=e.data,r=i7.empty(),i=new iN(r4.comparator);for(let s of t.fields)if(!i.has(s)){let o=n.field(s);null===o&&s.length>1&&(s=s.popLast(),o=n.field(s)),null===o?r.delete(s):r.set(s,o),i=i.add(s)}return new s6(e.key,r,new iD(i.toArray()),sJ.none())}}function s2(e,t,n,r){return e instanceof s4?function(e,t,n,r){if(!sZ(e.precondition,t))return n;let i=e.value.clone(),s=s9(e.fieldTransforms,r,t);return i.setAll(s),t.convertToFoundDocument(t.version,i).setHasLocalMutations(),null}(e,t,n,r):e instanceof s6?function(e,t,n,r){if(!sZ(e.precondition,t))return n;let i=s9(e.fieldTransforms,r,t),s=t.data;return(s.setAll(s5(e)),s.setAll(i),t.convertToFoundDocument(t.version,s).setHasLocalMutations(),null===n)?null:n.unionWith(e.fieldMask.fields).unionWith(e.fieldTransforms.map(e=>e.field))}(e,t,n,r):sZ(e.precondition,t)?(t.convertToNoDocument(t.version).setHasLocalMutations(),null):n}function s3(e,t){var n,r;return e.type===t.type&&!!e.key.isEqual(t.key)&&!!e.precondition.isEqual(t.precondition)&&(n=e.fieldTransforms,r=t.fieldTransforms,!!(void 0===n&&void 0===r||!(!n||!r)&&rJ(n,r,(e,t)=>{var n,r;return e.field.isEqual(t.field)&&(n=e.transform,r=t.transform,n instanceof s$&&r instanceof s$||n instanceof sG&&r instanceof sG?rJ(n.elements,r.elements,iK):n instanceof sH&&r instanceof sH?iK(n.yt,r.yt):n instanceof sB&&r instanceof sB)})))&&(0===e.type?e.value.isEqual(t.value):1!==e.type||e.data.isEqual(t.data)&&e.fieldMask.isEqual(t.fieldMask))}class s4 extends s0{constructor(e,t,n,r=[]){super(),this.key=e,this.value=t,this.precondition=n,this.fieldTransforms=r,this.type=0}getFieldMask(){return null}}class s6 extends s0{constructor(e,t,n,r,i=[]){super(),this.key=e,this.data=t,this.fieldMask=n,this.precondition=r,this.fieldTransforms=i,this.type=1}getFieldMask(){return this.fieldMask}}function s5(e){let t=new Map;return e.fieldMask.fields.forEach(n=>{if(!n.isEmpty()){let r=e.data.field(n);t.set(n,r)}}),t}function s8(e,t,n){var r;let i=new Map;e.length===n.length||rF();for(let s=0;s<n.length;s++){let o=e[s],a=o.transform,l=t.data.field(o.field);i.set(o.field,(r=n[s],a instanceof s$?sz(a,l):a instanceof sG?sW(a,l):r))}return i}function s9(e,t,n){let r=new Map;for(let i of e){let s=i.transform,o=n.data.field(i.field);r.set(i.field,s instanceof sB?function(e,t){let n={fields:{__type__:{stringValue:"server_timestamp"},__local_write_time__:{timestampValue:{seconds:e.seconds,nanos:e.nanoseconds}}}};return t&&(n.fields.__previous_value__=t),{mapValue:n}}(t,o):s instanceof s$?sz(s,o):s instanceof sG?sW(s,o):function(e,t){let n=sq(e,t),r=sK(n)+sK(e.yt);return i0(n)&&i0(e.yt)?sF(r):sj(e.It,r)}(s,o))}return r}class s7 extends s0{constructor(e,t){super(),this.key=e,this.precondition=t,this.type=2,this.fieldTransforms=[]}getFieldMask(){return null}}class oe extends s0{constructor(e,t){super(),this.key=e,this.precondition=t,this.type=3,this.fieldTransforms=[]}getFieldMask(){return null}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class ot{constructor(e){this.count=e}}function on(e){switch(e){default:return rF();case rU.CANCELLED:case rU.UNKNOWN:case rU.DEADLINE_EXCEEDED:case rU.RESOURCE_EXHAUSTED:case rU.INTERNAL:case rU.UNAVAILABLE:case rU.UNAUTHENTICATED:return!1;case rU.INVALID_ARGUMENT:case rU.NOT_FOUND:case rU.ALREADY_EXISTS:case rU.PERMISSION_DENIED:case rU.FAILED_PRECONDITION:case rU.ABORTED:case rU.OUT_OF_RANGE:case rU.UNIMPLEMENTED:case rU.DATA_LOSS:return!0}}function or(e){if(void 0===e)return rL("GRPC error has no .code"),rU.UNKNOWN;switch(e){case b.OK:return rU.OK;case b.CANCELLED:return rU.CANCELLED;case b.UNKNOWN:return rU.UNKNOWN;case b.DEADLINE_EXCEEDED:return rU.DEADLINE_EXCEEDED;case b.RESOURCE_EXHAUSTED:return rU.RESOURCE_EXHAUSTED;case b.INTERNAL:return rU.INTERNAL;case b.UNAVAILABLE:return rU.UNAVAILABLE;case b.UNAUTHENTICATED:return rU.UNAUTHENTICATED;case b.INVALID_ARGUMENT:return rU.INVALID_ARGUMENT;case b.NOT_FOUND:return rU.NOT_FOUND;case b.ALREADY_EXISTS:return rU.ALREADY_EXISTS;case b.PERMISSION_DENIED:return rU.PERMISSION_DENIED;case b.FAILED_PRECONDITION:return rU.FAILED_PRECONDITION;case b.ABORTED:return rU.ABORTED;case b.OUT_OF_RANGE:return rU.OUT_OF_RANGE;case b.UNIMPLEMENTED:return rU.UNIMPLEMENTED;case b.DATA_LOSS:return rU.DATA_LOSS;default:return rF()}}(I=b||(b={}))[I.OK=0]="OK",I[I.CANCELLED=1]="CANCELLED",I[I.UNKNOWN=2]="UNKNOWN",I[I.INVALID_ARGUMENT=3]="INVALID_ARGUMENT",I[I.DEADLINE_EXCEEDED=4]="DEADLINE_EXCEEDED",I[I.NOT_FOUND=5]="NOT_FOUND",I[I.ALREADY_EXISTS=6]="ALREADY_EXISTS",I[I.PERMISSION_DENIED=7]="PERMISSION_DENIED",I[I.UNAUTHENTICATED=16]="UNAUTHENTICATED",I[I.RESOURCE_EXHAUSTED=8]="RESOURCE_EXHAUSTED",I[I.FAILED_PRECONDITION=9]="FAILED_PRECONDITION",I[I.ABORTED=10]="ABORTED",I[I.OUT_OF_RANGE=11]="OUT_OF_RANGE",I[I.UNIMPLEMENTED=12]="UNIMPLEMENTED",I[I.INTERNAL=13]="INTERNAL",I[I.UNAVAILABLE=14]="UNAVAILABLE",I[I.DATA_LOSS=15]="DATA_LOSS";/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class oi{constructor(e,t){this.mapKeyFn=e,this.equalsFn=t,this.inner={},this.innerSize=0}get(e){let t=this.mapKeyFn(e),n=this.inner[t];if(void 0!==n){for(let[r,i]of n)if(this.equalsFn(r,e))return i}}has(e){return void 0!==this.get(e)}set(e,t){let n=this.mapKeyFn(e),r=this.inner[n];if(void 0===r)return this.inner[n]=[[e,t]],void this.innerSize++;for(let i=0;i<r.length;i++)if(this.equalsFn(r[i][0],e))return void(r[i]=[e,t]);r.push([e,t]),this.innerSize++}delete(e){let t=this.mapKeyFn(e),n=this.inner[t];if(void 0===n)return!1;for(let r=0;r<n.length;r++)if(this.equalsFn(n[r][0],e))return 1===n.length?delete this.inner[t]:n.splice(r,1),this.innerSize--,!0;return!1}forEach(e){iE(this.inner,(t,n)=>{for(let[r,i]of n)e(r,i)})}isEmpty(){return iS(this.inner)}size(){return this.innerSize}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let os=new ik(r6.comparator),oo=new ik(r6.comparator);function oa(...e){let t=oo;for(let n of e)t=t.insert(n.key,n);return t}function ol(e){let t=oo;return e.forEach((e,n)=>t=t.insert(e,n.overlayedDocument)),t}function ou(){return new oi(e=>e.toString(),(e,t)=>e.isEqual(t))}let oc=new ik(r6.comparator),oh=new iN(r6.comparator);function od(...e){let t=oh;for(let n of e)t=t.add(n);return t}let of=new iN(rX);/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class op{constructor(e,t,n,r,i){this.snapshotVersion=e,this.targetChanges=t,this.targetMismatches=n,this.documentUpdates=r,this.resolvedLimboDocuments=i}static createSynthesizedRemoteEventForCurrentChange(e,t,n){let r=new Map;return r.set(e,om.createSynthesizedTargetChangeForCurrentChange(e,t,n)),new op(r0.min(),r,of,os,od())}}class om{constructor(e,t,n,r,i){this.resumeToken=e,this.current=t,this.addedDocuments=n,this.modifiedDocuments=r,this.removedDocuments=i}static createSynthesizedTargetChangeForCurrentChange(e,t,n){return new om(n,t,od(),od(),od())}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class og{constructor(e,t,n,r){this.Tt=e,this.removedTargetIds=t,this.key=n,this.Et=r}}class oy{constructor(e,t){this.targetId=e,this.At=t}}class ov{constructor(e,t,n=iO.EMPTY_BYTE_STRING,r=null){this.state=e,this.targetIds=t,this.resumeToken=n,this.cause=r}}class o_{constructor(){this.Rt=0,this.bt=oI(),this.Pt=iO.EMPTY_BYTE_STRING,this.vt=!1,this.Vt=!0}get current(){return this.vt}get resumeToken(){return this.Pt}get St(){return 0!==this.Rt}get Dt(){return this.Vt}Ct(e){e.approximateByteSize()>0&&(this.Vt=!0,this.Pt=e)}xt(){let e=od(),t=od(),n=od();return this.bt.forEach((r,i)=>{switch(i){case 0:e=e.add(r);break;case 2:t=t.add(r);break;case 1:n=n.add(r);break;default:rF()}}),new om(this.Pt,this.vt,e,t,n)}Nt(){this.Vt=!1,this.bt=oI()}kt(e,t){this.Vt=!0,this.bt=this.bt.insert(e,t)}Ot(e){this.Vt=!0,this.bt=this.bt.remove(e)}Mt(){this.Rt+=1}Ft(){this.Rt-=1}$t(){this.Vt=!0,this.vt=!0}}class ow{constructor(e){this.Bt=e,this.Lt=new Map,this.Ut=os,this.qt=ob(),this.Kt=new iN(rX)}Gt(e){for(let t of e.Tt)e.Et&&e.Et.isFoundDocument()?this.Qt(t,e.Et):this.jt(t,e.key,e.Et);for(let n of e.removedTargetIds)this.jt(n,e.key,e.Et)}Wt(e){this.forEachTarget(e,t=>{let n=this.zt(t);switch(e.state){case 0:this.Ht(t)&&n.Ct(e.resumeToken);break;case 1:n.Ft(),n.St||n.Nt(),n.Ct(e.resumeToken);break;case 2:n.Ft(),n.St||this.removeTarget(t);break;case 3:this.Ht(t)&&(n.$t(),n.Ct(e.resumeToken));break;case 4:this.Ht(t)&&(this.Jt(t),n.Ct(e.resumeToken));break;default:rF()}})}forEachTarget(e,t){e.targetIds.length>0?e.targetIds.forEach(t):this.Lt.forEach((e,n)=>{this.Ht(n)&&t(n)})}Yt(e){let t=e.targetId,n=e.At.count,r=this.Xt(t);if(r){let i=r.target;if(ss(i)){if(0===n){let s=new r6(i.path);this.jt(t,s,se.newNoDocument(s,r0.min()))}else 1===n||rF()}else this.Zt(t)!==n&&(this.Jt(t),this.Kt=this.Kt.add(t))}}te(e){let t=new Map;this.Lt.forEach((n,r)=>{let i=this.Xt(r);if(i){if(n.current&&ss(i.target)){let s=new r6(i.target.path);null!==this.Ut.get(s)||this.ee(r,s)||this.jt(r,s,se.newNoDocument(s,e))}n.Dt&&(t.set(r,n.xt()),n.Nt())}});let n=od();this.qt.forEach((e,t)=>{let r=!0;t.forEachWhile(e=>{let t=this.Xt(e);return!t||2===t.purpose||(r=!1,!1)}),r&&(n=n.add(e))}),this.Ut.forEach((t,n)=>n.setReadTime(e));let r=new op(e,t,this.Kt,this.Ut,n);return this.Ut=os,this.qt=ob(),this.Kt=new iN(rX),r}Qt(e,t){if(!this.Ht(e))return;let n=this.ee(e,t.key)?2:0;this.zt(e).kt(t.key,n),this.Ut=this.Ut.insert(t.key,t),this.qt=this.qt.insert(t.key,this.ne(t.key).add(e))}jt(e,t,n){if(!this.Ht(e))return;let r=this.zt(e);this.ee(e,t)?r.kt(t,1):r.Ot(t),this.qt=this.qt.insert(t,this.ne(t).delete(e)),n&&(this.Ut=this.Ut.insert(t,n))}removeTarget(e){this.Lt.delete(e)}Zt(e){let t=this.zt(e).xt();return this.Bt.getRemoteKeysForTarget(e).size+t.addedDocuments.size-t.removedDocuments.size}Mt(e){this.zt(e).Mt()}zt(e){let t=this.Lt.get(e);return t||(t=new o_,this.Lt.set(e,t)),t}ne(e){let t=this.qt.get(e);return t||(t=new iN(rX),this.qt=this.qt.insert(e,t)),t}Ht(e){let t=null!==this.Xt(e);return t||rP("WatchChangeAggregator","Detected inactive target",e),t}Xt(e){let t=this.Lt.get(e);return t&&t.St?null:this.Bt.se(e)}Jt(e){this.Lt.set(e,new o_),this.Bt.getRemoteKeysForTarget(e).forEach(t=>{this.jt(e,t,null)})}ee(e,t){return this.Bt.getRemoteKeysForTarget(e).has(t)}}function ob(){return new ik(r6.comparator)}function oI(){return new ik(r6.comparator)}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let oT={asc:"ASCENDING",desc:"DESCENDING"},oE={"<":"LESS_THAN","<=":"LESS_THAN_OR_EQUAL",">":"GREATER_THAN",">=":"GREATER_THAN_OR_EQUAL","==":"EQUAL","!=":"NOT_EQUAL","array-contains":"ARRAY_CONTAINS",in:"IN","not-in":"NOT_IN","array-contains-any":"ARRAY_CONTAINS_ANY"};class oS{constructor(e,t){this.databaseId=e,this.gt=t}}function ok(e,t){return e.gt?`${new Date(1e3*t.seconds).toISOString().replace(/\.\d*/,"").replace("Z","")}.${("000000000"+t.nanoseconds).slice(-9)}Z`:{seconds:""+t.seconds,nanos:t.nanoseconds}}function ox(e,t){return e.gt?t.toBase64():t.toUint8Array()}function oC(e){return e||rF(),r0.fromTimestamp(function(e){let t=iL(e);return new rZ(t.seconds,t.nanos)}(e))}function oN(e,t){return new r2(["projects",e.projectId,"databases",e.database]).child("documents").child(t).canonicalString()}function oA(e){let t=r2.fromString(e);return oW(t)||rF(),t}function oR(e,t){return oN(e.databaseId,t.path)}function oD(e,t){let n=oA(t);if(n.get(1)!==e.databaseId.projectId)throw new rV(rU.INVALID_ARGUMENT,"Tried to deserialize key from different project: "+n.get(1)+" vs "+e.databaseId.projectId);if(n.get(3)!==e.databaseId.database)throw new rV(rU.INVALID_ARGUMENT,"Tried to deserialize key from different database: "+n.get(3)+" vs "+e.databaseId.database);return new r6(oM(n))}function oO(e,t){return oN(e.databaseId,t)}function oP(e){let t=oA(e);return 4===t.length?r2.emptyPath():oM(t)}function oL(e){return new r2(["projects",e.databaseId.projectId,"databases",e.databaseId.database]).canonicalString()}function oM(e){return e.length>4&&"documents"===e.get(4)||rF(),e.popFirst(5)}function oj(e,t,n){return{name:oR(e,t),fields:n.value.mapValue.fields}}function oF(e,t,n){let r=oD(e,t.name),i=oC(t.updateTime),s=new i7({mapValue:{fields:t.fields}}),o=se.newFoundDocument(r,i,s);return n&&o.setHasCommittedMutations(),n?o.setHasCommittedMutations():o}function oU(e,t){var n;let r;if(t instanceof s4)r={update:oj(e,t.key,t.value)};else if(t instanceof s7)r={delete:oR(e,t.key)};else if(t instanceof s6)r={update:oj(e,t.key,t.data),updateMask:function(e){let t=[];return e.fields.forEach(e=>t.push(e.canonicalString())),{fieldPaths:t}}(t.fieldMask)};else{if(!(t instanceof oe))return rF();r={verify:oR(e,t.key)}}return t.fieldTransforms.length>0&&(r.updateTransforms=t.fieldTransforms.map(e=>(function(e,t){let n=t.transform;if(n instanceof sB)return{fieldPath:t.field.canonicalString(),setToServerValue:"REQUEST_TIME"};if(n instanceof s$)return{fieldPath:t.field.canonicalString(),appendMissingElements:{values:n.elements}};if(n instanceof sG)return{fieldPath:t.field.canonicalString(),removeAllFromArray:{values:n.elements}};if(n instanceof sH)return{fieldPath:t.field.canonicalString(),increment:n.yt};throw rF()})(0,e))),t.precondition.isNone||(r.currentDocument=void 0!==(n=t.precondition).updateTime?{updateTime:ok(e,n.updateTime.toTimestamp())}:void 0!==n.exists?{exists:n.exists}:rF()),r}function oV(e,t){var n;let r=t.currentDocument?void 0!==(n=t.currentDocument).updateTime?sJ.updateTime(oC(n.updateTime)):void 0!==n.exists?sJ.exists(n.exists):sJ.none():sJ.none(),i=t.updateTransforms?t.updateTransforms.map(t=>(function(e,t){let n=null;if("setToServerValue"in t)"REQUEST_TIME"===t.setToServerValue||rF(),n=new sB;else if("appendMissingElements"in t){let r=t.appendMissingElements.values||[];n=new s$(r)}else if("removeAllFromArray"in t){let i=t.removeAllFromArray.values||[];n=new sG(i)}else"increment"in t?n=new sH(e,t.increment):rF();let s=r4.fromServerFormat(t.fieldPath);return new sY(s,n)})(e,t)):[];if(t.update){t.update.name;let s=oD(e,t.update.name),o=new i7({mapValue:{fields:t.update.fields}});if(t.updateMask){let a=function(e){let t=e.fieldPaths||[];return new iD(t.map(e=>r4.fromServerFormat(e)))}(t.updateMask);return new s6(s,o,a,r,i)}return new s4(s,o,r,i)}if(t.delete){let l=oD(e,t.delete);return new s7(l,r)}if(t.verify){let u=oD(e,t.verify);return new oe(u,r)}return rF()}function oq(e,t){return{documents:[oO(e,t.path)]}}function oB(e,t){var n,r,i;let s={structuredQuery:{}},o=t.path;null!==t.collectionGroup?(s.parent=oO(e,o),s.structuredQuery.from=[{collectionId:t.collectionGroup,allDescendants:!0}]):(s.parent=oO(e,o.popLast()),s.structuredQuery.from=[{collectionId:o.lastSegment()}]);let a=function(e){if(0===e.length)return;let t=e.map(e=>(function(e){if("=="===e.op){if(i3(e.value))return{unaryFilter:{field:oz(e.field),op:"IS_NAN"}};if(i2(e.value))return{unaryFilter:{field:oz(e.field),op:"IS_NULL"}}}else if("!="===e.op){if(i3(e.value))return{unaryFilter:{field:oz(e.field),op:"IS_NOT_NAN"}};if(i2(e.value))return{unaryFilter:{field:oz(e.field),op:"IS_NOT_NULL"}}}return{fieldFilter:{field:oz(e.field),op:oE[e.op],value:e.value}}})(e));return 1===t.length?t[0]:{compositeFilter:{op:"AND",filters:t}}}(t.filters);a&&(s.structuredQuery.where=a);let l=function(e){if(0!==e.length)return e.map(e=>({field:oz(e.field),direction:oT[e.dir]}))}(t.orderBy);l&&(s.structuredQuery.orderBy=l);let u=(r=t.limit,e.gt||iB(r)?r:{value:r});return null!==u&&(s.structuredQuery.limit=u),t.startAt&&(s.structuredQuery.startAt={before:(n=t.startAt).inclusive,values:n.position}),t.endAt&&(s.structuredQuery.endAt={before:!(i=t.endAt).inclusive,values:i.position}),s}function o$(e){var t,n,r,i,s,o,a,l;let u,c=oP(e.parent),h=e.structuredQuery,d=h.from?h.from.length:0,f=null;if(d>0){1===d||rF();let p=h.from[0];p.allDescendants?f=p.collectionId:c=c.child(p.collectionId)}let m=[];h.where&&(m=function e(t){return t?void 0!==t.unaryFilter?[function(e){switch(e.unaryFilter.op){case"IS_NAN":let t=oG(e.unaryFilter.field);return su.create(t,"==",{doubleValue:NaN});case"IS_NULL":let n=oG(e.unaryFilter.field);return su.create(n,"==",{nullValue:"NULL_VALUE"});case"IS_NOT_NAN":let r=oG(e.unaryFilter.field);return su.create(r,"!=",{doubleValue:NaN});case"IS_NOT_NULL":let i=oG(e.unaryFilter.field);return su.create(i,"!=",{nullValue:"NULL_VALUE"});default:return rF()}}(t)]:void 0!==t.fieldFilter?[su.create(oG(t.fieldFilter.field),function(e){switch(e){case"EQUAL":return"==";case"NOT_EQUAL":return"!=";case"GREATER_THAN":return">";case"GREATER_THAN_OR_EQUAL":return">=";case"LESS_THAN":return"<";case"LESS_THAN_OR_EQUAL":return"<=";case"ARRAY_CONTAINS":return"array-contains";case"IN":return"in";case"NOT_IN":return"not-in";case"ARRAY_CONTAINS_ANY":return"array-contains-any";default:return rF()}}(t.fieldFilter.op),t.fieldFilter.value)]:void 0!==t.compositeFilter?t.compositeFilter.filters.map(t=>e(t)).reduce((e,t)=>e.concat(t)):rF():[]}(h.where));let g=[];h.orderBy&&(g=h.orderBy.map(e=>new s_(oG(e.field),function(e){switch(e){case"ASCENDING":return"asc";case"DESCENDING":return"desc";default:return}}(e.direction))));let y=null;h.limit&&(y=iB(u="object"==typeof(t=h.limit)?t.value:t)?null:u);let v=null;h.startAt&&(v=function(e){let t=!!e.before,n=e.values||[];return new sv(n,t)}(h.startAt));let _=null;return h.endAt&&(_=function(e){let t=!e.before,n=e.values||[];return new sv(n,t)}(h.endAt)),n=c,r=f,i=g,s=m,o=y,a=v,l=_,new sI(n,r,i,s,o,"F",a,l)}function oz(e){return{fieldPath:e.canonicalString()}}function oG(e){return r4.fromServerFormat(e.fieldPath)}function oW(e){return e.length>=4&&"projects"===e.get(0)&&"databases"===e.get(2)}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function oH(e){var t,n;let r="";for(let i=0;i<e.length;i++)r.length>0&&(r+="\x01\x01"),r=function(e,t){let n=t,r=e.length;for(let i=0;i<r;i++){let s=e.charAt(i);switch(s){case"\0":n+="\x01\x10";break;case"\x01":n+="\x01\x11";break;default:n+=s}}return n}(e.get(i),r);return r+"\x01\x01"}function oK(e){let t=e.length;if(t>=2||rF(),2===t)return"\x01"===e.charAt(0)&&"\x01"===e.charAt(1)||rF(),r2.emptyPath();let n=t-2,r=[],i="";for(let s=0;s<t;){let o=e.indexOf("\x01",s);switch((o<0||o>n)&&rF(),e.charAt(o+1)){case"\x01":let a;let l=e.substring(s,o);0===i.length?a=l:(i+=l,a=i,i=""),r.push(a);break;case"\x10":i+=e.substring(s,o)+"\0";break;case"\x11":i+=e.substring(s,o+1);break;default:rF()}s=o+2}return new r2(r)}/**
 * @license
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let oQ=["userId","batchId"],oY={},oX=["prefixPath","collectionGroup","readTime","documentId"],oJ=["prefixPath","collectionGroup","documentId"],oZ=["collectionGroup","readTime","prefixPath","documentId"],o0=["canonicalId","targetId"],o1=["targetId","path"],o2=["path","targetId"],o3=["collectionId","parent"],o4=["indexId","uid"],o6=["uid","sequenceNumber"],o5=["indexId","uid","arrayValue","directionalValue","orderedDocumentKey","documentKey"],o8=["indexId","uid","orderedDocumentKey"],o9=["userId","collectionPath","documentId"],o7=["userId","collectionPath","largestBatchId"],ae=["userId","collectionGroup","largestBatchId"],at=["mutationQueues","mutations","documentMutations","remoteDocuments","targets","owner","targetGlobal","targetDocuments","clientMetadata","remoteDocumentGlobal","collectionParents","bundles","namedQueries"],an=[...at,"documentOverlays"],ar=["mutationQueues","mutations","documentMutations","remoteDocumentsV14","targets","owner","targetGlobal","targetDocuments","clientMetadata","remoteDocumentGlobal","collectionParents","bundles","namedQueries","documentOverlays"],ai=[...ar,"indexConfiguration","indexState","indexEntries"];/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class as extends ia{constructor(e,t){super(),this.ie=e,this.currentSequenceNumber=t}}function ao(e,t){return ih.M(e.ie,t)}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class aa{constructor(e,t,n,r){this.batchId=e,this.localWriteTime=t,this.baseMutations=n,this.mutations=r}applyToRemoteDocument(e,t){let n=t.mutationResults;for(let r=0;r<this.mutations.length;r++){let i=this.mutations[r];if(i.key.isEqual(e.key)){var s;s=n[r],i instanceof s4?function(e,t,n){let r=e.value.clone(),i=s8(e.fieldTransforms,t,n.transformResults);r.setAll(i),t.convertToFoundDocument(n.version,r).setHasCommittedMutations()}(i,e,s):i instanceof s6?function(e,t,n){if(!sZ(e.precondition,t))return void t.convertToUnknownDocument(n.version);let r=s8(e.fieldTransforms,t,n.transformResults),i=t.data;i.setAll(s5(e)),i.setAll(r),t.convertToFoundDocument(n.version,i).setHasCommittedMutations()}(i,e,s):function(e,t,n){t.convertToNoDocument(n.version).setHasCommittedMutations()}(0,e,s)}}}applyToLocalView(e,t){for(let n of this.baseMutations)n.key.isEqual(e.key)&&(t=s2(n,e,t,this.localWriteTime));for(let r of this.mutations)r.key.isEqual(e.key)&&(t=s2(r,e,t,this.localWriteTime));return t}applyToLocalDocumentSet(e,t){let n=ou();return this.mutations.forEach(r=>{let i=e.get(r.key),s=i.overlayedDocument,o=this.applyToLocalView(s,i.mutatedFields);o=t.has(r.key)?null:o;let a=s1(s,o);null!==a&&n.set(r.key,a),s.isValidDocument()||s.convertToNoDocument(r0.min())}),n}keys(){return this.mutations.reduce((e,t)=>e.add(t.key),od())}isEqual(e){return this.batchId===e.batchId&&rJ(this.mutations,e.mutations,(e,t)=>s3(e,t))&&rJ(this.baseMutations,e.baseMutations,(e,t)=>s3(e,t))}}class al{constructor(e,t,n,r){this.batch=e,this.commitVersion=t,this.mutationResults=n,this.docVersions=r}static from(e,t,n){e.mutations.length===n.length||rF();let r=oc,i=e.mutations;for(let s=0;s<i.length;s++)r=r.insert(i[s].key,n[s].version);return new al(e,t,n,r)}}/**
 * @license
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class au{constructor(e,t){this.largestBatchId=e,this.mutation=t}getKey(){return this.mutation.key}isEqual(e){return null!==e&&this.mutation===e.mutation}toString(){return`Overlay{
      largestBatchId: ${this.largestBatchId},
      mutation: ${this.mutation.toString()}
    }`}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class ac{constructor(e,t,n,r,i=r0.min(),s=r0.min(),o=iO.EMPTY_BYTE_STRING){this.target=e,this.targetId=t,this.purpose=n,this.sequenceNumber=r,this.snapshotVersion=i,this.lastLimboFreeSnapshotVersion=s,this.resumeToken=o}withSequenceNumber(e){return new ac(this.target,this.targetId,this.purpose,e,this.snapshotVersion,this.lastLimboFreeSnapshotVersion,this.resumeToken)}withResumeToken(e,t){return new ac(this.target,this.targetId,this.purpose,this.sequenceNumber,t,this.lastLimboFreeSnapshotVersion,e)}withLastLimboFreeSnapshotVersion(e){return new ac(this.target,this.targetId,this.purpose,this.sequenceNumber,this.snapshotVersion,e,this.resumeToken)}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class ah{constructor(e){this.re=e}}function ad(e,t){let n=t.key,r={prefixPath:n.getCollectionPath().popLast().toArray(),collectionGroup:n.collectionGroup,documentId:n.path.lastSegment(),readTime:af(t.readTime),hasCommittedMutations:t.hasCommittedMutations};if(t.isFoundDocument()){var i;r.document={name:oR(i=e.re,t.key),fields:t.data.value.mapValue.fields,updateTime:ok(i,t.version.toTimestamp())}}else if(t.isNoDocument())r.noDocument={path:n.path.toArray(),readTime:ap(t.version)};else{if(!t.isUnknownDocument())return rF();r.unknownDocument={path:n.path.toArray(),version:ap(t.version)}}return r}function af(e){let t=e.toTimestamp();return[t.seconds,t.nanoseconds]}function ap(e){let t=e.toTimestamp();return{seconds:t.seconds,nanoseconds:t.nanoseconds}}function am(e){let t=new rZ(e.seconds,e.nanoseconds);return r0.fromTimestamp(t)}function ag(e,t){let n=(t.baseMutations||[]).map(t=>oV(e.re,t));for(let r=0;r<t.mutations.length-1;++r){let i=t.mutations[r];if(r+1<t.mutations.length&&void 0!==t.mutations[r+1].transform){let s=t.mutations[r+1];i.updateTransforms=s.transform.fieldTransforms,t.mutations.splice(r+1,1),++r}}let o=t.mutations.map(t=>oV(e.re,t)),a=rZ.fromMillis(t.localWriteTimeMs);return new aa(t.batchId,a,n,o)}function ay(e){var t;let n;let r=am(e.readTime),i=void 0!==e.lastLimboFreeSnapshotVersion?am(e.lastLimboFreeSnapshotVersion):r0.min();return void 0!==e.query.documents?(1===(t=e.query).documents.length||rF(),n=sN(sT(oP(t.documents[0])))):n=sN(o$(e.query)),new ac(n,e.targetId,0,e.lastListenSequenceNumber,r,i,iO.fromBase64String(e.resumeToken))}function av(e,t){let n;let r=ap(t.snapshotVersion),i=ap(t.lastLimboFreeSnapshotVersion);n=ss(t.target)?oq(e.re,t.target):oB(e.re,t.target);let s=t.resumeToken.toBase64();return{targetId:t.targetId,canonicalId:sr(t.target),readTime:r,resumeToken:s,lastListenSequenceNumber:t.sequenceNumber,lastLimboFreeSnapshotVersion:i,query:n}}function a_(e){let t=o$({parent:e.parent,structuredQuery:e.structuredQuery});return"LAST"===e.limitType?sA(t,t.limit,"L"):t}function aw(e,t){return new au(t.largestBatchId,oV(e.re,t.overlayMutation))}function ab(e,t){let n=t.path.lastSegment();return[e,oH(t.path.popLast()),n]}function aI(e,t,n,r){return{indexId:e,uid:t.uid||"",sequenceNumber:n,readTime:ap(r.readTime),documentKey:oH(r.documentKey.path),largestBatchId:r.largestBatchId}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class aT{getBundleMetadata(e,t){return aE(e).get(t).next(e=>{if(e)return{id:e.bundleId,createTime:am(e.createTime),version:e.version}})}saveBundleMetadata(e,t){return aE(e).put({bundleId:t.id,createTime:ap(oC(t.createTime)),version:t.version})}getNamedQuery(e,t){return aS(e).get(t).next(e=>{if(e)return{name:e.name,query:a_(e.bundledQuery),readTime:am(e.readTime)}})}saveNamedQuery(e,t){return aS(e).put({name:t.name,readTime:ap(oC(t.readTime)),bundledQuery:t.bundledQuery})}}function aE(e){return ao(e,"bundles")}function aS(e){return ao(e,"namedQueries")}/**
 * @license
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class ak{constructor(e,t){this.It=e,this.userId=t}static oe(e,t){let n=t.uid||"";return new ak(e,n)}getOverlay(e,t){return ax(e).get(ab(this.userId,t)).next(e=>e?aw(this.It,e):null)}getOverlays(e,t){let n=ou();return iu.forEach(t,t=>this.getOverlay(e,t).next(e=>{null!==e&&n.set(t,e)})).next(()=>n)}saveOverlays(e,t,n){let r=[];return n.forEach((n,i)=>{let s=new au(t,i);r.push(this.ue(e,s))}),iu.waitFor(r)}removeOverlaysForBatchId(e,t,n){let r=new Set;t.forEach(e=>r.add(oH(e.getCollectionPath())));let i=[];return r.forEach(t=>{let r=IDBKeyRange.bound([this.userId,t,n],[this.userId,t,n+1],!1,!0);i.push(ax(e).Y("collectionPathOverlayIndex",r))}),iu.waitFor(i)}getOverlaysForCollection(e,t,n){let r=ou(),i=oH(t),s=IDBKeyRange.bound([this.userId,i,n],[this.userId,i,Number.POSITIVE_INFINITY],!0);return ax(e).W("collectionPathOverlayIndex",s).next(e=>{for(let t of e){let n=aw(this.It,t);r.set(n.getKey(),n)}return r})}getOverlaysForCollectionGroup(e,t,n,r){let i;let s=ou(),o=IDBKeyRange.bound([this.userId,t,n],[this.userId,t,Number.POSITIVE_INFINITY],!0);return ax(e).Z({index:"collectionGroupOverlayIndex",range:o},(e,t,n)=>{let o=aw(this.It,t);s.size()<r||o.largestBatchId===i?(s.set(o.getKey(),o),i=o.largestBatchId):n.done()}).next(()=>s)}ue(e,t){return ax(e).put(function(e,t,n){let[r,i,s]=ab(t,n.mutation.key);return{userId:t,collectionPath:i,documentId:s,collectionGroup:n.mutation.key.getCollectionGroup(),largestBatchId:n.largestBatchId,overlayMutation:oU(e.re,n.mutation)}}(this.It,this.userId,t))}}function ax(e){return ao(e,"documentOverlays")}/**
 * @license
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class aC{constructor(){}ce(e,t){this.ae(e,t),t.he()}ae(e,t){if("nullValue"in e)this.le(t,5);else if("booleanValue"in e)this.le(t,10),t.fe(e.booleanValue?1:0);else if("integerValue"in e)this.le(t,15),t.fe(iM(e.integerValue));else if("doubleValue"in e){let n=iM(e.doubleValue);isNaN(n)?this.le(t,13):(this.le(t,15),i$(n)?t.fe(0):t.fe(n))}else if("timestampValue"in e){let r=e.timestampValue;this.le(t,20),"string"==typeof r?t.de(r):(t.de(`${r.seconds||""}`),t.fe(r.nanos||0))}else if("stringValue"in e)this._e(e.stringValue,t),this.we(t);else if("bytesValue"in e)this.le(t,30),t.me(ij(e.bytesValue)),this.we(t);else if("referenceValue"in e)this.ge(e.referenceValue,t);else if("geoPointValue"in e){let i=e.geoPointValue;this.le(t,45),t.fe(i.latitude||0),t.fe(i.longitude||0)}else"mapValue"in e?i5(e)?this.le(t,Number.MAX_SAFE_INTEGER):(this.ye(e.mapValue,t),this.we(t)):"arrayValue"in e?(this.pe(e.arrayValue,t),this.we(t)):rF()}_e(e,t){this.le(t,25),this.Ie(e,t)}Ie(e,t){t.de(e)}ye(e,t){let n=e.fields||{};for(let r of(this.le(t,55),Object.keys(n)))this._e(r,t),this.ae(n[r],t)}pe(e,t){let n=e.values||[];for(let r of(this.le(t,50),n))this.ae(r,t)}ge(e,t){this.le(t,37),r6.fromName(e).path.forEach(e=>{this.le(t,60),this.Ie(e,t)})}le(e,t){e.fe(t)}we(e){e.fe(2)}}function aN(e){let t=64-function(e){let t=0;for(let n=0;n<8;++n){let r=function(e){if(0===e)return 8;let t=0;return e>>4==0&&(t+=4,e<<=4),e>>6==0&&(t+=2,e<<=2),e>>7==0&&(t+=1),t}(255&e[n]);if(t+=r,8!==r)break}return t}(e);return Math.ceil(t/8)}aC.Te=new aC;class aA{constructor(){this.buffer=new Uint8Array(1024),this.position=0}Ee(e){let t=e[Symbol.iterator](),n=t.next();for(;!n.done;)this.Ae(n.value),n=t.next();this.Re()}be(e){let t=e[Symbol.iterator](),n=t.next();for(;!n.done;)this.Pe(n.value),n=t.next();this.ve()}Ve(e){for(let t of e){let n=t.charCodeAt(0);if(n<128)this.Ae(n);else if(n<2048)this.Ae(960|n>>>6),this.Ae(128|63&n);else if(t<"\ud800"||"\udbff"<t)this.Ae(480|n>>>12),this.Ae(128|63&n>>>6),this.Ae(128|63&n);else{let r=t.codePointAt(0);this.Ae(240|r>>>18),this.Ae(128|63&r>>>12),this.Ae(128|63&r>>>6),this.Ae(128|63&r)}}this.Re()}Se(e){for(let t of e){let n=t.charCodeAt(0);if(n<128)this.Pe(n);else if(n<2048)this.Pe(960|n>>>6),this.Pe(128|63&n);else if(t<"\ud800"||"\udbff"<t)this.Pe(480|n>>>12),this.Pe(128|63&n>>>6),this.Pe(128|63&n);else{let r=t.codePointAt(0);this.Pe(240|r>>>18),this.Pe(128|63&r>>>12),this.Pe(128|63&r>>>6),this.Pe(128|63&r)}}this.ve()}De(e){let t=this.Ce(e),n=aN(t);this.xe(1+n),this.buffer[this.position++]=255&n;for(let r=t.length-n;r<t.length;++r)this.buffer[this.position++]=255&t[r]}Ne(e){let t=this.Ce(e),n=aN(t);this.xe(1+n),this.buffer[this.position++]=~(255&n);for(let r=t.length-n;r<t.length;++r)this.buffer[this.position++]=~(255&t[r])}ke(){this.Oe(255),this.Oe(255)}Me(){this.Fe(255),this.Fe(255)}reset(){this.position=0}seed(e){this.xe(e.length),this.buffer.set(e,this.position),this.position+=e.length}$e(){return this.buffer.slice(0,this.position)}Ce(e){let t=function(e){let t=new DataView(new ArrayBuffer(8));return t.setFloat64(0,e,!1),new Uint8Array(t.buffer)}(e),n=0!=(128&t[0]);t[0]^=n?255:128;for(let r=1;r<t.length;++r)t[r]^=n?255:0;return t}Ae(e){let t=255&e;0===t?(this.Oe(0),this.Oe(255)):255===t?(this.Oe(255),this.Oe(0)):this.Oe(t)}Pe(e){let t=255&e;0===t?(this.Fe(0),this.Fe(255)):255===t?(this.Fe(255),this.Fe(0)):this.Fe(e)}Re(){this.Oe(0),this.Oe(1)}ve(){this.Fe(0),this.Fe(1)}Oe(e){this.xe(1),this.buffer[this.position++]=e}Fe(e){this.xe(1),this.buffer[this.position++]=~e}xe(e){let t=e+this.position;if(t<=this.buffer.length)return;let n=2*this.buffer.length;n<t&&(n=t);let r=new Uint8Array(n);r.set(this.buffer),this.buffer=r}}class aR{constructor(e){this.Be=e}me(e){this.Be.Ee(e)}de(e){this.Be.Ve(e)}fe(e){this.Be.De(e)}he(){this.Be.ke()}}class aD{constructor(e){this.Be=e}me(e){this.Be.be(e)}de(e){this.Be.Se(e)}fe(e){this.Be.Ne(e)}he(){this.Be.Me()}}class aO{constructor(){this.Be=new aA,this.Le=new aR(this.Be),this.Ue=new aD(this.Be)}seed(e){this.Be.seed(e)}qe(e){return 0===e?this.Le:this.Ue}$e(){return this.Be.$e()}reset(){this.Be.reset()}}/**
 * @license
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class aP{constructor(e,t,n,r){this.indexId=e,this.documentKey=t,this.arrayValue=n,this.directionalValue=r}Ke(){let e=this.directionalValue.length,t=0===e||255===this.directionalValue[e-1]?e+1:e,n=new Uint8Array(t);return n.set(this.directionalValue,0),t!==e?n.set([0],this.directionalValue.length):++n[n.length-1],new aP(this.indexId,this.documentKey,this.arrayValue,n)}}function aL(e,t){let n=e.indexId-t.indexId;return 0!==n?n:0!==(n=aM(e.arrayValue,t.arrayValue))?n:0!==(n=aM(e.directionalValue,t.directionalValue))?n:r6.comparator(e.documentKey,t.documentKey)}function aM(e,t){for(let n=0;n<e.length&&n<t.length;++n){let r=e[n]-t[n];if(0!==r)return r}return e.length-t.length}/**
 * @license
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class aj{constructor(e){for(let t of(this.collectionId=null!=e.collectionGroup?e.collectionGroup:e.path.lastSegment(),this.Ge=e.orderBy,this.Qe=[],e.filters)){let n=t;n.dt()?this.je=n:this.Qe.push(n)}}We(e){let t=r8(e);if(void 0!==t&&!this.ze(t))return!1;let n=r9(e),r=0,i=0;for(;r<n.length&&this.ze(n[r]);++r);if(r===n.length)return!0;if(void 0!==this.je){let s=n[r];if(!this.He(this.je,s)||!this.Je(this.Ge[i++],s))return!1;++r}for(;r<n.length;++r){let o=n[r];if(i>=this.Ge.length||!this.Je(this.Ge[i++],o))return!1}return!0}ze(e){for(let t of this.Qe)if(this.He(t,e))return!0;return!1}He(e,t){if(void 0===e||!e.field.isEqual(t.fieldPath))return!1;let n="array-contains"===e.op||"array-contains-any"===e.op;return 2===t.kind===n}Je(e,t){return!!e.field.isEqual(t.fieldPath)&&(0===t.kind&&"asc"===e.dir||1===t.kind&&"desc"===e.dir)}}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class aF{constructor(){this.Ye=new aU}addToCollectionParentIndex(e,t){return this.Ye.add(t),iu.resolve()}getCollectionParents(e,t){return iu.resolve(this.Ye.getEntries(t))}addFieldIndex(e,t){return iu.resolve()}deleteFieldIndex(e,t){return iu.resolve()}getDocumentsMatchingTarget(e,t){return iu.resolve(null)}getIndexType(e,t){return iu.resolve(0)}getFieldIndexes(e,t){return iu.resolve([])}getNextCollectionGroupToUpdate(e){return iu.resolve(null)}getMinOffset(e,t){return iu.resolve(ii.min())}getMinOffsetFromCollectionGroup(e,t){return iu.resolve(ii.min())}updateCollectionGroup(e,t,n){return iu.resolve()}updateIndexEntries(e,t){return iu.resolve()}}class aU{constructor(){this.index={}}add(e){let t=e.lastSegment(),n=e.popLast(),r=this.index[t]||new iN(r2.comparator),i=!r.has(n);return this.index[t]=r.add(n),i}has(e){let t=e.lastSegment(),n=e.popLast(),r=this.index[t];return r&&r.has(n)}getEntries(e){return(this.index[e]||new iN(r2.comparator)).toArray()}}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let aV=new Uint8Array(0);class aq{constructor(e,t){this.user=e,this.databaseId=t,this.Xe=new aU,this.Ze=new oi(e=>sr(e),(e,t)=>si(e,t)),this.uid=e.uid||""}addToCollectionParentIndex(e,t){if(!this.Xe.has(t)){let n=t.lastSegment(),r=t.popLast();e.addOnCommittedListener(()=>{this.Xe.add(t)});let i={collectionId:n,parent:oH(r)};return aB(e).put(i)}return iu.resolve()}getCollectionParents(e,t){let n=[],r=IDBKeyRange.bound([t,""],[t+"\0",""],!1,!0);return aB(e).W(r).next(e=>{for(let r of e){if(r.collectionId!==t)break;n.push(oK(r.parent))}return n})}addFieldIndex(e,t){let n=az(e),r={indexId:t.indexId,collectionGroup:t.collectionGroup,fields:t.fields.map(e=>[e.fieldPath.canonicalString(),e.kind])};delete r.indexId;let i=n.add(r);if(t.indexState){let s=aG(e);return i.next(e=>{s.put(aI(e,this.user,t.indexState.sequenceNumber,t.indexState.offset))})}return i.next()}deleteFieldIndex(e,t){let n=az(e),r=aG(e),i=a$(e);return n.delete(t.indexId).next(()=>r.delete(IDBKeyRange.bound([t.indexId],[t.indexId+1],!1,!0))).next(()=>i.delete(IDBKeyRange.bound([t.indexId],[t.indexId+1],!1,!0)))}getDocumentsMatchingTarget(e,t){let n=a$(e),r=!0,i=new Map;return iu.forEach(this.tn(t),t=>this.en(e,t).next(e=>{r&&(r=!!e),i.set(t,e)})).next(()=>{if(r){let e=od(),s=[];return iu.forEach(i,(r,i)=>{rP("IndexedDbIndexManager",`Using index id=${r.indexId}|cg=${r.collectionGroup}|f=${r.fields.map(e=>`${e.fieldPath}:${e.kind}`).join(",")} to execute ${sr(t)}`);let o=function(e,t){let n=r8(t);if(void 0===n)return null;for(let r of so(e,n.fieldPath))switch(r.op){case"array-contains-any":return r.value.arrayValue.values||[];case"array-contains":return[r.value]}return null}(i,r),a=function(e,t){let n=new Map;for(let r of r9(t))for(let i of so(e,r.fieldPath))switch(i.op){case"==":case"in":n.set(r.fieldPath.canonicalString(),i.value);break;case"not-in":case"!=":return n.set(r.fieldPath.canonicalString(),i.value),Array.from(n.values())}return null}(i,r),l=function(e,t){let n=[],r=!0;for(let i of r9(t)){let s=0===i.kind?sa(e,i.fieldPath,e.startAt):sl(e,i.fieldPath,e.startAt);n.push(s.value),r&&(r=s.inclusive)}return new sv(n,r)}(i,r),u=function(e,t){let n=[],r=!0;for(let i of r9(t)){let s=0===i.kind?sl(e,i.fieldPath,e.endAt):sa(e,i.fieldPath,e.endAt);n.push(s.value),r&&(r=s.inclusive)}return new sv(n,r)}(i,r),c=this.nn(r,i,l),h=this.nn(r,i,u),d=this.sn(r,i,a),f=this.rn(r.indexId,o,c,l.inclusive,h,u.inclusive,d);return iu.forEach(f,r=>n.J(r,t.limit).next(t=>{t.forEach(t=>{let n=r6.fromSegments(t.documentKey);e.has(n)||(e=e.add(n),s.push(n))})}))}).next(()=>s)}return iu.resolve(null)})}tn(e){let t=this.Ze.get(e);return t||(t=[e],this.Ze.set(e,t),t)}rn(e,t,n,r,i,s,o){let a=(null!=t?t.length:1)*Math.max(n.length,i.length),l=a/(null!=t?t.length:1),u=[];for(let c=0;c<a;++c){let h=t?this.on(t[c/l]):aV,d=this.un(e,h,n[c%l],r),f=this.cn(e,h,i[c%l],s),p=o.map(t=>this.un(e,h,t,!0));u.push(...this.createRange(d,f,p))}return u}un(e,t,n,r){let i=new aP(e,r6.empty(),t,n);return r?i:i.Ke()}cn(e,t,n,r){let i=new aP(e,r6.empty(),t,n);return r?i.Ke():i}en(e,t){let n=new aj(t),r=null!=t.collectionGroup?t.collectionGroup:t.path.lastSegment();return this.getFieldIndexes(e,r).next(e=>{let t=null;for(let r of e)n.We(r)&&(!t||r.fields.length>t.fields.length)&&(t=r);return t})}getIndexType(e,t){let n=2;return iu.forEach(this.tn(t),t=>this.en(e,t).next(e=>{e?0!==n&&e.fields.length<function(e){let t=new iN(r4.comparator),n=!1;for(let r of e.filters){let i=r;i.field.isKeyField()||("array-contains"===i.op||"array-contains-any"===i.op?n=!0:t=t.add(i.field))}for(let s of e.orderBy)s.field.isKeyField()||(t=t.add(s.field));return t.size+(n?1:0)}(t)&&(n=1):n=0})).next(()=>n)}an(e,t){let n=new aO;for(let r of r9(e)){let i=t.data.field(r.fieldPath);if(null==i)return null;let s=n.qe(r.kind);aC.Te.ce(i,s)}return n.$e()}on(e){let t=new aO;return aC.Te.ce(e,t.qe(0)),t.$e()}hn(e,t){let n=new aO;return aC.Te.ce(iZ(this.databaseId,t),n.qe(function(e){let t=r9(e);return 0===t.length?0:t[t.length-1].kind}(e))),n.$e()}sn(e,t,n){if(null===n)return[];let r=[];r.push(new aO);let i=0;for(let s of r9(e)){let o=n[i++];for(let a of r)if(this.ln(t,s.fieldPath)&&i1(o))r=this.fn(r,s,o);else{let l=a.qe(s.kind);aC.Te.ce(o,l)}}return this.dn(r)}nn(e,t,n){return this.sn(e,t,n.position)}dn(e){let t=[];for(let n=0;n<e.length;++n)t[n]=e[n].$e();return t}fn(e,t,n){let r=[...e],i=[];for(let s of n.arrayValue.values||[])for(let o of r){let a=new aO;a.seed(o.$e()),aC.Te.ce(s,a.qe(t.kind)),i.push(a)}return i}ln(e,t){return!!e.filters.find(e=>e instanceof su&&e.field.isEqual(t)&&("in"===e.op||"not-in"===e.op))}getFieldIndexes(e,t){let n=az(e),r=aG(e);return(t?n.W("collectionGroupIndex",IDBKeyRange.bound(t,t)):n.W()).next(e=>{let t=[];return iu.forEach(e,e=>r.get([e.indexId,this.uid]).next(n=>{t.push(function(e,t){let n=t?new ie(t.sequenceNumber,new ii(am(t.readTime),new r6(oK(t.documentKey)),t.largestBatchId)):ie.empty(),r=e.fields.map(([e,t])=>new r7(r4.fromServerFormat(e),t));return new r5(e.indexId,e.collectionGroup,r,n)}(e,n))})).next(()=>t)})}getNextCollectionGroupToUpdate(e){return this.getFieldIndexes(e).next(e=>0===e.length?null:(e.sort((e,t)=>{let n=e.indexState.sequenceNumber-t.indexState.sequenceNumber;return 0!==n?n:rX(e.collectionGroup,t.collectionGroup)}),e[0].collectionGroup))}updateCollectionGroup(e,t,n){let r=az(e),i=aG(e);return this._n(e).next(e=>r.W("collectionGroupIndex",IDBKeyRange.bound(t,t)).next(t=>iu.forEach(t,t=>i.put(aI(t.indexId,this.user,e,n)))))}updateIndexEntries(e,t){let n=new Map;return iu.forEach(t,(t,r)=>{let i=n.get(t.collectionGroup);return(i?iu.resolve(i):this.getFieldIndexes(e,t.collectionGroup)).next(i=>(n.set(t.collectionGroup,i),iu.forEach(i,n=>this.wn(e,t,n).next(t=>{let i=this.mn(r,n);return t.isEqual(i)?iu.resolve():this.gn(e,r,n,t,i)}))))})}yn(e,t,n,r){return a$(e).put({indexId:r.indexId,uid:this.uid,arrayValue:r.arrayValue,directionalValue:r.directionalValue,orderedDocumentKey:this.hn(n,t.key),documentKey:t.key.path.toArray()})}pn(e,t,n,r){return a$(e).delete([r.indexId,this.uid,r.arrayValue,r.directionalValue,this.hn(n,t.key),t.key.path.toArray()])}wn(e,t,n){let r=a$(e),i=new iN(aL);return r.Z({index:"documentKeyIndex",range:IDBKeyRange.only([n.indexId,this.uid,this.hn(n,t)])},(e,r)=>{i=i.add(new aP(n.indexId,t,r.arrayValue,r.directionalValue))}).next(()=>i)}mn(e,t){let n=new iN(aL),r=this.an(t,e);if(null==r)return n;let i=r8(t);if(null!=i){let s=e.data.field(i.fieldPath);if(i1(s))for(let o of s.arrayValue.values||[])n=n.add(new aP(t.indexId,e.key,this.on(o),r))}else n=n.add(new aP(t.indexId,e.key,aV,r));return n}gn(e,t,n,r,i){rP("IndexedDbIndexManager","Updating index entries for document '%s'",t.key);let s=[];return function(e,t,n,r,i){let s=e.getIterator(),o=t.getIterator(),a=iR(s),l=iR(o);for(;a||l;){let u=!1,c=!1;if(a&&l){let h=n(a,l);h<0?c=!0:h>0&&(u=!0)}else null!=a?c=!0:u=!0;u?(r(l),l=iR(o)):c?(i(a),a=iR(s)):(a=iR(s),l=iR(o))}}(r,i,aL,r=>{s.push(this.yn(e,t,n,r))},r=>{s.push(this.pn(e,t,n,r))}),iu.waitFor(s)}_n(e){let t=1;return aG(e).Z({index:"sequenceNumberIndex",reverse:!0,range:IDBKeyRange.upperBound([this.uid,Number.MAX_SAFE_INTEGER])},(e,n,r)=>{r.done(),t=n.sequenceNumber+1}).next(()=>t)}createRange(e,t,n){n=n.sort((e,t)=>aL(e,t)).filter((e,t,n)=>!t||0!==aL(e,n[t-1]));let r=[];for(let i of(r.push(e),n)){let s=aL(i,e),o=aL(i,t);if(0===s)r[0]=e.Ke();else if(s>0&&o<0)r.push(i),r.push(i.Ke());else if(o>0)break}r.push(t);let a=[];for(let l=0;l<r.length;l+=2)a.push(IDBKeyRange.bound([r[l].indexId,this.uid,r[l].arrayValue,r[l].directionalValue,aV,[]],[r[l+1].indexId,this.uid,r[l+1].arrayValue,r[l+1].directionalValue,aV,[]]));return a}getMinOffsetFromCollectionGroup(e,t){return this.getFieldIndexes(e,t).next(aW)}getMinOffset(e,t){return iu.mapArray(this.tn(t),t=>this.en(e,t).next(e=>e||rF())).next(aW)}}function aB(e){return ao(e,"collectionParents")}function a$(e){return ao(e,"indexEntries")}function az(e){return ao(e,"indexConfiguration")}function aG(e){return ao(e,"indexState")}function aW(e){0!==e.length||rF();let t=e[0].indexState.offset,n=t.largestBatchId;for(let r=1;r<e.length;r++){let i=e[r].indexState.offset;0>is(i,t)&&(t=i),n<i.largestBatchId&&(n=i.largestBatchId)}return new ii(t.readTime,t.documentKey,n)}/**
 * @license
 * Copyright 2018 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let aH={didRun:!1,sequenceNumbersCollected:0,targetsRemoved:0,documentsRemoved:0};class aK{constructor(e,t,n){this.cacheSizeCollectionThreshold=e,this.percentileToCollect=t,this.maximumSequenceNumbersToCollect=n}static withCacheSize(e){return new aK(e,aK.DEFAULT_COLLECTION_PERCENTILE,aK.DEFAULT_MAX_SEQUENCE_NUMBERS_TO_COLLECT)}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function aQ(e,t,n){let r=e.store("mutations"),i=e.store("documentMutations"),s=[],o=IDBKeyRange.only(n.batchId),a=0,l=r.Z({range:o},(e,t,n)=>(a++,n.delete()));s.push(l.next(()=>{1===a||rF()}));let u=[];for(let c of n.mutations){var h,d;let f=(h=c.key.path,d=n.batchId,[t,oH(h),d]);s.push(i.delete(f)),u.push(c.key)}return iu.waitFor(s).next(()=>u)}function aY(e){let t;if(!e)return 0;if(e.document)t=e.document;else if(e.unknownDocument)t=e.unknownDocument;else{if(!e.noDocument)throw rF();t=e.noDocument}return JSON.stringify(t).length}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */aK.DEFAULT_COLLECTION_PERCENTILE=10,aK.DEFAULT_MAX_SEQUENCE_NUMBERS_TO_COLLECT=1e3,aK.DEFAULT=new aK(41943040,aK.DEFAULT_COLLECTION_PERCENTILE,aK.DEFAULT_MAX_SEQUENCE_NUMBERS_TO_COLLECT),aK.DISABLED=new aK(-1,0,0);class aX{constructor(e,t,n,r){this.userId=e,this.It=t,this.indexManager=n,this.referenceDelegate=r,this.In={}}static oe(e,t,n,r){""!==e.uid||rF();let i=e.isAuthenticated()?e.uid:"";return new aX(i,t,n,r)}checkEmpty(e){let t=!0,n=IDBKeyRange.bound([this.userId,Number.NEGATIVE_INFINITY],[this.userId,Number.POSITIVE_INFINITY]);return aZ(e).Z({index:"userMutationsIndex",range:n},(e,n,r)=>{t=!1,r.done()}).next(()=>t)}addMutationBatch(e,t,n,r){let i=a0(e),s=aZ(e);return s.add({}).next(o=>{"number"==typeof o||rF();let a=new aa(o,t,n,r),l=function(e,t,n){let r=n.baseMutations.map(t=>oU(e.re,t)),i=n.mutations.map(t=>oU(e.re,t));return{userId:t,batchId:n.batchId,localWriteTimeMs:n.localWriteTime.toMillis(),baseMutations:r,mutations:i}}(this.It,this.userId,a),u=[],c=new iN((e,t)=>rX(e.canonicalString(),t.canonicalString()));for(let h of r){let d=[this.userId,oH(h.key.path),o];c=c.add(h.key.path.popLast()),u.push(s.put(l)),u.push(i.put(d,oY))}return c.forEach(t=>{u.push(this.indexManager.addToCollectionParentIndex(e,t))}),e.addOnCommittedListener(()=>{this.In[o]=a.keys()}),iu.waitFor(u).next(()=>a)})}lookupMutationBatch(e,t){return aZ(e).get(t).next(e=>e?(e.userId===this.userId||rF(),ag(this.It,e)):null)}Tn(e,t){return this.In[t]?iu.resolve(this.In[t]):this.lookupMutationBatch(e,t).next(e=>{if(e){let n=e.keys();return this.In[t]=n,n}return null})}getNextMutationBatchAfterBatchId(e,t){let n=t+1,r=IDBKeyRange.lowerBound([this.userId,n]),i=null;return aZ(e).Z({index:"userMutationsIndex",range:r},(e,t,r)=>{t.userId===this.userId&&(t.batchId>=n||rF(),i=ag(this.It,t)),r.done()}).next(()=>i)}getHighestUnacknowledgedBatchId(e){let t=IDBKeyRange.upperBound([this.userId,Number.POSITIVE_INFINITY]),n=-1;return aZ(e).Z({index:"userMutationsIndex",range:t,reverse:!0},(e,t,r)=>{n=t.batchId,r.done()}).next(()=>n)}getAllMutationBatches(e){let t=IDBKeyRange.bound([this.userId,-1],[this.userId,Number.POSITIVE_INFINITY]);return aZ(e).W("userMutationsIndex",t).next(e=>e.map(e=>ag(this.It,e)))}getAllMutationBatchesAffectingDocumentKey(e,t){let n=[this.userId,oH(t.path)],r=IDBKeyRange.lowerBound(n),i=[];return a0(e).Z({range:r},(n,r,s)=>{let[o,a,l]=n,u=oK(a);if(o===this.userId&&t.path.isEqual(u))return aZ(e).get(l).next(e=>{if(!e)throw rF();e.userId===this.userId||rF(),i.push(ag(this.It,e))});s.done()}).next(()=>i)}getAllMutationBatchesAffectingDocumentKeys(e,t){let n=new iN(rX),r=[];return t.forEach(t=>{let i=[this.userId,oH(t.path)],s=IDBKeyRange.lowerBound(i),o=a0(e).Z({range:s},(e,r,i)=>{let[s,o,a]=e,l=oK(o);s===this.userId&&t.path.isEqual(l)?n=n.add(a):i.done()});r.push(o)}),iu.waitFor(r).next(()=>this.En(e,n))}getAllMutationBatchesAffectingQuery(e,t){let n=t.path,r=n.length+1,i=[this.userId,oH(n)],s=IDBKeyRange.lowerBound(i),o=new iN(rX);return a0(e).Z({range:s},(e,t,i)=>{let[s,a,l]=e,u=oK(a);s===this.userId&&n.isPrefixOf(u)?u.length===r&&(o=o.add(l)):i.done()}).next(()=>this.En(e,o))}En(e,t){let n=[],r=[];return t.forEach(t=>{r.push(aZ(e).get(t).next(e=>{if(null===e)throw rF();e.userId===this.userId||rF(),n.push(ag(this.It,e))}))}),iu.waitFor(r).next(()=>n)}removeMutationBatch(e,t){return aQ(e.ie,this.userId,t).next(n=>(e.addOnCommittedListener(()=>{this.An(t.batchId)}),iu.forEach(n,t=>this.referenceDelegate.markPotentiallyOrphaned(e,t))))}An(e){delete this.In[e]}performConsistencyCheck(e){return this.checkEmpty(e).next(t=>{if(!t)return iu.resolve();let n=IDBKeyRange.lowerBound([this.userId]),r=[];return a0(e).Z({range:n},(e,t,n)=>{if(e[0]===this.userId){let i=oK(e[1]);r.push(i)}else n.done()}).next(()=>{0===r.length||rF()})})}containsKey(e,t){return aJ(e,this.userId,t)}Rn(e){return a1(e).get(this.userId).next(e=>e||{userId:this.userId,lastAcknowledgedBatchId:-1,lastStreamToken:""})}}function aJ(e,t,n){let r=[t,oH(n.path)],i=r[1],s=IDBKeyRange.lowerBound(r),o=!1;return a0(e).Z({range:s,X:!0},(e,n,r)=>{let[s,a,l]=e;s===t&&a===i&&(o=!0),r.done()}).next(()=>o)}function aZ(e){return ao(e,"mutations")}function a0(e){return ao(e,"documentMutations")}function a1(e){return ao(e,"mutationQueues")}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class a2{constructor(e){this.bn=e}next(){return this.bn+=2,this.bn}static Pn(){return new a2(0)}static vn(){return new a2(-1)}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class a3{constructor(e,t){this.referenceDelegate=e,this.It=t}allocateTargetId(e){return this.Vn(e).next(t=>{let n=new a2(t.highestTargetId);return t.highestTargetId=n.next(),this.Sn(e,t).next(()=>t.highestTargetId)})}getLastRemoteSnapshotVersion(e){return this.Vn(e).next(e=>r0.fromTimestamp(new rZ(e.lastRemoteSnapshotVersion.seconds,e.lastRemoteSnapshotVersion.nanoseconds)))}getHighestSequenceNumber(e){return this.Vn(e).next(e=>e.highestListenSequenceNumber)}setTargetsMetadata(e,t,n){return this.Vn(e).next(r=>(r.highestListenSequenceNumber=t,n&&(r.lastRemoteSnapshotVersion=n.toTimestamp()),t>r.highestListenSequenceNumber&&(r.highestListenSequenceNumber=t),this.Sn(e,r)))}addTargetData(e,t){return this.Dn(e,t).next(()=>this.Vn(e).next(n=>(n.targetCount+=1,this.Cn(t,n),this.Sn(e,n))))}updateTargetData(e,t){return this.Dn(e,t)}removeTargetData(e,t){return this.removeMatchingKeysForTargetId(e,t.targetId).next(()=>a4(e).delete(t.targetId)).next(()=>this.Vn(e)).next(t=>(t.targetCount>0||rF(),t.targetCount-=1,this.Sn(e,t)))}removeTargets(e,t,n){let r=0,i=[];return a4(e).Z((s,o)=>{let a=ay(o);a.sequenceNumber<=t&&null===n.get(a.targetId)&&(r++,i.push(this.removeTargetData(e,a)))}).next(()=>iu.waitFor(i)).next(()=>r)}forEachTarget(e,t){return a4(e).Z((e,n)=>{let r=ay(n);t(r)})}Vn(e){return a6(e).get("targetGlobalKey").next(e=>(null!==e||rF(),e))}Sn(e,t){return a6(e).put("targetGlobalKey",t)}Dn(e,t){return a4(e).put(av(this.It,t))}Cn(e,t){let n=!1;return e.targetId>t.highestTargetId&&(t.highestTargetId=e.targetId,n=!0),e.sequenceNumber>t.highestListenSequenceNumber&&(t.highestListenSequenceNumber=e.sequenceNumber,n=!0),n}getTargetCount(e){return this.Vn(e).next(e=>e.targetCount)}getTargetData(e,t){let n=sr(t),r=IDBKeyRange.bound([n,Number.NEGATIVE_INFINITY],[n,Number.POSITIVE_INFINITY]),i=null;return a4(e).Z({range:r,index:"queryTargetsIndex"},(e,n,r)=>{let s=ay(n);si(t,s.target)&&(i=s,r.done())}).next(()=>i)}addMatchingKeys(e,t,n){let r=[],i=a5(e);return t.forEach(t=>{let s=oH(t.path);r.push(i.put({targetId:n,path:s})),r.push(this.referenceDelegate.addReference(e,n,t))}),iu.waitFor(r)}removeMatchingKeys(e,t,n){let r=a5(e);return iu.forEach(t,t=>{let i=oH(t.path);return iu.waitFor([r.delete([n,i]),this.referenceDelegate.removeReference(e,n,t)])})}removeMatchingKeysForTargetId(e,t){let n=a5(e),r=IDBKeyRange.bound([t],[t+1],!1,!0);return n.delete(r)}getMatchingKeysForTargetId(e,t){let n=IDBKeyRange.bound([t],[t+1],!1,!0),r=a5(e),i=od();return r.Z({range:n,X:!0},(e,t,n)=>{let r=oK(e[1]),s=new r6(r);i=i.add(s)}).next(()=>i)}containsKey(e,t){let n=oH(t.path),r=IDBKeyRange.bound([n],[n+"\0"],!1,!0),i=0;return a5(e).Z({index:"documentTargetsIndex",X:!0,range:r},([e,t],n,r)=>{0!==e&&(i++,r.done())}).next(()=>i>0)}se(e,t){return a4(e).get(t).next(e=>e?ay(e):null)}}function a4(e){return ao(e,"targets")}function a6(e){return ao(e,"targetGlobal")}function a5(e){return ao(e,"targetDocuments")}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function a8([e,t],[n,r]){let i=rX(e,n);return 0===i?rX(t,r):i}class a9{constructor(e){this.xn=e,this.buffer=new iN(a8),this.Nn=0}kn(){return++this.Nn}On(e){let t=[e,this.kn()];if(this.buffer.size<this.xn)this.buffer=this.buffer.add(t);else{let n=this.buffer.last();0>a8(t,n)&&(this.buffer=this.buffer.delete(n).add(t))}}get maxValue(){return this.buffer.last()[0]}}class a7{constructor(e,t,n){this.garbageCollector=e,this.asyncQueue=t,this.localStore=n,this.Mn=null}start(){-1!==this.garbageCollector.params.cacheSizeCollectionThreshold&&this.Fn(6e4)}stop(){this.Mn&&(this.Mn.cancel(),this.Mn=null)}get started(){return null!==this.Mn}Fn(e){rP("LruGarbageCollector",`Garbage collection scheduled in ${e}ms`),this.Mn=this.asyncQueue.enqueueAfterDelay("lru_garbage_collection",e,async()=>{this.Mn=null;try{await this.localStore.collectGarbage(this.garbageCollector)}catch(e){im(e)?rP("LruGarbageCollector","Ignoring IndexedDB error during garbage collection: ",e):await il(e)}await this.Fn(3e5)})}}class le{constructor(e,t){this.$n=e,this.params=t}calculateTargetCount(e,t){return this.$n.Bn(e).next(e=>Math.floor(t/100*e))}nthSequenceNumber(e,t){if(0===t)return iu.resolve(iI.at);let n=new a9(t);return this.$n.forEachTarget(e,e=>n.On(e.sequenceNumber)).next(()=>this.$n.Ln(e,e=>n.On(e))).next(()=>n.maxValue)}removeTargets(e,t,n){return this.$n.removeTargets(e,t,n)}removeOrphanedDocuments(e,t){return this.$n.removeOrphanedDocuments(e,t)}collect(e,t){return -1===this.params.cacheSizeCollectionThreshold?(rP("LruGarbageCollector","Garbage collection skipped; disabled"),iu.resolve(aH)):this.getCacheSize(e).next(n=>n<this.params.cacheSizeCollectionThreshold?(rP("LruGarbageCollector",`Garbage collection skipped; Cache size ${n} is lower than threshold ${this.params.cacheSizeCollectionThreshold}`),aH):this.Un(e,t))}getCacheSize(e){return this.$n.getCacheSize(e)}Un(e,t){let n,r,i,s,o,a,l;let u=Date.now();return this.calculateTargetCount(e,this.params.percentileToCollect).next(t=>(t>this.params.maximumSequenceNumbersToCollect?(rP("LruGarbageCollector",`Capping sequence numbers to collect down to the maximum of ${this.params.maximumSequenceNumbersToCollect} from ${t}`),r=this.params.maximumSequenceNumbersToCollect):r=t,s=Date.now(),this.nthSequenceNumber(e,r))).next(r=>(n=r,o=Date.now(),this.removeTargets(e,n,t))).next(t=>(i=t,a=Date.now(),this.removeOrphanedDocuments(e,n))).next(e=>(l=Date.now(),rO()<=C.in.DEBUG&&rP("LruGarbageCollector",`LRU Garbage Collection
	Counted targets in ${s-u}ms
	Determined least recently used ${r} in `+(o-s)+"ms\n"+`	Removed ${i} targets in `+(a-o)+"ms\n"+`	Removed ${e} documents in `+(l-a)+"ms\n"+`Total Duration: ${l-u}ms`),iu.resolve({didRun:!0,sequenceNumbersCollected:r,targetsRemoved:i,documentsRemoved:e})))}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class lt{constructor(e,t){this.db=e,this.garbageCollector=new le(this,t)}Bn(e){let t=this.qn(e);return this.db.getTargetCache().getTargetCount(e).next(e=>t.next(t=>e+t))}qn(e){let t=0;return this.Ln(e,e=>{t++}).next(()=>t)}forEachTarget(e,t){return this.db.getTargetCache().forEachTarget(e,t)}Ln(e,t){return this.Kn(e,(e,n)=>t(n))}addReference(e,t,n){return ln(e,n)}removeReference(e,t,n){return ln(e,n)}removeTargets(e,t,n){return this.db.getTargetCache().removeTargets(e,t,n)}markPotentiallyOrphaned(e,t){return ln(e,t)}Gn(e,t){let n;return n=!1,a1(e).tt(r=>aJ(e,r,t).next(e=>(e&&(n=!0),iu.resolve(!e)))).next(()=>n)}removeOrphanedDocuments(e,t){let n=this.db.getRemoteDocumentCache().newChangeBuffer(),r=[],i=0;return this.Kn(e,(s,o)=>{if(o<=t){let a=this.Gn(e,s).next(t=>{if(!t)return i++,n.getEntry(e,s).next(()=>(n.removeEntry(s,r0.min()),a5(e).delete([0,oH(s.path)])))});r.push(a)}}).next(()=>iu.waitFor(r)).next(()=>n.apply(e)).next(()=>i)}removeTarget(e,t){let n=t.withSequenceNumber(e.currentSequenceNumber);return this.db.getTargetCache().updateTargetData(e,n)}updateLimboDocument(e,t){return ln(e,t)}Kn(e,t){let n=a5(e),r,i=iI.at;return n.Z({index:"documentTargetsIndex"},([e,n],{path:s,sequenceNumber:o})=>{0===e?(i!==iI.at&&t(new r6(oK(r)),i),i=o,r=s):i=iI.at}).next(()=>{i!==iI.at&&t(new r6(oK(r)),i)})}getCacheSize(e){return this.db.getRemoteDocumentCache().getSize(e)}}function ln(e,t){var n;return a5(e).put((n=e.currentSequenceNumber,{targetId:0,path:oH(t.path),sequenceNumber:n}))}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class lr{constructor(){this.changes=new oi(e=>e.toString(),(e,t)=>e.isEqual(t)),this.changesApplied=!1}addEntry(e){this.assertNotApplied(),this.changes.set(e.key,e)}removeEntry(e,t){this.assertNotApplied(),this.changes.set(e,se.newInvalidDocument(e).setReadTime(t))}getEntry(e,t){this.assertNotApplied();let n=this.changes.get(t);return void 0!==n?iu.resolve(n):this.getFromCache(e,t)}getEntries(e,t){return this.getAllFromCache(e,t)}apply(e){return this.assertNotApplied(),this.changesApplied=!0,this.applyChanges(e)}assertNotApplied(){}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class li{constructor(e){this.It=e}setIndexManager(e){this.indexManager=e}addEntry(e,t,n){return la(e).put(n)}removeEntry(e,t,n){return la(e).delete(function(e,t){let n=e.path.toArray();return[n.slice(0,n.length-2),n[n.length-2],af(t),n[n.length-1]]}(t,n))}updateMetadata(e,t){return this.getMetadata(e).next(n=>(n.byteSize+=t,this.Qn(e,n)))}getEntry(e,t){let n=se.newInvalidDocument(t);return la(e).Z({index:"documentKeyIndex",range:IDBKeyRange.only(ll(t))},(e,r)=>{n=this.jn(t,r)}).next(()=>n)}Wn(e,t){let n={size:0,document:se.newInvalidDocument(t)};return la(e).Z({index:"documentKeyIndex",range:IDBKeyRange.only(ll(t))},(e,r)=>{n={document:this.jn(t,r),size:aY(r)}}).next(()=>n)}getEntries(e,t){let n=os;return this.zn(e,t,(e,t)=>{let r=this.jn(e,t);n=n.insert(e,r)}).next(()=>n)}Hn(e,t){let n=os,r=new ik(r6.comparator);return this.zn(e,t,(e,t)=>{let i=this.jn(e,t);n=n.insert(e,i),r=r.insert(e,aY(t))}).next(()=>({documents:n,Jn:r}))}zn(e,t,n){if(t.isEmpty())return iu.resolve();let r=new iN(lc);t.forEach(e=>r=r.add(e));let i=IDBKeyRange.bound(ll(r.first()),ll(r.last())),s=r.getIterator(),o=s.getNext();return la(e).Z({index:"documentKeyIndex",range:i},(e,t,r)=>{let i=r6.fromSegments([...t.prefixPath,t.collectionGroup,t.documentId]);for(;o&&0>lc(o,i);)n(o,null),o=s.getNext();o&&o.isEqual(i)&&(n(o,t),o=s.hasNext()?s.getNext():null),o?r.j(ll(o)):r.done()}).next(()=>{for(;o;)n(o,null),o=s.hasNext()?s.getNext():null})}getAllFromCollection(e,t,n){let r=[t.popLast().toArray(),t.lastSegment(),af(n.readTime),n.documentKey.path.isEmpty()?"":n.documentKey.path.lastSegment()],i=[t.popLast().toArray(),t.lastSegment(),[Number.MAX_SAFE_INTEGER,Number.MAX_SAFE_INTEGER],""];return la(e).W(IDBKeyRange.bound(r,i,!0)).next(e=>{let t=os;for(let n of e){let r=this.jn(r6.fromSegments(n.prefixPath.concat(n.collectionGroup,n.documentId)),n);t=t.insert(r.key,r)}return t})}getAllFromCollectionGroup(e,t,n,r){let i=os,s=lu(t,n),o=lu(t,ii.max());return la(e).Z({index:"collectionGroupIndex",range:IDBKeyRange.bound(s,o,!0)},(e,t,n)=>{let s=this.jn(r6.fromSegments(t.prefixPath.concat(t.collectionGroup,t.documentId)),t);(i=i.insert(s.key,s)).size===r&&n.done()}).next(()=>i)}newChangeBuffer(e){return new ls(this,!!e&&e.trackRemovals)}getSize(e){return this.getMetadata(e).next(e=>e.byteSize)}getMetadata(e){return lo(e).get("remoteDocumentGlobalKey").next(e=>(e||rF(),e))}Qn(e,t){return lo(e).put("remoteDocumentGlobalKey",t)}jn(e,t){if(t){let n=function(e,t){let n;if(t.document)n=oF(e.re,t.document,!!t.hasCommittedMutations);else if(t.noDocument){let r=r6.fromSegments(t.noDocument.path),i=am(t.noDocument.readTime);n=se.newNoDocument(r,i),t.hasCommittedMutations&&n.setHasCommittedMutations()}else{if(!t.unknownDocument)return rF();{let s=r6.fromSegments(t.unknownDocument.path),o=am(t.unknownDocument.version);n=se.newUnknownDocument(s,o)}}return t.readTime&&n.setReadTime(function(e){let t=new rZ(e[0],e[1]);return r0.fromTimestamp(t)}(t.readTime)),n}(this.It,t);if(!(n.isNoDocument()&&n.version.isEqual(r0.min())))return n}return se.newInvalidDocument(e)}}class ls extends lr{constructor(e,t){super(),this.Yn=e,this.trackRemovals=t,this.Xn=new oi(e=>e.toString(),(e,t)=>e.isEqual(t))}applyChanges(e){let t=[],n=0,r=new iN((e,t)=>rX(e.canonicalString(),t.canonicalString()));return this.changes.forEach((i,s)=>{let o=this.Xn.get(i);if(t.push(this.Yn.removeEntry(e,i,o.readTime)),s.isValidDocument()){let a=ad(this.Yn.It,s);r=r.add(i.path.popLast());let l=aY(a);n+=l-o.size,t.push(this.Yn.addEntry(e,i,a))}else if(n-=o.size,this.trackRemovals){let u=ad(this.Yn.It,s.convertToNoDocument(r0.min()));t.push(this.Yn.addEntry(e,i,u))}}),r.forEach(n=>{t.push(this.Yn.indexManager.addToCollectionParentIndex(e,n))}),t.push(this.Yn.updateMetadata(e,n)),iu.waitFor(t)}getFromCache(e,t){return this.Yn.Wn(e,t).next(e=>(this.Xn.set(t,{size:e.size,readTime:e.document.readTime}),e.document))}getAllFromCache(e,t){return this.Yn.Hn(e,t).next(({documents:e,Jn:t})=>(t.forEach((t,n)=>{this.Xn.set(t,{size:n,readTime:e.get(t).readTime})}),e))}}function lo(e){return ao(e,"remoteDocumentGlobal")}function la(e){return ao(e,"remoteDocumentsV14")}function ll(e){let t=e.path.toArray();return[t.slice(0,t.length-2),t[t.length-2],t[t.length-1]]}function lu(e,t){let n=t.documentKey.path.toArray();return[e,af(t.readTime),n.slice(0,n.length-2),n.length>0?n[n.length-1]:""]}function lc(e,t){let n=e.path.toArray(),r=t.path.toArray(),i=0;for(let s=0;s<n.length-2&&s<r.length-2;++s)if(i=rX(n[s],r[s]))return i;return(i=rX(n.length,r.length))||(i=rX(n[n.length-2],r[r.length-2]))||rX(n[n.length-1],r[r.length-1])}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *//**
 * @license
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class lh{constructor(e,t){this.overlayedDocument=e,this.mutatedFields=t}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class ld{constructor(e,t,n,r){this.remoteDocumentCache=e,this.mutationQueue=t,this.documentOverlayCache=n,this.indexManager=r}getDocument(e,t){let n=null;return this.documentOverlayCache.getOverlay(e,t).next(r=>(n=r,this.getBaseDocument(e,t,n))).next(e=>(null!==n&&s2(n.mutation,e,iD.empty(),rZ.now()),e))}getDocuments(e,t){return this.remoteDocumentCache.getEntries(e,t).next(t=>this.getLocalViewOfDocuments(e,t,od()).next(()=>t))}getLocalViewOfDocuments(e,t,n=od()){let r=ou();return this.populateOverlays(e,r,t).next(()=>this.computeViews(e,t,r,n).next(e=>{let t=oa();return e.forEach((e,n)=>{t=t.insert(e,n.overlayedDocument)}),t}))}getOverlayedDocuments(e,t){let n=ou();return this.populateOverlays(e,n,t).next(()=>this.computeViews(e,t,n,od()))}populateOverlays(e,t,n){let r=[];return n.forEach(e=>{t.has(e)||r.push(e)}),this.documentOverlayCache.getOverlays(e,r).next(e=>{e.forEach((e,n)=>{t.set(e,n)})})}computeViews(e,t,n,r){let i=os,s=ou(),o=ou();return t.forEach((e,t)=>{let o=n.get(t.key);r.has(t.key)&&(void 0===o||o.mutation instanceof s6)?i=i.insert(t.key,t):void 0!==o&&(s.set(t.key,o.mutation.getFieldMask()),s2(o.mutation,t,o.mutation.getFieldMask(),rZ.now()))}),this.recalculateAndSaveOverlays(e,i).next(e=>(e.forEach((e,t)=>s.set(e,t)),t.forEach((e,t)=>{var n;return o.set(e,new lh(t,null!==(n=s.get(e))&&void 0!==n?n:null))}),o))}recalculateAndSaveOverlays(e,t){let n=ou(),r=new ik((e,t)=>e-t),i=od();return this.mutationQueue.getAllMutationBatchesAffectingDocumentKeys(e,t).next(e=>{for(let i of e)i.keys().forEach(e=>{let s=t.get(e);if(null===s)return;let o=n.get(e)||iD.empty();o=i.applyToLocalView(s,o),n.set(e,o);let a=(r.get(i.batchId)||od()).add(e);r=r.insert(i.batchId,a)})}).next(()=>{let s=[],o=r.getReverseIterator();for(;o.hasNext();){let a=o.getNext(),l=a.key,u=a.value,c=ou();u.forEach(e=>{if(!i.has(e)){let r=s1(t.get(e),n.get(e));null!==r&&c.set(e,r),i=i.add(e)}}),s.push(this.documentOverlayCache.saveOverlays(e,l,c))}return iu.waitFor(s)}).next(()=>n)}recalculateAndSaveOverlaysForDocumentKeys(e,t){return this.remoteDocumentCache.getEntries(e,t).next(t=>this.recalculateAndSaveOverlays(e,t))}getDocumentsMatchingQuery(e,t,n){return r6.isDocumentKey(t.path)&&null===t.collectionGroup&&0===t.filters.length?this.getDocumentsMatchingDocumentQuery(e,t.path):sx(t)?this.getDocumentsMatchingCollectionGroupQuery(e,t,n):this.getDocumentsMatchingCollectionQuery(e,t,n)}getNextDocuments(e,t,n,r){return this.remoteDocumentCache.getAllFromCollectionGroup(e,t,n,r).next(i=>{let s=r-i.size>0?this.documentOverlayCache.getOverlaysForCollectionGroup(e,t,n.largestBatchId,r-i.size):iu.resolve(ou()),o=-1,a=i;return s.next(t=>iu.forEach(t,(t,n)=>(o<n.largestBatchId&&(o=n.largestBatchId),i.get(t)?iu.resolve():this.getBaseDocument(e,t,n).next(e=>{a=a.insert(t,e)}))).next(()=>this.populateOverlays(e,t,i)).next(()=>this.computeViews(e,a,t,od())).next(e=>({batchId:o,changes:ol(e)})))})}getDocumentsMatchingDocumentQuery(e,t){return this.getDocument(e,new r6(t)).next(e=>{let t=oa();return e.isFoundDocument()&&(t=t.insert(e.key,e)),t})}getDocumentsMatchingCollectionGroupQuery(e,t,n){let r=t.collectionGroup,i=oa();return this.indexManager.getCollectionParents(e,r).next(s=>iu.forEach(s,s=>{var o;let a=(o=s.child(r),new sI(o,null,t.explicitOrderBy.slice(),t.filters.slice(),t.limit,t.limitType,t.startAt,t.endAt));return this.getDocumentsMatchingCollectionQuery(e,a,n).next(e=>{e.forEach((e,t)=>{i=i.insert(e,t)})})}).next(()=>i))}getDocumentsMatchingCollectionQuery(e,t,n){let r;return this.remoteDocumentCache.getAllFromCollection(e,t.path,n).next(i=>(r=i,this.documentOverlayCache.getOverlaysForCollection(e,t.path,n.largestBatchId))).next(e=>{e.forEach((e,t)=>{let n=t.getKey();null===r.get(n)&&(r=r.insert(n,se.newInvalidDocument(n)))});let n=oa();return r.forEach((r,i)=>{let s=e.get(r);void 0!==s&&s2(s.mutation,i,iD.empty(),rZ.now()),sP(t,i)&&(n=n.insert(r,i))}),n})}getBaseDocument(e,t,n){return null===n||1===n.mutation.type?this.remoteDocumentCache.getEntry(e,t):iu.resolve(se.newInvalidDocument(t))}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class lf{constructor(e){this.It=e,this.Zn=new Map,this.ts=new Map}getBundleMetadata(e,t){return iu.resolve(this.Zn.get(t))}saveBundleMetadata(e,t){return this.Zn.set(t.id,{id:t.id,version:t.version,createTime:oC(t.createTime)}),iu.resolve()}getNamedQuery(e,t){return iu.resolve(this.ts.get(t))}saveNamedQuery(e,t){return this.ts.set(t.name,{name:t.name,query:a_(t.bundledQuery),readTime:oC(t.readTime)}),iu.resolve()}}/**
 * @license
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class lp{constructor(){this.overlays=new ik(r6.comparator),this.es=new Map}getOverlay(e,t){return iu.resolve(this.overlays.get(t))}getOverlays(e,t){let n=ou();return iu.forEach(t,t=>this.getOverlay(e,t).next(e=>{null!==e&&n.set(t,e)})).next(()=>n)}saveOverlays(e,t,n){return n.forEach((n,r)=>{this.ue(e,t,r)}),iu.resolve()}removeOverlaysForBatchId(e,t,n){let r=this.es.get(n);return void 0!==r&&(r.forEach(e=>this.overlays=this.overlays.remove(e)),this.es.delete(n)),iu.resolve()}getOverlaysForCollection(e,t,n){let r=ou(),i=t.length+1,s=new r6(t.child("")),o=this.overlays.getIteratorFrom(s);for(;o.hasNext();){let a=o.getNext().value,l=a.getKey();if(!t.isPrefixOf(l.path))break;l.path.length===i&&a.largestBatchId>n&&r.set(a.getKey(),a)}return iu.resolve(r)}getOverlaysForCollectionGroup(e,t,n,r){let i=new ik((e,t)=>e-t),s=this.overlays.getIterator();for(;s.hasNext();){let o=s.getNext().value;if(o.getKey().getCollectionGroup()===t&&o.largestBatchId>n){let a=i.get(o.largestBatchId);null===a&&(a=ou(),i=i.insert(o.largestBatchId,a)),a.set(o.getKey(),o)}}let l=ou(),u=i.getIterator();for(;u.hasNext()&&(u.getNext().value.forEach((e,t)=>l.set(e,t)),!(l.size()>=r)););return iu.resolve(l)}ue(e,t,n){let r=this.overlays.get(n.key);if(null!==r){let i=this.es.get(r.largestBatchId).delete(n.key);this.es.set(r.largestBatchId,i)}this.overlays=this.overlays.insert(n.key,new au(t,n));let s=this.es.get(t);void 0===s&&(s=od(),this.es.set(t,s)),this.es.set(t,s.add(n.key))}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class lm{constructor(){this.ns=new iN(lg.ss),this.rs=new iN(lg.os)}isEmpty(){return this.ns.isEmpty()}addReference(e,t){let n=new lg(e,t);this.ns=this.ns.add(n),this.rs=this.rs.add(n)}us(e,t){e.forEach(e=>this.addReference(e,t))}removeReference(e,t){this.cs(new lg(e,t))}hs(e,t){e.forEach(e=>this.removeReference(e,t))}ls(e){let t=new r6(new r2([])),n=new lg(t,e),r=new lg(t,e+1),i=[];return this.rs.forEachInRange([n,r],e=>{this.cs(e),i.push(e.key)}),i}fs(){this.ns.forEach(e=>this.cs(e))}cs(e){this.ns=this.ns.delete(e),this.rs=this.rs.delete(e)}ds(e){let t=new r6(new r2([])),n=new lg(t,e),r=new lg(t,e+1),i=od();return this.rs.forEachInRange([n,r],e=>{i=i.add(e.key)}),i}containsKey(e){let t=new lg(e,0),n=this.ns.firstAfterOrEqual(t);return null!==n&&e.isEqual(n.key)}}class lg{constructor(e,t){this.key=e,this._s=t}static ss(e,t){return r6.comparator(e.key,t.key)||rX(e._s,t._s)}static os(e,t){return rX(e._s,t._s)||r6.comparator(e.key,t.key)}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class ly{constructor(e,t){this.indexManager=e,this.referenceDelegate=t,this.mutationQueue=[],this.ws=1,this.gs=new iN(lg.ss)}checkEmpty(e){return iu.resolve(0===this.mutationQueue.length)}addMutationBatch(e,t,n,r){let i=this.ws;this.ws++,this.mutationQueue.length>0&&this.mutationQueue[this.mutationQueue.length-1];let s=new aa(i,t,n,r);for(let o of(this.mutationQueue.push(s),r))this.gs=this.gs.add(new lg(o.key,i)),this.indexManager.addToCollectionParentIndex(e,o.key.path.popLast());return iu.resolve(s)}lookupMutationBatch(e,t){return iu.resolve(this.ys(t))}getNextMutationBatchAfterBatchId(e,t){let n=this.ps(t+1),r=n<0?0:n;return iu.resolve(this.mutationQueue.length>r?this.mutationQueue[r]:null)}getHighestUnacknowledgedBatchId(){return iu.resolve(0===this.mutationQueue.length?-1:this.ws-1)}getAllMutationBatches(e){return iu.resolve(this.mutationQueue.slice())}getAllMutationBatchesAffectingDocumentKey(e,t){let n=new lg(t,0),r=new lg(t,Number.POSITIVE_INFINITY),i=[];return this.gs.forEachInRange([n,r],e=>{let t=this.ys(e._s);i.push(t)}),iu.resolve(i)}getAllMutationBatchesAffectingDocumentKeys(e,t){let n=new iN(rX);return t.forEach(e=>{let t=new lg(e,0),r=new lg(e,Number.POSITIVE_INFINITY);this.gs.forEachInRange([t,r],e=>{n=n.add(e._s)})}),iu.resolve(this.Is(n))}getAllMutationBatchesAffectingQuery(e,t){let n=t.path,r=n.length+1,i=n;r6.isDocumentKey(i)||(i=i.child(""));let s=new lg(new r6(i),0),o=new iN(rX);return this.gs.forEachWhile(e=>{let t=e.key.path;return!!n.isPrefixOf(t)&&(t.length===r&&(o=o.add(e._s)),!0)},s),iu.resolve(this.Is(o))}Is(e){let t=[];return e.forEach(e=>{let n=this.ys(e);null!==n&&t.push(n)}),t}removeMutationBatch(e,t){0===this.Ts(t.batchId,"removed")||rF(),this.mutationQueue.shift();let n=this.gs;return iu.forEach(t.mutations,r=>{let i=new lg(r.key,t.batchId);return n=n.delete(i),this.referenceDelegate.markPotentiallyOrphaned(e,r.key)}).next(()=>{this.gs=n})}An(e){}containsKey(e,t){let n=new lg(t,0),r=this.gs.firstAfterOrEqual(n);return iu.resolve(t.isEqual(r&&r.key))}performConsistencyCheck(e){return this.mutationQueue.length,iu.resolve()}Ts(e,t){return this.ps(e)}ps(e){return 0===this.mutationQueue.length?0:e-this.mutationQueue[0].batchId}ys(e){let t=this.ps(e);return t<0||t>=this.mutationQueue.length?null:this.mutationQueue[t]}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class lv{constructor(e){this.Es=e,this.docs=new ik(r6.comparator),this.size=0}setIndexManager(e){this.indexManager=e}addEntry(e,t){let n=t.key,r=this.docs.get(n),i=r?r.size:0,s=this.Es(t);return this.docs=this.docs.insert(n,{document:t.mutableCopy(),size:s}),this.size+=s-i,this.indexManager.addToCollectionParentIndex(e,n.path.popLast())}removeEntry(e){let t=this.docs.get(e);t&&(this.docs=this.docs.remove(e),this.size-=t.size)}getEntry(e,t){let n=this.docs.get(t);return iu.resolve(n?n.document.mutableCopy():se.newInvalidDocument(t))}getEntries(e,t){let n=os;return t.forEach(e=>{let t=this.docs.get(e);n=n.insert(e,t?t.document.mutableCopy():se.newInvalidDocument(e))}),iu.resolve(n)}getAllFromCollection(e,t,n){let r=os,i=new r6(t.child("")),s=this.docs.getIteratorFrom(i);for(;s.hasNext();){let{key:o,value:{document:a}}=s.getNext();if(!t.isPrefixOf(o.path))break;o.path.length>t.length+1||0>=is(ir(a),n)||(r=r.insert(a.key,a.mutableCopy()))}return iu.resolve(r)}getAllFromCollectionGroup(e,t,n,r){rF()}As(e,t){return iu.forEach(this.docs,e=>t(e))}newChangeBuffer(e){return new l_(this)}getSize(e){return iu.resolve(this.size)}}class l_ extends lr{constructor(e){super(),this.Yn=e}applyChanges(e){let t=[];return this.changes.forEach((n,r)=>{r.isValidDocument()?t.push(this.Yn.addEntry(e,r)):this.Yn.removeEntry(n)}),iu.waitFor(t)}getFromCache(e,t){return this.Yn.getEntry(e,t)}getAllFromCache(e,t){return this.Yn.getEntries(e,t)}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class lw{constructor(e){this.persistence=e,this.Rs=new oi(e=>sr(e),si),this.lastRemoteSnapshotVersion=r0.min(),this.highestTargetId=0,this.bs=0,this.Ps=new lm,this.targetCount=0,this.vs=a2.Pn()}forEachTarget(e,t){return this.Rs.forEach((e,n)=>t(n)),iu.resolve()}getLastRemoteSnapshotVersion(e){return iu.resolve(this.lastRemoteSnapshotVersion)}getHighestSequenceNumber(e){return iu.resolve(this.bs)}allocateTargetId(e){return this.highestTargetId=this.vs.next(),iu.resolve(this.highestTargetId)}setTargetsMetadata(e,t,n){return n&&(this.lastRemoteSnapshotVersion=n),t>this.bs&&(this.bs=t),iu.resolve()}Dn(e){this.Rs.set(e.target,e);let t=e.targetId;t>this.highestTargetId&&(this.vs=new a2(t),this.highestTargetId=t),e.sequenceNumber>this.bs&&(this.bs=e.sequenceNumber)}addTargetData(e,t){return this.Dn(t),this.targetCount+=1,iu.resolve()}updateTargetData(e,t){return this.Dn(t),iu.resolve()}removeTargetData(e,t){return this.Rs.delete(t.target),this.Ps.ls(t.targetId),this.targetCount-=1,iu.resolve()}removeTargets(e,t,n){let r=0,i=[];return this.Rs.forEach((s,o)=>{o.sequenceNumber<=t&&null===n.get(o.targetId)&&(this.Rs.delete(s),i.push(this.removeMatchingKeysForTargetId(e,o.targetId)),r++)}),iu.waitFor(i).next(()=>r)}getTargetCount(e){return iu.resolve(this.targetCount)}getTargetData(e,t){let n=this.Rs.get(t)||null;return iu.resolve(n)}addMatchingKeys(e,t,n){return this.Ps.us(t,n),iu.resolve()}removeMatchingKeys(e,t,n){this.Ps.hs(t,n);let r=this.persistence.referenceDelegate,i=[];return r&&t.forEach(t=>{i.push(r.markPotentiallyOrphaned(e,t))}),iu.waitFor(i)}removeMatchingKeysForTargetId(e,t){return this.Ps.ls(t),iu.resolve()}getMatchingKeysForTargetId(e,t){let n=this.Ps.ds(t);return iu.resolve(n)}containsKey(e,t){return iu.resolve(this.Ps.containsKey(t))}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class lb{constructor(e,t){var n;this.Vs={},this.overlays={},this.Ss=new iI(0),this.Ds=!1,this.Ds=!0,this.referenceDelegate=e(this),this.Cs=new lw(this),this.indexManager=new aF,this.remoteDocumentCache=(n=e=>this.referenceDelegate.xs(e),new lv(n)),this.It=new ah(t),this.Ns=new lf(this.It)}start(){return Promise.resolve()}shutdown(){return this.Ds=!1,Promise.resolve()}get started(){return this.Ds}setDatabaseDeletedListener(){}setNetworkEnabled(){}getIndexManager(e){return this.indexManager}getDocumentOverlayCache(e){let t=this.overlays[e.toKey()];return t||(t=new lp,this.overlays[e.toKey()]=t),t}getMutationQueue(e,t){let n=this.Vs[e.toKey()];return n||(n=new ly(t,this.referenceDelegate),this.Vs[e.toKey()]=n),n}getTargetCache(){return this.Cs}getRemoteDocumentCache(){return this.remoteDocumentCache}getBundleCache(){return this.Ns}runTransaction(e,t,n){rP("MemoryPersistence","Starting transaction:",e);let r=new lI(this.Ss.next());return this.referenceDelegate.ks(),n(r).next(e=>this.referenceDelegate.Os(r).next(()=>e)).toPromise().then(e=>(r.raiseOnCommittedEvent(),e))}Ms(e,t){return iu.or(Object.values(this.Vs).map(n=>()=>n.containsKey(e,t)))}}class lI extends ia{constructor(e){super(),this.currentSequenceNumber=e}}class lT{constructor(e){this.persistence=e,this.Fs=new lm,this.$s=null}static Bs(e){return new lT(e)}get Ls(){if(this.$s)return this.$s;throw rF()}addReference(e,t,n){return this.Fs.addReference(n,t),this.Ls.delete(n.toString()),iu.resolve()}removeReference(e,t,n){return this.Fs.removeReference(n,t),this.Ls.add(n.toString()),iu.resolve()}markPotentiallyOrphaned(e,t){return this.Ls.add(t.toString()),iu.resolve()}removeTarget(e,t){this.Fs.ls(t.targetId).forEach(e=>this.Ls.add(e.toString()));let n=this.persistence.getTargetCache();return n.getMatchingKeysForTargetId(e,t.targetId).next(e=>{e.forEach(e=>this.Ls.add(e.toString()))}).next(()=>n.removeTargetData(e,t))}ks(){this.$s=new Set}Os(e){let t=this.persistence.getRemoteDocumentCache().newChangeBuffer();return iu.forEach(this.Ls,n=>{let r=r6.fromPath(n);return this.Us(e,r).next(e=>{e||t.removeEntry(r,r0.min())})}).next(()=>(this.$s=null,t.apply(e)))}updateLimboDocument(e,t){return this.Us(e,t).next(e=>{e?this.Ls.delete(t.toString()):this.Ls.add(t.toString())})}xs(e){return 0}Us(e,t){return iu.or([()=>iu.resolve(this.Fs.containsKey(t)),()=>this.persistence.getTargetCache().containsKey(e,t),()=>this.persistence.Ms(e,t)])}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class lE{constructor(e){this.It=e}$(e,t,n,r){let i=new ic("createOrUpgrade",t);n<1&&r>=1&&(function(e){e.createObjectStore("owner")}(e),e.createObjectStore("mutationQueues",{keyPath:"userId"}),e.createObjectStore("mutations",{keyPath:"batchId",autoIncrement:!0}).createIndex("userMutationsIndex",oQ,{unique:!0}),e.createObjectStore("documentMutations"),lS(e),function(e){e.createObjectStore("remoteDocuments")}(e));let s=iu.resolve();return n<3&&r>=3&&(0!==n&&(e.deleteObjectStore("targetDocuments"),e.deleteObjectStore("targets"),e.deleteObjectStore("targetGlobal"),lS(e)),s=s.next(()=>(function(e){let t=e.store("targetGlobal"),n={highestTargetId:0,highestListenSequenceNumber:0,lastRemoteSnapshotVersion:r0.min().toTimestamp(),targetCount:0};return t.put("targetGlobalKey",n)})(i))),n<4&&r>=4&&(0!==n&&(s=s.next(()=>i.store("mutations").W().next(t=>{e.deleteObjectStore("mutations"),e.createObjectStore("mutations",{keyPath:"batchId",autoIncrement:!0}).createIndex("userMutationsIndex",oQ,{unique:!0});let n=i.store("mutations"),r=t.map(e=>n.put(e));return iu.waitFor(r)}))),s=s.next(()=>{!function(e){e.createObjectStore("clientMetadata",{keyPath:"clientId"})}(e)})),n<5&&r>=5&&(s=s.next(()=>this.qs(i))),n<6&&r>=6&&(s=s.next(()=>((function(e){e.createObjectStore("remoteDocumentGlobal")})(e),this.Ks(i)))),n<7&&r>=7&&(s=s.next(()=>this.Gs(i))),n<8&&r>=8&&(s=s.next(()=>this.Qs(e,i))),n<9&&r>=9&&(s=s.next(()=>{e.objectStoreNames.contains("remoteDocumentChanges")&&e.deleteObjectStore("remoteDocumentChanges")})),n<10&&r>=10&&(s=s.next(()=>this.js(i))),n<11&&r>=11&&(s=s.next(()=>{(function(e){e.createObjectStore("bundles",{keyPath:"bundleId"})})(e),function(e){e.createObjectStore("namedQueries",{keyPath:"name"})}(e)})),n<12&&r>=12&&(s=s.next(()=>{!function(e){let t=e.createObjectStore("documentOverlays",{keyPath:o9});t.createIndex("collectionPathOverlayIndex",o7,{unique:!1}),t.createIndex("collectionGroupOverlayIndex",ae,{unique:!1})}(e)})),n<13&&r>=13&&(s=s.next(()=>(function(e){let t=e.createObjectStore("remoteDocumentsV14",{keyPath:oX});t.createIndex("documentKeyIndex",oJ),t.createIndex("collectionGroupIndex",oZ)})(e)).next(()=>this.Ws(e,i)).next(()=>e.deleteObjectStore("remoteDocuments"))),n<14&&r>=14&&(s=s.next(()=>this.zs(e,i))),n<15&&r>=15&&(s=s.next(()=>{e.createObjectStore("indexConfiguration",{keyPath:"indexId",autoIncrement:!0}).createIndex("collectionGroupIndex","collectionGroup",{unique:!1}),e.createObjectStore("indexState",{keyPath:o4}).createIndex("sequenceNumberIndex",o6,{unique:!1}),e.createObjectStore("indexEntries",{keyPath:o5}).createIndex("documentKeyIndex",o8,{unique:!1})})),s}Ks(e){let t=0;return e.store("remoteDocuments").Z((e,n)=>{t+=aY(n)}).next(()=>{let n={byteSize:t};return e.store("remoteDocumentGlobal").put("remoteDocumentGlobalKey",n)})}qs(e){let t=e.store("mutationQueues"),n=e.store("mutations");return t.W().next(t=>iu.forEach(t,t=>{let r=IDBKeyRange.bound([t.userId,-1],[t.userId,t.lastAcknowledgedBatchId]);return n.W("userMutationsIndex",r).next(n=>iu.forEach(n,n=>{n.userId===t.userId||rF();let r=ag(this.It,n);return aQ(e,t.userId,r).next(()=>{})}))}))}Gs(e){let t=e.store("targetDocuments"),n=e.store("remoteDocuments");return e.store("targetGlobal").get("targetGlobalKey").next(e=>{let r=[];return n.Z((n,i)=>{let s=new r2(n),o=[0,oH(s)];r.push(t.get(o).next(n=>n?iu.resolve():t.put({targetId:0,path:oH(s),sequenceNumber:e.highestListenSequenceNumber})))}).next(()=>iu.waitFor(r))})}Qs(e,t){e.createObjectStore("collectionParents",{keyPath:o3});let n=t.store("collectionParents"),r=new aU,i=e=>{if(r.add(e)){let t=e.lastSegment(),i=e.popLast();return n.put({collectionId:t,parent:oH(i)})}};return t.store("remoteDocuments").Z({X:!0},(e,t)=>{let n=new r2(e);return i(n.popLast())}).next(()=>t.store("documentMutations").Z({X:!0},([e,t,n],r)=>{let s=oK(t);return i(s.popLast())}))}js(e){let t=e.store("targets");return t.Z((e,n)=>{let r=ay(n),i=av(this.It,r);return t.put(i)})}Ws(e,t){let n=t.store("remoteDocuments"),r=[];return n.Z((e,n)=>{let i=t.store("remoteDocumentsV14"),s=(n.document?new r6(r2.fromString(n.document.name).popFirst(5)):n.noDocument?r6.fromSegments(n.noDocument.path):n.unknownDocument?r6.fromSegments(n.unknownDocument.path):rF()).path.toArray(),o={prefixPath:s.slice(0,s.length-2),collectionGroup:s[s.length-2],documentId:s[s.length-1],readTime:n.readTime||[0,0],unknownDocument:n.unknownDocument,noDocument:n.noDocument,document:n.document,hasCommittedMutations:!!n.hasCommittedMutations};r.push(i.put(o))}).next(()=>iu.waitFor(r))}zs(e,t){var n;let r=t.store("mutations"),i=(n=this.It,new li(n)),s=new lb(lT.Bs,this.It.re);return r.W().next(e=>{let n=new Map;return e.forEach(e=>{var t;let r=null!==(t=n.get(e.userId))&&void 0!==t?t:od();ag(this.It,e).keys().forEach(e=>r=r.add(e)),n.set(e.userId,r)}),iu.forEach(n,(e,n)=>{let r=new rA(n),o=ak.oe(this.It,r),a=s.getIndexManager(r),l=aX.oe(r,this.It,a,s.referenceDelegate);return new ld(i,l,o,a).recalculateAndSaveOverlaysForDocumentKeys(new as(t,iI.at),e).next()})})}}function lS(e){e.createObjectStore("targetDocuments",{keyPath:o1}).createIndex("documentTargetsIndex",o2,{unique:!0}),e.createObjectStore("targets",{keyPath:"targetId"}).createIndex("queryTargetsIndex",o0,{unique:!0}),e.createObjectStore("targetGlobal")}let lk="Failed to obtain exclusive access to the persistence layer. To allow shared access, multi-tab synchronization has to be enabled in all tabs. If you are using `experimentalForceOwningTab:true`, make sure that only one tab has persistence enabled at any given time.";class lx{constructor(e,t,n,r,i,s,o,a,l,u,c=15){var h;if(this.allowTabSynchronization=e,this.persistenceKey=t,this.clientId=n,this.Hs=i,this.window=s,this.document=o,this.Js=l,this.Ys=u,this.Xs=c,this.Ss=null,this.Ds=!1,this.isPrimary=!1,this.networkEnabled=!0,this.Zs=null,this.inForeground=!1,this.ti=null,this.ei=null,this.ni=Number.NEGATIVE_INFINITY,this.si=e=>Promise.resolve(),!lx.C())throw new rV(rU.UNIMPLEMENTED,"This platform is either missing IndexedDB or is known to have an incomplete implementation. Offline persistence has been disabled.");this.referenceDelegate=new lt(this,r),this.ii=t+"main",this.It=new ah(a),this.ri=new ih(this.ii,this.Xs,new lE(this.It)),this.Cs=new a3(this.referenceDelegate,this.It),this.remoteDocumentCache=(h=this.It,new li(h)),this.Ns=new aT,this.window&&this.window.localStorage?this.oi=this.window.localStorage:(this.oi=null,!1===u&&rL("IndexedDbPersistence","LocalStorage is unavailable. As a result, persistence may not work reliably. In particular enablePersistence() could fail immediately after refreshing the page."))}start(){return this.ui().then(()=>{if(!this.isPrimary&&!this.allowTabSynchronization)throw new rV(rU.FAILED_PRECONDITION,lk);return this.ci(),this.ai(),this.hi(),this.runTransaction("getHighestListenSequenceNumber","readonly",e=>this.Cs.getHighestSequenceNumber(e))}).then(e=>{this.Ss=new iI(e,this.Js)}).then(()=>{this.Ds=!0}).catch(e=>(this.ri&&this.ri.close(),Promise.reject(e)))}li(e){return this.si=async t=>{if(this.started)return e(t)},e(this.isPrimary)}setDatabaseDeletedListener(e){this.ri.L(async t=>{null===t.newVersion&&await e()})}setNetworkEnabled(e){this.networkEnabled!==e&&(this.networkEnabled=e,this.Hs.enqueueAndForget(async()=>{this.started&&await this.ui()}))}ui(){return this.runTransaction("updateClientMetadataAndTryBecomePrimary","readwrite",e=>lN(e).put({clientId:this.clientId,updateTimeMs:Date.now(),networkEnabled:this.networkEnabled,inForeground:this.inForeground}).next(()=>{if(this.isPrimary)return this.fi(e).next(e=>{e||(this.isPrimary=!1,this.Hs.enqueueRetryable(()=>this.si(!1)))})}).next(()=>this.di(e)).next(t=>this.isPrimary&&!t?this._i(e).next(()=>!1):!!t&&this.wi(e).next(()=>!0))).catch(e=>{if(im(e))return rP("IndexedDbPersistence","Failed to extend owner lease: ",e),this.isPrimary;if(!this.allowTabSynchronization)throw e;return rP("IndexedDbPersistence","Releasing owner lease after error during lease refresh",e),!1}).then(e=>{this.isPrimary!==e&&this.Hs.enqueueRetryable(()=>this.si(e)),this.isPrimary=e})}fi(e){return lC(e).get("owner").next(e=>iu.resolve(this.mi(e)))}gi(e){return lN(e).delete(this.clientId)}async yi(){if(this.isPrimary&&!this.pi(this.ni,18e5)){this.ni=Date.now();let e=await this.runTransaction("maybeGarbageCollectMultiClientState","readwrite-primary",e=>{let t=ao(e,"clientMetadata");return t.W().next(e=>{let n=this.Ii(e,18e5),r=e.filter(e=>-1===n.indexOf(e));return iu.forEach(r,e=>t.delete(e.clientId)).next(()=>r)})}).catch(()=>[]);if(this.oi)for(let t of e)this.oi.removeItem(this.Ti(t.clientId))}}hi(){this.ei=this.Hs.enqueueAfterDelay("client_metadata_refresh",4e3,()=>this.ui().then(()=>this.yi()).then(()=>this.hi()))}mi(e){return!!e&&e.ownerId===this.clientId}di(e){return this.Ys?iu.resolve(!0):lC(e).get("owner").next(t=>{if(null!==t&&this.pi(t.leaseTimestampMs,5e3)&&!this.Ei(t.ownerId)){if(this.mi(t)&&this.networkEnabled)return!0;if(!this.mi(t)){if(!t.allowTabSynchronization)throw new rV(rU.FAILED_PRECONDITION,lk);return!1}}return!(!this.networkEnabled||!this.inForeground)||lN(e).W().next(e=>void 0===this.Ii(e,5e3).find(e=>{if(this.clientId!==e.clientId){let t=!this.networkEnabled&&e.networkEnabled,n=!this.inForeground&&e.inForeground,r=this.networkEnabled===e.networkEnabled;if(t||n&&r)return!0}return!1}))}).next(e=>(this.isPrimary!==e&&rP("IndexedDbPersistence",`Client ${e?"is":"is not"} eligible for a primary lease.`),e))}async shutdown(){this.Ds=!1,this.Ai(),this.ei&&(this.ei.cancel(),this.ei=null),this.Ri(),this.bi(),await this.ri.runTransaction("shutdown","readwrite",["owner","clientMetadata"],e=>{let t=new as(e,iI.at);return this._i(t).next(()=>this.gi(t))}),this.ri.close(),this.Pi()}Ii(e,t){return e.filter(e=>this.pi(e.updateTimeMs,t)&&!this.Ei(e.clientId))}vi(){return this.runTransaction("getActiveClients","readonly",e=>lN(e).W().next(e=>this.Ii(e,18e5).map(e=>e.clientId)))}get started(){return this.Ds}getMutationQueue(e,t){return aX.oe(e,this.It,t,this.referenceDelegate)}getTargetCache(){return this.Cs}getRemoteDocumentCache(){return this.remoteDocumentCache}getIndexManager(e){return new aq(e,this.It.re.databaseId)}getDocumentOverlayCache(e){return ak.oe(this.It,e)}getBundleCache(){return this.Ns}runTransaction(e,t,n){var r;let i;rP("IndexedDbPersistence","Starting transaction:",e);let s=15===(r=this.Xs)?ai:14===r?ar:13===r?ar:12===r?an:11===r?at:void rF();return this.ri.runTransaction(e,"readonly"===t?"readonly":"readwrite",s,r=>(i=new as(r,this.Ss?this.Ss.next():iI.at),"readwrite-primary"===t?this.fi(i).next(e=>!!e||this.di(i)).next(t=>{if(!t)throw rL(`Failed to obtain primary lease for action '${e}'.`),this.isPrimary=!1,this.Hs.enqueueRetryable(()=>this.si(!1)),new rV(rU.FAILED_PRECONDITION,io);return n(i)}).next(e=>this.wi(i).next(()=>e)):this.Vi(i).next(()=>n(i)))).then(e=>(i.raiseOnCommittedEvent(),e))}Vi(e){return lC(e).get("owner").next(e=>{if(null!==e&&this.pi(e.leaseTimestampMs,5e3)&&!this.Ei(e.ownerId)&&!this.mi(e)&&!(this.Ys||this.allowTabSynchronization&&e.allowTabSynchronization))throw new rV(rU.FAILED_PRECONDITION,lk)})}wi(e){let t={ownerId:this.clientId,allowTabSynchronization:this.allowTabSynchronization,leaseTimestampMs:Date.now()};return lC(e).put("owner",t)}static C(){return ih.C()}_i(e){let t=lC(e);return t.get("owner").next(e=>this.mi(e)?(rP("IndexedDbPersistence","Releasing primary lease."),t.delete("owner")):iu.resolve())}pi(e,t){let n=Date.now();return!(e<n-t)&&(!(e>n)||(rL(`Detected an update time that is in the future: ${e} > ${n}`),!1))}ci(){null!==this.document&&"function"==typeof this.document.addEventListener&&(this.ti=()=>{this.Hs.enqueueAndForget(()=>(this.inForeground="visible"===this.document.visibilityState,this.ui()))},this.document.addEventListener("visibilitychange",this.ti),this.inForeground="visible"===this.document.visibilityState)}Ri(){this.ti&&(this.document.removeEventListener("visibilitychange",this.ti),this.ti=null)}ai(){var e;"function"==typeof(null===(e=this.window)||void 0===e?void 0:e.addEventListener)&&(this.Zs=()=>{this.Ai(),(0,S.G6)()&&navigator.appVersion.match(/Version\/1[45]/)&&this.Hs.enterRestrictedMode(!0),this.Hs.enqueueAndForget(()=>this.shutdown())},this.window.addEventListener("pagehide",this.Zs))}bi(){this.Zs&&(this.window.removeEventListener("pagehide",this.Zs),this.Zs=null)}Ei(e){var t;try{let n=null!==(null===(t=this.oi)||void 0===t?void 0:t.getItem(this.Ti(e)));return rP("IndexedDbPersistence",`Client '${e}' ${n?"is":"is not"} zombied in LocalStorage`),n}catch(r){return rL("IndexedDbPersistence","Failed to get zombied client id.",r),!1}}Ai(){if(this.oi)try{this.oi.setItem(this.Ti(this.clientId),String(Date.now()))}catch(e){rL("Failed to set zombie client id.",e)}}Pi(){if(this.oi)try{this.oi.removeItem(this.Ti(this.clientId))}catch(e){}}Ti(e){return`firestore_zombie_${this.persistenceKey}_${e}`}}function lC(e){return ao(e,"owner")}function lN(e){return ao(e,"clientMetadata")}function lA(e,t){let n=e.projectId;return e.isDefaultDatabase||(n+="."+e.database),"firestore/"+t+"/"+n+"/"}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class lR{constructor(e,t,n,r){this.targetId=e,this.fromCache=t,this.Si=n,this.Di=r}static Ci(e,t){let n=od(),r=od();for(let i of t.docChanges)switch(i.type){case 0:n=n.add(i.doc.key);break;case 1:r=r.add(i.doc.key)}return new lR(e,t.fromCache,n,r)}}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class lD{constructor(){this.xi=!1}initialize(e,t){this.Ni=e,this.indexManager=t,this.xi=!0}getDocumentsMatchingQuery(e,t,n,r){return this.ki(e,t).next(i=>i||this.Oi(e,t,r,n)).next(n=>n||this.Mi(e,t))}ki(e,t){if(sE(t))return iu.resolve(null);let n=sN(t);return this.indexManager.getIndexType(e,n).next(r=>0===r?null:(null!==t.limit&&1===r&&(n=sN(t=sA(t,null,"F"))),this.indexManager.getDocumentsMatchingTarget(e,n).next(r=>{let i=od(...r);return this.Ni.getDocuments(e,i).next(r=>this.indexManager.getMinOffset(e,n).next(n=>{let s=this.Fi(t,r);return this.$i(t,s,i,n.readTime)?this.ki(e,sA(t,null,"F")):this.Bi(e,s,t,n)}))})))}Oi(e,t,n,r){return sE(t)||r.isEqual(r0.min())?this.Mi(e,t):this.Ni.getDocuments(e,n).next(i=>{let s=this.Fi(t,i);return this.$i(t,s,n,r)?this.Mi(e,t):(rO()<=C.in.DEBUG&&rP("QueryEngine","Re-using previous result from %s to execute query: %s",r.toString(),sO(t)),this.Bi(e,s,t,it(r,-1)))})}Fi(e,t){let n=new iN(sM(e));return t.forEach((t,r)=>{sP(e,r)&&(n=n.add(r))}),n}$i(e,t,n,r){if(null===e.limit)return!1;if(n.size!==t.size)return!0;let i="F"===e.limitType?t.last():t.first();return!!i&&(i.hasPendingWrites||i.version.compareTo(r)>0)}Mi(e,t){return rO()<=C.in.DEBUG&&rP("QueryEngine","Using full collection scan to execute query:",sO(t)),this.Ni.getDocumentsMatchingQuery(e,t,ii.min())}Bi(e,t,n,r){return this.Ni.getDocumentsMatchingQuery(e,n,r).next(e=>(t.forEach(t=>{e=e.insert(t.key,t)}),e))}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class lO{constructor(e,t,n,r){this.persistence=e,this.Li=t,this.It=r,this.Ui=new ik(rX),this.qi=new oi(e=>sr(e),si),this.Ki=new Map,this.Gi=e.getRemoteDocumentCache(),this.Cs=e.getTargetCache(),this.Ns=e.getBundleCache(),this.Qi(n)}Qi(e){this.documentOverlayCache=this.persistence.getDocumentOverlayCache(e),this.indexManager=this.persistence.getIndexManager(e),this.mutationQueue=this.persistence.getMutationQueue(e,this.indexManager),this.localDocuments=new ld(this.Gi,this.mutationQueue,this.documentOverlayCache,this.indexManager),this.Gi.setIndexManager(this.indexManager),this.Li.initialize(this.localDocuments,this.indexManager)}collectGarbage(e){return this.persistence.runTransaction("Collect garbage","readwrite-primary",t=>e.collect(t,this.Ui))}}async function lP(e,t){return await e.persistence.runTransaction("Handle user change","readonly",n=>{let r;return e.mutationQueue.getAllMutationBatches(n).next(i=>(r=i,e.Qi(t),e.mutationQueue.getAllMutationBatches(n))).next(t=>{let i=[],s=[],o=od();for(let a of r)for(let l of(i.push(a.batchId),a.mutations))o=o.add(l.key);for(let u of t)for(let c of(s.push(u.batchId),u.mutations))o=o.add(c.key);return e.localDocuments.getDocuments(n,o).next(e=>({ji:e,removedBatchIds:i,addedBatchIds:s}))})})}function lL(e){return e.persistence.runTransaction("Get last remote snapshot version","readonly",t=>e.Cs.getLastRemoteSnapshotVersion(t))}function lM(e,t,n){let r=od(),i=od();return n.forEach(e=>r=r.add(e)),t.getEntries(e,r).next(e=>{let r=os;return n.forEach((n,s)=>{let o=e.get(n);s.isFoundDocument()!==o.isFoundDocument()&&(i=i.add(n)),s.isNoDocument()&&s.version.isEqual(r0.min())?(t.removeEntry(n,s.readTime),r=r.insert(n,s)):!o.isValidDocument()||s.version.compareTo(o.version)>0||0===s.version.compareTo(o.version)&&o.hasPendingWrites?(t.addEntry(s),r=r.insert(n,s)):rP("LocalStore","Ignoring outdated watch update for ",n,". Current version:",o.version," Watch version:",s.version)}),{Wi:r,zi:i}})}function lj(e,t){let n=e;return n.persistence.runTransaction("Allocate target","readwrite",e=>{let r;return n.Cs.getTargetData(e,t).next(i=>i?(r=i,iu.resolve(r)):n.Cs.allocateTargetId(e).next(i=>(r=new ac(t,i,0,e.currentSequenceNumber),n.Cs.addTargetData(e,r).next(()=>r))))}).then(e=>{let r=n.Ui.get(e.targetId);return(null===r||e.snapshotVersion.compareTo(r.snapshotVersion)>0)&&(n.Ui=n.Ui.insert(e.targetId,e),n.qi.set(t,e.targetId)),e})}async function lF(e,t,n){let r=e,i=r.Ui.get(t);try{n||await r.persistence.runTransaction("Release target",n?"readwrite":"readwrite-primary",e=>r.persistence.referenceDelegate.removeTarget(e,i))}catch(s){if(!im(s))throw s;rP("LocalStore",`Failed to update sequence numbers for target ${t}: ${s}`)}r.Ui=r.Ui.remove(t),r.qi.delete(i.target)}function lU(e,t,n){let r=r0.min(),i=od();return e.persistence.runTransaction("Execute query","readonly",s=>(function(e,t,n){let r=e.qi.get(n);return void 0!==r?iu.resolve(e.Ui.get(r)):e.Cs.getTargetData(t,n)})(e,s,sN(t)).next(t=>{if(t)return r=t.lastLimboFreeSnapshotVersion,e.Cs.getMatchingKeysForTargetId(s,t.targetId).next(e=>{i=e})}).next(()=>e.Li.getDocumentsMatchingQuery(s,t,n?r:r0.min(),n?i:od())).next(n=>(lB(e,sL(t),n),{documents:n,Hi:i})))}function lV(e,t){let n=e.Cs,r=e.Ui.get(t);return r?Promise.resolve(r.target):e.persistence.runTransaction("Get target data","readonly",e=>n.se(e,t).next(e=>e?e.target:null))}function lq(e,t){let n=e.Ki.get(t)||r0.min();return e.persistence.runTransaction("Get new document changes","readonly",r=>e.Gi.getAllFromCollectionGroup(r,t,it(n,-1),Number.MAX_SAFE_INTEGER)).then(n=>(lB(e,t,n),n))}function lB(e,t,n){let r=e.Ki.get(t)||r0.min();n.forEach((e,t)=>{t.readTime.compareTo(r)>0&&(r=t.readTime)}),e.Ki.set(t,r)}async function l$(e,t,n,r){let i=od(),s=os;for(let o of n){let a=t.Ji(o.metadata.name);o.document&&(i=i.add(a));let l=t.Yi(o);l.setReadTime(t.Xi(o.metadata.readTime)),s=s.insert(a,l)}let u=e.Gi.newChangeBuffer({trackRemovals:!0}),c=await lj(e,sN(sT(r2.fromString(`__bundle__/docs/${r}`))));return e.persistence.runTransaction("Apply bundle documents","readwrite",t=>lM(t,u,s).next(e=>(u.apply(t),e)).next(n=>e.Cs.removeMatchingKeysForTargetId(t,c.targetId).next(()=>e.Cs.addMatchingKeys(t,i,c.targetId)).next(()=>e.localDocuments.getLocalViewOfDocuments(t,n.Wi,n.zi)).next(()=>n.Wi)))}async function lz(e,t,n=od()){let r=await lj(e,sN(a_(t.bundledQuery))),i=e;return i.persistence.runTransaction("Save named query","readwrite",e=>{let s=oC(t.readTime);if(r.snapshotVersion.compareTo(s)>=0)return i.Ns.saveNamedQuery(e,t);let o=r.withResumeToken(iO.EMPTY_BYTE_STRING,s);return i.Ui=i.Ui.insert(o.targetId,o),i.Cs.updateTargetData(e,o).next(()=>i.Cs.removeMatchingKeysForTargetId(e,r.targetId)).next(()=>i.Cs.addMatchingKeys(e,n,r.targetId)).next(()=>i.Ns.saveNamedQuery(e,t))})}function lG(e,t){return`firestore_clients_${e}_${t}`}function lW(e,t,n){let r=`firestore_mutations_${e}_${n}`;return t.isAuthenticated()&&(r+=`_${t.uid}`),r}function lH(e,t){return`firestore_targets_${e}_${t}`}class lK{constructor(e,t,n,r){this.user=e,this.batchId=t,this.state=n,this.error=r}static Zi(e,t,n){let r=JSON.parse(n),i,s="object"==typeof r&&-1!==["pending","acknowledged","rejected"].indexOf(r.state)&&(void 0===r.error||"object"==typeof r.error);return s&&r.error&&(s="string"==typeof r.error.message&&"string"==typeof r.error.code)&&(i=new rV(r.error.code,r.error.message)),s?new lK(e,t,r.state,i):(rL("SharedClientState",`Failed to parse mutation state for ID '${t}': ${n}`),null)}tr(){let e={state:this.state,updateTimeMs:Date.now()};return this.error&&(e.error={code:this.error.code,message:this.error.message}),JSON.stringify(e)}}class lQ{constructor(e,t,n){this.targetId=e,this.state=t,this.error=n}static Zi(e,t){let n=JSON.parse(t),r,i="object"==typeof n&&-1!==["not-current","current","rejected"].indexOf(n.state)&&(void 0===n.error||"object"==typeof n.error);return i&&n.error&&(i="string"==typeof n.error.message&&"string"==typeof n.error.code)&&(r=new rV(n.error.code,n.error.message)),i?new lQ(e,n.state,r):(rL("SharedClientState",`Failed to parse target state for ID '${e}': ${t}`),null)}tr(){let e={state:this.state,updateTimeMs:Date.now()};return this.error&&(e.error={code:this.error.code,message:this.error.message}),JSON.stringify(e)}}class lY{constructor(e,t){this.clientId=e,this.activeTargetIds=t}static Zi(e,t){let n=JSON.parse(t),r="object"==typeof n&&n.activeTargetIds instanceof Array,i=of;for(let s=0;r&&s<n.activeTargetIds.length;++s)r=iz(n.activeTargetIds[s]),i=i.add(n.activeTargetIds[s]);return r?new lY(e,i):(rL("SharedClientState",`Failed to parse client data for instance '${e}': ${t}`),null)}}class lX{constructor(e,t){this.clientId=e,this.onlineState=t}static Zi(e){let t=JSON.parse(e);return"object"==typeof t&&-1!==["Unknown","Online","Offline"].indexOf(t.onlineState)&&"string"==typeof t.clientId?new lX(t.clientId,t.onlineState):(rL("SharedClientState",`Failed to parse online state: ${e}`),null)}}class lJ{constructor(){this.activeTargetIds=of}er(e){this.activeTargetIds=this.activeTargetIds.add(e)}nr(e){this.activeTargetIds=this.activeTargetIds.delete(e)}tr(){let e={activeTargetIds:this.activeTargetIds.toArray(),updateTimeMs:Date.now()};return JSON.stringify(e)}}class lZ{constructor(e,t,n,r,i){this.window=e,this.Hs=t,this.persistenceKey=n,this.sr=r,this.syncEngine=null,this.onlineStateHandler=null,this.sequenceNumberHandler=null,this.ir=this.rr.bind(this),this.ur=new ik(rX),this.started=!1,this.cr=[];let s=n.replace(/[.*+?^${}()|[\]\\]/g,"\\$&");this.storage=this.window.localStorage,this.currentUser=i,this.ar=lG(this.persistenceKey,this.sr),this.hr=`firestore_sequence_number_${this.persistenceKey}`,this.ur=this.ur.insert(this.sr,new lJ),this.lr=RegExp(`^firestore_clients_${s}_([^_]*)$`),this.dr=RegExp(`^firestore_mutations_${s}_(\\d+)(?:_(.*))?$`),this._r=RegExp(`^firestore_targets_${s}_(\\d+)$`),this.wr=`firestore_online_state_${this.persistenceKey}`,this.mr=`firestore_bundle_loaded_v2_${this.persistenceKey}`,this.window.addEventListener("storage",this.ir)}static C(e){return!(!e||!e.localStorage)}async start(){let e=await this.syncEngine.vi();for(let t of e){if(t===this.sr)continue;let n=this.getItem(lG(this.persistenceKey,t));if(n){let r=lY.Zi(t,n);r&&(this.ur=this.ur.insert(r.clientId,r))}}this.gr();let i=this.storage.getItem(this.wr);if(i){let s=this.yr(i);s&&this.pr(s)}for(let o of this.cr)this.rr(o);this.cr=[],this.window.addEventListener("pagehide",()=>this.shutdown()),this.started=!0}writeSequenceNumber(e){this.setItem(this.hr,JSON.stringify(e))}getAllActiveQueryTargets(){return this.Ir(this.ur)}isActiveQueryTarget(e){let t=!1;return this.ur.forEach((n,r)=>{r.activeTargetIds.has(e)&&(t=!0)}),t}addPendingMutation(e){this.Tr(e,"pending")}updateMutationState(e,t,n){this.Tr(e,t,n),this.Er(e)}addLocalQueryTarget(e){let t="not-current";if(this.isActiveQueryTarget(e)){let n=this.storage.getItem(lH(this.persistenceKey,e));if(n){let r=lQ.Zi(e,n);r&&(t=r.state)}}return this.Ar.er(e),this.gr(),t}removeLocalQueryTarget(e){this.Ar.nr(e),this.gr()}isLocalQueryTarget(e){return this.Ar.activeTargetIds.has(e)}clearQueryState(e){this.removeItem(lH(this.persistenceKey,e))}updateQueryState(e,t,n){this.Rr(e,t,n)}handleUserChange(e,t,n){t.forEach(e=>{this.Er(e)}),this.currentUser=e,n.forEach(e=>{this.addPendingMutation(e)})}setOnlineState(e){this.br(e)}notifyBundleLoaded(e){this.Pr(e)}shutdown(){this.started&&(this.window.removeEventListener("storage",this.ir),this.removeItem(this.ar),this.started=!1)}getItem(e){let t=this.storage.getItem(e);return rP("SharedClientState","READ",e,t),t}setItem(e,t){rP("SharedClientState","SET",e,t),this.storage.setItem(e,t)}removeItem(e){rP("SharedClientState","REMOVE",e),this.storage.removeItem(e)}rr(e){if(e.storageArea===this.storage){if(rP("SharedClientState","EVENT",e.key,e.newValue),e.key===this.ar)return void rL("Received WebStorage notification for local change. Another client might have garbage-collected our state");this.Hs.enqueueRetryable(async()=>{if(this.started){if(null!==e.key){if(this.lr.test(e.key)){if(null==e.newValue){let t=this.vr(e.key);return this.Vr(t,null)}{let n=this.Sr(e.key,e.newValue);if(n)return this.Vr(n.clientId,n)}}else if(this.dr.test(e.key)){if(null!==e.newValue){let r=this.Dr(e.key,e.newValue);if(r)return this.Cr(r)}}else if(this._r.test(e.key)){if(null!==e.newValue){let i=this.Nr(e.key,e.newValue);if(i)return this.kr(i)}}else if(e.key===this.wr){if(null!==e.newValue){let s=this.yr(e.newValue);if(s)return this.pr(s)}}else if(e.key===this.hr){let o=function(e){let t=iI.at;if(null!=e)try{let n=JSON.parse(e);"number"==typeof n||rF(),t=n}catch(r){rL("SharedClientState","Failed to read sequence number from WebStorage",r)}return t}(e.newValue);o!==iI.at&&this.sequenceNumberHandler(o)}else if(e.key===this.mr){let a=this.Or(e.newValue);await Promise.all(a.map(e=>this.syncEngine.Mr(e)))}}}else this.cr.push(e)})}}get Ar(){return this.ur.get(this.sr)}gr(){this.setItem(this.ar,this.Ar.tr())}Tr(e,t,n){let r=new lK(this.currentUser,e,t,n),i=lW(this.persistenceKey,this.currentUser,e);this.setItem(i,r.tr())}Er(e){let t=lW(this.persistenceKey,this.currentUser,e);this.removeItem(t)}br(e){let t={clientId:this.sr,onlineState:e};this.storage.setItem(this.wr,JSON.stringify(t))}Rr(e,t,n){let r=lH(this.persistenceKey,e),i=new lQ(e,t,n);this.setItem(r,i.tr())}Pr(e){let t=JSON.stringify(Array.from(e));this.setItem(this.mr,t)}vr(e){let t=this.lr.exec(e);return t?t[1]:null}Sr(e,t){let n=this.vr(e);return lY.Zi(n,t)}Dr(e,t){let n=this.dr.exec(e),r=Number(n[1]),i=void 0!==n[2]?n[2]:null;return lK.Zi(new rA(i),r,t)}Nr(e,t){let n=this._r.exec(e),r=Number(n[1]);return lQ.Zi(r,t)}yr(e){return lX.Zi(e)}Or(e){return JSON.parse(e)}async Cr(e){if(e.user.uid===this.currentUser.uid)return this.syncEngine.Fr(e.batchId,e.state,e.error);rP("SharedClientState",`Ignoring mutation for non-active user ${e.user.uid}`)}kr(e){return this.syncEngine.$r(e.targetId,e.state,e.error)}Vr(e,t){let n=t?this.ur.insert(e,t):this.ur.remove(e),r=this.Ir(this.ur),i=this.Ir(n),s=[],o=[];return i.forEach(e=>{r.has(e)||s.push(e)}),r.forEach(e=>{i.has(e)||o.push(e)}),this.syncEngine.Br(s,o).then(()=>{this.ur=n})}pr(e){this.ur.get(e.clientId)&&this.onlineStateHandler(e.onlineState)}Ir(e){let t=of;return e.forEach((e,n)=>{t=t.unionWith(n.activeTargetIds)}),t}}class l0{constructor(){this.Lr=new lJ,this.Ur={},this.onlineStateHandler=null,this.sequenceNumberHandler=null}addPendingMutation(e){}updateMutationState(e,t,n){}addLocalQueryTarget(e){return this.Lr.er(e),this.Ur[e]||"not-current"}updateQueryState(e,t,n){this.Ur[e]=t}removeLocalQueryTarget(e){this.Lr.nr(e)}isLocalQueryTarget(e){return this.Lr.activeTargetIds.has(e)}clearQueryState(e){delete this.Ur[e]}getAllActiveQueryTargets(){return this.Lr.activeTargetIds}isActiveQueryTarget(e){return this.Lr.activeTargetIds.has(e)}start(){return this.Lr=new lJ,Promise.resolve()}handleUserChange(e,t,n){}setOnlineState(e){}shutdown(){}writeSequenceNumber(e){}notifyBundleLoaded(e){}}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class l1{qr(e){}shutdown(){}}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class l2{constructor(){this.Kr=()=>this.Gr(),this.Qr=()=>this.jr(),this.Wr=[],this.zr()}qr(e){this.Wr.push(e)}shutdown(){window.removeEventListener("online",this.Kr),window.removeEventListener("offline",this.Qr)}zr(){window.addEventListener("online",this.Kr),window.addEventListener("offline",this.Qr)}Gr(){for(let e of(rP("ConnectivityMonitor","Network connectivity changed: AVAILABLE"),this.Wr))e(0)}jr(){for(let e of(rP("ConnectivityMonitor","Network connectivity changed: UNAVAILABLE"),this.Wr))e(1)}static C(){return"undefined"!=typeof window&&void 0!==window.addEventListener&&void 0!==window.removeEventListener}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let l3={BatchGetDocuments:"batchGet",Commit:"commit",RunQuery:"runQuery",RunAggregationQuery:"runAggregationQuery"};/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class l4{constructor(e){this.Hr=e.Hr,this.Jr=e.Jr}Yr(e){this.Xr=e}Zr(e){this.eo=e}onMessage(e){this.no=e}close(){this.Jr()}send(e){this.Hr(e)}so(){this.Xr()}io(e){this.eo(e)}ro(e){this.no(e)}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class l6 extends class{constructor(e){this.databaseInfo=e,this.databaseId=e.databaseId;let t=e.ssl?"https":"http";this.oo=t+"://"+e.host,this.uo="projects/"+this.databaseId.projectId+"/databases/"+this.databaseId.database+"/documents"}get co(){return!1}ao(e,t,n,r,i){let s=this.ho(e,t);rP("RestConnection","Sending: ",s,n);let o={};return this.lo(o,r,i),this.fo(e,s,o,n).then(e=>(rP("RestConnection","Received: ",e),e),t=>{throw rM("RestConnection",`${e} failed with error: `,t,"url: ",s,"request:",n),t})}_o(e,t,n,r,i,s){return this.ao(e,t,n,r,i)}lo(e,t,n){e["X-Goog-Api-Client"]="gl-js/ fire/"+rR,e["Content-Type"]="text/plain",this.databaseInfo.appId&&(e["X-Firebase-GMPID"]=this.databaseInfo.appId),t&&t.headers.forEach((t,n)=>e[n]=t),n&&n.headers.forEach((t,n)=>e[n]=t)}ho(e,t){let n=l3[e];return`${this.oo}/v1/${t}:${n}`}}{constructor(e){super(e),this.forceLongPolling=e.forceLongPolling,this.autoDetectLongPolling=e.autoDetectLongPolling,this.useFetchStreams=e.useFetchStreams}fo(e,t,n,r){return new Promise((i,s)=>{let o=new rx;o.setWithCredentials(!0),o.listenOnce(rI.COMPLETE,()=>{try{switch(o.getLastErrorCode()){case rb.NO_ERROR:let t=o.getResponseJson();rP("Connection","XHR received:",JSON.stringify(t)),i(t);break;case rb.TIMEOUT:rP("Connection",'RPC "'+e+'" timed out'),s(new rV(rU.DEADLINE_EXCEEDED,"Request time out"));break;case rb.HTTP_ERROR:let n=o.getStatus();if(rP("Connection",'RPC "'+e+'" failed with status:',n,"response text:",o.getResponseText()),n>0){let r=o.getResponseJson().error;if(r&&r.status&&r.message){let a=function(e){let t=e.toLowerCase().replace(/_/g,"-");return Object.values(rU).indexOf(t)>=0?t:rU.UNKNOWN}(r.status);s(new rV(a,r.message))}else s(new rV(rU.UNKNOWN,"Server responded with status "+o.getStatus()))}else s(new rV(rU.UNAVAILABLE,"Connection failed."));break;default:rF()}}finally{rP("Connection",'RPC "'+e+'" completed.')}});let a=JSON.stringify(r);o.send(t,"POST",a,n,15)})}wo(e,t,n){let r=[this.oo,"/","google.firestore.v1.Firestore","/",e,"/channel"],i=r_(),s=rw(),o={httpSessionIdParam:"gsessionid",initMessageHeaders:{},messageUrlParams:{database:`projects/${this.databaseId.projectId}/databases/${this.databaseId.database}`},sendRawJson:!0,supportsCrossDomainXhr:!0,internalChannelParams:{forwardChannelRequestTimeoutMs:6e5},forceLongPolling:this.forceLongPolling,detectBufferingProxy:this.autoDetectLongPolling};this.useFetchStreams&&(o.xmlHttpFactory=new rS({})),this.lo(o.initMessageHeaders,t,n),o.encodeInitMessageHeaders=!0;let a=r.join("");rP("Connection","Creating WebChannel: "+a,o);let l=i.createWebChannel(a,o),u=!1,c=!1,h=new l4({Hr:e=>{c?rP("Connection","Not sending because WebChannel is closed:",e):(u||(rP("Connection","Opening WebChannel transport."),l.open(),u=!0),rP("Connection","WebChannel sending:",e),l.send(e))},Jr:()=>l.close()}),d=(e,t,n)=>{e.listen(t,e=>{try{n(e)}catch(t){setTimeout(()=>{throw t},0)}})};return d(l,rk.EventType.OPEN,()=>{c||rP("Connection","WebChannel transport opened.")}),d(l,rk.EventType.CLOSE,()=>{c||(c=!0,rP("Connection","WebChannel transport closed"),h.io())}),d(l,rk.EventType.ERROR,e=>{c||(c=!0,rM("Connection","WebChannel transport errored:",e),h.io(new rV(rU.UNAVAILABLE,"The operation could not be completed")))}),d(l,rk.EventType.MESSAGE,e=>{var t;if(!c){let n=e.data[0];n||rF();let r=n.error||(null===(t=n[0])||void 0===t?void 0:t.error);if(r){rP("Connection","WebChannel received error:",r);let i=r.status,s=function(e){let t=b[e];if(void 0!==t)return or(t)}(i),o=r.message;void 0===s&&(s=rU.INTERNAL,o="Unknown error status: "+i+" with message "+r.message),c=!0,h.io(new rV(s,o)),l.close()}else rP("Connection","WebChannel received:",n),h.ro(n)}}),d(s,rT.STAT_EVENT,e=>{e.stat===rE.PROXY?rP("Connection","Detected buffering proxy"):e.stat===rE.NOPROXY&&rP("Connection","Detected no buffering proxy")}),setTimeout(()=>{h.so()},0),h}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *//**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function l5(){return"undefined"!=typeof window?window:null}function l8(){return"undefined"!=typeof document?document:null}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function l9(e){return new oS(e,!0)}class l7{constructor(e,t,n=1e3,r=1.5,i=6e4){this.Hs=e,this.timerId=t,this.mo=n,this.yo=r,this.po=i,this.Io=0,this.To=null,this.Eo=Date.now(),this.reset()}reset(){this.Io=0}Ao(){this.Io=this.po}Ro(e){this.cancel();let t=Math.floor(this.Io+this.bo()),n=Math.max(0,Date.now()-this.Eo),r=Math.max(0,t-n);r>0&&rP("ExponentialBackoff",`Backing off for ${r} ms (base delay: ${this.Io} ms, delay with jitter: ${t} ms, last attempt: ${n} ms ago)`),this.To=this.Hs.enqueueAfterDelay(this.timerId,r,()=>(this.Eo=Date.now(),e())),this.Io*=this.yo,this.Io<this.mo&&(this.Io=this.mo),this.Io>this.po&&(this.Io=this.po)}Po(){null!==this.To&&(this.To.skipDelay(),this.To=null)}cancel(){null!==this.To&&(this.To.cancel(),this.To=null)}bo(){return(Math.random()-.5)*this.Io}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class ue{constructor(e,t,n,r,i,s,o,a){this.Hs=e,this.vo=n,this.Vo=r,this.So=i,this.authCredentialsProvider=s,this.appCheckCredentialsProvider=o,this.listener=a,this.state=0,this.Do=0,this.Co=null,this.xo=null,this.stream=null,this.No=new l7(e,t)}ko(){return 1===this.state||5===this.state||this.Oo()}Oo(){return 2===this.state||3===this.state}start(){4!==this.state?this.auth():this.Mo()}async stop(){this.ko()&&await this.close(0)}Fo(){this.state=0,this.No.reset()}$o(){this.Oo()&&null===this.Co&&(this.Co=this.Hs.enqueueAfterDelay(this.vo,6e4,()=>this.Bo()))}Lo(e){this.Uo(),this.stream.send(e)}async Bo(){if(this.Oo())return this.close(0)}Uo(){this.Co&&(this.Co.cancel(),this.Co=null)}qo(){this.xo&&(this.xo.cancel(),this.xo=null)}async close(e,t){this.Uo(),this.qo(),this.No.cancel(),this.Do++,4!==e?this.No.reset():t&&t.code===rU.RESOURCE_EXHAUSTED?(rL(t.toString()),rL("Using maximum backoff delay to prevent overloading the backend."),this.No.Ao()):t&&t.code===rU.UNAUTHENTICATED&&3!==this.state&&(this.authCredentialsProvider.invalidateToken(),this.appCheckCredentialsProvider.invalidateToken()),null!==this.stream&&(this.Ko(),this.stream.close(),this.stream=null),this.state=e,await this.listener.Zr(t)}Ko(){}auth(){this.state=1;let e=this.Go(this.Do),t=this.Do;Promise.all([this.authCredentialsProvider.getToken(),this.appCheckCredentialsProvider.getToken()]).then(([e,n])=>{this.Do===t&&this.Qo(e,n)},t=>{e(()=>{let e=new rV(rU.UNKNOWN,"Fetching auth token failed: "+t.message);return this.jo(e)})})}Qo(e,t){let n=this.Go(this.Do);this.stream=this.Wo(e,t),this.stream.Yr(()=>{n(()=>(this.state=2,this.xo=this.Hs.enqueueAfterDelay(this.Vo,1e4,()=>(this.Oo()&&(this.state=3),Promise.resolve())),this.listener.Yr()))}),this.stream.Zr(e=>{n(()=>this.jo(e))}),this.stream.onMessage(e=>{n(()=>this.onMessage(e))})}Mo(){this.state=5,this.No.Ro(async()=>{this.state=0,this.start()})}jo(e){return rP("PersistentStream",`close with error: ${e}`),this.stream=null,this.close(4,e)}Go(e){return t=>{this.Hs.enqueueAndForget(()=>this.Do===e?t():(rP("PersistentStream","stream callback skipped by getCloseGuardedDispatcher."),Promise.resolve()))}}}class ut extends ue{constructor(e,t,n,r,i,s){super(e,"listen_stream_connection_backoff","listen_stream_idle","health_check_timeout",t,n,r,s),this.It=i}Wo(e,t){return this.So.wo("Listen",e,t)}onMessage(e){this.No.reset();let t=function(e,t){let n;if("targetChange"in t){var r,i;t.targetChange;let s="NO_CHANGE"===(r=t.targetChange.targetChangeType||"NO_CHANGE")?0:"ADD"===r?1:"REMOVE"===r?2:"CURRENT"===r?3:"RESET"===r?4:rF(),o=t.targetChange.targetIds||[],a=(i=t.targetChange.resumeToken,e.gt?(void 0===i||"string"==typeof i||rF(),iO.fromBase64String(i||"")):(void 0===i||i instanceof Uint8Array||rF(),iO.fromUint8Array(i||new Uint8Array))),l=t.targetChange.cause,u=l&&function(e){let t=void 0===e.code?rU.UNKNOWN:or(e.code);return new rV(t,e.message||"")}(l);n=new ov(s,o,a,u||null)}else if("documentChange"in t){t.documentChange;let c=t.documentChange;c.document,c.document.name,c.document.updateTime;let h=oD(e,c.document.name),d=oC(c.document.updateTime),f=new i7({mapValue:{fields:c.document.fields}}),p=se.newFoundDocument(h,d,f),m=c.targetIds||[],g=c.removedTargetIds||[];n=new og(m,g,p.key,p)}else if("documentDelete"in t){t.documentDelete;let y=t.documentDelete;y.document;let v=oD(e,y.document),_=y.readTime?oC(y.readTime):r0.min(),w=se.newNoDocument(v,_),b=y.removedTargetIds||[];n=new og([],b,w.key,w)}else if("documentRemove"in t){t.documentRemove;let I=t.documentRemove;I.document;let T=oD(e,I.document),E=I.removedTargetIds||[];n=new og([],E,T,null)}else{if(!("filter"in t))return rF();{t.filter;let S=t.filter;S.targetId;let k=S.count||0,x=new ot(k),C=S.targetId;n=new oy(C,x)}}return n}(this.It,e),n=function(e){if(!("targetChange"in e))return r0.min();let t=e.targetChange;return t.targetIds&&t.targetIds.length?r0.min():t.readTime?oC(t.readTime):r0.min()}(e);return this.listener.zo(t,n)}Ho(e){let t={};t.database=oL(this.It),t.addTarget=function(e,t){let n;let r=t.target;return(n=ss(r)?{documents:oq(e,r)}:{query:oB(e,r)}).targetId=t.targetId,t.resumeToken.approximateByteSize()>0?n.resumeToken=ox(e,t.resumeToken):t.snapshotVersion.compareTo(r0.min())>0&&(n.readTime=ok(e,t.snapshotVersion.toTimestamp())),n}(this.It,e);let n=function(e,t){let n=function(e,t){switch(t){case 0:return null;case 1:return"existence-filter-mismatch";case 2:return"limbo-document";default:return rF()}}(0,t.purpose);return null==n?null:{"goog-listen-tags":n}}(this.It,e);n&&(t.labels=n),this.Lo(t)}Jo(e){let t={};t.database=oL(this.It),t.removeTarget=e,this.Lo(t)}}class un extends ue{constructor(e,t,n,r,i,s){super(e,"write_stream_connection_backoff","write_stream_idle","health_check_timeout",t,n,r,s),this.It=i,this.Yo=!1}get Xo(){return this.Yo}start(){this.Yo=!1,this.lastStreamToken=void 0,super.start()}Ko(){this.Yo&&this.Zo([])}Wo(e,t){return this.So.wo("Write",e,t)}onMessage(e){var t,n;if(e.streamToken||rF(),this.lastStreamToken=e.streamToken,this.Yo){this.No.reset();let r=(t=e.writeResults,n=e.commitTime,t&&t.length>0?(void 0!==n||rF(),t.map(e=>{let t;return(t=e.updateTime?oC(e.updateTime):oC(n)).isEqual(r0.min())&&(t=oC(n)),new sX(t,e.transformResults||[])})):[]),i=oC(e.commitTime);return this.listener.tu(i,r)}return e.writeResults&&0!==e.writeResults.length&&rF(),this.Yo=!0,this.listener.eu()}nu(){let e={};e.database=oL(this.It),this.Lo(e)}Zo(e){let t={streamToken:this.lastStreamToken,writes:e.map(e=>oU(this.It,e))};this.Lo(t)}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class ur extends class{}{constructor(e,t,n,r){super(),this.authCredentials=e,this.appCheckCredentials=t,this.So=n,this.It=r,this.su=!1}iu(){if(this.su)throw new rV(rU.FAILED_PRECONDITION,"The client has already been terminated.")}ao(e,t,n){return this.iu(),Promise.all([this.authCredentials.getToken(),this.appCheckCredentials.getToken()]).then(([r,i])=>this.So.ao(e,t,n,r,i)).catch(e=>{throw"FirebaseError"===e.name?(e.code===rU.UNAUTHENTICATED&&(this.authCredentials.invalidateToken(),this.appCheckCredentials.invalidateToken()),e):new rV(rU.UNKNOWN,e.toString())})}_o(e,t,n,r){return this.iu(),Promise.all([this.authCredentials.getToken(),this.appCheckCredentials.getToken()]).then(([i,s])=>this.So._o(e,t,n,i,s,r)).catch(e=>{throw"FirebaseError"===e.name?(e.code===rU.UNAUTHENTICATED&&(this.authCredentials.invalidateToken(),this.appCheckCredentials.invalidateToken()),e):new rV(rU.UNKNOWN,e.toString())})}terminate(){this.su=!0}}class ui{constructor(e,t){this.asyncQueue=e,this.onlineStateHandler=t,this.state="Unknown",this.ru=0,this.ou=null,this.uu=!0}cu(){0===this.ru&&(this.au("Unknown"),this.ou=this.asyncQueue.enqueueAfterDelay("online_state_timeout",1e4,()=>(this.ou=null,this.hu("Backend didn't respond within 10 seconds."),this.au("Offline"),Promise.resolve())))}lu(e){"Online"===this.state?this.au("Unknown"):(this.ru++,this.ru>=1&&(this.fu(),this.hu(`Connection failed 1 times. Most recent error: ${e.toString()}`),this.au("Offline")))}set(e){this.fu(),this.ru=0,"Online"===e&&(this.uu=!1),this.au(e)}au(e){e!==this.state&&(this.state=e,this.onlineStateHandler(e))}hu(e){let t=`Could not reach Cloud Firestore backend. ${e}
This typically indicates that your device does not have a healthy Internet connection at the moment. The client will operate in offline mode until it is able to successfully connect to the backend.`;this.uu?(rL(t),this.uu=!1):rP("OnlineStateTracker",t)}fu(){null!==this.ou&&(this.ou.cancel(),this.ou=null)}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class us{constructor(e,t,n,r,i){this.localStore=e,this.datastore=t,this.asyncQueue=n,this.remoteSyncer={},this.du=[],this._u=new Map,this.wu=new Set,this.mu=[],this.gu=i,this.gu.qr(e=>{n.enqueueAndForget(async()=>{up(this)&&(rP("RemoteStore","Restarting streams for network reachability change."),await async function(e){e.wu.add(4),await ua(e),e.yu.set("Unknown"),e.wu.delete(4),await uo(e)}(this))})}),this.yu=new ui(n,r)}}async function uo(e){if(up(e))for(let t of e.mu)await t(!0)}async function ua(e){for(let t of e.mu)await t(!1)}function ul(e,t){e._u.has(t.targetId)||(e._u.set(t.targetId,t),uf(e)?ud(e):uN(e).Oo()&&uc(e,t))}function uu(e,t){let n=uN(e);e._u.delete(t),n.Oo()&&uh(e,t),0===e._u.size&&(n.Oo()?n.$o():up(e)&&e.yu.set("Unknown"))}function uc(e,t){e.pu.Mt(t.targetId),uN(e).Ho(t)}function uh(e,t){e.pu.Mt(t),uN(e).Jo(t)}function ud(e){e.pu=new ow({getRemoteKeysForTarget:t=>e.remoteSyncer.getRemoteKeysForTarget(t),se:t=>e._u.get(t)||null}),uN(e).start(),e.yu.cu()}function uf(e){return up(e)&&!uN(e).ko()&&e._u.size>0}function up(e){return 0===e.wu.size}async function um(e){e._u.forEach((t,n)=>{uc(e,t)})}async function ug(e,t){e.pu=void 0,uf(e)?(e.yu.lu(t),ud(e)):e.yu.set("Unknown")}async function uy(e,t,n){if(e.yu.set("Online"),t instanceof ov&&2===t.state&&t.cause)try{await async function(e,t){let n=t.cause;for(let r of t.targetIds)e._u.has(r)&&(await e.remoteSyncer.rejectListen(r,n),e._u.delete(r),e.pu.removeTarget(r))}(e,t)}catch(r){rP("RemoteStore","Failed to remove targets %s: %s ",t.targetIds.join(","),r),await uv(e,r)}else if(t instanceof og?e.pu.Gt(t):t instanceof oy?e.pu.Yt(t):e.pu.Wt(t),!n.isEqual(r0.min()))try{let i=await lL(e.localStore);n.compareTo(i)>=0&&await function(e,t){let n=e.pu.te(t);return n.targetChanges.forEach((n,r)=>{if(n.resumeToken.approximateByteSize()>0){let i=e._u.get(r);i&&e._u.set(r,i.withResumeToken(n.resumeToken,t))}}),n.targetMismatches.forEach(t=>{let n=e._u.get(t);if(!n)return;e._u.set(t,n.withResumeToken(iO.EMPTY_BYTE_STRING,n.snapshotVersion)),uh(e,t);let r=new ac(n.target,t,1,n.sequenceNumber);uc(e,r)}),e.remoteSyncer.applyRemoteEvent(n)}(e,n)}catch(s){rP("RemoteStore","Failed to raise snapshot:",s),await uv(e,s)}}async function uv(e,t,n){if(!im(t))throw t;e.wu.add(1),await ua(e),e.yu.set("Offline"),n||(n=()=>lL(e.localStore)),e.asyncQueue.enqueueRetryable(async()=>{rP("RemoteStore","Retrying IndexedDB access"),await n(),e.wu.delete(1),await uo(e)})}function u_(e,t){return t().catch(n=>uv(e,n,t))}async function uw(e){let t=uA(e),n=e.du.length>0?e.du[e.du.length-1].batchId:-1;for(;up(e)&&e.du.length<10;)try{let r=await function(e,t){return e.persistence.runTransaction("Get next mutation batch","readonly",n=>(void 0===t&&(t=-1),e.mutationQueue.getNextMutationBatchAfterBatchId(n,t)))}(e.localStore,n);if(null===r){0===e.du.length&&t.$o();break}n=r.batchId,function(e,t){e.du.push(t);let n=uA(e);n.Oo()&&n.Xo&&n.Zo(t.mutations)}(e,r)}catch(i){await uv(e,i)}ub(e)&&uI(e)}function ub(e){return up(e)&&!uA(e).ko()&&e.du.length>0}function uI(e){uA(e).start()}async function uT(e){uA(e).nu()}async function uE(e){let t=uA(e);for(let n of e.du)t.Zo(n.mutations)}async function uS(e,t,n){let r=e.du.shift(),i=al.from(r,t,n);await u_(e,()=>e.remoteSyncer.applySuccessfulWrite(i)),await uw(e)}async function uk(e,t){t&&uA(e).Xo&&await async function(e,t){var n;if(on(n=t.code)&&n!==rU.ABORTED){let r=e.du.shift();uA(e).Fo(),await u_(e,()=>e.remoteSyncer.rejectFailedWrite(r.batchId,t)),await uw(e)}}(e,t),ub(e)&&uI(e)}async function ux(e,t){e.asyncQueue.verifyOperationInProgress(),rP("RemoteStore","RemoteStore received new credentials");let n=up(e);e.wu.add(3),await ua(e),n&&e.yu.set("Unknown"),await e.remoteSyncer.handleCredentialChange(t),e.wu.delete(3),await uo(e)}async function uC(e,t){t?(e.wu.delete(2),await uo(e)):t||(e.wu.add(2),await ua(e),e.yu.set("Unknown"))}function uN(e){var t,n,r;return e.Iu||(e.Iu=(t=e.datastore,n=e.asyncQueue,r={Yr:um.bind(null,e),Zr:ug.bind(null,e),zo:uy.bind(null,e)},t.iu(),new ut(n,t.So,t.authCredentials,t.appCheckCredentials,t.It,r)),e.mu.push(async t=>{t?(e.Iu.Fo(),uf(e)?ud(e):e.yu.set("Unknown")):(await e.Iu.stop(),e.pu=void 0)})),e.Iu}function uA(e){var t,n,r;return e.Tu||(e.Tu=(t=e.datastore,n=e.asyncQueue,r={Yr:uT.bind(null,e),Zr:uk.bind(null,e),eu:uE.bind(null,e),tu:uS.bind(null,e)},t.iu(),new un(n,t.So,t.authCredentials,t.appCheckCredentials,t.It,r)),e.mu.push(async t=>{t?(e.Tu.Fo(),await uw(e)):(await e.Tu.stop(),e.du.length>0&&(rP("RemoteStore",`Stopping write stream with ${e.du.length} pending writes`),e.du=[]))})),e.Tu}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class uR{constructor(e,t,n,r,i){this.asyncQueue=e,this.timerId=t,this.targetTimeMs=n,this.op=r,this.removalCallback=i,this.deferred=new rq,this.then=this.deferred.promise.then.bind(this.deferred.promise),this.deferred.promise.catch(e=>{})}static createAndSchedule(e,t,n,r,i){let s=Date.now()+n,o=new uR(e,t,s,r,i);return o.start(n),o}start(e){this.timerHandle=setTimeout(()=>this.handleDelayElapsed(),e)}skipDelay(){return this.handleDelayElapsed()}cancel(e){null!==this.timerHandle&&(this.clearTimeout(),this.deferred.reject(new rV(rU.CANCELLED,"Operation cancelled"+(e?": "+e:""))))}handleDelayElapsed(){this.asyncQueue.enqueueAndForget(()=>null!==this.timerHandle?(this.clearTimeout(),this.op().then(e=>this.deferred.resolve(e))):Promise.resolve())}clearTimeout(){null!==this.timerHandle&&(this.removalCallback(this),clearTimeout(this.timerHandle),this.timerHandle=null)}}function uD(e,t){if(rL("AsyncQueue",`${t}: ${e}`),im(e))return new rV(rU.UNAVAILABLE,`${t}: ${e}`);throw e}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class uO{constructor(e){this.comparator=e?(t,n)=>e(t,n)||r6.comparator(t.key,n.key):(e,t)=>r6.comparator(e.key,t.key),this.keyedMap=oa(),this.sortedSet=new ik(this.comparator)}static emptySet(e){return new uO(e.comparator)}has(e){return null!=this.keyedMap.get(e)}get(e){return this.keyedMap.get(e)}first(){return this.sortedSet.minKey()}last(){return this.sortedSet.maxKey()}isEmpty(){return this.sortedSet.isEmpty()}indexOf(e){let t=this.keyedMap.get(e);return t?this.sortedSet.indexOf(t):-1}get size(){return this.sortedSet.size}forEach(e){this.sortedSet.inorderTraversal((t,n)=>(e(t),!1))}add(e){let t=this.delete(e.key);return t.copy(t.keyedMap.insert(e.key,e),t.sortedSet.insert(e,null))}delete(e){let t=this.get(e);return t?this.copy(this.keyedMap.remove(e),this.sortedSet.remove(t)):this}isEqual(e){if(!(e instanceof uO)||this.size!==e.size)return!1;let t=this.sortedSet.getIterator(),n=e.sortedSet.getIterator();for(;t.hasNext();){let r=t.getNext().key,i=n.getNext().key;if(!r.isEqual(i))return!1}return!0}toString(){let e=[];return this.forEach(t=>{e.push(t.toString())}),0===e.length?"DocumentSet ()":"DocumentSet (\n  "+e.join("  \n")+"\n)"}copy(e,t){let n=new uO;return n.comparator=this.comparator,n.keyedMap=e,n.sortedSet=t,n}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class uP{constructor(){this.Eu=new ik(r6.comparator)}track(e){let t=e.doc.key,n=this.Eu.get(t);n?0!==e.type&&3===n.type?this.Eu=this.Eu.insert(t,e):3===e.type&&1!==n.type?this.Eu=this.Eu.insert(t,{type:n.type,doc:e.doc}):2===e.type&&2===n.type?this.Eu=this.Eu.insert(t,{type:2,doc:e.doc}):2===e.type&&0===n.type?this.Eu=this.Eu.insert(t,{type:0,doc:e.doc}):1===e.type&&0===n.type?this.Eu=this.Eu.remove(t):1===e.type&&2===n.type?this.Eu=this.Eu.insert(t,{type:1,doc:n.doc}):0===e.type&&1===n.type?this.Eu=this.Eu.insert(t,{type:2,doc:e.doc}):rF():this.Eu=this.Eu.insert(t,e)}Au(){let e=[];return this.Eu.inorderTraversal((t,n)=>{e.push(n)}),e}}class uL{constructor(e,t,n,r,i,s,o,a,l){this.query=e,this.docs=t,this.oldDocs=n,this.docChanges=r,this.mutatedKeys=i,this.fromCache=s,this.syncStateChanged=o,this.excludesMetadataChanges=a,this.hasCachedResults=l}static fromInitialDocuments(e,t,n,r,i){let s=[];return t.forEach(e=>{s.push({type:0,doc:e})}),new uL(e,t,uO.emptySet(t),s,n,r,!0,!1,i)}get hasPendingWrites(){return!this.mutatedKeys.isEmpty()}isEqual(e){if(!(this.fromCache===e.fromCache&&this.hasCachedResults===e.hasCachedResults&&this.syncStateChanged===e.syncStateChanged&&this.mutatedKeys.isEqual(e.mutatedKeys)&&sR(this.query,e.query)&&this.docs.isEqual(e.docs)&&this.oldDocs.isEqual(e.oldDocs)))return!1;let t=this.docChanges,n=e.docChanges;if(t.length!==n.length)return!1;for(let r=0;r<t.length;r++)if(t[r].type!==n[r].type||!t[r].doc.isEqual(n[r].doc))return!1;return!0}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class uM{constructor(){this.Ru=void 0,this.listeners=[]}}class uj{constructor(){this.queries=new oi(e=>sD(e),sR),this.onlineState="Unknown",this.bu=new Set}}async function uF(e,t){let n=t.query,r=!1,i=e.queries.get(n);if(i||(r=!0,i=new uM),r)try{i.Ru=await e.onListen(n)}catch(o){let s=uD(o,`Initialization of query '${sO(t.query)}' failed`);return void t.onError(s)}e.queries.set(n,i),i.listeners.push(t),t.Pu(e.onlineState),i.Ru&&t.vu(i.Ru)&&uB(e)}async function uU(e,t){let n=t.query,r=!1,i=e.queries.get(n);if(i){let s=i.listeners.indexOf(t);s>=0&&(i.listeners.splice(s,1),r=0===i.listeners.length)}if(r)return e.queries.delete(n),e.onUnlisten(n)}function uV(e,t){let n=!1;for(let r of t){let i=r.query,s=e.queries.get(i);if(s){for(let o of s.listeners)o.vu(r)&&(n=!0);s.Ru=r}}n&&uB(e)}function uq(e,t,n){let r=e.queries.get(t);if(r)for(let i of r.listeners)i.onError(n);e.queries.delete(t)}function uB(e){e.bu.forEach(e=>{e.next()})}class u${constructor(e,t,n){this.query=e,this.Vu=t,this.Su=!1,this.Du=null,this.onlineState="Unknown",this.options=n||{}}vu(e){if(!this.options.includeMetadataChanges){let t=[];for(let n of e.docChanges)3!==n.type&&t.push(n);e=new uL(e.query,e.docs,e.oldDocs,t,e.mutatedKeys,e.fromCache,e.syncStateChanged,!0,e.hasCachedResults)}let r=!1;return this.Su?this.Cu(e)&&(this.Vu.next(e),r=!0):this.xu(e,this.onlineState)&&(this.Nu(e),r=!0),this.Du=e,r}onError(e){this.Vu.error(e)}Pu(e){this.onlineState=e;let t=!1;return this.Du&&!this.Su&&this.xu(this.Du,e)&&(this.Nu(this.Du),t=!0),t}xu(e,t){return!e.fromCache||(!this.options.ku||!("Offline"!==t))&&(!e.docs.isEmpty()||e.hasCachedResults||"Offline"===t)}Cu(e){if(e.docChanges.length>0)return!0;let t=this.Du&&this.Du.hasPendingWrites!==e.hasPendingWrites;return!(!e.syncStateChanged&&!t)&&!0===this.options.includeMetadataChanges}Nu(e){e=uL.fromInitialDocuments(e.query,e.docs,e.mutatedKeys,e.fromCache,e.hasCachedResults),this.Su=!0,this.Vu.next(e)}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class uz{constructor(e,t){this.payload=e,this.byteLength=t}Ou(){return"metadata"in this.payload}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class uG{constructor(e){this.It=e}Ji(e){return oD(this.It,e)}Yi(e){return e.metadata.exists?oF(this.It,e.document,!1):se.newNoDocument(this.Ji(e.metadata.name),this.Xi(e.metadata.readTime))}Xi(e){return oC(e)}}class uW{constructor(e,t,n){this.Mu=e,this.localStore=t,this.It=n,this.queries=[],this.documents=[],this.collectionGroups=new Set,this.progress=uH(e)}Fu(e){this.progress.bytesLoaded+=e.byteLength;let t=this.progress.documentsLoaded;if(e.payload.namedQuery)this.queries.push(e.payload.namedQuery);else if(e.payload.documentMetadata){this.documents.push({metadata:e.payload.documentMetadata}),e.payload.documentMetadata.exists||++t;let n=r2.fromString(e.payload.documentMetadata.name);this.collectionGroups.add(n.get(n.length-2))}else e.payload.document&&(this.documents[this.documents.length-1].document=e.payload.document,++t);return t!==this.progress.documentsLoaded?(this.progress.documentsLoaded=t,Object.assign({},this.progress)):null}$u(e){let t=new Map,n=new uG(this.It);for(let r of e)if(r.metadata.queries){let i=n.Ji(r.metadata.name);for(let s of r.metadata.queries){let o=(t.get(s)||od()).add(i);t.set(s,o)}}return t}async complete(){let e=await l$(this.localStore,new uG(this.It),this.documents,this.Mu.id),t=this.$u(this.documents);for(let n of this.queries)await lz(this.localStore,n,t.get(n.name));return this.progress.taskState="Success",{progress:this.progress,Bu:this.collectionGroups,Lu:e}}}function uH(e){return{taskState:"Running",documentsLoaded:0,bytesLoaded:0,totalDocuments:e.totalDocuments,totalBytes:e.totalBytes}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class uK{constructor(e){this.key=e}}class uQ{constructor(e){this.key=e}}class uY{constructor(e,t){this.query=e,this.Uu=t,this.qu=null,this.hasCachedResults=!1,this.current=!1,this.Ku=od(),this.mutatedKeys=od(),this.Gu=sM(e),this.Qu=new uO(this.Gu)}get ju(){return this.Uu}Wu(e,t){let n=t?t.zu:new uP,r=t?t.Qu:this.Qu,i=t?t.mutatedKeys:this.mutatedKeys,s=r,o=!1,a="F"===this.query.limitType&&r.size===this.query.limit?r.last():null,l="L"===this.query.limitType&&r.size===this.query.limit?r.first():null;if(e.inorderTraversal((e,t)=>{let u=r.get(e),c=sP(this.query,t)?t:null,h=!!u&&this.mutatedKeys.has(u.key),d=!!c&&(c.hasLocalMutations||this.mutatedKeys.has(c.key)&&c.hasCommittedMutations),f=!1;u&&c?u.data.isEqual(c.data)?h!==d&&(n.track({type:3,doc:c}),f=!0):this.Hu(u,c)||(n.track({type:2,doc:c}),f=!0,(a&&this.Gu(c,a)>0||l&&0>this.Gu(c,l))&&(o=!0)):!u&&c?(n.track({type:0,doc:c}),f=!0):u&&!c&&(n.track({type:1,doc:u}),f=!0,(a||l)&&(o=!0)),f&&(c?(s=s.add(c),i=d?i.add(e):i.delete(e)):(s=s.delete(e),i=i.delete(e)))}),null!==this.query.limit)for(;s.size>this.query.limit;){let u="F"===this.query.limitType?s.last():s.first();s=s.delete(u.key),i=i.delete(u.key),n.track({type:1,doc:u})}return{Qu:s,zu:n,$i:o,mutatedKeys:i}}Hu(e,t){return e.hasLocalMutations&&t.hasCommittedMutations&&!t.hasLocalMutations}applyChanges(e,t,n){let r=this.Qu;this.Qu=e.Qu,this.mutatedKeys=e.mutatedKeys;let i=e.zu.Au();i.sort((e,t)=>(function(e,t){let n=e=>{switch(e){case 0:return 1;case 2:case 3:return 2;case 1:return 0;default:return rF()}};return n(e)-n(t)})(e.type,t.type)||this.Gu(e.doc,t.doc)),this.Ju(n);let s=t?this.Yu():[],o=0===this.Ku.size&&this.current?1:0,a=o!==this.qu;return(this.qu=o,0!==i.length||a)?{snapshot:new uL(this.query,e.Qu,r,i,e.mutatedKeys,0===o,a,!1,!!n&&n.resumeToken.approximateByteSize()>0),Xu:s}:{Xu:s}}Pu(e){return this.current&&"Offline"===e?(this.current=!1,this.applyChanges({Qu:this.Qu,zu:new uP,mutatedKeys:this.mutatedKeys,$i:!1},!1)):{Xu:[]}}Zu(e){return!this.Uu.has(e)&&!!this.Qu.has(e)&&!this.Qu.get(e).hasLocalMutations}Ju(e){e&&(e.addedDocuments.forEach(e=>this.Uu=this.Uu.add(e)),e.modifiedDocuments.forEach(e=>{}),e.removedDocuments.forEach(e=>this.Uu=this.Uu.delete(e)),this.current=e.current)}Yu(){if(!this.current)return[];let e=this.Ku;this.Ku=od(),this.Qu.forEach(e=>{this.Zu(e.key)&&(this.Ku=this.Ku.add(e.key))});let t=[];return e.forEach(e=>{this.Ku.has(e)||t.push(new uQ(e))}),this.Ku.forEach(n=>{e.has(n)||t.push(new uK(n))}),t}tc(e){this.Uu=e.Hi,this.Ku=od();let t=this.Wu(e.documents);return this.applyChanges(t,!0)}ec(){return uL.fromInitialDocuments(this.query,this.Qu,this.mutatedKeys,0===this.qu,this.hasCachedResults)}}class uX{constructor(e,t,n){this.query=e,this.targetId=t,this.view=n}}class uJ{constructor(e){this.key=e,this.nc=!1}}class uZ{constructor(e,t,n,r,i,s){this.localStore=e,this.remoteStore=t,this.eventManager=n,this.sharedClientState=r,this.currentUser=i,this.maxConcurrentLimboResolutions=s,this.sc={},this.ic=new oi(e=>sD(e),sR),this.rc=new Map,this.oc=new Set,this.uc=new ik(r6.comparator),this.cc=new Map,this.ac=new lm,this.hc={},this.lc=new Map,this.fc=a2.vn(),this.onlineState="Unknown",this.dc=void 0}get isPrimaryClient(){return!0===this.dc}}async function u0(e,t){let n,r;let i=cv(e),s=i.ic.get(t);if(s)n=s.targetId,i.sharedClientState.addLocalQueryTarget(n),r=s.view.ec();else{let o=await lj(i.localStore,sN(t));i.isPrimaryClient&&ul(i.remoteStore,o);let a=i.sharedClientState.addLocalQueryTarget(o.targetId);r=await u1(i,t,n=o.targetId,"current"===a,o.resumeToken)}return r}async function u1(e,t,n,r,i){e._c=(t,n,r)=>(async function(e,t,n,r){let i=t.view.Wu(n);i.$i&&(i=await lU(e.localStore,t.query,!1).then(({documents:e})=>t.view.Wu(e,i)));let s=r&&r.targetChanges.get(t.targetId),o=t.view.applyChanges(i,e.isPrimaryClient,s);return ci(e,t.targetId,o.Xu),o.snapshot})(e,t,n,r);let s=await lU(e.localStore,t,!0),o=new uY(t,s.Hi),a=o.Wu(s.documents),l=om.createSynthesizedTargetChangeForCurrentChange(n,r&&"Offline"!==e.onlineState,i),u=o.applyChanges(a,e.isPrimaryClient,l);ci(e,n,u.Xu);let c=new uX(t,n,o);return e.ic.set(t,c),e.rc.has(n)?e.rc.get(n).push(t):e.rc.set(n,[t]),u.snapshot}async function u2(e,t){let n=e.ic.get(t),r=e.rc.get(n.targetId);if(r.length>1)return e.rc.set(n.targetId,r.filter(e=>!sR(e,t))),void e.ic.delete(t);e.isPrimaryClient?(e.sharedClientState.removeLocalQueryTarget(n.targetId),e.sharedClientState.isActiveQueryTarget(n.targetId)||await lF(e.localStore,n.targetId,!1).then(()=>{e.sharedClientState.clearQueryState(n.targetId),uu(e.remoteStore,n.targetId),cn(e,n.targetId)}).catch(il)):(cn(e,n.targetId),await lF(e.localStore,n.targetId,!0))}async function u3(e,t,n){let r=c_(e);try{var i,s;let o;let a=await function(e,t){let n,r;let i=rZ.now(),s=t.reduce((e,t)=>e.add(t.key),od());return e.persistence.runTransaction("Locally write mutations","readwrite",o=>{let a=os,l=od();return e.Gi.getEntries(o,s).next(e=>{(a=e).forEach((e,t)=>{t.isValidDocument()||(l=l.add(e))})}).next(()=>e.localDocuments.getOverlayedDocuments(o,a)).next(r=>{n=r;let s=[];for(let a of t){let l=function(e,t){let n=null;for(let r of e.fieldTransforms){let i=t.data.field(r.field),s=sq(r.transform,i||null);null!=s&&(null===n&&(n=i7.empty()),n.set(r.field,s))}return n||null}(a,n.get(a.key).overlayedDocument);null!=l&&s.push(new s6(a.key,l,function e(t){let n=[];return iE(t.fields,(t,r)=>{let i=new r4([t]);if(i4(r)){let s=e(r.mapValue).fields;if(0===s.length)n.push(i);else for(let o of s)n.push(i.child(o))}else n.push(i)}),new iD(n)}(l.value.mapValue),sJ.exists(!0)))}return e.mutationQueue.addMutationBatch(o,i,s,t)}).next(t=>{r=t;let i=t.applyToLocalDocumentSet(n,l);return e.documentOverlayCache.saveOverlays(o,t.batchId,i)})}).then(()=>({batchId:r.batchId,changes:ol(n)}))}(r.localStore,t);r.sharedClientState.addPendingMutation(a.batchId),i=r,s=a.batchId,(o=i.hc[i.currentUser.toKey()])||(o=new ik(rX)),o=o.insert(s,n),i.hc[i.currentUser.toKey()]=o,await co(r,a.changes),await uw(r.remoteStore)}catch(u){let l=uD(u,"Failed to persist write");n.reject(l)}}async function u4(e,t){try{let n=await function(e,t){let n=e,r=t.snapshotVersion,i=n.Ui;return n.persistence.runTransaction("Apply remote event","readwrite-primary",e=>{let s=n.Gi.newChangeBuffer({trackRemovals:!0});i=n.Ui;let o=[];t.targetChanges.forEach((s,a)=>{var l;let u=i.get(a);if(!u)return;o.push(n.Cs.removeMatchingKeys(e,s.removedDocuments,a).next(()=>n.Cs.addMatchingKeys(e,s.addedDocuments,a)));let c=u.withSequenceNumber(e.currentSequenceNumber);t.targetMismatches.has(a)?c=c.withResumeToken(iO.EMPTY_BYTE_STRING,r0.min()).withLastLimboFreeSnapshotVersion(r0.min()):s.resumeToken.approximateByteSize()>0&&(c=c.withResumeToken(s.resumeToken,r)),i=i.insert(a,c),l=c,(0===u.resumeToken.approximateByteSize()||l.snapshotVersion.toMicroseconds()-u.snapshotVersion.toMicroseconds()>=3e8||s.addedDocuments.size+s.modifiedDocuments.size+s.removedDocuments.size>0)&&o.push(n.Cs.updateTargetData(e,c))});let a=os,l=od();if(t.documentUpdates.forEach(r=>{t.resolvedLimboDocuments.has(r)&&o.push(n.persistence.referenceDelegate.updateLimboDocument(e,r))}),o.push(lM(e,s,t.documentUpdates).next(e=>{a=e.Wi,l=e.zi})),!r.isEqual(r0.min())){let u=n.Cs.getLastRemoteSnapshotVersion(e).next(t=>n.Cs.setTargetsMetadata(e,e.currentSequenceNumber,r));o.push(u)}return iu.waitFor(o).next(()=>s.apply(e)).next(()=>n.localDocuments.getLocalViewOfDocuments(e,a,l)).next(()=>a)}).then(e=>(n.Ui=i,e))}(e.localStore,t);t.targetChanges.forEach((t,n)=>{let r=e.cc.get(n);r&&(t.addedDocuments.size+t.modifiedDocuments.size+t.removedDocuments.size<=1||rF(),t.addedDocuments.size>0?r.nc=!0:t.modifiedDocuments.size>0?r.nc||rF():t.removedDocuments.size>0&&(r.nc||rF(),r.nc=!1))}),await co(e,n,t)}catch(r){await il(r)}}function u6(e,t,n){let r=e;if(r.isPrimaryClient&&0===n||!r.isPrimaryClient&&1===n){let i=[];r.ic.forEach((e,n)=>{let r=n.view.Pu(t);r.snapshot&&i.push(r.snapshot)}),function(e,t){let n=e;n.onlineState=t;let r=!1;n.queries.forEach((e,n)=>{for(let i of n.listeners)i.Pu(t)&&(r=!0)}),r&&uB(n)}(r.eventManager,t),i.length&&r.sc.zo(i),r.onlineState=t,r.isPrimaryClient&&r.sharedClientState.setOnlineState(t)}}async function u5(e,t,n){let r=e;r.sharedClientState.updateQueryState(t,"rejected",n);let i=r.cc.get(t),s=i&&i.key;if(s){let o=new ik(r6.comparator);o=o.insert(s,se.newNoDocument(s,r0.min()));let a=od().add(s),l=new op(r0.min(),new Map,new iN(rX),o,a);await u4(r,l),r.uc=r.uc.remove(s),r.cc.delete(t),cs(r)}else await lF(r.localStore,t,!1).then(()=>cn(r,t,n)).catch(il)}async function u8(e,t){var n;let r=t.batch.batchId;try{let i=await (n=e.localStore).persistence.runTransaction("Acknowledge batch","readwrite-primary",e=>{let r=t.batch.keys(),i=n.Gi.newChangeBuffer({trackRemovals:!0});return(function(e,t,n,r){let i=n.batch,s=i.keys(),o=iu.resolve();return s.forEach(e=>{o=o.next(()=>r.getEntry(t,e)).next(t=>{let s=n.docVersions.get(e);null!==s||rF(),0>t.version.compareTo(s)&&(i.applyToRemoteDocument(t,n),t.isValidDocument()&&(t.setReadTime(n.commitVersion),r.addEntry(t)))})}),o.next(()=>e.mutationQueue.removeMutationBatch(t,i))})(n,e,t,i).next(()=>i.apply(e)).next(()=>n.mutationQueue.performConsistencyCheck(e)).next(()=>n.documentOverlayCache.removeOverlaysForBatchId(e,r,t.batch.batchId)).next(()=>n.localDocuments.recalculateAndSaveOverlaysForDocumentKeys(e,function(e){let t=od();for(let n=0;n<e.mutationResults.length;++n)e.mutationResults[n].transformResults.length>0&&(t=t.add(e.batch.mutations[n].key));return t}(t))).next(()=>n.localDocuments.getDocuments(e,r))});ct(e,r,null),ce(e,r),e.sharedClientState.updateMutationState(r,"acknowledged"),await co(e,i)}catch(s){await il(s)}}async function u9(e,t,n){var r;try{let i=await (r=e.localStore).persistence.runTransaction("Reject batch","readwrite-primary",e=>{let n;return r.mutationQueue.lookupMutationBatch(e,t).next(t=>(null!==t||rF(),n=t.keys(),r.mutationQueue.removeMutationBatch(e,t))).next(()=>r.mutationQueue.performConsistencyCheck(e)).next(()=>r.documentOverlayCache.removeOverlaysForBatchId(e,n,t)).next(()=>r.localDocuments.recalculateAndSaveOverlaysForDocumentKeys(e,n)).next(()=>r.localDocuments.getDocuments(e,n))});ct(e,t,n),ce(e,t),e.sharedClientState.updateMutationState(t,"rejected",n),await co(e,i)}catch(s){await il(s)}}async function u7(e,t){var n;up(e.remoteStore)||rP("SyncEngine","The network is disabled. The task returned by 'awaitPendingWrites()' will not complete until the network is enabled.");try{let r=await (n=e.localStore).persistence.runTransaction("Get highest unacknowledged batch id","readonly",e=>n.mutationQueue.getHighestUnacknowledgedBatchId(e));if(-1===r)return void t.resolve();let i=e.lc.get(r)||[];i.push(t),e.lc.set(r,i)}catch(o){let s=uD(o,"Initialization of waitForPendingWrites() operation failed");t.reject(s)}}function ce(e,t){(e.lc.get(t)||[]).forEach(e=>{e.resolve()}),e.lc.delete(t)}function ct(e,t,n){let r=e,i=r.hc[r.currentUser.toKey()];if(i){let s=i.get(t);s&&(n?s.reject(n):s.resolve(),i=i.remove(t)),r.hc[r.currentUser.toKey()]=i}}function cn(e,t,n=null){for(let r of(e.sharedClientState.removeLocalQueryTarget(t),e.rc.get(t)))e.ic.delete(r),n&&e.sc.wc(r,n);e.rc.delete(t),e.isPrimaryClient&&e.ac.ls(t).forEach(t=>{e.ac.containsKey(t)||cr(e,t)})}function cr(e,t){e.oc.delete(t.path.canonicalString());let n=e.uc.get(t);null!==n&&(uu(e.remoteStore,n),e.uc=e.uc.remove(t),e.cc.delete(n),cs(e))}function ci(e,t,n){for(let r of n)r instanceof uK?(e.ac.addReference(r.key,t),function(e,t){let n=t.key,r=n.path.canonicalString();e.uc.get(n)||e.oc.has(r)||(rP("SyncEngine","New document in limbo: "+n),e.oc.add(r),cs(e))}(e,r)):r instanceof uQ?(rP("SyncEngine","Document no longer in limbo: "+r.key),e.ac.removeReference(r.key,t),e.ac.containsKey(r.key)||cr(e,r.key)):rF()}function cs(e){for(;e.oc.size>0&&e.uc.size<e.maxConcurrentLimboResolutions;){let t=e.oc.values().next().value;e.oc.delete(t);let n=new r6(r2.fromString(t)),r=e.fc.next();e.cc.set(r,new uJ(n)),e.uc=e.uc.insert(n,r),ul(e.remoteStore,new ac(sN(sT(n.path)),r,2,iI.at))}}async function co(e,t,n){let r=[],i=[],s=[];e.ic.isEmpty()||(e.ic.forEach((o,a)=>{s.push(e._c(a,t,n).then(t=>{if((t||n)&&e.isPrimaryClient&&e.sharedClientState.updateQueryState(a.targetId,(null==t?void 0:t.fromCache)?"not-current":"current"),t){r.push(t);let s=lR.Ci(a.targetId,t);i.push(s)}}))}),await Promise.all(s),e.sc.zo(r),await async function(e,t){let n=e;try{await n.persistence.runTransaction("notifyLocalViewChanges","readwrite",e=>iu.forEach(t,t=>iu.forEach(t.Si,r=>n.persistence.referenceDelegate.addReference(e,t.targetId,r)).next(()=>iu.forEach(t.Di,r=>n.persistence.referenceDelegate.removeReference(e,t.targetId,r)))))}catch(r){if(!im(r))throw r;rP("LocalStore","Failed to update sequence numbers: "+r)}for(let i of t){let s=i.targetId;if(!i.fromCache){let o=n.Ui.get(s),a=o.snapshotVersion,l=o.withLastLimboFreeSnapshotVersion(a);n.Ui=n.Ui.insert(s,l)}}}(e.localStore,i))}async function ca(e,t){let n=e;if(!n.currentUser.isEqual(t)){rP("SyncEngine","User change. New user:",t.toKey());let r=await lP(n.localStore,t);n.currentUser=t,n.lc.forEach(e=>{e.forEach(e=>{e.reject(new rV(rU.CANCELLED,"'waitForPendingWrites' promise is rejected due to a user change."))})}),n.lc.clear(),n.sharedClientState.handleUserChange(t,r.removedBatchIds,r.addedBatchIds),await co(n,r.ji)}}function cl(e,t){let n=e.cc.get(t);if(n&&n.nc)return od().add(n.key);{let r=od(),i=e.rc.get(t);if(!i)return r;for(let s of i){let o=e.ic.get(s);r=r.unionWith(o.view.ju)}return r}}async function cu(e,t){let n=await lU(e.localStore,t.query,!0),r=t.view.tc(n);return e.isPrimaryClient&&ci(e,t.targetId,r.Xu),r}async function cc(e,t){return lq(e.localStore,t).then(t=>co(e,t))}async function ch(e,t,n,r){let i=await function(e,t){let n=e.mutationQueue;return e.persistence.runTransaction("Lookup mutation documents","readonly",r=>n.Tn(r,t).next(t=>t?e.localDocuments.getDocuments(r,t):iu.resolve(null)))}(e.localStore,t);null!==i?("pending"===n?await uw(e.remoteStore):"acknowledged"===n||"rejected"===n?(ct(e,t,r||null),ce(e,t),function(e,t){e.mutationQueue.An(t)}(e.localStore,t)):rF(),await co(e,i)):rP("SyncEngine","Cannot apply mutation batch with id: "+t)}async function cd(e,t){let n=e;if(cv(n),c_(n),!0===t&&!0!==n.dc){let r=n.sharedClientState.getAllActiveQueryTargets(),i=await cf(n,r.toArray());for(let s of(n.dc=!0,await uC(n.remoteStore,!0),i))ul(n.remoteStore,s)}else if(!1===t&&!1!==n.dc){let o=[],a=Promise.resolve();n.rc.forEach((e,t)=>{n.sharedClientState.isLocalQueryTarget(t)?o.push(t):a=a.then(()=>(cn(n,t),lF(n.localStore,t,!0))),uu(n.remoteStore,t)}),await a,await cf(n,o),function(e){let t=e;t.cc.forEach((e,n)=>{uu(t.remoteStore,n)}),t.ac.fs(),t.cc=new Map,t.uc=new ik(r6.comparator)}(n),n.dc=!1,await uC(n.remoteStore,!1)}}async function cf(e,t,n){let r=[],i=[];for(let s of t){let o;let a=e.rc.get(s);if(a&&0!==a.length)for(let l of(o=await lj(e.localStore,sN(a[0])),a)){let u=e.ic.get(l),c=await cu(e,u);c.snapshot&&i.push(c.snapshot)}else{let h=await lV(e.localStore,s);await u1(e,cp(h),s,!1,(o=await lj(e.localStore,h)).resumeToken)}r.push(o)}return e.sc.zo(i),r}function cp(e){var t,n,r,i,s,o,a;return t=e.path,n=e.collectionGroup,r=e.orderBy,i=e.filters,s=e.limit,o=e.startAt,a=e.endAt,new sI(t,n,r,i,s,"F",o,a)}function cm(e){return e.localStore.persistence.vi()}async function cg(e,t,n,r){if(e.dc)return void rP("SyncEngine","Ignoring unexpected query state notification.");let i=e.rc.get(t);if(i&&i.length>0)switch(n){case"current":case"not-current":{let s=await lq(e.localStore,sL(i[0])),o=op.createSynthesizedRemoteEventForCurrentChange(t,"current"===n,iO.EMPTY_BYTE_STRING);await co(e,s,o);break}case"rejected":await lF(e.localStore,t,!0),cn(e,t,r);break;default:rF()}}async function cy(e,t,n){let r=cv(e);if(r.dc){for(let i of t){if(r.rc.has(i)){rP("SyncEngine","Adding an already active target "+i);continue}let s=await lV(r.localStore,i),o=await lj(r.localStore,s);await u1(r,cp(s),o.targetId,!1,o.resumeToken),ul(r.remoteStore,o)}for(let a of n)r.rc.has(a)&&await lF(r.localStore,a,!1).then(()=>{uu(r.remoteStore,a),cn(r,a)}).catch(il)}}function cv(e){let t=e;return t.remoteStore.remoteSyncer.applyRemoteEvent=u4.bind(null,t),t.remoteStore.remoteSyncer.getRemoteKeysForTarget=cl.bind(null,t),t.remoteStore.remoteSyncer.rejectListen=u5.bind(null,t),t.sc.zo=uV.bind(null,t.eventManager),t.sc.wc=uq.bind(null,t.eventManager),t}function c_(e){let t=e;return t.remoteStore.remoteSyncer.applySuccessfulWrite=u8.bind(null,t),t.remoteStore.remoteSyncer.rejectFailedWrite=u9.bind(null,t),t}class cw{constructor(){this.synchronizeTabs=!1}async initialize(e){this.It=l9(e.databaseInfo.databaseId),this.sharedClientState=this.gc(e),this.persistence=this.yc(e),await this.persistence.start(),this.localStore=this.Ic(e),this.gcScheduler=this.Tc(e,this.localStore),this.indexBackfillerScheduler=this.Ec(e,this.localStore)}Tc(e,t){return null}Ec(e,t){return null}Ic(e){var t,n,r,i;return t=this.persistence,n=new lD,r=e.initialUser,i=this.It,new lO(t,n,r,i)}yc(e){return new lb(lT.Bs,this.It)}gc(e){return new l0}async terminate(){this.gcScheduler&&this.gcScheduler.stop(),await this.sharedClientState.shutdown(),await this.persistence.shutdown()}}class cb extends cw{constructor(e,t,n){super(),this.Ac=e,this.cacheSizeBytes=t,this.forceOwnership=n,this.synchronizeTabs=!1}async initialize(e){await super.initialize(e),await this.Ac.initialize(this,e),await c_(this.Ac.syncEngine),await uw(this.Ac.remoteStore),await this.persistence.li(()=>(this.gcScheduler&&!this.gcScheduler.started&&this.gcScheduler.start(),this.indexBackfillerScheduler&&!this.indexBackfillerScheduler.started&&this.indexBackfillerScheduler.start(),Promise.resolve()))}Ic(e){var t,n,r,i;return t=this.persistence,n=new lD,r=e.initialUser,i=this.It,new lO(t,n,r,i)}Tc(e,t){let n=this.persistence.referenceDelegate.garbageCollector;return new a7(n,e.asyncQueue,t)}Ec(e,t){let n=new ib(t,this.persistence);return new iw(e.asyncQueue,n)}yc(e){let t=lA(e.databaseInfo.databaseId,e.databaseInfo.persistenceKey),n=void 0!==this.cacheSizeBytes?aK.withCacheSize(this.cacheSizeBytes):aK.DEFAULT;return new lx(this.synchronizeTabs,t,e.clientId,n,e.asyncQueue,l5(),l8(),this.It,this.sharedClientState,!!this.forceOwnership)}gc(e){return new l0}}class cI extends cb{constructor(e,t){super(e,t,!1),this.Ac=e,this.cacheSizeBytes=t,this.synchronizeTabs=!0}async initialize(e){await super.initialize(e);let t=this.Ac.syncEngine;this.sharedClientState instanceof lZ&&(this.sharedClientState.syncEngine={Fr:ch.bind(null,t),$r:cg.bind(null,t),Br:cy.bind(null,t),vi:cm.bind(null,t),Mr:cc.bind(null,t)},await this.sharedClientState.start()),await this.persistence.li(async e=>{await cd(this.Ac.syncEngine,e),this.gcScheduler&&(e&&!this.gcScheduler.started?this.gcScheduler.start():e||this.gcScheduler.stop()),this.indexBackfillerScheduler&&(e&&!this.indexBackfillerScheduler.started?this.indexBackfillerScheduler.start():e||this.indexBackfillerScheduler.stop())})}gc(e){let t=l5();if(!lZ.C(t))throw new rV(rU.UNIMPLEMENTED,"IndexedDB persistence is only available on platforms that support LocalStorage.");let n=lA(e.databaseInfo.databaseId,e.databaseInfo.persistenceKey);return new lZ(t,e.asyncQueue,n,e.clientId,e.initialUser)}}class cT{async initialize(e,t){this.localStore||(this.localStore=e.localStore,this.sharedClientState=e.sharedClientState,this.datastore=this.createDatastore(t),this.remoteStore=this.createRemoteStore(t),this.eventManager=this.createEventManager(t),this.syncEngine=this.createSyncEngine(t,!e.synchronizeTabs),this.sharedClientState.onlineStateHandler=e=>u6(this.syncEngine,e,1),this.remoteStore.remoteSyncer.handleCredentialChange=ca.bind(null,this.syncEngine),await uC(this.remoteStore,this.syncEngine.isPrimaryClient))}createEventManager(e){return new uj}createDatastore(e){var t,n,r;let i=l9(e.databaseInfo.databaseId),s=(t=e.databaseInfo,new l6(t));return n=e.authCredentials,r=e.appCheckCredentials,new ur(n,r,s,i)}createRemoteStore(e){var t,n,r,i,s;return t=this.localStore,n=this.datastore,r=e.asyncQueue,i=e=>u6(this.syncEngine,e,0),s=l2.C()?new l2:new l1,new us(t,n,r,i,s)}createSyncEngine(e,t){return function(e,t,n,r,i,s,o){let a=new uZ(e,t,n,r,i,s);return o&&(a.dc=!0),a}(this.localStore,this.remoteStore,this.eventManager,this.sharedClientState,e.initialUser,e.maxConcurrentLimboResolutions,t)}terminate(){return async function(e){rP("RemoteStore","RemoteStore shutting down."),e.wu.add(5),await ua(e),e.gu.shutdown(),e.yu.set("Unknown")}(this.remoteStore)}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function cE(e,t,n){if(!n)throw new rV(rU.INVALID_ARGUMENT,`Function ${e}() cannot be called with an empty ${t}.`)}function cS(e,t,n,r){if(!0===t&&!0===r)throw new rV(rU.INVALID_ARGUMENT,`${e} and ${n} cannot be used together.`)}function ck(e){if(!r6.isDocumentKey(e))throw new rV(rU.INVALID_ARGUMENT,`Invalid document reference. Document references must have an even number of segments, but ${e} has ${e.length}.`)}function cx(e){if(r6.isDocumentKey(e))throw new rV(rU.INVALID_ARGUMENT,`Invalid collection reference. Collection references must have an odd number of segments, but ${e} has ${e.length}.`)}function cC(e){if(void 0===e)return"undefined";if(null===e)return"null";if("string"==typeof e)return e.length>20&&(e=`${e.substring(0,20)}...`),JSON.stringify(e);if("number"==typeof e||"boolean"==typeof e)return""+e;if("object"==typeof e){if(e instanceof Array)return"an array";{var t;let n=(t=e).constructor?t.constructor.name:null;return n?`a custom ${n} object`:"an object"}}return"function"==typeof e?"a function":rF()}function cN(e,t){if("_delegate"in e&&(e=e._delegate),!(e instanceof t)){if(t.name===e.constructor.name)throw new rV(rU.INVALID_ARGUMENT,"Type does not match the expected instance. Did you pass a reference from a different Firestore SDK?");{let n=cC(e);throw new rV(rU.INVALID_ARGUMENT,`Expected type '${t.name}', but it was: ${n}`)}}return e}function cA(e,t){if(t<=0)throw new rV(rU.INVALID_ARGUMENT,`Function ${e}() requires a positive number, but it was: ${t}.`)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let cR=new Map;class cD{constructor(e){var t;if(void 0===e.host){if(void 0!==e.ssl)throw new rV(rU.INVALID_ARGUMENT,"Can't provide ssl option if host option is not set");this.host="firestore.googleapis.com",this.ssl=!0}else this.host=e.host,this.ssl=null===(t=e.ssl)||void 0===t||t;if(this.credentials=e.credentials,this.ignoreUndefinedProperties=!!e.ignoreUndefinedProperties,void 0===e.cacheSizeBytes)this.cacheSizeBytes=41943040;else{if(-1!==e.cacheSizeBytes&&e.cacheSizeBytes<1048576)throw new rV(rU.INVALID_ARGUMENT,"cacheSizeBytes must be at least 1048576");this.cacheSizeBytes=e.cacheSizeBytes}this.experimentalForceLongPolling=!!e.experimentalForceLongPolling,this.experimentalAutoDetectLongPolling=!!e.experimentalAutoDetectLongPolling,this.useFetchStreams=!!e.useFetchStreams,cS("experimentalForceLongPolling",e.experimentalForceLongPolling,"experimentalAutoDetectLongPolling",e.experimentalAutoDetectLongPolling)}isEqual(e){return this.host===e.host&&this.ssl===e.ssl&&this.credentials===e.credentials&&this.cacheSizeBytes===e.cacheSizeBytes&&this.experimentalForceLongPolling===e.experimentalForceLongPolling&&this.experimentalAutoDetectLongPolling===e.experimentalAutoDetectLongPolling&&this.ignoreUndefinedProperties===e.ignoreUndefinedProperties&&this.useFetchStreams===e.useFetchStreams}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class cO{constructor(e,t,n,r){this._authCredentials=e,this._appCheckCredentials=t,this._databaseId=n,this._app=r,this.type="firestore-lite",this._persistenceKey="(lite)",this._settings=new cD({}),this._settingsFrozen=!1}get app(){if(!this._app)throw new rV(rU.FAILED_PRECONDITION,"Firestore was not initialized using the Firebase SDK. 'app' is not available");return this._app}get _initialized(){return this._settingsFrozen}get _terminated(){return void 0!==this._terminateTask}_setSettings(e){if(this._settingsFrozen)throw new rV(rU.FAILED_PRECONDITION,"Firestore has already been started and its settings can no longer be changed. You can only modify settings before calling any other methods on a Firestore object.");this._settings=new cD(e),void 0!==e.credentials&&(this._authCredentials=function(e){if(!e)return new r$;switch(e.type){case"gapi":let t=e.client;return new rH(t,e.sessionIndex||"0",e.iamToken||null,e.authTokenFactory||null);case"provider":return e.client;default:throw new rV(rU.INVALID_ARGUMENT,"makeAuthCredentialsProvider failed due to invalid credential type")}}(e.credentials))}_getSettings(){return this._settings}_freezeSettings(){return this._settingsFrozen=!0,this._settings}_delete(){return this._terminateTask||(this._terminateTask=this._terminate()),this._terminateTask}toJSON(){return{app:this._app,databaseId:this._databaseId,settings:this._settings}}_terminate(){return function(e){let t=cR.get(e);t&&(rP("ComponentProvider","Removing Datastore"),cR.delete(e),t.terminate())}(this),Promise.resolve()}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class cP{constructor(e,t,n){this.converter=t,this._key=n,this.type="document",this.firestore=e}get _path(){return this._key.path}get id(){return this._key.path.lastSegment()}get path(){return this._key.path.canonicalString()}get parent(){return new cM(this.firestore,this.converter,this._key.path.popLast())}withConverter(e){return new cP(this.firestore,e,this._key)}}class cL{constructor(e,t,n){this.converter=t,this._query=n,this.type="query",this.firestore=e}withConverter(e){return new cL(this.firestore,e,this._query)}}class cM extends cL{constructor(e,t,n){super(e,t,sT(n)),this._path=n,this.type="collection"}get id(){return this._query.path.lastSegment()}get path(){return this._query.path.canonicalString()}get parent(){let e=this._path.popLast();return e.isEmpty()?null:new cP(this.firestore,null,new r6(e))}withConverter(e){return new cM(this.firestore,e,this._path)}}function cj(e,t,...n){if(e=(0,S.m9)(e),cE("collection","path",t),e instanceof cO){let r=r2.fromString(t,...n);return cx(r),new cM(e,null,r)}{if(!(e instanceof cP||e instanceof cM))throw new rV(rU.INVALID_ARGUMENT,"Expected first argument to collection() to be a CollectionReference, a DocumentReference or FirebaseFirestore");let i=e._path.child(r2.fromString(t,...n));return cx(i),new cM(e.firestore,null,i)}}function cF(e,t,...n){if(e=(0,S.m9)(e),1==arguments.length&&(t=rY.R()),cE("doc","path",t),e instanceof cO){let r=r2.fromString(t,...n);return ck(r),new cP(e,null,new r6(r))}{if(!(e instanceof cP||e instanceof cM))throw new rV(rU.INVALID_ARGUMENT,"Expected first argument to collection() to be a CollectionReference, a DocumentReference or FirebaseFirestore");let i=e._path.child(r2.fromString(t,...n));return ck(i),new cP(e.firestore,e instanceof cM?e.converter:null,new r6(i))}}function cU(e,t){return e=(0,S.m9)(e),t=(0,S.m9)(t),(e instanceof cP||e instanceof cM)&&(t instanceof cP||t instanceof cM)&&e.firestore===t.firestore&&e.path===t.path&&e.converter===t.converter}function cV(e,t){return e=(0,S.m9)(e),t=(0,S.m9)(t),e instanceof cL&&t instanceof cL&&e.firestore===t.firestore&&sR(e._query,t._query)&&e.converter===t.converter}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function cq(e,t=10240){let n=0;return{async read(){if(n<e.byteLength){let r={value:e.slice(n,n+t),done:!1};return n+=t,r}return{done:!0}},async cancel(){},releaseLock(){},closed:Promise.reject("unimplemented")}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *//**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class cB{constructor(e){this.observer=e,this.muted=!1}next(e){this.observer.next&&this.Rc(this.observer.next,e)}error(e){this.observer.error?this.Rc(this.observer.error,e):rL("Uncaught Error in snapshot listener:",e)}bc(){this.muted=!0}Rc(e,t){this.muted||setTimeout(()=>{this.muted||e(t)},0)}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class c${constructor(e,t){this.Pc=e,this.It=t,this.metadata=new rq,this.buffer=new Uint8Array,this.vc=new TextDecoder("utf-8"),this.Vc().then(e=>{e&&e.Ou()?this.metadata.resolve(e.payload.metadata):this.metadata.reject(Error(`The first element of the bundle is not a metadata, it is
             ${JSON.stringify(null==e?void 0:e.payload)}`))},e=>this.metadata.reject(e))}close(){return this.Pc.cancel()}async getMetadata(){return this.metadata.promise}async mc(){return await this.getMetadata(),this.Vc()}async Vc(){let e=await this.Sc();if(null===e)return null;let t=this.vc.decode(e),n=Number(t);isNaN(n)&&this.Dc(`length string (${t}) is not valid number`);let r=await this.Cc(n);return new uz(JSON.parse(r),e.length+n)}xc(){return this.buffer.findIndex(e=>123===e)}async Sc(){for(;0>this.xc()&&!await this.Nc(););if(0===this.buffer.length)return null;let e=this.xc();e<0&&this.Dc("Reached the end of bundle when a length string is expected.");let t=this.buffer.slice(0,e);return this.buffer=this.buffer.slice(e),t}async Cc(e){for(;this.buffer.length<e;)await this.Nc()&&this.Dc("Reached the end of bundle when more is expected.");let t=this.vc.decode(this.buffer.slice(0,e));return this.buffer=this.buffer.slice(e),t}Dc(e){throw this.Pc.cancel(),Error(`Invalid bundle format: ${e}`)}async Nc(){let e=await this.Pc.read();if(!e.done){let t=new Uint8Array(this.buffer.length+e.value.length);t.set(this.buffer),t.set(e.value,this.buffer.length),this.buffer=t}return e.done}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class cz{constructor(e){this.datastore=e,this.readVersions=new Map,this.mutations=[],this.committed=!1,this.lastWriteError=null,this.writtenDocs=new Set}async lookup(e){if(this.ensureCommitNotCalled(),this.mutations.length>0)throw new rV(rU.INVALID_ARGUMENT,"Firestore transactions require all reads to be executed before all writes.");let t=await async function(e,t){let n=oL(e.It)+"/documents",r={documents:t.map(t=>oR(e.It,t))},i=await e._o("BatchGetDocuments",n,r,t.length),s=new Map;i.forEach(t=>{var n;let r=(n=e.It,"found"in t?function(e,t){t.found||rF(),t.found.name,t.found.updateTime;let n=oD(e,t.found.name),r=oC(t.found.updateTime),i=new i7({mapValue:{fields:t.found.fields}});return se.newFoundDocument(n,r,i)}(n,t):"missing"in t?function(e,t){t.missing||rF(),t.readTime||rF();let n=oD(e,t.missing),r=oC(t.readTime);return se.newNoDocument(n,r)}(n,t):rF());s.set(r.key.toString(),r)});let o=[];return t.forEach(e=>{let t=s.get(e.toString());t||rF(),o.push(t)}),o}(this.datastore,e);return t.forEach(e=>this.recordVersion(e)),t}set(e,t){this.write(t.toMutation(e,this.precondition(e))),this.writtenDocs.add(e.toString())}update(e,t){try{this.write(t.toMutation(e,this.preconditionForUpdate(e)))}catch(n){this.lastWriteError=n}this.writtenDocs.add(e.toString())}delete(e){this.write(new s7(e,this.precondition(e))),this.writtenDocs.add(e.toString())}async commit(){if(this.ensureCommitNotCalled(),this.lastWriteError)throw this.lastWriteError;let e=this.readVersions;this.mutations.forEach(t=>{e.delete(t.key.toString())}),e.forEach((e,t)=>{let n=r6.fromPath(t);this.mutations.push(new oe(n,this.precondition(n)))}),await async function(e,t){let n=oL(e.It)+"/documents",r={writes:t.map(t=>oU(e.It,t))};await e.ao("Commit",n,r)}(this.datastore,this.mutations),this.committed=!0}recordVersion(e){let t;if(e.isFoundDocument())t=e.version;else{if(!e.isNoDocument())throw rF();t=r0.min()}let n=this.readVersions.get(e.key.toString());if(n){if(!t.isEqual(n))throw new rV(rU.ABORTED,"Document version changed between two reads.")}else this.readVersions.set(e.key.toString(),t)}precondition(e){let t=this.readVersions.get(e.toString());return!this.writtenDocs.has(e.toString())&&t?t.isEqual(r0.min())?sJ.exists(!1):sJ.updateTime(t):sJ.none()}preconditionForUpdate(e){let t=this.readVersions.get(e.toString());if(!this.writtenDocs.has(e.toString())&&t){if(t.isEqual(r0.min()))throw new rV(rU.INVALID_ARGUMENT,"Can't update a document that doesn't exist.");return sJ.updateTime(t)}return sJ.exists(!0)}write(e){this.ensureCommitNotCalled(),this.mutations.push(e)}ensureCommitNotCalled(){}}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class cG{constructor(e,t,n,r,i){this.asyncQueue=e,this.datastore=t,this.options=n,this.updateFunction=r,this.deferred=i,this.kc=n.maxAttempts,this.No=new l7(this.asyncQueue,"transaction_retry")}run(){this.kc-=1,this.Oc()}Oc(){this.No.Ro(async()=>{let e=new cz(this.datastore),t=this.Mc(e);t&&t.then(t=>{this.asyncQueue.enqueueAndForget(()=>e.commit().then(()=>{this.deferred.resolve(t)}).catch(e=>{this.Fc(e)}))}).catch(e=>{this.Fc(e)})})}Mc(e){try{let t=this.updateFunction(e);return!iB(t)&&t.catch&&t.then?t:(this.deferred.reject(Error("Transaction callback must return a Promise")),null)}catch(n){return this.deferred.reject(n),null}}Fc(e){this.kc>0&&this.$c(e)?(this.kc-=1,this.asyncQueue.enqueueAndForget(()=>(this.Oc(),Promise.resolve()))):this.deferred.reject(e)}$c(e){if("FirebaseError"===e.name){let t=e.code;return"aborted"===t||"failed-precondition"===t||!on(t)}return!1}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class cW{constructor(e,t,n,r){this.authCredentials=e,this.appCheckCredentials=t,this.asyncQueue=n,this.databaseInfo=r,this.user=rA.UNAUTHENTICATED,this.clientId=rY.R(),this.authCredentialListener=()=>Promise.resolve(),this.appCheckCredentialListener=()=>Promise.resolve(),this.authCredentials.start(n,async e=>{rP("FirestoreClient","Received user=",e.uid),await this.authCredentialListener(e),this.user=e}),this.appCheckCredentials.start(n,e=>(rP("FirestoreClient","Received new app check token=",e),this.appCheckCredentialListener(e,this.user)))}async getConfiguration(){return{asyncQueue:this.asyncQueue,databaseInfo:this.databaseInfo,clientId:this.clientId,authCredentials:this.authCredentials,appCheckCredentials:this.appCheckCredentials,initialUser:this.user,maxConcurrentLimboResolutions:100}}setCredentialChangeListener(e){this.authCredentialListener=e}setAppCheckTokenChangeListener(e){this.appCheckCredentialListener=e}verifyNotTerminated(){if(this.asyncQueue.isShuttingDown)throw new rV(rU.FAILED_PRECONDITION,"The client has already been terminated.")}terminate(){this.asyncQueue.enterRestrictedMode();let e=new rq;return this.asyncQueue.enqueueAndForgetEvenWhileRestricted(async()=>{try{this.onlineComponents&&await this.onlineComponents.terminate(),this.offlineComponents&&await this.offlineComponents.terminate(),this.authCredentials.shutdown(),this.appCheckCredentials.shutdown(),e.resolve()}catch(n){let t=uD(n,"Failed to shutdown persistence");e.reject(t)}}),e.promise}}async function cH(e,t){e.asyncQueue.verifyOperationInProgress(),rP("FirestoreClient","Initializing OfflineComponentProvider");let n=await e.getConfiguration();await t.initialize(n);let r=n.initialUser;e.setCredentialChangeListener(async e=>{r.isEqual(e)||(await lP(t.localStore,e),r=e)}),t.persistence.setDatabaseDeletedListener(()=>e.terminate()),e.offlineComponents=t}async function cK(e,t){e.asyncQueue.verifyOperationInProgress();let n=await cQ(e);rP("FirestoreClient","Initializing OnlineComponentProvider");let r=await e.getConfiguration();await t.initialize(n,r),e.setCredentialChangeListener(e=>ux(t.remoteStore,e)),e.setAppCheckTokenChangeListener((e,n)=>ux(t.remoteStore,n)),e.onlineComponents=t}async function cQ(e){return e.offlineComponents||(rP("FirestoreClient","Using default OfflineComponentProvider"),await cH(e,new cw)),e.offlineComponents}async function cY(e){return e.onlineComponents||(rP("FirestoreClient","Using default OnlineComponentProvider"),await cK(e,new cT)),e.onlineComponents}function cX(e){return cQ(e).then(e=>e.persistence)}function cJ(e){return cQ(e).then(e=>e.localStore)}function cZ(e){return cY(e).then(e=>e.remoteStore)}function c0(e){return cY(e).then(e=>e.syncEngine)}async function c1(e){let t=await cY(e),n=t.eventManager;return n.onListen=u0.bind(null,t.syncEngine),n.onUnlisten=u2.bind(null,t.syncEngine),n}function c2(e,t,n={}){let r=new rq;return e.asyncQueue.enqueueAndForget(async()=>(function(e,t,n,r,i){let s=new cB({next:s=>{t.enqueueAndForget(()=>uU(e,o));let a=s.docs.has(n);!a&&s.fromCache?i.reject(new rV(rU.UNAVAILABLE,"Failed to get document because the client is offline.")):a&&s.fromCache&&r&&"server"===r.source?i.reject(new rV(rU.UNAVAILABLE,'Failed to get document from server. (However, this document does exist in the local cache. Run again without setting source to "server" to retrieve the cached document.)')):i.resolve(s)},error:e=>i.reject(e)}),o=new u$(sT(n.path),s,{includeMetadataChanges:!0,ku:!0});return uF(e,o)})(await c1(e),e.asyncQueue,t,n,r)),r.promise}function c3(e,t,n={}){let r=new rq;return e.asyncQueue.enqueueAndForget(async()=>(function(e,t,n,r,i){let s=new cB({next:n=>{t.enqueueAndForget(()=>uU(e,o)),n.fromCache&&"server"===r.source?i.reject(new rV(rU.UNAVAILABLE,'Failed to get documents from server. (However, these documents may exist in the local cache. Run again without setting source to "server" to retrieve the cached documents.)')):i.resolve(n)},error:e=>i.reject(e)}),o=new u$(n,s,{includeMetadataChanges:!0,ku:!0});return uF(e,o)})(await c1(e),e.asyncQueue,t,n,r)),r.promise}class c4{constructor(){this.Bc=Promise.resolve(),this.Lc=[],this.Uc=!1,this.qc=[],this.Kc=null,this.Gc=!1,this.Qc=!1,this.jc=[],this.No=new l7(this,"async_queue_retry"),this.Wc=()=>{let e=l8();e&&rP("AsyncQueue","Visibility state changed to "+e.visibilityState),this.No.Po()};let e=l8();e&&"function"==typeof e.addEventListener&&e.addEventListener("visibilitychange",this.Wc)}get isShuttingDown(){return this.Uc}enqueueAndForget(e){this.enqueue(e)}enqueueAndForgetEvenWhileRestricted(e){this.zc(),this.Hc(e)}enterRestrictedMode(e){if(!this.Uc){this.Uc=!0,this.Qc=e||!1;let t=l8();t&&"function"==typeof t.removeEventListener&&t.removeEventListener("visibilitychange",this.Wc)}}enqueue(e){if(this.zc(),this.Uc)return new Promise(()=>{});let t=new rq;return this.Hc(()=>this.Uc&&this.Qc?Promise.resolve():(e().then(t.resolve,t.reject),t.promise)).then(()=>t.promise)}enqueueRetryable(e){this.enqueueAndForget(()=>(this.Lc.push(e),this.Jc()))}async Jc(){if(0!==this.Lc.length){try{await this.Lc[0](),this.Lc.shift(),this.No.reset()}catch(e){if(!im(e))throw e;rP("AsyncQueue","Operation failed with retryable error: "+e)}this.Lc.length>0&&this.No.Ro(()=>this.Jc())}}Hc(e){let t=this.Bc.then(()=>(this.Gc=!0,e().catch(e=>{let t;this.Kc=e,this.Gc=!1;let n=(t=e.message||"",e.stack&&(t=e.stack.includes(e.message)?e.stack:e.message+"\n"+e.stack),t);throw rL("INTERNAL UNHANDLED ERROR: ",n),e}).then(e=>(this.Gc=!1,e))));return this.Bc=t,t}enqueueAfterDelay(e,t,n){this.zc(),this.jc.indexOf(e)>-1&&(t=0);let r=uR.createAndSchedule(this,e,t,n,e=>this.Yc(e));return this.qc.push(r),r}zc(){this.Kc&&rF()}verifyOperationInProgress(){}async Xc(){let e;do await (e=this.Bc);while(e!==this.Bc)}Zc(e){for(let t of this.qc)if(t.timerId===e)return!0;return!1}ta(e){return this.Xc().then(()=>{for(let t of(this.qc.sort((e,t)=>e.targetTimeMs-t.targetTimeMs),this.qc))if(t.skipDelay(),"all"!==e&&t.timerId===e)break;return this.Xc()})}ea(e){this.jc.push(e)}Yc(e){let t=this.qc.indexOf(e);this.qc.splice(t,1)}}function c6(e){return function(e,t){if("object"!=typeof e||null===e)return!1;for(let n of t)if(n in e&&"function"==typeof e[n])return!0;return!1}(e,["next","error","complete"])}class c5{constructor(){this._progressObserver={},this._taskCompletionResolver=new rq,this._lastProgress={taskState:"Running",totalBytes:0,totalDocuments:0,bytesLoaded:0,documentsLoaded:0}}onProgress(e,t,n){this._progressObserver={next:e,error:t,complete:n}}catch(e){return this._taskCompletionResolver.promise.catch(e)}then(e,t){return this._taskCompletionResolver.promise.then(e,t)}_completeWith(e){this._updateProgress(e),this._progressObserver.complete&&this._progressObserver.complete(),this._taskCompletionResolver.resolve(e)}_failWith(e){this._lastProgress.taskState="Error",this._progressObserver.next&&this._progressObserver.next(this._lastProgress),this._progressObserver.error&&this._progressObserver.error(e),this._taskCompletionResolver.reject(e)}_updateProgress(e){this._lastProgress=e,this._progressObserver.next&&this._progressObserver.next(e)}}class c8 extends cO{constructor(e,t,n,r){super(e,t,n,r),this.type="firestore",this._queue=new c4,this._persistenceKey=(null==r?void 0:r.name)||"[DEFAULT]"}_terminate(){return this._firestoreClient||c7(this),this._firestoreClient.terminate()}}function c9(e){return e._firestoreClient||c7(e),e._firestoreClient.verifyNotTerminated(),e._firestoreClient}function c7(e){var t,n,r,i;let s=e._freezeSettings(),o=(n=e._databaseId,r=(null===(t=e._app)||void 0===t?void 0:t.options.appId)||"",i=e._persistenceKey,new iV(n,r,i,s.host,s.ssl,s.experimentalForceLongPolling,s.experimentalAutoDetectLongPolling,s.useFetchStreams));e._firestoreClient=new cW(e._authCredentials,e._appCheckCredentials,e._queue,o)}function he(e,t,n){let r=new rq;return e.asyncQueue.enqueue(async()=>{try{await cH(e,n),await cK(e,t),r.resolve()}catch(i){if(!("FirebaseError"===i.name?i.code===rU.FAILED_PRECONDITION||i.code===rU.UNIMPLEMENTED:!("undefined"!=typeof DOMException&&i instanceof DOMException)||22===i.code||20===i.code||11===i.code))throw i;rM("Error enabling offline persistence. Falling back to persistence disabled: "+i),r.reject(i)}}).then(()=>r.promise)}function ht(e){if(e._initialized||e._terminated)throw new rV(rU.FAILED_PRECONDITION,"Firestore has already been started and persistence can no longer be enabled. You can only enable persistence before calling any other methods on a Firestore object.")}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *//**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class hn{constructor(e){this._byteString=e}static fromBase64String(e){try{return new hn(iO.fromBase64String(e))}catch(t){throw new rV(rU.INVALID_ARGUMENT,"Failed to construct data from Base64 string: "+t)}}static fromUint8Array(e){return new hn(iO.fromUint8Array(e))}toBase64(){return this._byteString.toBase64()}toUint8Array(){return this._byteString.toUint8Array()}toString(){return"Bytes(base64: "+this.toBase64()+")"}isEqual(e){return this._byteString.isEqual(e._byteString)}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class hr{constructor(...e){for(let t=0;t<e.length;++t)if(0===e[t].length)throw new rV(rU.INVALID_ARGUMENT,"Invalid field name at argument $(i + 1). Field names must not be empty.");this._internalPath=new r4(e)}isEqual(e){return this._internalPath.isEqual(e._internalPath)}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class hi{constructor(e){this._methodName=e}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class hs{constructor(e,t){if(!isFinite(e)||e<-90||e>90)throw new rV(rU.INVALID_ARGUMENT,"Latitude must be a number between -90 and 90, but was: "+e);if(!isFinite(t)||t<-180||t>180)throw new rV(rU.INVALID_ARGUMENT,"Longitude must be a number between -180 and 180, but was: "+t);this._lat=e,this._long=t}get latitude(){return this._lat}get longitude(){return this._long}isEqual(e){return this._lat===e._lat&&this._long===e._long}toJSON(){return{latitude:this._lat,longitude:this._long}}_compareTo(e){return rX(this._lat,e._lat)||rX(this._long,e._long)}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let ho=/^__.*__$/;class ha{constructor(e,t,n){this.data=e,this.fieldMask=t,this.fieldTransforms=n}toMutation(e,t){return null!==this.fieldMask?new s6(e,this.data,this.fieldMask,t,this.fieldTransforms):new s4(e,this.data,t,this.fieldTransforms)}}class hl{constructor(e,t,n){this.data=e,this.fieldMask=t,this.fieldTransforms=n}toMutation(e,t){return new s6(e,this.data,this.fieldMask,t,this.fieldTransforms)}}function hu(e){switch(e){case 0:case 2:case 1:return!0;case 3:case 4:return!1;default:throw rF()}}class hc{constructor(e,t,n,r,i,s){this.settings=e,this.databaseId=t,this.It=n,this.ignoreUndefinedProperties=r,void 0===i&&this.na(),this.fieldTransforms=i||[],this.fieldMask=s||[]}get path(){return this.settings.path}get sa(){return this.settings.sa}ia(e){return new hc(Object.assign(Object.assign({},this.settings),e),this.databaseId,this.It,this.ignoreUndefinedProperties,this.fieldTransforms,this.fieldMask)}ra(e){var t;let n=null===(t=this.path)||void 0===t?void 0:t.child(e),r=this.ia({path:n,oa:!1});return r.ua(e),r}ca(e){var t;let n=null===(t=this.path)||void 0===t?void 0:t.child(e),r=this.ia({path:n,oa:!1});return r.na(),r}aa(e){return this.ia({path:void 0,oa:!0})}ha(e){return hA(e,this.settings.methodName,this.settings.la||!1,this.path,this.settings.fa)}contains(e){return void 0!==this.fieldMask.find(t=>e.isPrefixOf(t))||void 0!==this.fieldTransforms.find(t=>e.isPrefixOf(t.field))}na(){if(this.path)for(let e=0;e<this.path.length;e++)this.ua(this.path.get(e))}ua(e){if(0===e.length)throw this.ha("Document fields must not be empty");if(hu(this.sa)&&ho.test(e))throw this.ha('Document fields cannot begin and end with "__"')}}class hh{constructor(e,t,n){this.databaseId=e,this.ignoreUndefinedProperties=t,this.It=n||l9(e)}da(e,t,n,r=!1){return new hc({sa:e,methodName:t,fa:n,path:r4.emptyPath(),oa:!1,la:r},this.databaseId,this.It,this.ignoreUndefinedProperties)}}function hd(e){let t=e._freezeSettings(),n=l9(e._databaseId);return new hh(e._databaseId,!!t.ignoreUndefinedProperties,n)}function hf(e,t,n,r,i,s={}){let o,a;let l=e.da(s.merge||s.mergeFields?2:0,t,n,i);hk("Data must be an object, but it was:",l,r);let u=hE(r,l);if(s.merge)o=new iD(l.fieldMask),a=l.fieldTransforms;else if(s.mergeFields){let c=[];for(let h of s.mergeFields){let d=hx(t,h,n);if(!l.contains(d))throw new rV(rU.INVALID_ARGUMENT,`Field '${d}' is specified in your field mask but missing from your input data.`);hR(c,d)||c.push(d)}o=new iD(c),a=l.fieldTransforms.filter(e=>o.covers(e.field))}else o=null,a=l.fieldTransforms;return new ha(new i7(u),o,a)}class hp extends hi{_toFieldTransform(e){if(2!==e.sa)throw 1===e.sa?e.ha(`${this._methodName}() can only appear at the top level of your update data`):e.ha(`${this._methodName}() cannot be used with set() unless you pass {merge:true}`);return e.fieldMask.push(e.path),null}isEqual(e){return e instanceof hp}}function hm(e,t,n){return new hc({sa:3,fa:t.settings.fa,methodName:e._methodName,oa:n},t.databaseId,t.It,t.ignoreUndefinedProperties)}class hg extends hi{_toFieldTransform(e){return new sY(e.path,new sB)}isEqual(e){return e instanceof hg}}class hy extends hi{constructor(e,t){super(e),this._a=t}_toFieldTransform(e){let t=hm(this,e,!0),n=this._a.map(e=>hT(e,t)),r=new s$(n);return new sY(e.path,r)}isEqual(e){return this===e}}class hv extends hi{constructor(e,t){super(e),this._a=t}_toFieldTransform(e){let t=hm(this,e,!0),n=this._a.map(e=>hT(e,t)),r=new sG(n);return new sY(e.path,r)}isEqual(e){return this===e}}class h_ extends hi{constructor(e,t){super(e),this.wa=t}_toFieldTransform(e){let t=new sH(e.It,sU(e.It,this.wa));return new sY(e.path,t)}isEqual(e){return this===e}}function hw(e,t,n,r){let i=e.da(1,t,n);hk("Data must be an object, but it was:",i,r);let s=[],o=i7.empty();iE(r,(e,r)=>{let a=hN(t,e,n);r=(0,S.m9)(r);let l=i.ca(a);if(r instanceof hp)s.push(a);else{let u=hT(r,l);null!=u&&(s.push(a),o.set(a,u))}});let a=new iD(s);return new hl(o,a,i.fieldTransforms)}function hb(e,t,n,r,i,s){let o=e.da(1,t,n),a=[hx(t,r,n)],l=[i];if(s.length%2!=0)throw new rV(rU.INVALID_ARGUMENT,`Function ${t}() needs to be called with an even number of arguments that alternate between field names and values.`);for(let u=0;u<s.length;u+=2)a.push(hx(t,s[u])),l.push(s[u+1]);let c=[],h=i7.empty();for(let d=a.length-1;d>=0;--d)if(!hR(c,a[d])){let f=a[d],p=l[d];p=(0,S.m9)(p);let m=o.ca(f);if(p instanceof hp)c.push(f);else{let g=hT(p,m);null!=g&&(c.push(f),h.set(f,g))}}let y=new iD(c);return new hl(h,y,o.fieldTransforms)}function hI(e,t,n,r=!1){return hT(n,e.da(r?4:3,t))}function hT(e,t){if(hS(e=(0,S.m9)(e)))return hk("Unsupported field value:",t,e),hE(e,t);if(e instanceof hi)return function(e,t){if(!hu(t.sa))throw t.ha(`${e._methodName}() can only be used with update() and set()`);if(!t.path)throw t.ha(`${e._methodName}() is not currently supported inside arrays`);let n=e._toFieldTransform(t);n&&t.fieldTransforms.push(n)}(e,t),null;if(void 0===e&&t.ignoreUndefinedProperties)return null;if(t.path&&t.fieldMask.push(t.path),e instanceof Array){if(t.settings.oa&&4!==t.sa)throw t.ha("Nested arrays are not supported");return function(e,t){let n=[],r=0;for(let i of e){let s=hT(i,t.aa(r));null==s&&(s={nullValue:"NULL_VALUE"}),n.push(s),r++}return{arrayValue:{values:n}}}(e,t)}return function(e,t){if(null===(e=(0,S.m9)(e)))return{nullValue:"NULL_VALUE"};if("number"==typeof e)return sU(t.It,e);if("boolean"==typeof e)return{booleanValue:e};if("string"==typeof e)return{stringValue:e};if(e instanceof Date){let n=rZ.fromDate(e);return{timestampValue:ok(t.It,n)}}if(e instanceof rZ){let r=new rZ(e.seconds,1e3*Math.floor(e.nanoseconds/1e3));return{timestampValue:ok(t.It,r)}}if(e instanceof hs)return{geoPointValue:{latitude:e.latitude,longitude:e.longitude}};if(e instanceof hn)return{bytesValue:ox(t.It,e._byteString)};if(e instanceof cP){let i=t.databaseId,s=e.firestore._databaseId;if(!s.isEqual(i))throw t.ha(`Document reference is for database ${s.projectId}/${s.database} but should be for database ${i.projectId}/${i.database}`);return{referenceValue:oN(e.firestore._databaseId||t.databaseId,e._key.path)}}throw t.ha(`Unsupported field value: ${cC(e)}`)}(e,t)}function hE(e,t){let n={};return iS(e)?t.path&&t.path.length>0&&t.fieldMask.push(t.path):iE(e,(e,r)=>{let i=hT(r,t.ra(e));null!=i&&(n[e]=i)}),{mapValue:{fields:n}}}function hS(e){return!("object"!=typeof e||null===e||e instanceof Array||e instanceof Date||e instanceof rZ||e instanceof hs||e instanceof hn||e instanceof cP||e instanceof hi)}function hk(e,t,n){if(!hS(n)||!("object"==typeof n&&null!==n&&(Object.getPrototypeOf(n)===Object.prototype||null===Object.getPrototypeOf(n)))){let r=cC(n);throw"an object"===r?t.ha(e+" a custom object"):t.ha(e+" "+r)}}function hx(e,t,n){if((t=(0,S.m9)(t))instanceof hr)return t._internalPath;if("string"==typeof t)return hN(e,t);throw hA("Field path arguments must be of type string or ",e,!1,void 0,n)}let hC=RegExp("[~\\*/\\[\\]]");function hN(e,t,n){if(t.search(hC)>=0)throw hA(`Invalid field path (${t}). Paths must not contain '~', '*', '/', '[', or ']'`,e,!1,void 0,n);try{return new hr(...t.split("."))._internalPath}catch(r){throw hA(`Invalid field path (${t}). Paths must not be empty, begin with '.', end with '.', or contain '..'`,e,!1,void 0,n)}}function hA(e,t,n,r,i){let s=r&&!r.isEmpty(),o=void 0!==i,a=`Function ${t}() called with invalid data`;n&&(a+=" (via `toFirestore()`)"),a+=". ";let l="";return(s||o)&&(l+=" (found",s&&(l+=` in field ${r}`),o&&(l+=` in document ${i}`),l+=")"),new rV(rU.INVALID_ARGUMENT,a+e+l)}function hR(e,t){return e.some(e=>e.isEqual(t))}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class hD{constructor(e,t,n,r,i){this._firestore=e,this._userDataWriter=t,this._key=n,this._document=r,this._converter=i}get id(){return this._key.path.lastSegment()}get ref(){return new cP(this._firestore,this._converter,this._key)}exists(){return null!==this._document}data(){if(this._document){if(this._converter){let e=new hO(this._firestore,this._userDataWriter,this._key,this._document,null);return this._converter.fromFirestore(e)}return this._userDataWriter.convertValue(this._document.data.value)}}get(e){if(this._document){let t=this._document.data.field(hP("DocumentSnapshot.get",e));if(null!==t)return this._userDataWriter.convertValue(t)}}}class hO extends hD{data(){return super.data()}}function hP(e,t){return"string"==typeof t?hN(e,t):t instanceof hr?t._internalPath:t._delegate._internalPath}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function hL(e){if("L"===e.limitType&&0===e.explicitOrderBy.length)throw new rV(rU.UNIMPLEMENTED,"limitToLast() queries require specifying at least one orderBy() clause")}class hM{}function hj(e,...t){for(let n of t)e=n._apply(e);return e}class hF extends hM{constructor(e,t,n){super(),this.ma=e,this.ga=t,this.ya=n,this.type="where"}_apply(e){let t=hd(e.firestore),n=function(e,t,n,r,i,s,o){let a;if(i.isKeyField()){if("array-contains"===s||"array-contains-any"===s)throw new rV(rU.INVALID_ARGUMENT,`Invalid Query. You can't perform '${s}' queries on documentId().`);if("in"===s||"not-in"===s){hG(o,s);let l=[];for(let u of o)l.push(hz(r,e,u));a={arrayValue:{values:l}}}else a=hz(r,e,o)}else"in"!==s&&"not-in"!==s&&"array-contains-any"!==s||hG(o,s),a=hI(n,t,o,"in"===s||"not-in"===s);let c=su.create(i,s,a);return function(e,t){if(t.dt()){let n=sk(e);if(null!==n&&!n.isEqual(t.field))throw new rV(rU.INVALID_ARGUMENT,`Invalid query. All where filters with an inequality (<, <=, !=, not-in, >, or >=) must be on the same field. But you have inequality filters on '${n.toString()}' and '${t.field.toString()}'`);let r=sS(e);null!==r&&hW(e,t.field,r)}let i=function(e,t){for(let n of e.filters)if(t.indexOf(n.op)>=0)return n.op;return null}(e,function(e){switch(e){case"!=":return["!=","not-in"];case"array-contains":return["array-contains","array-contains-any","not-in"];case"in":return["array-contains-any","in","not-in"];case"array-contains-any":return["array-contains","array-contains-any","in","not-in"];case"not-in":return["array-contains","array-contains-any","in","not-in","!="];default:return[]}}(t.op));if(null!==i)throw i===t.op?new rV(rU.INVALID_ARGUMENT,`Invalid query. You cannot use more than one '${t.op.toString()}' filter.`):new rV(rU.INVALID_ARGUMENT,`Invalid query. You cannot use '${t.op.toString()}' filters with '${i.toString()}' filters.`)}(e,c),c}(e._query,"where",t,e.firestore._databaseId,this.ma,this.ga,this.ya);return new cL(e.firestore,e.converter,function(e,t){let n=e.filters.concat([t]);return new sI(e.path,e.collectionGroup,e.explicitOrderBy.slice(),n,e.limit,e.limitType,e.startAt,e.endAt)}(e._query,n))}}class hU extends hM{constructor(e,t){super(),this.ma=e,this.pa=t,this.type="orderBy"}_apply(e){let t=function(e,t,n){if(null!==e.startAt)throw new rV(rU.INVALID_ARGUMENT,"Invalid query. You must not call startAt() or startAfter() before calling orderBy().");if(null!==e.endAt)throw new rV(rU.INVALID_ARGUMENT,"Invalid query. You must not call endAt() or endBefore() before calling orderBy().");let r=new s_(t,n);return function(e,t){if(null===sS(e)){let n=sk(e);null!==n&&hW(e,n,t.field)}}(e,r),r}(e._query,this.ma,this.pa);return new cL(e.firestore,e.converter,function(e,t){let n=e.explicitOrderBy.concat([t]);return new sI(e.path,e.collectionGroup,n,e.filters.slice(),e.limit,e.limitType,e.startAt,e.endAt)}(e._query,t))}}class hV extends hM{constructor(e,t,n){super(),this.type=e,this.Ia=t,this.Ta=n}_apply(e){return new cL(e.firestore,e.converter,sA(e._query,this.Ia,this.Ta))}}class hq extends hM{constructor(e,t,n){super(),this.type=e,this.Ea=t,this.Aa=n}_apply(e){var t;let n=h$(e,this.type,this.Ea,this.Aa);return new cL(e.firestore,e.converter,(t=e._query,new sI(t.path,t.collectionGroup,t.explicitOrderBy.slice(),t.filters.slice(),t.limit,t.limitType,n,t.endAt)))}}class hB extends hM{constructor(e,t,n){super(),this.type=e,this.Ea=t,this.Aa=n}_apply(e){var t;let n=h$(e,this.type,this.Ea,this.Aa);return new cL(e.firestore,e.converter,(t=e._query,new sI(t.path,t.collectionGroup,t.explicitOrderBy.slice(),t.filters.slice(),t.limit,t.limitType,t.startAt,n)))}}function h$(e,t,n,r){if(n[0]=(0,S.m9)(n[0]),n[0]instanceof hD)return function(e,t,n,r,i){if(!r)throw new rV(rU.NOT_FOUND,`Can't use a DocumentSnapshot that doesn't exist for ${n}().`);let s=[];for(let o of sC(e))if(o.field.isKeyField())s.push(iZ(t,r.key));else{let a=r.data.field(o.field);if(iF(a))throw new rV(rU.INVALID_ARGUMENT,'Invalid query. You are trying to start or end a query using a document for which the field "'+o.field+'" is an uncommitted server timestamp. (Since the value of this field is unknown, you cannot start/end a query with it.)');if(null===a){let l=o.field.canonicalString();throw new rV(rU.INVALID_ARGUMENT,`Invalid query. You are trying to start or end a query using a document for which the field '${l}' (used as the orderBy) does not exist.`)}s.push(a)}return new sv(s,i)}(e._query,e.firestore._databaseId,t,n[0]._document,r);{let i=hd(e.firestore);return function(e,t,n,r,i,s){let o=e.explicitOrderBy;if(i.length>o.length)throw new rV(rU.INVALID_ARGUMENT,`Too many arguments provided to ${r}(). The number of arguments must be less than or equal to the number of orderBy() clauses`);let a=[];for(let l=0;l<i.length;l++){let u=i[l];if(o[l].field.isKeyField()){if("string"!=typeof u)throw new rV(rU.INVALID_ARGUMENT,`Invalid query. Expected a string for document ID in ${r}(), but got a ${typeof u}`);if(!sx(e)&&-1!==u.indexOf("/"))throw new rV(rU.INVALID_ARGUMENT,`Invalid query. When querying a collection and ordering by documentId(), the value passed to ${r}() must be a plain document ID, but '${u}' contains a slash.`);let c=e.path.child(r2.fromString(u));if(!r6.isDocumentKey(c))throw new rV(rU.INVALID_ARGUMENT,`Invalid query. When querying a collection group and ordering by documentId(), the value passed to ${r}() must result in a valid document path, but '${c}' is not because it contains an odd number of segments.`);let h=new r6(c);a.push(iZ(t,h))}else{let d=hI(n,r,u);a.push(d)}}return new sv(a,s)}(e._query,e.firestore._databaseId,i,t,n,r)}}function hz(e,t,n){if("string"==typeof(n=(0,S.m9)(n))){if(""===n)throw new rV(rU.INVALID_ARGUMENT,"Invalid query. When querying with documentId(), you must provide a valid document ID, but it was an empty string.");if(!sx(t)&&-1!==n.indexOf("/"))throw new rV(rU.INVALID_ARGUMENT,`Invalid query. When querying a collection by documentId(), you must provide a plain document ID, but '${n}' contains a '/' character.`);let r=t.path.child(r2.fromString(n));if(!r6.isDocumentKey(r))throw new rV(rU.INVALID_ARGUMENT,`Invalid query. When querying a collection group by documentId(), the value provided must result in a valid document path, but '${r}' is not because it has an odd number of segments (${r.length}).`);return iZ(e,new r6(r))}if(n instanceof cP)return iZ(e,n._key);throw new rV(rU.INVALID_ARGUMENT,`Invalid query. When querying with documentId(), you must provide a valid string or a DocumentReference, but it was: ${cC(n)}.`)}function hG(e,t){if(!Array.isArray(e)||0===e.length)throw new rV(rU.INVALID_ARGUMENT,`Invalid Query. A non-empty array is required for '${t.toString()}' filters.`);if(e.length>10)throw new rV(rU.INVALID_ARGUMENT,`Invalid Query. '${t.toString()}' filters support a maximum of 10 elements in the value array.`)}function hW(e,t,n){if(!n.isEqual(t))throw new rV(rU.INVALID_ARGUMENT,`Invalid query. You have a where filter with an inequality (<, <=, !=, not-in, >, or >=) on field '${t.toString()}' and so you must also use '${t.toString()}' as your first argument to orderBy(), but your first orderBy() is on field '${n.toString()}' instead.`)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class hH{convertValue(e,t="none"){switch(iH(e)){case 0:return null;case 1:return e.booleanValue;case 2:return iM(e.integerValue||e.doubleValue);case 3:return this.convertTimestamp(e.timestampValue);case 4:return this.convertServerTimestamp(e,t);case 5:return e.stringValue;case 6:return this.convertBytes(ij(e.bytesValue));case 7:return this.convertReference(e.referenceValue);case 8:return this.convertGeoPoint(e.geoPointValue);case 9:return this.convertArray(e.arrayValue,t);case 10:return this.convertObject(e.mapValue,t);default:throw rF()}}convertObject(e,t){let n={};return iE(e.fields,(e,r)=>{n[e]=this.convertValue(r,t)}),n}convertGeoPoint(e){return new hs(iM(e.latitude),iM(e.longitude))}convertArray(e,t){return(e.values||[]).map(e=>this.convertValue(e,t))}convertServerTimestamp(e,t){switch(t){case"previous":let n=function e(t){let n=t.mapValue.fields.__previous_value__;return iF(n)?e(n):n}(e);return null==n?null:this.convertValue(n,t);case"estimate":return this.convertTimestamp(iU(e));default:return null}}convertTimestamp(e){let t=iL(e);return new rZ(t.seconds,t.nanos)}convertDocumentKey(e,t){let n=r2.fromString(e);oW(n)||rF();let r=new iq(n.get(1),n.get(3)),i=new r6(n.popFirst(5));return r.isEqual(t)||rL(`Document ${i} contains a document reference within a different database (${r.projectId}/${r.database}) which is not supported. It will be treated as a reference in the current database (${t.projectId}/${t.database}) instead.`),i}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function hK(e,t,n){return e?n&&(n.merge||n.mergeFields)?e.toFirestore(t,n):e.toFirestore(t):t}class hQ extends hH{constructor(e){super(),this.firestore=e}convertBytes(e){return new hn(e)}convertReference(e){let t=this.convertDocumentKey(e,this.firestore._databaseId);return new cP(this.firestore,null,t)}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class hY{constructor(e,t){this.hasPendingWrites=e,this.fromCache=t}isEqual(e){return this.hasPendingWrites===e.hasPendingWrites&&this.fromCache===e.fromCache}}class hX extends hD{constructor(e,t,n,r,i,s){super(e,t,n,r,s),this._firestore=e,this._firestoreImpl=e,this.metadata=i}exists(){return super.exists()}data(e={}){if(this._document){if(this._converter){let t=new hJ(this._firestore,this._userDataWriter,this._key,this._document,this.metadata,null);return this._converter.fromFirestore(t,e)}return this._userDataWriter.convertValue(this._document.data.value,e.serverTimestamps)}}get(e,t={}){if(this._document){let n=this._document.data.field(hP("DocumentSnapshot.get",e));if(null!==n)return this._userDataWriter.convertValue(n,t.serverTimestamps)}}}class hJ extends hX{data(e={}){return super.data(e)}}class hZ{constructor(e,t,n,r){this._firestore=e,this._userDataWriter=t,this._snapshot=r,this.metadata=new hY(r.hasPendingWrites,r.fromCache),this.query=n}get docs(){let e=[];return this.forEach(t=>e.push(t)),e}get size(){return this._snapshot.docs.size}get empty(){return 0===this.size}forEach(e,t){this._snapshot.docs.forEach(n=>{e.call(t,new hJ(this._firestore,this._userDataWriter,n.key,n,new hY(this._snapshot.mutatedKeys.has(n.key),this._snapshot.fromCache),this.query.converter))})}docChanges(e={}){let t=!!e.includeMetadataChanges;if(t&&this._snapshot.excludesMetadataChanges)throw new rV(rU.INVALID_ARGUMENT,"To include metadata changes with your document changes, you must also pass { includeMetadataChanges:true } to onSnapshot().");return this._cachedChanges&&this._cachedChangesIncludeMetadataChanges===t||(this._cachedChanges=function(e,t){if(e._snapshot.oldDocs.isEmpty()){let n=0;return e._snapshot.docChanges.map(t=>({type:"added",doc:new hJ(e._firestore,e._userDataWriter,t.doc.key,t.doc,new hY(e._snapshot.mutatedKeys.has(t.doc.key),e._snapshot.fromCache),e.query.converter),oldIndex:-1,newIndex:n++}))}{let r=e._snapshot.oldDocs;return e._snapshot.docChanges.filter(e=>t||3!==e.type).map(t=>{let n=new hJ(e._firestore,e._userDataWriter,t.doc.key,t.doc,new hY(e._snapshot.mutatedKeys.has(t.doc.key),e._snapshot.fromCache),e.query.converter),i=-1,s=-1;return 0!==t.type&&(i=r.indexOf(t.doc.key),r=r.delete(t.doc.key)),1!==t.type&&(s=(r=r.add(t.doc)).indexOf(t.doc.key)),{type:function(e){switch(e){case 0:return"added";case 2:case 3:return"modified";case 1:return"removed";default:return rF()}}(t.type),doc:n,oldIndex:i,newIndex:s}})}}(this,t),this._cachedChangesIncludeMetadataChanges=t),this._cachedChanges}}function h0(e,t){return e instanceof hX&&t instanceof hX?e._firestore===t._firestore&&e._key.isEqual(t._key)&&(null===e._document?null===t._document:e._document.isEqual(t._document))&&e._converter===t._converter:e instanceof hZ&&t instanceof hZ&&e._firestore===t._firestore&&cV(e.query,t.query)&&e.metadata.isEqual(t.metadata)&&e._snapshot.isEqual(t._snapshot)}class h1 extends hH{constructor(e){super(),this.firestore=e}convertBytes(e){return new hn(e)}convertReference(e){let t=this.convertDocumentKey(e,this.firestore._databaseId);return new cP(this.firestore,null,t)}}function h2(e,t,n){e=cN(e,cP);let r=cN(e.firestore,c8),i=hK(e.converter,t,n);return h6(r,[hf(hd(r),"setDoc",e._key,i,null!==e.converter,n).toMutation(e._key,sJ.none())])}function h3(e,t,n,...r){let i;e=cN(e,cP);let s=cN(e.firestore,c8),o=hd(s);return i="string"==typeof(t=(0,S.m9)(t))||t instanceof hr?hb(o,"updateDoc",e._key,t,n,r):hw(o,"updateDoc",e._key,t),h6(s,[i.toMutation(e._key,sJ.exists(!0))])}function h4(e,...t){var n,r,i;let s,o,a;e=(0,S.m9)(e);let l={includeMetadataChanges:!1},u=0;"object"!=typeof t[0]||c6(t[u])||(l=t[u],u++);let c={includeMetadataChanges:l.includeMetadataChanges};if(c6(t[u])){let h=t[u];t[u]=null===(n=h.next)||void 0===n?void 0:n.bind(h),t[u+1]=null===(r=h.error)||void 0===r?void 0:r.bind(h),t[u+2]=null===(i=h.complete)||void 0===i?void 0:i.bind(h)}if(e instanceof cP)o=cN(e.firestore,c8),a=sT(e._key.path),s={next:n=>{t[u]&&t[u](h5(o,e,n))},error:t[u+1],complete:t[u+2]};else{let d=cN(e,cL);o=cN(d.firestore,c8),a=d._query;let f=new h1(o);s={next:e=>{t[u]&&t[u](new hZ(o,f,d,e))},error:t[u+1],complete:t[u+2]},hL(e._query)}return function(e,t,n,r){let i=new cB(r),s=new u$(t,i,n);return e.asyncQueue.enqueueAndForget(async()=>uF(await c1(e),s)),()=>{i.bc(),e.asyncQueue.enqueueAndForget(async()=>uU(await c1(e),s))}}(c9(o),a,c,s)}function h6(e,t){return function(e,t){let n=new rq;return e.asyncQueue.enqueueAndForget(async()=>u3(await c0(e),t,n)),n.promise}(c9(e),t)}function h5(e,t,n){let r=n.docs.get(t._key),i=new h1(e);return new hX(e,i,t._key,r,new hY(n.hasPendingWrites,n.fromCache),t.converter)}/**
 * @license
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let h8={maxAttempts:5};/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class h9{constructor(e,t){this._firestore=e,this._commitHandler=t,this._mutations=[],this._committed=!1,this._dataReader=hd(e)}set(e,t,n){this._verifyNotCommitted();let r=h7(e,this._firestore),i=hK(r.converter,t,n),s=hf(this._dataReader,"WriteBatch.set",r._key,i,null!==r.converter,n);return this._mutations.push(s.toMutation(r._key,sJ.none())),this}update(e,t,n,...r){let i;this._verifyNotCommitted();let s=h7(e,this._firestore);return i="string"==typeof(t=(0,S.m9)(t))||t instanceof hr?hb(this._dataReader,"WriteBatch.update",s._key,t,n,r):hw(this._dataReader,"WriteBatch.update",s._key,t),this._mutations.push(i.toMutation(s._key,sJ.exists(!0))),this}delete(e){this._verifyNotCommitted();let t=h7(e,this._firestore);return this._mutations=this._mutations.concat(new s7(t._key,sJ.none())),this}commit(){return this._verifyNotCommitted(),this._committed=!0,this._mutations.length>0?this._commitHandler(this._mutations):Promise.resolve()}_verifyNotCommitted(){if(this._committed)throw new rV(rU.FAILED_PRECONDITION,"A write batch can no longer be used after commit() has been called.")}}function h7(e,t){if((e=(0,S.m9)(e)).firestore!==t)throw new rV(rU.INVALID_ARGUMENT,"Provided document reference is from a different Firestore instance.");return e}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *//**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class de extends class{constructor(e,t){this._firestore=e,this._transaction=t,this._dataReader=hd(e)}get(e){let t=h7(e,this._firestore),n=new hQ(this._firestore);return this._transaction.lookup([t._key]).then(e=>{if(!e||1!==e.length)return rF();let r=e[0];if(r.isFoundDocument())return new hD(this._firestore,n,r.key,r,t.converter);if(r.isNoDocument())return new hD(this._firestore,n,t._key,null,t.converter);throw rF()})}set(e,t,n){let r=h7(e,this._firestore),i=hK(r.converter,t,n),s=hf(this._dataReader,"Transaction.set",r._key,i,null!==r.converter,n);return this._transaction.set(r._key,s),this}update(e,t,n,...r){let i;let s=h7(e,this._firestore);return i="string"==typeof(t=(0,S.m9)(t))||t instanceof hr?hb(this._dataReader,"Transaction.update",s._key,t,n,r):hw(this._dataReader,"Transaction.update",s._key,t),this._transaction.update(s._key,i),this}delete(e){let t=h7(e,this._firestore);return this._transaction.delete(t._key),this}}{constructor(e,t){super(e,t),this._firestore=e}get(e){let t=h7(e,this._firestore),n=new h1(this._firestore);return super.get(e).then(e=>new hX(this._firestore,n,t._key,e._document,new hY(!1,!1),t.converter))}}/**
 * @license
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function dt(e,t){if(void 0===t)return{merge:!1};if(void 0!==t.mergeFields&&void 0!==t.merge)throw new rV("invalid-argument",`Invalid options passed to function ${e}(): You cannot specify both "merge" and "mergeFields".`);return t}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function dn(){if("undefined"==typeof Uint8Array)throw new rV("unimplemented","Uint8Arrays are not available in this environment.")}function dr(){if(!("undefined"!=typeof atob))throw new rV("unimplemented","Blobs are unavailable in Firestore in this environment.")}!function(e,t=!0){rR=x.SDK_VERSION,(0,x._registerComponent)(new k.wA("firestore",(e,{instanceIdentifier:n,options:r})=>{let i=e.getProvider("app").getImmediate(),s=new c8(new rG(e.getProvider("auth-internal")),new rQ(e.getProvider("app-check-internal")),function(e,t){if(!Object.prototype.hasOwnProperty.apply(e.options,["projectId"]))throw new rV(rU.INVALID_ARGUMENT,'"projectId" not provided in firebase.initializeApp.');return new iq(e.options.projectId,t)}(i,n),i);return r=Object.assign({useFetchStreams:t},r),s._setSettings(r),s},"PUBLIC").setMultipleInstances(!0)),(0,x.registerVersion)(rN,"3.7.1",void 0),(0,x.registerVersion)(rN,"3.7.1","esm2017")}();class di{constructor(e){this._delegate=e}static fromBase64String(e){return dr(),new di(hn.fromBase64String(e))}static fromUint8Array(e){return dn(),new di(hn.fromUint8Array(e))}toBase64(){return dr(),this._delegate.toBase64()}toUint8Array(){return dn(),this._delegate.toUint8Array()}isEqual(e){return this._delegate.isEqual(e._delegate)}toString(){return"Blob(base64: "+this.toBase64()+")"}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function ds(e){return function(e,t){if("object"!=typeof e||null===e)return!1;for(let n of t)if(n in e&&"function"==typeof e[n])return!0;return!1}(e,["next","error","complete"])}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class da{enableIndexedDbPersistence(e,t){return function(e,t){ht(e=cN(e,c8));let n=c9(e),r=e._freezeSettings(),i=new cT;return he(n,i,new cb(i,r.cacheSizeBytes,null==t?void 0:t.forceOwnership))}(e._delegate,{forceOwnership:t})}enableMultiTabIndexedDbPersistence(e){return function(e){ht(e=cN(e,c8));let t=c9(e),n=e._freezeSettings(),r=new cT;return he(t,r,new cI(r,n.cacheSizeBytes))}(e._delegate)}clearIndexedDbPersistence(e){return function(e){if(e._initialized&&!e._terminated)throw new rV(rU.FAILED_PRECONDITION,"Persistence can only be cleared before a Firestore instance is initialized or after it is terminated.");let t=new rq;return e._queue.enqueueAndForgetEvenWhileRestricted(async()=>{try{await async function(e){if(!ih.C())return Promise.resolve();await ih.delete(e+"main")}(lA(e._databaseId,e._persistenceKey)),t.resolve()}catch(n){t.reject(n)}}),t.promise}(e._delegate)}}class dl{constructor(e,t,n){this._delegate=t,this._persistenceProvider=n,this.INTERNAL={delete:()=>this.terminate()},e instanceof iq||(this._appCompat=e)}get _databaseId(){return this._delegate._databaseId}settings(e){let t=this._delegate._getSettings();e.merge||t.host===e.host||rM("You are overriding the original host. If you did not intend to override your settings, use {merge: true}."),e.merge&&delete(e=Object.assign(Object.assign({},t),e)).merge,this._delegate._setSettings(e)}useEmulator(e,t,n={}){!function(e,t,n,r={}){var i;let s=(e=cN(e,cO))._getSettings();if("firestore.googleapis.com"!==s.host&&s.host!==t&&rM("Host has been set in both settings() and useEmulator(), emulator host will be used"),e._setSettings(Object.assign(Object.assign({},s),{host:`${t}:${n}`,ssl:!1})),r.mockUserToken){let o,a;if("string"==typeof r.mockUserToken)o=r.mockUserToken,a=rA.MOCK_USER;else{o=(0,S.Sg)(r.mockUserToken,null===(i=e._app)||void 0===i?void 0:i.options.projectId);let l=r.mockUserToken.sub||r.mockUserToken.user_id;if(!l)throw new rV(rU.INVALID_ARGUMENT,"mockUserToken must contain 'sub' or 'user_id' field!");a=new rA(l)}e._authCredentials=new rz(new rB(o,a))}}(this._delegate,e,t,n)}enableNetwork(){var e;return(e=c9(cN(this._delegate,c8))).asyncQueue.enqueue(async()=>{let t=await cX(e),n=await cZ(e);return t.setNetworkEnabled(!0),n.wu.delete(0),uo(n)})}disableNetwork(){var e;return(e=c9(cN(this._delegate,c8))).asyncQueue.enqueue(async()=>{let t=await cX(e),n=await cZ(e);return t.setNetworkEnabled(!1),async function(e){e.wu.add(0),await ua(e),e.yu.set("Offline")}(n)})}enablePersistence(e){let t=!1,n=!1;return e&&cS("synchronizeTabs",t=!!e.synchronizeTabs,"experimentalForceOwningTab",n=!!e.experimentalForceOwningTab),t?this._persistenceProvider.enableMultiTabIndexedDbPersistence(this):this._persistenceProvider.enableIndexedDbPersistence(this,n)}clearPersistence(){return this._persistenceProvider.clearIndexedDbPersistence(this)}terminate(){return this._appCompat&&(this._appCompat._removeServiceInstance("firestore-compat"),this._appCompat._removeServiceInstance("firestore")),this._delegate._delete()}waitForPendingWrites(){return function(e){let t=new rq;return e.asyncQueue.enqueueAndForget(async()=>u7(await c0(e),t)),t.promise}(c9(cN(this._delegate,c8)))}onSnapshotsInSync(e){var t;return function(e,t){let n=new cB(t);return e.asyncQueue.enqueueAndForget(async()=>{(await c1(e)).bu.add(n),n.next()}),()=>{n.bc(),e.asyncQueue.enqueueAndForget(async()=>(function(e,t){e.bu.delete(t)})(await c1(e),n))}}(c9(cN(this._delegate,c8)),c6(e)?e:{next:e})}get app(){if(!this._appCompat)throw new rV("failed-precondition","Firestore was not initialized using the Firebase SDK. 'app' is not available");return this._appCompat}collection(e){try{return new dI(this,cj(this._delegate,e))}catch(t){throw dp(t,"collection()","Firestore.collection()")}}doc(e){try{return new df(this,cF(this._delegate,e))}catch(t){throw dp(t,"doc()","Firestore.doc()")}}collectionGroup(e){try{return new d_(this,function(e,t){if(e=cN(e,cO),cE("collectionGroup","collection id",t),t.indexOf("/")>=0)throw new rV(rU.INVALID_ARGUMENT,`Invalid collection ID '${t}' passed to function collectionGroup(). Collection IDs must not contain '/'.`);return new cL(e,null,new sI(r2.emptyPath(),t))}(this._delegate,e))}catch(t){throw dp(t,"collectionGroup()","Firestore.collectionGroup()")}}runTransaction(e){return function(e,t,n){e=cN(e,c8);let r=Object.assign(Object.assign({},h8),void 0);return!function(e){if(e.maxAttempts<1)throw new rV(rU.INVALID_ARGUMENT,"Max attempts must be at least 1")}(r),function(e,t,n){let r=new rq;return e.asyncQueue.enqueueAndForget(async()=>{let i=await cY(e).then(e=>e.datastore);new cG(e.asyncQueue,i,n,t,r).run()}),r.promise}(c9(e),n=>t(new de(e,n)),r)}(this._delegate,t=>e(new dc(this,t)))}batch(){return c9(this._delegate),new dh(new h9(this._delegate,e=>h6(this._delegate,e)))}loadBundle(e){return function(e,t){let n=c9(e=cN(e,c8)),r=new c5;return function(e,t,n,r){var i,s;let o=(i=l9(t),s=function(e,t){if(e instanceof Uint8Array)return cq(e,t);if(e instanceof ArrayBuffer)return cq(new Uint8Array(e),t);if(e instanceof ReadableStream)return e.getReader();throw Error("Source of `toByteStreamReader` has to be a ArrayBuffer or ReadableStream")}("string"==typeof n?(new TextEncoder).encode(n):n),new c$(s,i));e.asyncQueue.enqueueAndForget(async()=>{!function(e,t,n){(async function(e,t,n){try{var r;let i=await t.getMetadata();if(await function(e,t){let n=oC(t.createTime);return e.persistence.runTransaction("hasNewerBundle","readonly",n=>e.Ns.getBundleMetadata(n,t.id)).then(e=>!!e&&e.createTime.compareTo(n)>=0)}(e.localStore,i))return await t.close(),n._completeWith({taskState:"Success",documentsLoaded:i.totalDocuments,bytesLoaded:i.totalBytes,totalDocuments:i.totalDocuments,totalBytes:i.totalBytes}),Promise.resolve(new Set);n._updateProgress(uH(i));let s=new uW(i,e.localStore,t.It),o=await t.mc();for(;o;){let a=await s.Fu(o);a&&n._updateProgress(a),o=await t.mc()}let l=await s.complete();return await co(e,l.Lu,void 0),await (r=e.localStore).persistence.runTransaction("Save bundle","readwrite",e=>r.Ns.saveBundleMetadata(e,i)),n._completeWith(l.progress),Promise.resolve(l.Bu)}catch(u){return rM("SyncEngine",`Loading bundle failed with ${u}`),n._failWith(u),Promise.resolve(new Set)}})(e,t,n).then(t=>{e.sharedClientState.notifyBundleLoaded(t)})}(await c0(e),o,r)})}(n,e._databaseId,t,r),r}(this._delegate,e)}namedQuery(e){var t,n;return(n=c9(t=cN(t=this._delegate,c8))).asyncQueue.enqueue(async()=>{var t;return(t=await cJ(n)).persistence.runTransaction("Get named query","readonly",n=>t.Ns.getNamedQuery(n,e))}).then(e=>e?new cL(t,null,e.query):null).then(e=>e?new d_(this,e):null)}}class du extends hH{constructor(e){super(),this.firestore=e}convertBytes(e){return new di(new hn(e))}convertReference(e){let t=this.convertDocumentKey(e,this.firestore._databaseId);return df.forKey(t,this.firestore,null)}}class dc{constructor(e,t){this._firestore=e,this._delegate=t,this._userDataWriter=new du(e)}get(e){let t=cN(e,cP);return this._delegate.get(t).then(e=>new dy(this._firestore,new hX(this._firestore._delegate,this._userDataWriter,e._key,e._document,e.metadata,t.converter)))}set(e,t,n){let r=cN(e,cP);return n?(dt("Transaction.set",n),this._delegate.set(r,t,n)):this._delegate.set(r,t),this}update(e,t,n,...r){let i=cN(e,cP);return 2==arguments.length?this._delegate.update(i,t):this._delegate.update(i,t,n,...r),this}delete(e){let t=cN(e,cP);return this._delegate.delete(t),this}}class dh{constructor(e){this._delegate=e}set(e,t,n){let r=cN(e,cP);return n?(dt("WriteBatch.set",n),this._delegate.set(r,t,n)):this._delegate.set(r,t),this}update(e,t,n,...r){let i=cN(e,cP);return 2==arguments.length?this._delegate.update(i,t):this._delegate.update(i,t,n,...r),this}delete(e){let t=cN(e,cP);return this._delegate.delete(t),this}commit(){return this._delegate.commit()}}class dd{constructor(e,t,n){this._firestore=e,this._userDataWriter=t,this._delegate=n}fromFirestore(e,t){let n=new hJ(this._firestore._delegate,this._userDataWriter,e._key,e._document,e.metadata,null);return this._delegate.fromFirestore(new dv(this._firestore,n),null!=t?t:{})}toFirestore(e,t){return t?this._delegate.toFirestore(e,t):this._delegate.toFirestore(e)}static getInstance(e,t){let n=dd.INSTANCES,r=n.get(e);r||(r=new WeakMap,n.set(e,r));let i=r.get(t);return i||(i=new dd(e,new du(e),t),r.set(t,i)),i}}dd.INSTANCES=new WeakMap;class df{constructor(e,t){this.firestore=e,this._delegate=t,this._userDataWriter=new du(e)}static forPath(e,t,n){if(e.length%2!=0)throw new rV("invalid-argument",`Invalid document reference. Document references must have an even number of segments, but ${e.canonicalString()} has ${e.length}`);return new df(t,new cP(t._delegate,n,new r6(e)))}static forKey(e,t,n){return new df(t,new cP(t._delegate,n,e))}get id(){return this._delegate.id}get parent(){return new dI(this.firestore,this._delegate.parent)}get path(){return this._delegate.path}collection(e){try{return new dI(this.firestore,cj(this._delegate,e))}catch(t){throw dp(t,"collection()","DocumentReference.collection()")}}isEqual(e){return(e=(0,S.m9)(e))instanceof cP&&cU(this._delegate,e)}set(e,t){t=dt("DocumentReference.set",t);try{if(t)return h2(this._delegate,e,t);return h2(this._delegate,e)}catch(n){throw dp(n,"setDoc()","DocumentReference.set()")}}update(e,t,...n){try{if(1==arguments.length)return h3(this._delegate,e);return h3(this._delegate,e,t,...n)}catch(r){throw dp(r,"updateDoc()","DocumentReference.update()")}}delete(){var e;return h6(cN((e=this._delegate).firestore,c8),[new s7(e._key,sJ.none())])}onSnapshot(...e){let t=dm(e),n=dg(e,e=>new dy(this.firestore,new hX(this.firestore._delegate,this._userDataWriter,e._key,e._document,e.metadata,this._delegate.converter)));return h4(this._delegate,t,n)}get(e){return((null==e?void 0:e.source)==="cache"?function(e){e=cN(e,cP);let t=cN(e.firestore,c8),n=c9(t),r=new h1(t);return(function(e,t){let n=new rq;return e.asyncQueue.enqueueAndForget(async()=>(async function(e,t,n){try{let r=await e.persistence.runTransaction("read document","readonly",n=>e.localDocuments.getDocument(n,t));r.isFoundDocument()?n.resolve(r):r.isNoDocument()?n.resolve(null):n.reject(new rV(rU.UNAVAILABLE,"Failed to get document from cache. (However, this document may exist on the server. Run again without setting 'source' in the GetOptions to attempt to retrieve the document from the server.)"))}catch(s){let i=uD(s,`Failed to get document '${t} from cache`);n.reject(i)}})(await cJ(e),t,n)),n.promise})(n,e._key).then(n=>new hX(t,r,e._key,n,new hY(null!==n&&n.hasLocalMutations,!0),e.converter))}(this._delegate):(null==e?void 0:e.source)==="server"?function(e){e=cN(e,cP);let t=cN(e.firestore,c8);return c2(c9(t),e._key,{source:"server"}).then(n=>h5(t,e,n))}(this._delegate):/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function(e){e=cN(e,cP);let t=cN(e.firestore,c8);return c2(c9(t),e._key).then(n=>h5(t,e,n))}(this._delegate)).then(e=>new dy(this.firestore,new hX(this.firestore._delegate,this._userDataWriter,e._key,e._document,e.metadata,this._delegate.converter)))}withConverter(e){return new df(this.firestore,e?this._delegate.withConverter(dd.getInstance(this.firestore,e)):this._delegate.withConverter(null))}}function dp(e,t,n){return e.message=e.message.replace(t,n),e}function dm(e){for(let t of e)if("object"==typeof t&&!ds(t))return t;return{}}function dg(e,t){var n,r;let i;return{next:e=>{i.next&&i.next(t(e))},error:null===(n=(i=ds(e[0])?e[0]:ds(e[1])?e[1]:"function"==typeof e[0]?{next:e[0],error:e[1],complete:e[2]}:{next:e[1],error:e[2],complete:e[3]}).error)||void 0===n?void 0:n.bind(i),complete:null===(r=i.complete)||void 0===r?void 0:r.bind(i)}}class dy{constructor(e,t){this._firestore=e,this._delegate=t}get ref(){return new df(this._firestore,this._delegate.ref)}get id(){return this._delegate.id}get metadata(){return this._delegate.metadata}get exists(){return this._delegate.exists()}data(e){return this._delegate.data(e)}get(e,t){return this._delegate.get(e,t)}isEqual(e){return h0(this._delegate,e._delegate)}}class dv extends dy{data(e){let t=this._delegate.data(e);return void 0!==t||rF(),t}}class d_{constructor(e,t){this.firestore=e,this._delegate=t,this._userDataWriter=new du(e)}where(e,t,n){try{return new d_(this.firestore,hj(this._delegate,function(e,t,n){let r=hP("where",e);return new hF(r,t,n)}(e,t,n)))}catch(r){throw dp(r,/(orderBy|where)\(\)/,"Query.$1()")}}orderBy(e,t){try{return new d_(this.firestore,hj(this._delegate,function(e,t="asc"){let n=hP("orderBy",e);return new hU(n,t)}(e,t)))}catch(n){throw dp(n,/(orderBy|where)\(\)/,"Query.$1()")}}limit(e){try{return new d_(this.firestore,hj(this._delegate,(cA("limit",e),new hV("limit",e,"F"))))}catch(t){throw dp(t,"limit()","Query.limit()")}}limitToLast(e){try{return new d_(this.firestore,hj(this._delegate,(cA("limitToLast",e),new hV("limitToLast",e,"L"))))}catch(t){throw dp(t,"limitToLast()","Query.limitToLast()")}}startAt(...e){try{return new d_(this.firestore,hj(this._delegate,function(...e){return new hq("startAt",e,!0)}(...e)))}catch(t){throw dp(t,"startAt()","Query.startAt()")}}startAfter(...e){try{return new d_(this.firestore,hj(this._delegate,function(...e){return new hq("startAfter",e,!1)}(...e)))}catch(t){throw dp(t,"startAfter()","Query.startAfter()")}}endBefore(...e){try{return new d_(this.firestore,hj(this._delegate,function(...e){return new hB("endBefore",e,!1)}(...e)))}catch(t){throw dp(t,"endBefore()","Query.endBefore()")}}endAt(...e){try{return new d_(this.firestore,hj(this._delegate,function(...e){return new hB("endAt",e,!0)}(...e)))}catch(t){throw dp(t,"endAt()","Query.endAt()")}}isEqual(e){return cV(this._delegate,e._delegate)}get(e){return((null==e?void 0:e.source)==="cache"?function(e){e=cN(e,cL);let t=cN(e.firestore,c8),n=c9(t),r=new h1(t);return(function(e,t){let n=new rq;return e.asyncQueue.enqueueAndForget(async()=>(async function(e,t,n){try{let r=await lU(e,t,!0),i=new uY(t,r.Hi),s=i.Wu(r.documents),o=i.applyChanges(s,!1);n.resolve(o.snapshot)}catch(l){let a=uD(l,`Failed to execute query '${t} against cache`);n.reject(a)}})(await cJ(e),t,n)),n.promise})(n,e._query).then(n=>new hZ(t,r,e,n))}(this._delegate):(null==e?void 0:e.source)==="server"?function(e){e=cN(e,cL);let t=cN(e.firestore,c8),n=c9(t),r=new h1(t);return c3(n,e._query,{source:"server"}).then(n=>new hZ(t,r,e,n))}(this._delegate):function(e){e=cN(e,cL);let t=cN(e.firestore,c8),n=c9(t),r=new h1(t);return hL(e._query),c3(n,e._query).then(n=>new hZ(t,r,e,n))}(this._delegate)).then(e=>new db(this.firestore,new hZ(this.firestore._delegate,this._userDataWriter,this._delegate,e._snapshot)))}onSnapshot(...e){let t=dm(e),n=dg(e,e=>new db(this.firestore,new hZ(this.firestore._delegate,this._userDataWriter,this._delegate,e._snapshot)));return h4(this._delegate,t,n)}withConverter(e){return new d_(this.firestore,e?this._delegate.withConverter(dd.getInstance(this.firestore,e)):this._delegate.withConverter(null))}}class dw{constructor(e,t){this._firestore=e,this._delegate=t}get type(){return this._delegate.type}get doc(){return new dv(this._firestore,this._delegate.doc)}get oldIndex(){return this._delegate.oldIndex}get newIndex(){return this._delegate.newIndex}}class db{constructor(e,t){this._firestore=e,this._delegate=t}get query(){return new d_(this._firestore,this._delegate.query)}get metadata(){return this._delegate.metadata}get size(){return this._delegate.size}get empty(){return this._delegate.empty}get docs(){return this._delegate.docs.map(e=>new dv(this._firestore,e))}docChanges(e){return this._delegate.docChanges(e).map(e=>new dw(this._firestore,e))}forEach(e,t){this._delegate.forEach(n=>{e.call(t,new dv(this._firestore,n))})}isEqual(e){return h0(this._delegate,e._delegate)}}class dI extends d_{constructor(e,t){super(e,t),this.firestore=e,this._delegate=t}get id(){return this._delegate.id}get path(){return this._delegate.path}get parent(){let e=this._delegate.parent;return e?new df(this.firestore,e):null}doc(e){try{if(void 0===e)return new df(this.firestore,cF(this._delegate));return new df(this.firestore,cF(this._delegate,e))}catch(t){throw dp(t,"doc()","CollectionReference.doc()")}}add(e){return(function(e,t){let n=cN(e.firestore,c8),r=cF(e),i=hK(e.converter,t);return h6(n,[hf(hd(e.firestore),"addDoc",r._key,i,null!==e.converter,{}).toMutation(r._key,sJ.exists(!1))]).then(()=>r)})(this._delegate,e).then(e=>new df(this.firestore,e))}isEqual(e){return cU(this._delegate,e._delegate)}withConverter(e){return new dI(this.firestore,e?this._delegate.withConverter(dd.getInstance(this.firestore,e)):this._delegate.withConverter(null))}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class dT{constructor(...e){this._delegate=new hr(...e)}static documentId(){return new dT(r4.keyField().canonicalString())}isEqual(e){return(e=(0,S.m9)(e))instanceof hr&&this._delegate._internalPath.isEqual(e._internalPath)}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class dE{constructor(e){this._delegate=e}static serverTimestamp(){let e=new hg("serverTimestamp");return e._methodName="FieldValue.serverTimestamp",new dE(e)}static delete(){let e=new hp("deleteField");return e._methodName="FieldValue.delete",new dE(e)}static arrayUnion(...e){let t=function(...e){return new hy("arrayUnion",e)}(...e);return t._methodName="FieldValue.arrayUnion",new dE(t)}static arrayRemove(...e){let t=function(...e){return new hv("arrayRemove",e)}(...e);return t._methodName="FieldValue.arrayRemove",new dE(t)}static increment(e){let t=new h_("increment",e);return t._methodName="FieldValue.increment",new dE(t)}isEqual(e){return this._delegate.isEqual(e._delegate)}}/**
 * @license
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let dS={Firestore:dl,GeoPoint:hs,Timestamp:rZ,Blob:di,Transaction:dc,WriteBatch:dh,DocumentReference:df,DocumentSnapshot:dy,Query:d_,QueryDocumentSnapshot:dv,QuerySnapshot:db,CollectionReference:dI,FieldPath:dT,FieldValue:dE,setLogLevel:function(e){rD.setLogLevel(e)},CACHE_SIZE_UNLIMITED:-1};!function(e,t){e.INTERNAL.registerComponent(new k.wA("firestore-compat",e=>{let n=e.getProvider("app-compat").getImmediate(),r=e.getProvider("firestore").getImmediate();return t(n,r)},"PUBLIC").setServiceProps(Object.assign({},dS)))}(R,(e,t)=>new dl(e,t,new da)),R.registerVersion("@firebase/firestore-compat","0.2.1");/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let dk="firebasestorage.googleapis.com",dx="storageBucket";/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class dC extends S.ZR{constructor(e,t,n=0){super(dN(e),`Firebase Storage: ${t} (${dN(e)})`),this.status_=n,this.customData={serverResponse:null},this._baseMessage=this.message,Object.setPrototypeOf(this,dC.prototype)}get status(){return this.status_}set status(e){this.status_=e}_codeEquals(e){return dN(e)===this.code}get serverResponse(){return this.customData.serverResponse}set serverResponse(e){this.customData.serverResponse=e,this.customData.serverResponse?this.message=`${this._baseMessage}
${this.customData.serverResponse}`:this.message=this._baseMessage}}function dN(e){return"storage/"+e}function dA(){return new dC("unknown","An unknown error occurred, please check the error payload for server response.")}function dR(){return new dC("retry-limit-exceeded","Max retry time for operation exceeded, please try again.")}function dD(){return new dC("canceled","User canceled the upload/download.")}function dO(){return new dC("cannot-slice-blob","Cannot slice blob for upload. Please retry the upload.")}function dP(e){return new dC("invalid-argument",e)}function dL(){return new dC("app-deleted","The Firebase app was deleted.")}function dM(e){return new dC("invalid-root-operation","The operation '"+e+"' cannot be performed on a root reference, create a non-root reference using child, such as .child('file.png').")}function dj(e,t){return new dC("invalid-format","String does not match format '"+e+"': "+t)}function dF(e){throw new dC("internal-error","Internal error: "+e)}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class dU{constructor(e,t){this.bucket=e,this.path_=t}get path(){return this.path_}get isRoot(){return 0===this.path.length}fullServerUrl(){let e=encodeURIComponent;return"/b/"+e(this.bucket)+"/o/"+e(this.path)}bucketOnlyServerUrl(){let e=encodeURIComponent;return"/b/"+e(this.bucket)+"/o"}static makeFromBucketSpec(e,t){let n;try{n=dU.makeFromUrl(e,t)}catch(r){return new dU(e,"")}if(""===n.path)return n;throw new dC("invalid-default-bucket","Invalid default bucket '"+e+"'.")}static makeFromUrl(e,t){let n=null,r="([A-Za-z0-9.\\-_]+)",i=RegExp("^gs://"+r+"(/(.*))?$","i");function s(e){e.path_=decodeURIComponent(e.path)}let o=t.replace(/[.]/g,"\\."),a=RegExp(`^https?://${o}/v[A-Za-z0-9_]+/b/${r}/o(/([^?#]*).*)?$`,"i"),l=RegExp(`^https?://${t===dk?"(?:storage.googleapis.com|storage.cloud.google.com)":t}/${r}/([^?#]*)`,"i"),u=[{regex:i,indices:{bucket:1,path:3},postModify:function(e){"/"===e.path.charAt(e.path.length-1)&&(e.path_=e.path_.slice(0,-1))}},{regex:a,indices:{bucket:1,path:3},postModify:s},{regex:l,indices:{bucket:1,path:2},postModify:s}];for(let c=0;c<u.length;c++){let h=u[c],d=h.regex.exec(e);if(d){let f=d[h.indices.bucket],p=d[h.indices.path];p||(p=""),n=new dU(f,p),h.postModify(n);break}}if(null==n)throw new dC("invalid-url","Invalid URL '"+e+"'.");return n}}class dV{constructor(e){this.promise_=Promise.reject(e)}getPromise(){return this.promise_}cancel(e=!1){}}function dq(e){return"string"==typeof e||e instanceof String}function dB(e){return d$()&&e instanceof Blob}function d$(){return"undefined"!=typeof Blob}function dz(e,t,n,r){if(r<t)throw dP(`Invalid value for '${e}'. Expected ${t} or greater.`);if(r>n)throw dP(`Invalid value for '${e}'. Expected ${n} or less.`)}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function dG(e,t,n){let r=t;return null==n&&(r=`https://${t}`),`${n}://${r}/v0${e}`}function dW(e){let t=encodeURIComponent,n="?";for(let r in e)if(e.hasOwnProperty(r)){let i=t(r)+"="+t(e[r]);n=n+i+"&"}return n.slice(0,-1)}/**
 * @license
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function dH(e,t){let n=-1!==[408,429].indexOf(e),r=-1!==t.indexOf(e);return e>=500&&e<600||n||r}(m=T||(T={}))[m.NO_ERROR=0]="NO_ERROR",m[m.NETWORK_ERROR=1]="NETWORK_ERROR",m[m.ABORT=2]="ABORT";/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class dK{constructor(e,t,n,r,i,s,o,a,l,u,c,h=!0){this.url_=e,this.method_=t,this.headers_=n,this.body_=r,this.successCodes_=i,this.additionalRetryCodes_=s,this.callback_=o,this.errorCallback_=a,this.timeout_=l,this.progressCallback_=u,this.connectionFactory_=c,this.retry=h,this.pendingConnection_=null,this.backoffId_=null,this.canceled_=!1,this.appDelete_=!1,this.promise_=new Promise((e,t)=>{this.resolve_=e,this.reject_=t,this.start_()})}start_(){let e=(e,t)=>{if(t){e(!1,new dQ(!1,null,!0));return}let n=this.connectionFactory_();this.pendingConnection_=n;let r=e=>{let t=e.loaded,n=e.lengthComputable?e.total:-1;null!==this.progressCallback_&&this.progressCallback_(t,n)};null!==this.progressCallback_&&n.addUploadProgressListener(r),n.send(this.url_,this.method_,this.body_,this.headers_).then(()=>{null!==this.progressCallback_&&n.removeUploadProgressListener(r),this.pendingConnection_=null;let t=n.getErrorCode()===T.NO_ERROR,i=n.getStatus();if((!t||dH(i,this.additionalRetryCodes_))&&this.retry){let s=n.getErrorCode()===T.ABORT;e(!1,new dQ(!1,null,s));return}let o=-1!==this.successCodes_.indexOf(i);e(!0,new dQ(o,n))})},t=(e,t)=>{let n=this.resolve_,r=this.reject_,i=t.connection;if(t.wasSuccessCode)try{let s=this.callback_(i,i.getResponse());void 0!==s?n(s):n()}catch(o){r(o)}else if(null!==i){let a=dA();a.serverResponse=i.getErrorText(),r(this.errorCallback_?this.errorCallback_(i,a):a)}else if(t.canceled){let l=this.appDelete_?dL():dD();r(l)}else{let u=dR();r(u)}};this.canceled_?t(!1,new dQ(!1,null,!0)):this.backoffId_=/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function(e,t,n){let r=1,i=null,s=null,o=!1,a=0,l=!1;function u(...e){l||(l=!0,t.apply(null,e))}function c(t){i=setTimeout(()=>{i=null,e(d,2===a)},t)}function h(){s&&clearTimeout(s)}function d(e,...t){let n;if(l){h();return}if(e){h(),u.call(null,e,...t);return}let i=2===a||o;if(i){h(),u.call(null,e,...t);return}r<64&&(r*=2),1===a?(a=2,n=0):n=(r+Math.random())*1e3,c(n)}let f=!1;function p(e){!f&&(f=!0,h(),!l&&(null!==i?(e||(a=2),clearTimeout(i),c(0)):e||(a=1)))}return c(0),s=setTimeout(()=>{o=!0,p(!0)},n),p}(e,t,this.timeout_)}getPromise(){return this.promise_}cancel(e){this.canceled_=!0,this.appDelete_=e||!1,null!==this.backoffId_&&(0,this.backoffId_)(!1),null!==this.pendingConnection_&&this.pendingConnection_.abort()}}class dQ{constructor(e,t,n){this.wasSuccessCode=e,this.connection=t,this.canceled=!!n}}function dY(...e){let t="undefined"!=typeof BlobBuilder?BlobBuilder:"undefined"!=typeof WebKitBlobBuilder?WebKitBlobBuilder:void 0;if(void 0!==t){let n=new t;for(let r=0;r<e.length;r++)n.append(e[r]);return n.getBlob()}if(d$())return new Blob(e);throw new dC("unsupported-environment","This browser doesn't seem to support creating Blobs")}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let dX={RAW:"raw",BASE64:"base64",BASE64URL:"base64url",DATA_URL:"data_url"};class dJ{constructor(e,t){this.data=e,this.contentType=t||null}}function dZ(e,t){switch(e){case dX.RAW:return new dJ(d0(t));case dX.BASE64:case dX.BASE64URL:return new dJ(d1(e,t));case dX.DATA_URL:return new dJ(function(e){let t=new d2(e);return t.base64?d1(dX.BASE64,t.rest):function(e){let t;try{t=decodeURIComponent(e)}catch(n){throw dj(dX.DATA_URL,"Malformed data URL.")}return d0(t)}(t.rest)}(t),function(e){let t=new d2(e);return t.contentType}(t))}throw dA()}function d0(e){let t=[];for(let n=0;n<e.length;n++){let r=e.charCodeAt(n);if(r<=127)t.push(r);else if(r<=2047)t.push(192|r>>6,128|63&r);else if((64512&r)==55296){let i=n<e.length-1&&(64512&e.charCodeAt(n+1))==56320;if(i){let s=r,o=e.charCodeAt(++n);r=65536|(1023&s)<<10|1023&o,t.push(240|r>>18,128|r>>12&63,128|r>>6&63,128|63&r)}else t.push(239,191,189)}else(64512&r)==56320?t.push(239,191,189):t.push(224|r>>12,128|r>>6&63,128|63&r)}return new Uint8Array(t)}function d1(e,t){let n;switch(e){case dX.BASE64:{let r=-1!==t.indexOf("-"),i=-1!==t.indexOf("_");if(r||i)throw dj(e,"Invalid character '"+(r?"-":"_")+"' found: is it base64url encoded?");break}case dX.BASE64URL:{let s=-1!==t.indexOf("+"),o=-1!==t.indexOf("/");if(s||o)throw dj(e,"Invalid character '"+(s?"+":"/")+"' found: is it base64 encoded?");t=t.replace(/-/g,"+").replace(/_/g,"/")}}try{var a;a=t,n=atob(a)}catch(l){throw dj(e,"Invalid character found")}let u=new Uint8Array(n.length);for(let c=0;c<n.length;c++)u[c]=n.charCodeAt(c);return u}class d2{constructor(e){this.base64=!1,this.contentType=null;let t=e.match(/^data:([^,]+)?,/);if(null===t)throw dj(dX.DATA_URL,"Must be formatted 'data:[<mediatype>][;base64],<data>");let n=t[1]||null;null!=n&&(this.base64=function(e,t){let n=e.length>=t.length;return!!n&&e.substring(e.length-t.length)===t}(n,";base64"),this.contentType=this.base64?n.substring(0,n.length-7):n),this.rest=e.substring(e.indexOf(",")+1)}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class d3{constructor(e,t){let n=0,r="";dB(e)?(this.data_=e,n=e.size,r=e.type):e instanceof ArrayBuffer?(t?this.data_=new Uint8Array(e):(this.data_=new Uint8Array(e.byteLength),this.data_.set(new Uint8Array(e))),n=this.data_.length):e instanceof Uint8Array&&(t?this.data_=e:(this.data_=new Uint8Array(e.length),this.data_.set(e)),n=e.length),this.size_=n,this.type_=r}size(){return this.size_}type(){return this.type_}slice(e,t){if(dB(this.data_)){let n=this.data_,r=n.webkitSlice?n.webkitSlice(e,t):n.mozSlice?n.mozSlice(e,t):n.slice?n.slice(e,t):null;return null===r?null:new d3(r)}{let i=new Uint8Array(this.data_.buffer,e,t-e);return new d3(i,!0)}}static getBlob(...e){if(d$()){let t=e.map(e=>e instanceof d3?e.data_:e);return new d3(dY.apply(null,t))}{let n=e.map(e=>dq(e)?dZ(dX.RAW,e).data:e.data_),r=0;n.forEach(e=>{r+=e.byteLength});let i=new Uint8Array(r),s=0;return n.forEach(e=>{for(let t=0;t<e.length;t++)i[s++]=e[t]}),new d3(i,!0)}}uploadData(){return this.data_}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function d4(e){var t;let n;try{n=JSON.parse(e)}catch(r){return null}return"object"!=typeof(t=n)||Array.isArray(t)?null:n}function d6(e){let t=e.lastIndexOf("/",e.length-2);return -1===t?e:e.slice(t+1)}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function d5(e,t){return t}class d8{constructor(e,t,n,r){this.server=e,this.local=t||e,this.writable=!!n,this.xform=r||d5}}let d9=null;function d7(){if(d9)return d9;let e=[];e.push(new d8("bucket")),e.push(new d8("generation")),e.push(new d8("metageneration")),e.push(new d8("name","fullPath",!0));let t=new d8("name");t.xform=function(e,t){return!dq(t)||t.length<2?t:d6(t)},e.push(t);let n=new d8("size");return n.xform=function(e,t){return void 0!==t?Number(t):t},e.push(n),e.push(new d8("timeCreated")),e.push(new d8("updated")),e.push(new d8("md5Hash",null,!0)),e.push(new d8("cacheControl",null,!0)),e.push(new d8("contentDisposition",null,!0)),e.push(new d8("contentEncoding",null,!0)),e.push(new d8("contentLanguage",null,!0)),e.push(new d8("contentType",null,!0)),e.push(new d8("metadata","customMetadata",!0)),d9=e}function fe(e,t,n){let r=d4(t);return null===r?null:function(e,t,n){let r={};r.type="file";let i=n.length;for(let s=0;s<i;s++){let o=n[s];r[o.local]=o.xform(r,t[o.server])}return Object.defineProperty(r,"ref",{get:function(){let t=r.bucket,n=r.fullPath,i=new dU(t,n);return e._makeStorageReference(i)}}),r}(e,r,n)}function ft(e,t){let n={},r=t.length;for(let i=0;i<r;i++){let s=t[i];s.writable&&(n[s.server]=e[s.local])}return JSON.stringify(n)}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let fn="prefixes",fr="items";class fi{constructor(e,t,n,r){this.url=e,this.method=t,this.handler=n,this.timeout=r,this.urlParams={},this.headers={},this.body=null,this.errorHandler=null,this.progressCallback=null,this.successCodes=[200],this.additionalRetryCodes=[]}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function fs(e){if(!e)throw dA()}function fo(e,t){return function(n,r){let i=fe(e,r,t);return fs(null!==i),i}}function fa(e){return function(t,n){var r,i;let s;return 401===t.getStatus()?s=t.getErrorText().includes("Firebase App Check token is invalid")?new dC("unauthorized-app","This app does not have permission to access Firebase Storage on this project."):new dC("unauthenticated","User is not authenticated, please authenticate using Firebase Authentication and try again."):402===t.getStatus()?(r=e.bucket,s=new dC("quota-exceeded","Quota for bucket '"+r+"' exceeded, please view quota on https://firebase.google.com/pricing/.")):403===t.getStatus()?(i=e.path,s=new dC("unauthorized","User does not have permission to access '"+i+"'.")):s=n,s.status=t.getStatus(),s.serverResponse=n.serverResponse,s}}function fl(e){let t=fa(e);return function(n,r){let i=t(n,r);if(404===n.getStatus()){var s;s=e.path,i=new dC("object-not-found","Object '"+s+"' does not exist.")}return i.serverResponse=r.serverResponse,i}}function fu(e,t,n){let r=t.fullServerUrl(),i=dG(r,e.host,e._protocol),s=e.maxOperationRetryTime,o=new fi(i,"GET",fo(e,n),s);return o.errorHandler=fl(t),o}function fc(e,t,n){let r=Object.assign({},n);return r.fullPath=e.path,r.size=t.size(),!r.contentType&&(r.contentType=t&&t.type()||"application/octet-stream"),r}class fh{constructor(e,t,n,r){this.current=e,this.total=t,this.finalized=!!n,this.metadata=r||null}}function fd(e,t){let n=null;try{n=e.getResponseHeader("X-Goog-Upload-Status")}catch(r){fs(!1)}return fs(!!n&&-1!==(t||["active"]).indexOf(n)),n}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let ff={RUNNING:"running",PAUSED:"paused",SUCCESS:"success",CANCELED:"canceled",ERROR:"error"};function fp(e){switch(e){case"running":case"pausing":case"canceling":return ff.RUNNING;case"paused":return ff.PAUSED;case"success":return ff.SUCCESS;case"canceled":return ff.CANCELED;default:return ff.ERROR}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class fm{constructor(e,t,n){"function"==typeof e||null!=t||null!=n?(this.next=e,this.error=null!=t?t:void 0,this.complete=null!=n?n:void 0):(this.next=e.next,this.error=e.error,this.complete=e.complete)}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function fg(e){return(...t)=>{Promise.resolve().then(()=>e(...t))}}class fy{constructor(){this.sent_=!1,this.xhr_=new XMLHttpRequest,this.initXhr(),this.errorCode_=T.NO_ERROR,this.sendPromise_=new Promise(e=>{this.xhr_.addEventListener("abort",()=>{this.errorCode_=T.ABORT,e()}),this.xhr_.addEventListener("error",()=>{this.errorCode_=T.NETWORK_ERROR,e()}),this.xhr_.addEventListener("load",()=>{e()})})}send(e,t,n,r){if(this.sent_)throw dF("cannot .send() more than once");if(this.sent_=!0,this.xhr_.open(t,e,!0),void 0!==r)for(let i in r)r.hasOwnProperty(i)&&this.xhr_.setRequestHeader(i,r[i].toString());return void 0!==n?this.xhr_.send(n):this.xhr_.send(),this.sendPromise_}getErrorCode(){if(!this.sent_)throw dF("cannot .getErrorCode() before sending");return this.errorCode_}getStatus(){if(!this.sent_)throw dF("cannot .getStatus() before sending");try{return this.xhr_.status}catch(e){return -1}}getResponse(){if(!this.sent_)throw dF("cannot .getResponse() before sending");return this.xhr_.response}getErrorText(){if(!this.sent_)throw dF("cannot .getErrorText() before sending");return this.xhr_.statusText}abort(){this.xhr_.abort()}getResponseHeader(e){return this.xhr_.getResponseHeader(e)}addUploadProgressListener(e){null!=this.xhr_.upload&&this.xhr_.upload.addEventListener("progress",e)}removeUploadProgressListener(e){null!=this.xhr_.upload&&this.xhr_.upload.removeEventListener("progress",e)}}class fv extends fy{initXhr(){this.xhr_.responseType="text"}}function f_(){return new fv}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class fw{constructor(e,t,n=null){this._transferred=0,this._needToFetchStatus=!1,this._needToFetchMetadata=!1,this._observers=[],this._error=void 0,this._uploadUrl=void 0,this._request=void 0,this._chunkMultiplier=1,this._resolve=void 0,this._reject=void 0,this._ref=e,this._blob=t,this._metadata=n,this._mappings=d7(),this._resumable=this._shouldDoResumable(this._blob),this._state="running",this._errorHandler=e=>{if(this._request=void 0,this._chunkMultiplier=1,e._codeEquals("canceled"))this._needToFetchStatus=!0,this.completeTransitions_();else{let t=this.isExponentialBackoffExpired();if(dH(e.status,[])){if(t)e=dR();else{this.sleepTime=Math.max(2*this.sleepTime,1e3),this._needToFetchStatus=!0,this.completeTransitions_();return}}this._error=e,this._transition("error")}},this._metadataErrorHandler=e=>{this._request=void 0,e._codeEquals("canceled")?this.completeTransitions_():(this._error=e,this._transition("error"))},this.sleepTime=0,this.maxSleepTime=this._ref.storage.maxUploadRetryTime,this._promise=new Promise((e,t)=>{this._resolve=e,this._reject=t,this._start()}),this._promise.then(null,()=>{})}isExponentialBackoffExpired(){return this.sleepTime>this.maxSleepTime}_makeProgressCallback(){let e=this._transferred;return t=>this._updateProgress(e+t)}_shouldDoResumable(e){return e.size()>262144}_start(){"running"===this._state&&void 0===this._request&&(this._resumable?void 0===this._uploadUrl?this._createResumable():this._needToFetchStatus?this._fetchStatus():this._needToFetchMetadata?this._fetchMetadata():this.pendingTimeout=setTimeout(()=>{this.pendingTimeout=void 0,this._continueUpload()},this.sleepTime):this._oneShotUpload())}_resolveToken(e){Promise.all([this._ref.storage._getAuthToken(),this._ref.storage._getAppCheckToken()]).then(([t,n])=>{switch(this._state){case"running":e(t,n);break;case"canceling":this._transition("canceled");break;case"pausing":this._transition("paused")}})}_createResumable(){this._resolveToken((e,t)=>{let n=function(e,t,n,r,i){let s=t.bucketOnlyServerUrl(),o=fc(t,r,i),a={name:o.fullPath},l=dG(s,e.host,e._protocol),u={"X-Goog-Upload-Protocol":"resumable","X-Goog-Upload-Command":"start","X-Goog-Upload-Header-Content-Length":`${r.size()}`,"X-Goog-Upload-Header-Content-Type":o.contentType,"Content-Type":"application/json; charset=utf-8"},c=ft(o,n),h=e.maxUploadRetryTime,d=new fi(l,"POST",function(e){let t;fd(e);try{t=e.getResponseHeader("X-Goog-Upload-URL")}catch(n){fs(!1)}return fs(dq(t)),t},h);return d.urlParams=a,d.headers=u,d.body=c,d.errorHandler=fa(t),d}(this._ref.storage,this._ref._location,this._mappings,this._blob,this._metadata),r=this._ref.storage._makeRequest(n,f_,e,t);this._request=r,r.getPromise().then(e=>{this._request=void 0,this._uploadUrl=e,this._needToFetchStatus=!1,this.completeTransitions_()},this._errorHandler)})}_fetchStatus(){let e=this._uploadUrl;this._resolveToken((t,n)=>{let r=function(e,t,n,r){let i=e.maxUploadRetryTime,s=new fi(n,"POST",function(e){let t=fd(e,["active","final"]),n=null;try{n=e.getResponseHeader("X-Goog-Upload-Size-Received")}catch(i){fs(!1)}n||fs(!1);let s=Number(n);return fs(!isNaN(s)),new fh(s,r.size(),"final"===t)},i);return s.headers={"X-Goog-Upload-Command":"query"},s.errorHandler=fa(t),s}(this._ref.storage,this._ref._location,e,this._blob),i=this._ref.storage._makeRequest(r,f_,t,n);this._request=i,i.getPromise().then(e=>{this._request=void 0,this._updateProgress(e.current),this._needToFetchStatus=!1,e.finalized&&(this._needToFetchMetadata=!0),this.completeTransitions_()},this._errorHandler)})}_continueUpload(){let e=262144*this._chunkMultiplier,t=new fh(this._transferred,this._blob.size()),n=this._uploadUrl;this._resolveToken((r,i)=>{let s;try{s=function(e,t,n,r,i,s,o,a){let l=new fh(0,0);if(o?(l.current=o.current,l.total=o.total):(l.current=0,l.total=r.size()),r.size()!==l.total)throw new dC("server-file-wrong-size","Server recorded incorrect upload file size, please retry the upload.");let u=l.total-l.current,c=u;i>0&&(c=Math.min(c,i));let h=l.current,d=h+c,f="";f=0===c?"finalize":u===c?"upload, finalize":"upload";let p={"X-Goog-Upload-Command":f,"X-Goog-Upload-Offset":`${l.current}`},m=r.slice(h,d);if(null===m)throw dO();let g=t.maxUploadRetryTime,y=new fi(n,"POST",function(e,n){let i;let o=fd(e,["active","final"]),a=l.current+c,u=r.size();return i="final"===o?fo(t,s)(e,n):null,new fh(a,u,"final"===o,i)},g);return y.headers=p,y.body=m.uploadData(),y.progressCallback=a||null,y.errorHandler=fa(e),y}(this._ref._location,this._ref.storage,n,this._blob,e,this._mappings,t,this._makeProgressCallback())}catch(o){this._error=o,this._transition("error");return}let a=this._ref.storage._makeRequest(s,f_,r,i,!1);this._request=a,a.getPromise().then(e=>{this._increaseMultiplier(),this._request=void 0,this._updateProgress(e.current),e.finalized?(this._metadata=e.metadata,this._transition("success")):this.completeTransitions_()},this._errorHandler)})}_increaseMultiplier(){let e=262144*this._chunkMultiplier;2*e<33554432&&(this._chunkMultiplier*=2)}_fetchMetadata(){this._resolveToken((e,t)=>{let n=fu(this._ref.storage,this._ref._location,this._mappings),r=this._ref.storage._makeRequest(n,f_,e,t);this._request=r,r.getPromise().then(e=>{this._request=void 0,this._metadata=e,this._transition("success")},this._metadataErrorHandler)})}_oneShotUpload(){this._resolveToken((e,t)=>{let n=function(e,t,n,r,i){let s=t.bucketOnlyServerUrl(),o={"X-Goog-Upload-Protocol":"multipart"},a=function(){let e="";for(let t=0;t<2;t++)e+=Math.random().toString().slice(2);return e}();o["Content-Type"]="multipart/related; boundary="+a;let l=fc(t,r,i),u=ft(l,n),c="--"+a+"\r\nContent-Type: application/json; charset=utf-8\r\n\r\n"+u+"\r\n--"+a+"\r\nContent-Type: "+l.contentType+"\r\n\r\n",h=d3.getBlob(c,r,"\r\n--"+a+"--");if(null===h)throw dO();let d={name:l.fullPath},f=dG(s,e.host,e._protocol),p=e.maxUploadRetryTime,m=new fi(f,"POST",fo(e,n),p);return m.urlParams=d,m.headers=o,m.body=h.uploadData(),m.errorHandler=fa(t),m}(this._ref.storage,this._ref._location,this._mappings,this._blob,this._metadata),r=this._ref.storage._makeRequest(n,f_,e,t);this._request=r,r.getPromise().then(e=>{this._request=void 0,this._metadata=e,this._updateProgress(this._blob.size()),this._transition("success")},this._errorHandler)})}_updateProgress(e){let t=this._transferred;this._transferred=e,this._transferred!==t&&this._notifyObservers()}_transition(e){if(this._state!==e)switch(e){case"canceling":case"pausing":this._state=e,void 0!==this._request?this._request.cancel():this.pendingTimeout&&(clearTimeout(this.pendingTimeout),this.pendingTimeout=void 0,this.completeTransitions_());break;case"running":let t="paused"===this._state;this._state=e,t&&(this._notifyObservers(),this._start());break;case"paused":case"error":case"success":this._state=e,this._notifyObservers();break;case"canceled":this._error=dD(),this._state=e,this._notifyObservers()}}completeTransitions_(){switch(this._state){case"pausing":this._transition("paused");break;case"canceling":this._transition("canceled");break;case"running":this._start()}}get snapshot(){let e=fp(this._state);return{bytesTransferred:this._transferred,totalBytes:this._blob.size(),state:e,metadata:this._metadata,task:this,ref:this._ref}}on(e,t,n,r){let i=new fm(t||void 0,n||void 0,r||void 0);return this._addObserver(i),()=>{this._removeObserver(i)}}then(e,t){return this._promise.then(e,t)}catch(e){return this.then(null,e)}_addObserver(e){this._observers.push(e),this._notifyObserver(e)}_removeObserver(e){let t=this._observers.indexOf(e);-1!==t&&this._observers.splice(t,1)}_notifyObservers(){this._finishPromise();let e=this._observers.slice();e.forEach(e=>{this._notifyObserver(e)})}_finishPromise(){if(void 0!==this._resolve){let e=!0;switch(fp(this._state)){case ff.SUCCESS:fg(this._resolve.bind(null,this.snapshot))();break;case ff.CANCELED:case ff.ERROR:let t=this._reject;fg(t.bind(null,this._error))();break;default:e=!1}e&&(this._resolve=void 0,this._reject=void 0)}}_notifyObserver(e){let t=fp(this._state);switch(t){case ff.RUNNING:case ff.PAUSED:e.next&&fg(e.next.bind(e,this.snapshot))();break;case ff.SUCCESS:e.complete&&fg(e.complete.bind(e))();break;case ff.CANCELED:case ff.ERROR:default:e.error&&fg(e.error.bind(e,this._error))()}}resume(){let e="paused"===this._state||"pausing"===this._state;return e&&this._transition("running"),e}pause(){let e="running"===this._state;return e&&this._transition("pausing"),e}cancel(){let e="running"===this._state||"pausing"===this._state;return e&&this._transition("canceling"),e}}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class fb{constructor(e,t){this._service=e,t instanceof dU?this._location=t:this._location=dU.makeFromUrl(t,e.host)}toString(){return"gs://"+this._location.bucket+"/"+this._location.path}_newRef(e,t){return new fb(e,t)}get root(){let e=new dU(this._location.bucket,"");return this._newRef(this._service,e)}get bucket(){return this._location.bucket}get fullPath(){return this._location.path}get name(){return d6(this._location.path)}get storage(){return this._service}get parent(){let e=/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function(e){if(0===e.length)return null;let t=e.lastIndexOf("/");if(-1===t)return"";let n=e.slice(0,t);return n}(this._location.path);if(null===e)return null;let t=new dU(this._location.bucket,e);return new fb(this._service,t)}_throwIfRoot(e){if(""===this._location.path)throw dM(e)}}async function fI(e,t,n){let r=await fT(e,{pageToken:n});t.prefixes.push(...r.prefixes),t.items.push(...r.items),null!=r.nextPageToken&&await fI(e,t,r.nextPageToken)}function fT(e,t){null!=t&&"number"==typeof t.maxResults&&dz("options.maxResults",1,1e3,t.maxResults);let n=t||{},r=function(e,t,n,r,i){var s;let o={};t.isRoot?o.prefix="":o.prefix=t.path+"/",n&&n.length>0&&(o.delimiter=n),r&&(o.pageToken=r),i&&(o.maxResults=i);let a=t.bucketOnlyServerUrl(),l=dG(a,e.host,e._protocol),u=e.maxOperationRetryTime,c=new fi(l,"GET",(s=t.bucket,function(t,n){let r=function(e,t,n){let r=d4(n);return null===r?null:function(e,t,n){let r={prefixes:[],items:[],nextPageToken:n.nextPageToken};if(n[fn])for(let i of n[fn]){let s=i.replace(/\/$/,""),o=e._makeStorageReference(new dU(t,s));r.prefixes.push(o)}if(n[fr])for(let a of n[fr]){let l=e._makeStorageReference(new dU(t,a.name));r.items.push(l)}return r}(e,t,r)}(e,s,n);return fs(null!==r),r}),u);return c.urlParams=o,c.errorHandler=fa(t),c}(e.storage,e._location,"/",n.pageToken,n.maxResults);return e.storage.makeRequestWithTokens(r,f_)}function fE(e,t){let n=function(e,t){let n=t.split("/").filter(e=>e.length>0).join("/");return 0===e.length?n:e+"/"+n}(e._location.path,t),r=new dU(e._location.bucket,n);return new fb(e.storage,r)}function fS(e,t){let n=null==t?void 0:t[dx];return null==n?null:dU.makeFromBucketSpec(n,e)}class fk{constructor(e,t,n,r,i){this.app=e,this._authProvider=t,this._appCheckProvider=n,this._url=r,this._firebaseVersion=i,this._bucket=null,this._host=dk,this._protocol="https",this._appId=null,this._deleted=!1,this._maxOperationRetryTime=12e4,this._maxUploadRetryTime=6e5,this._requests=new Set,null!=r?this._bucket=dU.makeFromBucketSpec(r,this._host):this._bucket=fS(this._host,this.app.options)}get host(){return this._host}set host(e){this._host=e,null!=this._url?this._bucket=dU.makeFromBucketSpec(this._url,e):this._bucket=fS(e,this.app.options)}get maxUploadRetryTime(){return this._maxUploadRetryTime}set maxUploadRetryTime(e){dz("time",0,Number.POSITIVE_INFINITY,e),this._maxUploadRetryTime=e}get maxOperationRetryTime(){return this._maxOperationRetryTime}set maxOperationRetryTime(e){dz("time",0,Number.POSITIVE_INFINITY,e),this._maxOperationRetryTime=e}async _getAuthToken(){if(this._overrideAuthToken)return this._overrideAuthToken;let e=this._authProvider.getImmediate({optional:!0});if(e){let t=await e.getToken();if(null!==t)return t.accessToken}return null}async _getAppCheckToken(){let e=this._appCheckProvider.getImmediate({optional:!0});if(e){let t=await e.getToken();return t.token}return null}_delete(){return this._deleted||(this._deleted=!0,this._requests.forEach(e=>e.cancel()),this._requests.clear()),Promise.resolve()}_makeStorageReference(e){return new fb(this,e)}_makeRequest(e,t,n,r,i=!0){if(this._deleted)return new dV(dL());{let s=function(e,t,n,r,i,s,o=!0){var a,l,u;let c=dW(e.urlParams),h=e.url+c,d=Object.assign({},e.headers);return a=d,t&&(a["X-Firebase-GMPID"]=t),l=d,null!==n&&n.length>0&&(l.Authorization="Firebase "+n),d["X-Firebase-Storage-Version"]="webjs/"+(null!=s?s:"AppManager"),u=d,null!==r&&(u["X-Firebase-AppCheck"]=r),new dK(h,e.method,d,e.body,e.successCodes,e.additionalRetryCodes,e.handler,e.errorHandler,e.timeout,e.progressCallback,i,o)}(e,this._appId,n,r,t,this._firebaseVersion,i);return this._requests.add(s),s.getPromise().then(()=>this._requests.delete(s),()=>this._requests.delete(s)),s}}async makeRequestWithTokens(e,t){let[n,r]=await Promise.all([this._getAuthToken(),this._getAppCheckToken()]);return this._makeRequest(e,t,n,r).getPromise()}}let fx="@firebase/storage",fC="0.9.12";function fN(e,t){return function(e,t){if(!(t&&/^[A-Za-z]+:\/\//.test(t)))return function e(t,n){if(t instanceof fk){if(null==t._bucket)throw new dC("no-default-bucket","No default bucket found. Did you set the '"+dx+"' property when initializing the app?");let r=new fb(t,t._bucket);return null!=n?e(r,n):r}return void 0!==n?fE(t,n):t}(e,t);if(e instanceof fk)return new fb(e,t);throw dP("To use ref(service, url), the first argument must be a Storage instance.")}(e=(0,S.m9)(e),t)}(0,x._registerComponent)(new k.wA("storage",function(e,{instanceIdentifier:t}){let n=e.getProvider("app").getImmediate(),r=e.getProvider("auth-internal"),i=e.getProvider("app-check-internal");return new fk(n,r,i,t,x.SDK_VERSION)},"PUBLIC").setMultipleInstances(!0)),(0,x.registerVersion)(fx,fC,""),(0,x.registerVersion)(fx,fC,"esm2017");/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class fA{constructor(e,t,n){this._delegate=e,this.task=t,this.ref=n}get bytesTransferred(){return this._delegate.bytesTransferred}get metadata(){return this._delegate.metadata}get state(){return this._delegate.state}get totalBytes(){return this._delegate.totalBytes}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class fR{constructor(e,t){this._delegate=e,this._ref=t,this.cancel=this._delegate.cancel.bind(this._delegate),this.catch=this._delegate.catch.bind(this._delegate),this.pause=this._delegate.pause.bind(this._delegate),this.resume=this._delegate.resume.bind(this._delegate)}get snapshot(){return new fA(this._delegate.snapshot,this,this._ref)}then(e,t){return this._delegate.then(t=>{if(e)return e(new fA(t,this,this._ref))},t)}on(e,t,n,r){let i;return t&&(i="function"==typeof t?e=>t(new fA(e,this,this._ref)):{next:t.next?e=>t.next(new fA(e,this,this._ref)):void 0,complete:t.complete||void 0,error:t.error||void 0}),this._delegate.on(e,i,n||void 0,r||void 0)}}class fD{constructor(e,t){this._delegate=e,this._service=t}get prefixes(){return this._delegate.prefixes.map(e=>new fO(e,this._service))}get items(){return this._delegate.items.map(e=>new fO(e,this._service))}get nextPageToken(){return this._delegate.nextPageToken||null}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class fO{constructor(e,t){this._delegate=e,this.storage=t}get name(){return this._delegate.name}get bucket(){return this._delegate.bucket}get fullPath(){return this._delegate.fullPath}toString(){return this._delegate.toString()}child(e){let t=fE(this._delegate,e);return new fO(t,this.storage)}get root(){return new fO(this._delegate.root,this.storage)}get parent(){let e=this._delegate.parent;return null==e?null:new fO(e,this.storage)}put(e,t){var n,r;return this._throwIfRoot("put"),new fR((n=this._delegate,(r=n=(0,S.m9)(n))._throwIfRoot("uploadBytesResumable"),new fw(r,new d3(e),t)),this)}putString(e,t=dX.RAW,n){this._throwIfRoot("putString");let r=dZ(t,e),i=Object.assign({},n);return null==i.contentType&&null!=r.contentType&&(i.contentType=r.contentType),new fR(new fw(this._delegate,new d3(r.data,!0),i),this)}listAll(){var e;return(e=this._delegate,function(e){let t={prefixes:[],items:[]};return fI(e,t).then(()=>t)}(e=(0,S.m9)(e))).then(e=>new fD(e,this.storage))}list(e){var t;return(t=this._delegate,fT(t=(0,S.m9)(t),e||void 0)).then(e=>new fD(e,this.storage))}getMetadata(){var e;return e=this._delegate,function(e){e._throwIfRoot("getMetadata");let t=fu(e.storage,e._location,d7());return e.storage.makeRequestWithTokens(t,f_)}(e=(0,S.m9)(e))}updateMetadata(e){var t;return t=this._delegate,function(e,t){e._throwIfRoot("updateMetadata");let n=function(e,t,n,r){let i=t.fullServerUrl(),s=dG(i,e.host,e._protocol),o=ft(n,r),a=e.maxOperationRetryTime,l=new fi(s,"PATCH",fo(e,r),a);return l.headers={"Content-Type":"application/json; charset=utf-8"},l.body=o,l.errorHandler=fl(t),l}(e.storage,e._location,t,d7());return e.storage.makeRequestWithTokens(n,f_)}(t=(0,S.m9)(t),e)}getDownloadURL(){var e;return e=this._delegate,function(e){e._throwIfRoot("getDownloadURL");let t=function(e,t,n){let r=t.fullServerUrl(),i=dG(r,e.host,e._protocol),s=e.maxOperationRetryTime,o=new fi(i,"GET",function(t,r){let i=fe(e,r,n);return fs(null!==i),function(e,t,n,r){let i=d4(t);if(null===i||!dq(i.downloadTokens))return null;let s=i.downloadTokens;if(0===s.length)return null;let o=encodeURIComponent,a=s.split(","),l=a.map(t=>{let i=e.bucket,s=e.fullPath,a="/b/"+o(i)+"/o/"+o(s),l=dG(a,n,r),u=dW({alt:"media",token:t});return l+u});return l[0]}(i,r,e.host,e._protocol)},s);return o.errorHandler=fl(t),o}(e.storage,e._location,d7());return e.storage.makeRequestWithTokens(t,f_).then(e=>{if(null===e)throw new dC("no-download-url","The given file does not have any download URLs.");return e})}(e=(0,S.m9)(e))}delete(){var e;return this._throwIfRoot("delete"),e=this._delegate,function(e){e._throwIfRoot("deleteObject");let t=function(e,t){let n=t.fullServerUrl(),r=dG(n,e.host,e._protocol),i=e.maxOperationRetryTime,s=new fi(r,"DELETE",function(e,t){},i);return s.successCodes=[200,204],s.errorHandler=fl(t),s}(e.storage,e._location);return e.storage.makeRequestWithTokens(t,f_)}(e=(0,S.m9)(e))}_throwIfRoot(e){if(""===this._delegate._location.path)throw dM(e)}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class fP{constructor(e,t){this.app=e,this._delegate=t}get maxOperationRetryTime(){return this._delegate.maxOperationRetryTime}get maxUploadRetryTime(){return this._delegate.maxUploadRetryTime}ref(e){if(fL(e))throw dP("ref() expected a child path but got a URL, use refFromURL instead.");return new fO(fN(this._delegate,e),this)}refFromURL(e){if(!fL(e))throw dP("refFromURL() expected a full URL but got a child path, use ref() instead.");try{dU.makeFromUrl(e,this._delegate.host)}catch(t){throw dP("refFromUrl() expected a valid full URL but got an invalid one.")}return new fO(fN(this._delegate,e),this)}setMaxUploadRetryTime(e){this._delegate.maxUploadRetryTime=e}setMaxOperationRetryTime(e){this._delegate.maxOperationRetryTime=e}useEmulator(e,t,n={}){!function(e,t,n,r={}){!function(e,t,n,r={}){e.host=`${t}:${n}`,e._protocol="http";let{mockUserToken:i}=r;i&&(e._overrideAuthToken="string"==typeof i?i:(0,S.Sg)(i,e.app.options.projectId))}(e,t,n,r)}(this._delegate,e,t,n)}}function fL(e){return/^[A-Za-z]+:\/\//.test(e)}R.INTERNAL.registerComponent(new k.wA("storage-compat",function(e,{instanceIdentifier:t}){let n=e.getProvider("app-compat").getImmediate(),r=e.getProvider("storage").getImmediate({identifier:t}),i=new fP(n,r);return i},"PUBLIC").setServiceProps({TaskState:ff,TaskEvent:{STATE_CHANGED:"state_changed"},StringFormat:dX,Storage:fP,Reference:fO}).setMultipleInstances(!0)),R.registerVersion("@firebase/storage-compat","0.1.20");var fM=n(3454);let fj="@firebase/database",fF="0.13.9",fU="";/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class fV{constructor(e){this.domStorage_=e,this.prefix_="firebase:"}set(e,t){null==t?this.domStorage_.removeItem(this.prefixedName_(e)):this.domStorage_.setItem(this.prefixedName_(e),(0,S.Wl)(t))}get(e){let t=this.domStorage_.getItem(this.prefixedName_(e));return null==t?null:(0,S.cI)(t)}remove(e){this.domStorage_.removeItem(this.prefixedName_(e))}prefixedName_(e){return this.prefix_+e}toString(){return this.domStorage_.toString()}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class fq{constructor(){this.cache_={},this.isInMemoryStorage=!0}set(e,t){null==t?delete this.cache_[e]:this.cache_[e]=t}get(e){return(0,S.r3)(this.cache_,e)?this.cache_[e]:null}remove(e){delete this.cache_[e]}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let fB=function(e){try{if("undefined"!=typeof window&&void 0!==window[e]){let t=window[e];return t.setItem("firebase:sentinel","cache"),t.removeItem("firebase:sentinel"),new fV(t)}}catch(n){}return new fq},f$=fB("localStorage"),fz=fB("sessionStorage"),fG=new C.Yd("@firebase/database"),fW=(f=1,function(){return f++}),fH=function(e){let t=(0,S.dS)(e),n=new S.gQ;n.update(t);let r=n.digest();return S.US.encodeByteArray(r)},fK=function(...e){let t="";for(let n=0;n<e.length;n++){let r=e[n];Array.isArray(r)||r&&"object"==typeof r&&"number"==typeof r.length?t+=fK.apply(null,r):"object"==typeof r?t+=(0,S.Wl)(r):t+=r,t+=" "}return t},fQ=null,fY=!0,fX=function(e,t){(0,S.hu)(!t||!0===e||!1===e,"Can't turn on custom loggers persistently."),!0===e?(fG.logLevel=C.in.VERBOSE,fQ=fG.log.bind(fG),t&&fz.set("logging_enabled",!0)):"function"==typeof e?fQ=e:(fQ=null,fz.remove("logging_enabled"))},fJ=function(...e){if(!0===fY&&(fY=!1,null===fQ&&!0===fz.get("logging_enabled")&&fX(!0)),fQ){let t=fK.apply(null,e);fQ(t)}},fZ=function(e){return function(...t){fJ(e,...t)}},f0=function(...e){let t="FIREBASE INTERNAL ERROR: "+fK(...e);fG.error(t)},f1=function(...e){let t=`FIREBASE FATAL ERROR: ${fK(...e)}`;throw fG.error(t),Error(t)},f2=function(...e){let t="FIREBASE WARNING: "+fK(...e);fG.warn(t)},f3=function(){"undefined"!=typeof window&&window.location&&window.location.protocol&&-1!==window.location.protocol.indexOf("https:")&&f2("Insecure Firebase access from a secure page. Please use https in calls to new Firebase().")},f4=function(e){return"number"==typeof e&&(e!=e||e===Number.POSITIVE_INFINITY||e===Number.NEGATIVE_INFINITY)},f6=function(e){if((0,S.Yr)()||"complete"===document.readyState)e();else{let t=!1,n=function(){if(!document.body){setTimeout(n,Math.floor(10));return}t||(t=!0,e())};document.addEventListener?(document.addEventListener("DOMContentLoaded",n,!1),window.addEventListener("load",n,!1)):document.attachEvent&&(document.attachEvent("onreadystatechange",()=>{"complete"===document.readyState&&n()}),window.attachEvent("onload",n))}},f5="[MIN_NAME]",f8="[MAX_NAME]",f9=function(e,t){if(e===t)return 0;if(e===f5||t===f8)return -1;if(t===f5||e===f8)return 1;{let n=po(e),r=po(t);return null!==n?null!==r?n-r==0?e.length-t.length:n-r:-1:null!==r?1:e<t?-1:1}},f7=function(e,t){return e===t?0:e<t?-1:1},pe=function(e,t){if(t&&e in t)return t[e];throw Error("Missing required key ("+e+") in object: "+(0,S.Wl)(t))},pt=function(e){if("object"!=typeof e||null===e)return(0,S.Wl)(e);let t=[];for(let n in e)t.push(n);t.sort();let r="{";for(let i=0;i<t.length;i++)0!==i&&(r+=","),r+=(0,S.Wl)(t[i])+":"+pt(e[t[i]]);return r+"}"},pn=function(e,t){let n=e.length;if(n<=t)return[e];let r=[];for(let i=0;i<n;i+=t)i+t>n?r.push(e.substring(i,n)):r.push(e.substring(i,i+t));return r};function pr(e,t){for(let n in e)e.hasOwnProperty(n)&&t(n,e[n])}let pi=function(e){let t,n,r,i,s;(0,S.hu)(!f4(e),"Invalid JSON number"),0===e?(n=0,r=0,t=1/e==-1/0?1:0):(t=e<0,(e=Math.abs(e))>=22250738585072014e-324?(n=(i=Math.min(Math.floor(Math.log(e)/Math.LN2),1023))+1023,r=Math.round(e*Math.pow(2,52-i)-4503599627370496)):(n=0,r=Math.round(e/5e-324)));let o=[];for(s=52;s;s-=1)o.push(r%2?1:0),r=Math.floor(r/2);for(s=11;s;s-=1)o.push(n%2?1:0),n=Math.floor(n/2);o.push(t?1:0),o.reverse();let a=o.join(""),l="";for(s=0;s<64;s+=8){let u=parseInt(a.substr(s,8),2).toString(16);1===u.length&&(u="0"+u),l+=u}return l.toLowerCase()},ps=RegExp("^-?(0*)\\d{1,10}$"),po=function(e){if(ps.test(e)){let t=Number(e);if(t>=-2147483648&&t<=2147483647)return t}return null},pa=function(e){try{e()}catch(t){setTimeout(()=>{let e=t.stack||"";throw f2("Exception was thrown by user callback.",e),t},Math.floor(0))}},pl=function(){let e="object"==typeof window&&window.navigator&&window.navigator.userAgent||"";return e.search(/googlebot|google webmaster tools|bingbot|yahoo! slurp|baiduspider|yandexbot|duckduckbot/i)>=0},pu=function(e,t){let n=setTimeout(e,t);return"number"==typeof n&&"undefined"!=typeof Deno&&Deno.unrefTimer?Deno.unrefTimer(n):"object"==typeof n&&n.unref&&n.unref(),n};/**
 * @license
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class pc{constructor(e,t){this.appName_=e,this.appCheckProvider=t,this.appCheck=null==t?void 0:t.getImmediate({optional:!0}),this.appCheck||null==t||t.get().then(e=>this.appCheck=e)}getToken(e){return this.appCheck?this.appCheck.getToken(e):new Promise((t,n)=>{setTimeout(()=>{this.appCheck?this.getToken(e).then(t,n):t(null)},0)})}addTokenChangeListener(e){var t;null===(t=this.appCheckProvider)||void 0===t||t.get().then(t=>t.addTokenListener(e))}notifyForInvalidToken(){f2(`Provided AppCheck credentials for the app named "${this.appName_}" are invalid. This usually indicates your app was not initialized correctly.`)}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class ph{constructor(e,t,n){this.appName_=e,this.firebaseOptions_=t,this.authProvider_=n,this.auth_=null,this.auth_=n.getImmediate({optional:!0}),this.auth_||n.onInit(e=>this.auth_=e)}getToken(e){return this.auth_?this.auth_.getToken(e).catch(e=>e&&"auth/token-not-initialized"===e.code?(fJ("Got auth/token-not-initialized error.  Treating as null token."),null):Promise.reject(e)):new Promise((t,n)=>{setTimeout(()=>{this.auth_?this.getToken(e).then(t,n):t(null)},0)})}addTokenChangeListener(e){this.auth_?this.auth_.addAuthTokenListener(e):this.authProvider_.get().then(t=>t.addAuthTokenListener(e))}removeTokenChangeListener(e){this.authProvider_.get().then(t=>t.removeAuthTokenListener(e))}notifyForInvalidToken(){let e='Provided authentication credentials for the app named "'+this.appName_+'" are invalid. This usually indicates your app was not initialized correctly. ';"credential"in this.firebaseOptions_?e+='Make sure the "credential" property provided to initializeApp() is authorized to access the specified "databaseURL" and is from the correct project.':"serviceAccount"in this.firebaseOptions_?e+='Make sure the "serviceAccount" property provided to initializeApp() is authorized to access the specified "databaseURL" and is from the correct project.':e+='Make sure the "apiKey" and "databaseURL" properties provided to initializeApp() match the values provided for your app at https://console.firebase.google.com/.',f2(e)}}class pd{constructor(e){this.accessToken=e}getToken(e){return Promise.resolve({accessToken:this.accessToken})}addTokenChangeListener(e){e(this.accessToken)}removeTokenChangeListener(e){}notifyForInvalidToken(){}}pd.OWNER="owner";let pf=/(console\.firebase|firebase-console-\w+\.corp|firebase\.corp)\.google\.com/,pp="websocket",pm="long_polling";/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class pg{constructor(e,t,n,r,i=!1,s="",o=!1){this.secure=t,this.namespace=n,this.webSocketOnly=r,this.nodeAdmin=i,this.persistenceKey=s,this.includeNamespaceInQueryParams=o,this._host=e.toLowerCase(),this._domain=this._host.substr(this._host.indexOf(".")+1),this.internalHost=f$.get("host:"+e)||this._host}isCacheableHost(){return"s-"===this.internalHost.substr(0,2)}isCustomHost(){return"firebaseio.com"!==this._domain&&"firebaseio-demo.com"!==this._domain}get host(){return this._host}set host(e){e!==this.internalHost&&(this.internalHost=e,this.isCacheableHost()&&f$.set("host:"+this._host,this.internalHost))}toString(){let e=this.toURLString();return this.persistenceKey&&(e+="<"+this.persistenceKey+">"),e}toURLString(){let e=this.secure?"https://":"http://",t=this.includeNamespaceInQueryParams?`?ns=${this.namespace}`:"";return`${e}${this.host}/${t}`}}function py(e,t,n){let r;if((0,S.hu)("string"==typeof t,"typeof type must == string"),(0,S.hu)("object"==typeof n,"typeof params must == object"),t===pp)r=(e.secure?"wss://":"ws://")+e.internalHost+"/.ws?";else if(t===pm)r=(e.secure?"https://":"http://")+e.internalHost+"/.lp?";else throw Error("Unknown connection type: "+t);(e.host!==e.internalHost||e.isCustomHost()||e.includeNamespaceInQueryParams)&&(n.ns=e.namespace);let i=[];return pr(n,(e,t)=>{i.push(e+"="+t)}),r+i.join("&")}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class pv{constructor(){this.counters_={}}incrementCounter(e,t=1){(0,S.r3)(this.counters_,e)||(this.counters_[e]=0),this.counters_[e]+=t}get(){return(0,S.p$)(this.counters_)}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let p_={},pw={};function pb(e){let t=e.toString();return p_[t]||(p_[t]=new pv),p_[t]}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class pI{constructor(e){this.onMessage_=e,this.pendingResponses=[],this.currentResponseNum=0,this.closeAfterResponse=-1,this.onClose=null}closeAfter(e,t){this.closeAfterResponse=e,this.onClose=t,this.closeAfterResponse<this.currentResponseNum&&(this.onClose(),this.onClose=null)}handleResponse(e,t){for(this.pendingResponses[e]=t;this.pendingResponses[this.currentResponseNum];){let n=this.pendingResponses[this.currentResponseNum];delete this.pendingResponses[this.currentResponseNum];for(let r=0;r<n.length;++r)n[r]&&pa(()=>{this.onMessage_(n[r])});if(this.currentResponseNum===this.closeAfterResponse){this.onClose&&(this.onClose(),this.onClose=null);break}this.currentResponseNum++}}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let pT="start";class pE{constructor(e,t,n,r,i,s,o){this.connId=e,this.repoInfo=t,this.applicationId=n,this.appCheckToken=r,this.authToken=i,this.transportSessionId=s,this.lastSessionId=o,this.bytesSent=0,this.bytesReceived=0,this.everConnected_=!1,this.log_=fZ(e),this.stats_=pb(t),this.urlFn=e=>(this.appCheckToken&&(e.ac=this.appCheckToken),py(t,pm,e))}open(e,t){this.curSegmentNum=0,this.onDisconnect_=t,this.myPacketOrderer=new pI(e),this.isClosed_=!1,this.connectTimeoutTimer_=setTimeout(()=>{this.log_("Timed out trying to connect."),this.onClosed_(),this.connectTimeoutTimer_=null},Math.floor(3e4)),f6(()=>{if(this.isClosed_)return;this.scriptTagHolder=new pS((...e)=>{let[t,n,r,i,s]=e;if(this.incrementIncomingBytes_(e),this.scriptTagHolder){if(this.connectTimeoutTimer_&&(clearTimeout(this.connectTimeoutTimer_),this.connectTimeoutTimer_=null),this.everConnected_=!0,t===pT)this.id=n,this.password=r;else if("close"===t)n?(this.scriptTagHolder.sendNewPolls=!1,this.myPacketOrderer.closeAfter(n,()=>{this.onClosed_()})):this.onClosed_();else throw Error("Unrecognized command received: "+t)}},(...e)=>{let[t,n]=e;this.incrementIncomingBytes_(e),this.myPacketOrderer.handleResponse(t,n)},()=>{this.onClosed_()},this.urlFn);let e={};e[pT]="t",e.ser=Math.floor(1e8*Math.random()),this.scriptTagHolder.uniqueCallbackIdentifier&&(e.cb=this.scriptTagHolder.uniqueCallbackIdentifier),e.v="5",this.transportSessionId&&(e.s=this.transportSessionId),this.lastSessionId&&(e.ls=this.lastSessionId),this.applicationId&&(e.p=this.applicationId),this.appCheckToken&&(e.ac=this.appCheckToken),"undefined"!=typeof location&&location.hostname&&pf.test(location.hostname)&&(e.r="f");let t=this.urlFn(e);this.log_("Connecting via long-poll to "+t),this.scriptTagHolder.addTag(t,()=>{})})}start(){this.scriptTagHolder.startLongPoll(this.id,this.password),this.addDisconnectPingFrame(this.id,this.password)}static forceAllow(){pE.forceAllow_=!0}static forceDisallow(){pE.forceDisallow_=!0}static isAvailable(){return!(0,S.Yr)()&&(!!pE.forceAllow_||!pE.forceDisallow_&&"undefined"!=typeof document&&null!=document.createElement&&!("object"==typeof window&&window.chrome&&window.chrome.extension&&!/^chrome/.test(window.location.href))&&!("object"==typeof Windows&&"object"==typeof Windows.UI))}markConnectionHealthy(){}shutdown_(){this.isClosed_=!0,this.scriptTagHolder&&(this.scriptTagHolder.close(),this.scriptTagHolder=null),this.myDisconnFrame&&(document.body.removeChild(this.myDisconnFrame),this.myDisconnFrame=null),this.connectTimeoutTimer_&&(clearTimeout(this.connectTimeoutTimer_),this.connectTimeoutTimer_=null)}onClosed_(){!this.isClosed_&&(this.log_("Longpoll is closing itself"),this.shutdown_(),this.onDisconnect_&&(this.onDisconnect_(this.everConnected_),this.onDisconnect_=null))}close(){this.isClosed_||(this.log_("Longpoll is being closed."),this.shutdown_())}send(e){let t=(0,S.Wl)(e);this.bytesSent+=t.length,this.stats_.incrementCounter("bytes_sent",t.length);let n=(0,S.h$)(t),r=pn(n,1840);for(let i=0;i<r.length;i++)this.scriptTagHolder.enqueueSegment(this.curSegmentNum,r.length,r[i]),this.curSegmentNum++}addDisconnectPingFrame(e,t){if((0,S.Yr)())return;this.myDisconnFrame=document.createElement("iframe");let n={};n.dframe="t",n.id=e,n.pw=t,this.myDisconnFrame.src=this.urlFn(n),this.myDisconnFrame.style.display="none",document.body.appendChild(this.myDisconnFrame)}incrementIncomingBytes_(e){let t=(0,S.Wl)(e).length;this.bytesReceived+=t,this.stats_.incrementCounter("bytes_received",t)}}class pS{constructor(e,t,n,r){if(this.onDisconnect=n,this.urlFn=r,this.outstandingRequests=new Set,this.pendingSegs=[],this.currentSerial=Math.floor(1e8*Math.random()),this.sendNewPolls=!0,(0,S.Yr)())this.commandCB=e,this.onMessageCB=t;else{this.uniqueCallbackIdentifier=fW(),window["pLPCommand"+this.uniqueCallbackIdentifier]=e,window["pRTLPCB"+this.uniqueCallbackIdentifier]=t,this.myIFrame=pS.createIFrame_();let i="";if(this.myIFrame.src&&"javascript:"===this.myIFrame.src.substr(0,11)){let s=document.domain;i='<script>document.domain="'+s+'";</script>'}let o="<html><body>"+i+"</body></html>";try{this.myIFrame.doc.open(),this.myIFrame.doc.write(o),this.myIFrame.doc.close()}catch(a){fJ("frame writing exception"),a.stack&&fJ(a.stack),fJ(a)}}}static createIFrame_(){let e=document.createElement("iframe");if(e.style.display="none",document.body){document.body.appendChild(e);try{let t=e.contentWindow.document;t||fJ("No IE domain setting required")}catch(r){let n=document.domain;e.src="javascript:void((function(){document.open();document.domain='"+n+"';document.close();})())"}}else throw"Document body has not initialized. Wait to initialize Firebase until after the document is ready.";return e.contentDocument?e.doc=e.contentDocument:e.contentWindow?e.doc=e.contentWindow.document:e.document&&(e.doc=e.document),e}close(){this.alive=!1,this.myIFrame&&(this.myIFrame.doc.body.innerHTML="",setTimeout(()=>{null!==this.myIFrame&&(document.body.removeChild(this.myIFrame),this.myIFrame=null)},Math.floor(0)));let e=this.onDisconnect;e&&(this.onDisconnect=null,e())}startLongPoll(e,t){for(this.myID=e,this.myPW=t,this.alive=!0;this.newRequest_(););}newRequest_(){if(!this.alive||!this.sendNewPolls||!(this.outstandingRequests.size<(this.pendingSegs.length>0?2:1)))return!1;{this.currentSerial++;let e={};e.id=this.myID,e.pw=this.myPW,e.ser=this.currentSerial;let t=this.urlFn(e),n="",r=0;for(;this.pendingSegs.length>0;){let i=this.pendingSegs[0];if(i.d.length+30+n.length<=1870){let s=this.pendingSegs.shift();n=n+"&seg"+r+"="+s.seg+"&ts"+r+"="+s.ts+"&d"+r+"="+s.d,r++}else break}return t+=n,this.addLongPollTag_(t,this.currentSerial),!0}}enqueueSegment(e,t,n){this.pendingSegs.push({seg:e,ts:t,d:n}),this.alive&&this.newRequest_()}addLongPollTag_(e,t){this.outstandingRequests.add(t);let n=()=>{this.outstandingRequests.delete(t),this.newRequest_()},r=setTimeout(n,Math.floor(25e3)),i=()=>{clearTimeout(r),n()};this.addTag(e,i)}addTag(e,t){(0,S.Yr)()?this.doNodeLongPoll(e,t):setTimeout(()=>{try{if(!this.sendNewPolls)return;let n=this.myIFrame.doc.createElement("script");n.type="text/javascript",n.async=!0,n.src=e,n.onload=n.onreadystatechange=function(){let e=n.readyState;e&&"loaded"!==e&&"complete"!==e||(n.onload=n.onreadystatechange=null,n.parentNode&&n.parentNode.removeChild(n),t())},n.onerror=()=>{fJ("Long-poll script failed to load: "+e),this.sendNewPolls=!1,this.close()},this.myIFrame.doc.body.appendChild(n)}catch(r){}},Math.floor(1))}}let pk=null;"undefined"!=typeof MozWebSocket?pk=MozWebSocket:"undefined"!=typeof WebSocket&&(pk=WebSocket);class px{constructor(e,t,n,r,i,s,o){this.connId=e,this.applicationId=n,this.appCheckToken=r,this.authToken=i,this.keepaliveTimer=null,this.frames=null,this.totalFrames=0,this.bytesSent=0,this.bytesReceived=0,this.log_=fZ(this.connId),this.stats_=pb(t),this.connURL=px.connectionURL_(t,s,o,r,n),this.nodeAdmin=t.nodeAdmin}static connectionURL_(e,t,n,r,i){let s={};return s.v="5",!(0,S.Yr)()&&"undefined"!=typeof location&&location.hostname&&pf.test(location.hostname)&&(s.r="f"),t&&(s.s=t),n&&(s.ls=n),r&&(s.ac=r),i&&(s.p=i),py(e,pp,s)}open(e,t){this.onDisconnect=t,this.onMessage=e,this.log_("Websocket connecting to "+this.connURL),this.everConnected_=!1,f$.set("previous_websocket_failure",!0);try{let n;if((0,S.Yr)()){let r=this.nodeAdmin?"AdminNode":"Node";n={headers:{"User-Agent":`Firebase/5/${fU}/${fM.platform}/${r}`,"X-Firebase-GMPID":this.applicationId||""}},this.authToken&&(n.headers.Authorization=`Bearer ${this.authToken}`),this.appCheckToken&&(n.headers["X-Firebase-AppCheck"]=this.appCheckToken);let i=fM.env,s=0===this.connURL.indexOf("wss://")?i.HTTPS_PROXY||i.https_proxy:i.HTTP_PROXY||i.http_proxy;s&&(n.proxy={origin:s})}this.mySock=new pk(this.connURL,[],n)}catch(a){this.log_("Error instantiating WebSocket.");let o=a.message||a.data;o&&this.log_(o),this.onClosed_();return}this.mySock.onopen=()=>{this.log_("Websocket connected."),this.everConnected_=!0},this.mySock.onclose=()=>{this.log_("Websocket connection was disconnected."),this.mySock=null,this.onClosed_()},this.mySock.onmessage=e=>{this.handleIncomingFrame(e)},this.mySock.onerror=e=>{this.log_("WebSocket error.  Closing connection.");let t=e.message||e.data;t&&this.log_(t),this.onClosed_()}}start(){}static forceDisallow(){px.forceDisallow_=!0}static isAvailable(){let e=!1;if("undefined"!=typeof navigator&&navigator.userAgent){let t=navigator.userAgent.match(/Android ([0-9]{0,}\.[0-9]{0,})/);t&&t.length>1&&4.4>parseFloat(t[1])&&(e=!0)}return!e&&null!==pk&&!px.forceDisallow_}static previouslyFailed(){return f$.isInMemoryStorage||!0===f$.get("previous_websocket_failure")}markConnectionHealthy(){f$.remove("previous_websocket_failure")}appendFrame_(e){if(this.frames.push(e),this.frames.length===this.totalFrames){let t=this.frames.join("");this.frames=null;let n=(0,S.cI)(t);this.onMessage(n)}}handleNewFrameCount_(e){this.totalFrames=e,this.frames=[]}extractFrameCount_(e){if((0,S.hu)(null===this.frames,"We already have a frame buffer"),e.length<=6){let t=Number(e);if(!isNaN(t))return this.handleNewFrameCount_(t),null}return this.handleNewFrameCount_(1),e}handleIncomingFrame(e){if(null===this.mySock)return;let t=e.data;if(this.bytesReceived+=t.length,this.stats_.incrementCounter("bytes_received",t.length),this.resetKeepAlive(),null!==this.frames)this.appendFrame_(t);else{let n=this.extractFrameCount_(t);null!==n&&this.appendFrame_(n)}}send(e){this.resetKeepAlive();let t=(0,S.Wl)(e);this.bytesSent+=t.length,this.stats_.incrementCounter("bytes_sent",t.length);let n=pn(t,16384);n.length>1&&this.sendString_(String(n.length));for(let r=0;r<n.length;r++)this.sendString_(n[r])}shutdown_(){this.isClosed_=!0,this.keepaliveTimer&&(clearInterval(this.keepaliveTimer),this.keepaliveTimer=null),this.mySock&&(this.mySock.close(),this.mySock=null)}onClosed_(){!this.isClosed_&&(this.log_("WebSocket is closing itself"),this.shutdown_(),this.onDisconnect&&(this.onDisconnect(this.everConnected_),this.onDisconnect=null))}close(){this.isClosed_||(this.log_("WebSocket is being closed"),this.shutdown_())}resetKeepAlive(){clearInterval(this.keepaliveTimer),this.keepaliveTimer=setInterval(()=>{this.mySock&&this.sendString_("0"),this.resetKeepAlive()},Math.floor(45e3))}sendString_(e){try{this.mySock.send(e)}catch(t){this.log_("Exception thrown from WebSocket.send():",t.message||t.data,"Closing connection."),setTimeout(this.onClosed_.bind(this),0)}}}px.responsesRequiredToBeHealthy=2,px.healthyTimeout=3e4;/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class pC{constructor(e){this.initTransports_(e)}static get ALL_TRANSPORTS(){return[pE,px]}static get IS_TRANSPORT_INITIALIZED(){return this.globalTransportInitialized_}initTransports_(e){let t=px&&px.isAvailable(),n=t&&!px.previouslyFailed();if(e.webSocketOnly&&(t||f2("wss:// URL used, but browser isn't known to support websockets.  Trying anyway."),n=!0),n)this.transports_=[px];else{let r=this.transports_=[];for(let i of pC.ALL_TRANSPORTS)i&&i.isAvailable()&&r.push(i);pC.globalTransportInitialized_=!0}}initialTransport(){if(this.transports_.length>0)return this.transports_[0];throw Error("No transports available")}upgradeTransport(){return this.transports_.length>1?this.transports_[1]:null}}pC.globalTransportInitialized_=!1;class pN{constructor(e,t,n,r,i,s,o,a,l,u){this.id=e,this.repoInfo_=t,this.applicationId_=n,this.appCheckToken_=r,this.authToken_=i,this.onMessage_=s,this.onReady_=o,this.onDisconnect_=a,this.onKill_=l,this.lastSessionId=u,this.connectionCount=0,this.pendingDataMessages=[],this.state_=0,this.log_=fZ("c:"+this.id+":"),this.transportManager_=new pC(t),this.log_("Connection created"),this.start_()}start_(){let e=this.transportManager_.initialTransport();this.conn_=new e(this.nextTransportId_(),this.repoInfo_,this.applicationId_,this.appCheckToken_,this.authToken_,null,this.lastSessionId),this.primaryResponsesRequired_=e.responsesRequiredToBeHealthy||0;let t=this.connReceiver_(this.conn_),n=this.disconnReceiver_(this.conn_);this.tx_=this.conn_,this.rx_=this.conn_,this.secondaryConn_=null,this.isHealthy_=!1,setTimeout(()=>{this.conn_&&this.conn_.open(t,n)},Math.floor(0));let r=e.healthyTimeout||0;r>0&&(this.healthyTimeout_=pu(()=>{this.healthyTimeout_=null,this.isHealthy_||(this.conn_&&this.conn_.bytesReceived>102400?(this.log_("Connection exceeded healthy timeout but has received "+this.conn_.bytesReceived+" bytes.  Marking connection healthy."),this.isHealthy_=!0,this.conn_.markConnectionHealthy()):this.conn_&&this.conn_.bytesSent>10240?this.log_("Connection exceeded healthy timeout but has sent "+this.conn_.bytesSent+" bytes.  Leaving connection alive."):(this.log_("Closing unhealthy connection after timeout."),this.close()))},Math.floor(r)))}nextTransportId_(){return"c:"+this.id+":"+this.connectionCount++}disconnReceiver_(e){return t=>{e===this.conn_?this.onConnectionLost_(t):e===this.secondaryConn_?(this.log_("Secondary connection lost."),this.onSecondaryConnectionLost_()):this.log_("closing an old connection")}}connReceiver_(e){return t=>{2!==this.state_&&(e===this.rx_?this.onPrimaryMessageReceived_(t):e===this.secondaryConn_?this.onSecondaryMessageReceived_(t):this.log_("message on old connection"))}}sendRequest(e){this.sendData_({t:"d",d:e})}tryCleanupConnection(){this.tx_===this.secondaryConn_&&this.rx_===this.secondaryConn_&&(this.log_("cleaning up and promoting a connection: "+this.secondaryConn_.connId),this.conn_=this.secondaryConn_,this.secondaryConn_=null)}onSecondaryControl_(e){if("t"in e){let t=e.t;"a"===t?this.upgradeIfSecondaryHealthy_():"r"===t?(this.log_("Got a reset on secondary, closing it"),this.secondaryConn_.close(),(this.tx_===this.secondaryConn_||this.rx_===this.secondaryConn_)&&this.close()):"o"===t&&(this.log_("got pong on secondary."),this.secondaryResponsesRequired_--,this.upgradeIfSecondaryHealthy_())}}onSecondaryMessageReceived_(e){let t=pe("t",e),n=pe("d",e);if("c"===t)this.onSecondaryControl_(n);else if("d"===t)this.pendingDataMessages.push(n);else throw Error("Unknown protocol layer: "+t)}upgradeIfSecondaryHealthy_(){this.secondaryResponsesRequired_<=0?(this.log_("Secondary connection is healthy."),this.isHealthy_=!0,this.secondaryConn_.markConnectionHealthy(),this.proceedWithUpgrade_()):(this.log_("sending ping on secondary."),this.secondaryConn_.send({t:"c",d:{t:"p",d:{}}}))}proceedWithUpgrade_(){this.secondaryConn_.start(),this.log_("sending client ack on secondary"),this.secondaryConn_.send({t:"c",d:{t:"a",d:{}}}),this.log_("Ending transmission on primary"),this.conn_.send({t:"c",d:{t:"n",d:{}}}),this.tx_=this.secondaryConn_,this.tryCleanupConnection()}onPrimaryMessageReceived_(e){let t=pe("t",e),n=pe("d",e);"c"===t?this.onControl_(n):"d"===t&&this.onDataMessage_(n)}onDataMessage_(e){this.onPrimaryResponse_(),this.onMessage_(e)}onPrimaryResponse_(){!this.isHealthy_&&(this.primaryResponsesRequired_--,this.primaryResponsesRequired_<=0&&(this.log_("Primary connection is healthy."),this.isHealthy_=!0,this.conn_.markConnectionHealthy()))}onControl_(e){let t=pe("t",e);if("d"in e){let n=e.d;if("h"===t)this.onHandshake_(n);else if("n"===t){this.log_("recvd end transmission on primary"),this.rx_=this.secondaryConn_;for(let r=0;r<this.pendingDataMessages.length;++r)this.onDataMessage_(this.pendingDataMessages[r]);this.pendingDataMessages=[],this.tryCleanupConnection()}else"s"===t?this.onConnectionShutdown_(n):"r"===t?this.onReset_(n):"e"===t?f0("Server Error: "+n):"o"===t?(this.log_("got pong on primary."),this.onPrimaryResponse_(),this.sendPingOnPrimaryIfNecessary_()):f0("Unknown control packet command: "+t)}}onHandshake_(e){let t=e.ts,n=e.v,r=e.h;this.sessionId=e.s,this.repoInfo_.host=r,0===this.state_&&(this.conn_.start(),this.onConnectionEstablished_(this.conn_,t),"5"!==n&&f2("Protocol version mismatch detected"),this.tryStartUpgrade_())}tryStartUpgrade_(){let e=this.transportManager_.upgradeTransport();e&&this.startUpgrade_(e)}startUpgrade_(e){this.secondaryConn_=new e(this.nextTransportId_(),this.repoInfo_,this.applicationId_,this.appCheckToken_,this.authToken_,this.sessionId),this.secondaryResponsesRequired_=e.responsesRequiredToBeHealthy||0;let t=this.connReceiver_(this.secondaryConn_),n=this.disconnReceiver_(this.secondaryConn_);this.secondaryConn_.open(t,n),pu(()=>{this.secondaryConn_&&(this.log_("Timed out trying to upgrade."),this.secondaryConn_.close())},Math.floor(6e4))}onReset_(e){this.log_("Reset packet received.  New host: "+e),this.repoInfo_.host=e,1===this.state_?this.close():(this.closeConnections_(),this.start_())}onConnectionEstablished_(e,t){this.log_("Realtime connection established."),this.conn_=e,this.state_=1,this.onReady_&&(this.onReady_(t,this.sessionId),this.onReady_=null),0===this.primaryResponsesRequired_?(this.log_("Primary connection is healthy."),this.isHealthy_=!0):pu(()=>{this.sendPingOnPrimaryIfNecessary_()},Math.floor(5e3))}sendPingOnPrimaryIfNecessary_(){this.isHealthy_||1!==this.state_||(this.log_("sending ping on primary."),this.sendData_({t:"c",d:{t:"p",d:{}}}))}onSecondaryConnectionLost_(){let e=this.secondaryConn_;this.secondaryConn_=null,(this.tx_===e||this.rx_===e)&&this.close()}onConnectionLost_(e){this.conn_=null,e||0!==this.state_?1===this.state_&&this.log_("Realtime connection lost."):(this.log_("Realtime connection failed."),this.repoInfo_.isCacheableHost()&&(f$.remove("host:"+this.repoInfo_.host),this.repoInfo_.internalHost=this.repoInfo_.host)),this.close()}onConnectionShutdown_(e){this.log_("Connection shutdown command received. Shutting down..."),this.onKill_&&(this.onKill_(e),this.onKill_=null),this.onDisconnect_=null,this.close()}sendData_(e){if(1!==this.state_)throw"Connection is not connected";this.tx_.send(e)}close(){2!==this.state_&&(this.log_("Closing realtime connection."),this.state_=2,this.closeConnections_(),this.onDisconnect_&&(this.onDisconnect_(),this.onDisconnect_=null))}closeConnections_(){this.log_("Shutting down all connections"),this.conn_&&(this.conn_.close(),this.conn_=null),this.secondaryConn_&&(this.secondaryConn_.close(),this.secondaryConn_=null),this.healthyTimeout_&&(clearTimeout(this.healthyTimeout_),this.healthyTimeout_=null)}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class pA{put(e,t,n,r){}merge(e,t,n,r){}refreshAuthToken(e){}refreshAppCheckToken(e){}onDisconnectPut(e,t,n){}onDisconnectMerge(e,t,n){}onDisconnectCancel(e,t){}reportStats(e){}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class pR{constructor(e){this.allowedEvents_=e,this.listeners_={},(0,S.hu)(Array.isArray(e)&&e.length>0,"Requires a non-empty array")}trigger(e,...t){if(Array.isArray(this.listeners_[e])){let n=[...this.listeners_[e]];for(let r=0;r<n.length;r++)n[r].callback.apply(n[r].context,t)}}on(e,t,n){this.validateEventType_(e),this.listeners_[e]=this.listeners_[e]||[],this.listeners_[e].push({callback:t,context:n});let r=this.getInitialEvent(e);r&&t.apply(n,r)}off(e,t,n){this.validateEventType_(e);let r=this.listeners_[e]||[];for(let i=0;i<r.length;i++)if(r[i].callback===t&&(!n||n===r[i].context)){r.splice(i,1);return}}validateEventType_(e){(0,S.hu)(this.allowedEvents_.find(t=>t===e),"Unknown event: "+e)}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class pD extends pR{constructor(){super(["online"]),this.online_=!0,"undefined"==typeof window||void 0===window.addEventListener||(0,S.uI)()||(window.addEventListener("online",()=>{this.online_||(this.online_=!0,this.trigger("online",!0))},!1),window.addEventListener("offline",()=>{this.online_&&(this.online_=!1,this.trigger("online",!1))},!1))}static getInstance(){return new pD}getInitialEvent(e){return(0,S.hu)("online"===e,"Unknown event type: "+e),[this.online_]}currentlyOnline(){return this.online_}}class pO{constructor(e,t){if(void 0===t){this.pieces_=e.split("/");let n=0;for(let r=0;r<this.pieces_.length;r++)this.pieces_[r].length>0&&(this.pieces_[n]=this.pieces_[r],n++);this.pieces_.length=n,this.pieceNum_=0}else this.pieces_=e,this.pieceNum_=t}toString(){let e="";for(let t=this.pieceNum_;t<this.pieces_.length;t++)""!==this.pieces_[t]&&(e+="/"+this.pieces_[t]);return e||"/"}}function pP(){return new pO("")}function pL(e){return e.pieceNum_>=e.pieces_.length?null:e.pieces_[e.pieceNum_]}function pM(e){return e.pieces_.length-e.pieceNum_}function pj(e){let t=e.pieceNum_;return t<e.pieces_.length&&t++,new pO(e.pieces_,t)}function pF(e){return e.pieceNum_<e.pieces_.length?e.pieces_[e.pieces_.length-1]:null}function pU(e,t=0){return e.pieces_.slice(e.pieceNum_+t)}function pV(e){if(e.pieceNum_>=e.pieces_.length)return null;let t=[];for(let n=e.pieceNum_;n<e.pieces_.length-1;n++)t.push(e.pieces_[n]);return new pO(t,0)}function pq(e,t){let n=[];for(let r=e.pieceNum_;r<e.pieces_.length;r++)n.push(e.pieces_[r]);if(t instanceof pO)for(let i=t.pieceNum_;i<t.pieces_.length;i++)n.push(t.pieces_[i]);else{let s=t.split("/");for(let o=0;o<s.length;o++)s[o].length>0&&n.push(s[o])}return new pO(n,0)}function pB(e){return e.pieceNum_>=e.pieces_.length}function p$(e,t){let n=pL(e),r=pL(t);if(null===n)return t;if(n===r)return p$(pj(e),pj(t));throw Error("INTERNAL ERROR: innerPath ("+t+") is not within outerPath ("+e+")")}function pz(e,t){if(pM(e)!==pM(t))return!1;for(let n=e.pieceNum_,r=t.pieceNum_;n<=e.pieces_.length;n++,r++)if(e.pieces_[n]!==t.pieces_[r])return!1;return!0}function pG(e,t){let n=e.pieceNum_,r=t.pieceNum_;if(pM(e)>pM(t))return!1;for(;n<e.pieces_.length;){if(e.pieces_[n]!==t.pieces_[r])return!1;++n,++r}return!0}class pW{constructor(e,t){this.errorPrefix_=t,this.parts_=pU(e,0),this.byteLength_=Math.max(1,this.parts_.length);for(let n=0;n<this.parts_.length;n++)this.byteLength_+=(0,S.ug)(this.parts_[n]);pH(this)}}function pH(e){if(e.byteLength_>768)throw Error(e.errorPrefix_+"has a key path longer than 768 bytes ("+e.byteLength_+").");if(e.parts_.length>32)throw Error(e.errorPrefix_+"path specified exceeds the maximum depth that can be written (32) or object contains a cycle "+pK(e))}function pK(e){return 0===e.parts_.length?"":"in property '"+e.parts_.join(".")+"'"}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class pQ extends pR{constructor(){let e,t;super(["visible"]),"undefined"!=typeof document&&void 0!==document.addEventListener&&(void 0!==document.hidden?(t="visibilitychange",e="hidden"):void 0!==document.mozHidden?(t="mozvisibilitychange",e="mozHidden"):void 0!==document.msHidden?(t="msvisibilitychange",e="msHidden"):void 0!==document.webkitHidden&&(t="webkitvisibilitychange",e="webkitHidden")),this.visible_=!0,t&&document.addEventListener(t,()=>{let t=!document[e];t!==this.visible_&&(this.visible_=t,this.trigger("visible",t))},!1)}static getInstance(){return new pQ}getInitialEvent(e){return(0,S.hu)("visible"===e,"Unknown event type: "+e),[this.visible_]}}class pY extends pA{constructor(e,t,n,r,i,s,o,a){if(super(),this.repoInfo_=e,this.applicationId_=t,this.onDataUpdate_=n,this.onConnectStatus_=r,this.onServerInfoUpdate_=i,this.authTokenProvider_=s,this.appCheckTokenProvider_=o,this.authOverride_=a,this.id=pY.nextPersistentConnectionId_++,this.log_=fZ("p:"+this.id+":"),this.interruptReasons_={},this.listens=new Map,this.outstandingPuts_=[],this.outstandingGets_=[],this.outstandingPutCount_=0,this.outstandingGetCount_=0,this.onDisconnectRequestQueue_=[],this.connected_=!1,this.reconnectDelay_=1e3,this.maxReconnectDelay_=3e5,this.securityDebugCallback_=null,this.lastSessionId=null,this.establishConnectionTimer_=null,this.visible_=!1,this.requestCBHash_={},this.requestNumber_=0,this.realtime_=null,this.authToken_=null,this.appCheckToken_=null,this.forceTokenRefresh_=!1,this.invalidAuthTokenCount_=0,this.invalidAppCheckTokenCount_=0,this.firstConnection_=!0,this.lastConnectionAttemptTime_=null,this.lastConnectionEstablishedTime_=null,a&&!(0,S.Yr)())throw Error("Auth override specified in options, but not supported on non Node.js platforms");pQ.getInstance().on("visible",this.onVisible_,this),-1===e.host.indexOf("fblocal")&&pD.getInstance().on("online",this.onOnline_,this)}sendRequest(e,t,n){let r=++this.requestNumber_,i={r:r,a:e,b:t};this.log_((0,S.Wl)(i)),(0,S.hu)(this.connected_,"sendRequest call when we're not connected not allowed."),this.realtime_.sendRequest(i),n&&(this.requestCBHash_[r]=n)}get(e){this.initConnection_();let t=new S.BH,n={p:e._path.toString(),q:e._queryObject};this.outstandingGets_.push({action:"g",request:n,onComplete:e=>{let n=e.d;"ok"===e.s?t.resolve(n):t.reject(n)}}),this.outstandingGetCount_++;let r=this.outstandingGets_.length-1;return this.connected_&&this.sendGet_(r),t.promise}listen(e,t,n,r){this.initConnection_();let i=e._queryIdentifier,s=e._path.toString();this.log_("Listen called for "+s+" "+i),this.listens.has(s)||this.listens.set(s,new Map),(0,S.hu)(e._queryParams.isDefault()||!e._queryParams.loadsAllData(),"listen() called for non-default but complete query"),(0,S.hu)(!this.listens.get(s).has(i),"listen() called twice for same path/queryId.");let o={onComplete:r,hashFn:t,query:e,tag:n};this.listens.get(s).set(i,o),this.connected_&&this.sendListen_(o)}sendGet_(e){let t=this.outstandingGets_[e];this.sendRequest("g",t.request,n=>{delete this.outstandingGets_[e],this.outstandingGetCount_--,0===this.outstandingGetCount_&&(this.outstandingGets_=[]),t.onComplete&&t.onComplete(n)})}sendListen_(e){let t=e.query,n=t._path.toString(),r=t._queryIdentifier;this.log_("Listen on "+n+" for "+r);let i={p:n};e.tag&&(i.q=t._queryObject,i.t=e.tag),i.h=e.hashFn(),this.sendRequest("q",i,i=>{let s=i.d,o=i.s;pY.warnOnListenWarnings_(s,t);let a=this.listens.get(n)&&this.listens.get(n).get(r);a===e&&(this.log_("listen response",i),"ok"!==o&&this.removeListen_(n,r),e.onComplete&&e.onComplete(o,s))})}static warnOnListenWarnings_(e,t){if(e&&"object"==typeof e&&(0,S.r3)(e,"w")){let n=(0,S.DV)(e,"w");if(Array.isArray(n)&&~n.indexOf("no_index")){let r='".indexOn": "'+t._queryParams.getIndex().toString()+'"',i=t._path.toString();f2(`Using an unspecified index. Your data will be downloaded and filtered on the client. Consider adding ${r} at ${i} to your security rules for better performance.`)}}}refreshAuthToken(e){this.authToken_=e,this.log_("Auth token refreshed"),this.authToken_?this.tryAuth():this.connected_&&this.sendRequest("unauth",{},()=>{}),this.reduceReconnectDelayIfAdminCredential_(e)}reduceReconnectDelayIfAdminCredential_(e){let t=e&&40===e.length;(t||(0,S.GJ)(e))&&(this.log_("Admin auth credential detected.  Reducing max reconnect time."),this.maxReconnectDelay_=3e4)}refreshAppCheckToken(e){this.appCheckToken_=e,this.log_("App check token refreshed"),this.appCheckToken_?this.tryAppCheck():this.connected_&&this.sendRequest("unappeck",{},()=>{})}tryAuth(){if(this.connected_&&this.authToken_){let e=this.authToken_,t=(0,S.w9)(e)?"auth":"gauth",n={cred:e};null===this.authOverride_?n.noauth=!0:"object"==typeof this.authOverride_&&(n.authvar=this.authOverride_),this.sendRequest(t,n,t=>{let n=t.s,r=t.d||"error";this.authToken_===e&&("ok"===n?this.invalidAuthTokenCount_=0:this.onAuthRevoked_(n,r))})}}tryAppCheck(){this.connected_&&this.appCheckToken_&&this.sendRequest("appcheck",{token:this.appCheckToken_},e=>{let t=e.s,n=e.d||"error";"ok"===t?this.invalidAppCheckTokenCount_=0:this.onAppCheckRevoked_(t,n)})}unlisten(e,t){let n=e._path.toString(),r=e._queryIdentifier;this.log_("Unlisten called for "+n+" "+r),(0,S.hu)(e._queryParams.isDefault()||!e._queryParams.loadsAllData(),"unlisten() called for non-default but complete query");let i=this.removeListen_(n,r);i&&this.connected_&&this.sendUnlisten_(n,r,e._queryObject,t)}sendUnlisten_(e,t,n,r){this.log_("Unlisten on "+e+" for "+t);let i={p:e};r&&(i.q=n,i.t=r),this.sendRequest("n",i)}onDisconnectPut(e,t,n){this.initConnection_(),this.connected_?this.sendOnDisconnect_("o",e,t,n):this.onDisconnectRequestQueue_.push({pathString:e,action:"o",data:t,onComplete:n})}onDisconnectMerge(e,t,n){this.initConnection_(),this.connected_?this.sendOnDisconnect_("om",e,t,n):this.onDisconnectRequestQueue_.push({pathString:e,action:"om",data:t,onComplete:n})}onDisconnectCancel(e,t){this.initConnection_(),this.connected_?this.sendOnDisconnect_("oc",e,null,t):this.onDisconnectRequestQueue_.push({pathString:e,action:"oc",data:null,onComplete:t})}sendOnDisconnect_(e,t,n,r){let i={p:t,d:n};this.log_("onDisconnect "+e,i),this.sendRequest(e,i,e=>{r&&setTimeout(()=>{r(e.s,e.d)},Math.floor(0))})}put(e,t,n,r){this.putInternal("p",e,t,n,r)}merge(e,t,n,r){this.putInternal("m",e,t,n,r)}putInternal(e,t,n,r,i){this.initConnection_();let s={p:t,d:n};void 0!==i&&(s.h=i),this.outstandingPuts_.push({action:e,request:s,onComplete:r}),this.outstandingPutCount_++;let o=this.outstandingPuts_.length-1;this.connected_?this.sendPut_(o):this.log_("Buffering put: "+t)}sendPut_(e){let t=this.outstandingPuts_[e].action,n=this.outstandingPuts_[e].request,r=this.outstandingPuts_[e].onComplete;this.outstandingPuts_[e].queued=this.connected_,this.sendRequest(t,n,n=>{this.log_(t+" response",n),delete this.outstandingPuts_[e],this.outstandingPutCount_--,0===this.outstandingPutCount_&&(this.outstandingPuts_=[]),r&&r(n.s,n.d)})}reportStats(e){if(this.connected_){let t={c:e};this.log_("reportStats",t),this.sendRequest("s",t,e=>{let t=e.s;if("ok"!==t){let n=e.d;this.log_("reportStats","Error sending stats: "+n)}})}}onDataMessage_(e){if("r"in e){this.log_("from server: "+(0,S.Wl)(e));let t=e.r,n=this.requestCBHash_[t];n&&(delete this.requestCBHash_[t],n(e.b))}else if("error"in e)throw"A server-side error has occurred: "+e.error;else"a"in e&&this.onDataPush_(e.a,e.b)}onDataPush_(e,t){this.log_("handleServerMessage",e,t),"d"===e?this.onDataUpdate_(t.p,t.d,!1,t.t):"m"===e?this.onDataUpdate_(t.p,t.d,!0,t.t):"c"===e?this.onListenRevoked_(t.p,t.q):"ac"===e?this.onAuthRevoked_(t.s,t.d):"apc"===e?this.onAppCheckRevoked_(t.s,t.d):"sd"===e?this.onSecurityDebugPacket_(t):f0("Unrecognized action received from server: "+(0,S.Wl)(e)+"\nAre you using the latest client?")}onReady_(e,t){this.log_("connection ready"),this.connected_=!0,this.lastConnectionEstablishedTime_=new Date().getTime(),this.handleTimestamp_(e),this.lastSessionId=t,this.firstConnection_&&this.sendConnectStats_(),this.restoreState_(),this.firstConnection_=!1,this.onConnectStatus_(!0)}scheduleConnect_(e){(0,S.hu)(!this.realtime_,"Scheduling a connect when we're already connected/ing?"),this.establishConnectionTimer_&&clearTimeout(this.establishConnectionTimer_),this.establishConnectionTimer_=setTimeout(()=>{this.establishConnectionTimer_=null,this.establishConnection_()},Math.floor(e))}initConnection_(){!this.realtime_&&this.firstConnection_&&this.scheduleConnect_(0)}onVisible_(e){!e||this.visible_||this.reconnectDelay_!==this.maxReconnectDelay_||(this.log_("Window became visible.  Reducing delay."),this.reconnectDelay_=1e3,this.realtime_||this.scheduleConnect_(0)),this.visible_=e}onOnline_(e){e?(this.log_("Browser went online."),this.reconnectDelay_=1e3,this.realtime_||this.scheduleConnect_(0)):(this.log_("Browser went offline.  Killing connection."),this.realtime_&&this.realtime_.close())}onRealtimeDisconnect_(){if(this.log_("data client disconnected"),this.connected_=!1,this.realtime_=null,this.cancelSentTransactions_(),this.requestCBHash_={},this.shouldReconnect_()){if(this.visible_){if(this.lastConnectionEstablishedTime_){let e=new Date().getTime()-this.lastConnectionEstablishedTime_;e>3e4&&(this.reconnectDelay_=1e3),this.lastConnectionEstablishedTime_=null}}else this.log_("Window isn't visible.  Delaying reconnect."),this.reconnectDelay_=this.maxReconnectDelay_,this.lastConnectionAttemptTime_=new Date().getTime();let t=new Date().getTime()-this.lastConnectionAttemptTime_,n=Math.max(0,this.reconnectDelay_-t);n=Math.random()*n,this.log_("Trying to reconnect in "+n+"ms"),this.scheduleConnect_(n),this.reconnectDelay_=Math.min(this.maxReconnectDelay_,1.3*this.reconnectDelay_)}this.onConnectStatus_(!1)}async establishConnection_(){if(this.shouldReconnect_()){this.log_("Making a connection attempt"),this.lastConnectionAttemptTime_=new Date().getTime(),this.lastConnectionEstablishedTime_=null;let e=this.onDataMessage_.bind(this),t=this.onReady_.bind(this),n=this.onRealtimeDisconnect_.bind(this),r=this.id+":"+pY.nextConnectionId_++,i=this.lastSessionId,s=!1,o=null,a=function(){o?o.close():(s=!0,n())};this.realtime_={close:a,sendRequest:function(e){(0,S.hu)(o,"sendRequest call when we're not connected not allowed."),o.sendRequest(e)}};let l=this.forceTokenRefresh_;this.forceTokenRefresh_=!1;try{let[u,c]=await Promise.all([this.authTokenProvider_.getToken(l),this.appCheckTokenProvider_.getToken(l)]);s?fJ("getToken() completed but was canceled"):(fJ("getToken() completed. Creating connection."),this.authToken_=u&&u.accessToken,this.appCheckToken_=c&&c.token,o=new pN(r,this.repoInfo_,this.applicationId_,this.appCheckToken_,this.authToken_,e,t,n,e=>{f2(e+" ("+this.repoInfo_.toString()+")"),this.interrupt("server_kill")},i))}catch(h){this.log_("Failed to get token: "+h),s||(this.repoInfo_.nodeAdmin&&f2(h),a())}}}interrupt(e){fJ("Interrupting connection for reason: "+e),this.interruptReasons_[e]=!0,this.realtime_?this.realtime_.close():(this.establishConnectionTimer_&&(clearTimeout(this.establishConnectionTimer_),this.establishConnectionTimer_=null),this.connected_&&this.onRealtimeDisconnect_())}resume(e){fJ("Resuming connection for reason: "+e),delete this.interruptReasons_[e],(0,S.xb)(this.interruptReasons_)&&(this.reconnectDelay_=1e3,this.realtime_||this.scheduleConnect_(0))}handleTimestamp_(e){let t=e-new Date().getTime();this.onServerInfoUpdate_({serverTimeOffset:t})}cancelSentTransactions_(){for(let e=0;e<this.outstandingPuts_.length;e++){let t=this.outstandingPuts_[e];t&&"h"in t.request&&t.queued&&(t.onComplete&&t.onComplete("disconnect"),delete this.outstandingPuts_[e],this.outstandingPutCount_--)}0===this.outstandingPutCount_&&(this.outstandingPuts_=[])}onListenRevoked_(e,t){let n;n=t?t.map(e=>pt(e)).join("$"):"default";let r=this.removeListen_(e,n);r&&r.onComplete&&r.onComplete("permission_denied")}removeListen_(e,t){let n;let r=new pO(e).toString();if(this.listens.has(r)){let i=this.listens.get(r);n=i.get(t),i.delete(t),0===i.size&&this.listens.delete(r)}else n=void 0;return n}onAuthRevoked_(e,t){fJ("Auth token revoked: "+e+"/"+t),this.authToken_=null,this.forceTokenRefresh_=!0,this.realtime_.close(),("invalid_token"===e||"permission_denied"===e)&&(this.invalidAuthTokenCount_++,this.invalidAuthTokenCount_>=3&&(this.reconnectDelay_=3e4,this.authTokenProvider_.notifyForInvalidToken()))}onAppCheckRevoked_(e,t){fJ("App check token revoked: "+e+"/"+t),this.appCheckToken_=null,this.forceTokenRefresh_=!0,("invalid_token"===e||"permission_denied"===e)&&(this.invalidAppCheckTokenCount_++,this.invalidAppCheckTokenCount_>=3&&this.appCheckTokenProvider_.notifyForInvalidToken())}onSecurityDebugPacket_(e){this.securityDebugCallback_?this.securityDebugCallback_(e):"msg"in e&&console.log("FIREBASE: "+e.msg.replace("\n","\nFIREBASE: "))}restoreState_(){for(let e of(this.tryAuth(),this.tryAppCheck(),this.listens.values()))for(let t of e.values())this.sendListen_(t);for(let n=0;n<this.outstandingPuts_.length;n++)this.outstandingPuts_[n]&&this.sendPut_(n);for(;this.onDisconnectRequestQueue_.length;){let r=this.onDisconnectRequestQueue_.shift();this.sendOnDisconnect_(r.action,r.pathString,r.data,r.onComplete)}for(let i=0;i<this.outstandingGets_.length;i++)this.outstandingGets_[i]&&this.sendGet_(i)}sendConnectStats_(){let e={},t="js";(0,S.Yr)()&&(t=this.repoInfo_.nodeAdmin?"admin_node":"node"),e["sdk."+t+"."+fU.replace(/\./g,"-")]=1,(0,S.uI)()?e["framework.cordova"]=1:(0,S.b$)()&&(e["framework.reactnative"]=1),this.reportStats(e)}shouldReconnect_(){let e=pD.getInstance().currentlyOnline();return(0,S.xb)(this.interruptReasons_)&&e}}pY.nextPersistentConnectionId_=0,pY.nextConnectionId_=0;/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class pX{constructor(e,t){this.name=e,this.node=t}static Wrap(e,t){return new pX(e,t)}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class pJ{getCompare(){return this.compare.bind(this)}indexedValueChanged(e,t){let n=new pX(f5,e),r=new pX(f5,t);return 0!==this.compare(n,r)}minPost(){return pX.MIN}}class pZ extends pJ{static get __EMPTY_NODE(){return r}static set __EMPTY_NODE(e){r=e}compare(e,t){return f9(e.name,t.name)}isDefinedOn(e){throw(0,S.g5)("KeyIndex.isDefinedOn not expected to be called.")}indexedValueChanged(e,t){return!1}minPost(){return pX.MIN}maxPost(){return new pX(f8,r)}makePost(e,t){return(0,S.hu)("string"==typeof e,"KeyIndex indexValue must always be a string."),new pX(e,r)}toString(){return".key"}}let p0=new pZ;/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class p1{constructor(e,t,n,r,i=null){this.isReverse_=r,this.resultGenerator_=i,this.nodeStack_=[];let s=1;for(;!e.isEmpty();)if(s=t?n(e.key,t):1,r&&(s*=-1),s<0)e=this.isReverse_?e.left:e.right;else if(0===s){this.nodeStack_.push(e);break}else this.nodeStack_.push(e),e=this.isReverse_?e.right:e.left}getNext(){let e;if(0===this.nodeStack_.length)return null;let t=this.nodeStack_.pop();if(e=this.resultGenerator_?this.resultGenerator_(t.key,t.value):{key:t.key,value:t.value},this.isReverse_)for(t=t.left;!t.isEmpty();)this.nodeStack_.push(t),t=t.right;else for(t=t.right;!t.isEmpty();)this.nodeStack_.push(t),t=t.left;return e}hasNext(){return this.nodeStack_.length>0}peek(){if(0===this.nodeStack_.length)return null;let e=this.nodeStack_[this.nodeStack_.length-1];return this.resultGenerator_?this.resultGenerator_(e.key,e.value):{key:e.key,value:e.value}}}class p2{constructor(e,t,n,r,i){this.key=e,this.value=t,this.color=null!=n?n:p2.RED,this.left=null!=r?r:p3.EMPTY_NODE,this.right=null!=i?i:p3.EMPTY_NODE}copy(e,t,n,r,i){return new p2(null!=e?e:this.key,null!=t?t:this.value,null!=n?n:this.color,null!=r?r:this.left,null!=i?i:this.right)}count(){return this.left.count()+1+this.right.count()}isEmpty(){return!1}inorderTraversal(e){return this.left.inorderTraversal(e)||!!e(this.key,this.value)||this.right.inorderTraversal(e)}reverseTraversal(e){return this.right.reverseTraversal(e)||e(this.key,this.value)||this.left.reverseTraversal(e)}min_(){return this.left.isEmpty()?this:this.left.min_()}minKey(){return this.min_().key}maxKey(){return this.right.isEmpty()?this.key:this.right.maxKey()}insert(e,t,n){let r=this,i=n(e,r.key);return(r=i<0?r.copy(null,null,null,r.left.insert(e,t,n),null):0===i?r.copy(null,t,null,null,null):r.copy(null,null,null,null,r.right.insert(e,t,n))).fixUp_()}removeMin_(){if(this.left.isEmpty())return p3.EMPTY_NODE;let e=this;return e.left.isRed_()||e.left.left.isRed_()||(e=e.moveRedLeft_()),(e=e.copy(null,null,null,e.left.removeMin_(),null)).fixUp_()}remove(e,t){let n,r;if(n=this,0>t(e,n.key))n.left.isEmpty()||n.left.isRed_()||n.left.left.isRed_()||(n=n.moveRedLeft_()),n=n.copy(null,null,null,n.left.remove(e,t),null);else{if(n.left.isRed_()&&(n=n.rotateRight_()),n.right.isEmpty()||n.right.isRed_()||n.right.left.isRed_()||(n=n.moveRedRight_()),0===t(e,n.key)){if(n.right.isEmpty())return p3.EMPTY_NODE;r=n.right.min_(),n=n.copy(r.key,r.value,null,null,n.right.removeMin_())}n=n.copy(null,null,null,null,n.right.remove(e,t))}return n.fixUp_()}isRed_(){return this.color}fixUp_(){let e=this;return e.right.isRed_()&&!e.left.isRed_()&&(e=e.rotateLeft_()),e.left.isRed_()&&e.left.left.isRed_()&&(e=e.rotateRight_()),e.left.isRed_()&&e.right.isRed_()&&(e=e.colorFlip_()),e}moveRedLeft_(){let e=this.colorFlip_();return e.right.left.isRed_()&&(e=(e=(e=e.copy(null,null,null,null,e.right.rotateRight_())).rotateLeft_()).colorFlip_()),e}moveRedRight_(){let e=this.colorFlip_();return e.left.left.isRed_()&&(e=(e=e.rotateRight_()).colorFlip_()),e}rotateLeft_(){let e=this.copy(null,null,p2.RED,null,this.right.left);return this.right.copy(null,null,this.color,e,null)}rotateRight_(){let e=this.copy(null,null,p2.RED,this.left.right,null);return this.left.copy(null,null,this.color,null,e)}colorFlip_(){let e=this.left.copy(null,null,!this.left.color,null,null),t=this.right.copy(null,null,!this.right.color,null,null);return this.copy(null,null,!this.color,e,t)}checkMaxDepth_(){let e=this.check_();return Math.pow(2,e)<=this.count()+1}check_(){if(this.isRed_()&&this.left.isRed_())throw Error("Red node has red child("+this.key+","+this.value+")");if(this.right.isRed_())throw Error("Right child of ("+this.key+","+this.value+") is red");let e=this.left.check_();if(e===this.right.check_())return e+(this.isRed_()?0:1);throw Error("Black depths differ")}}p2.RED=!0,p2.BLACK=!1;class p3{constructor(e,t=p3.EMPTY_NODE){this.comparator_=e,this.root_=t}insert(e,t){return new p3(this.comparator_,this.root_.insert(e,t,this.comparator_).copy(null,null,p2.BLACK,null,null))}remove(e){return new p3(this.comparator_,this.root_.remove(e,this.comparator_).copy(null,null,p2.BLACK,null,null))}get(e){let t;let n=this.root_;for(;!n.isEmpty();){if(0===(t=this.comparator_(e,n.key)))return n.value;t<0?n=n.left:t>0&&(n=n.right)}return null}getPredecessorKey(e){let t,n=this.root_,r=null;for(;!n.isEmpty();){if(0===(t=this.comparator_(e,n.key))){if(n.left.isEmpty()){if(r)return r.key;return null}for(n=n.left;!n.right.isEmpty();)n=n.right;return n.key}t<0?n=n.left:t>0&&(r=n,n=n.right)}throw Error("Attempted to find predecessor key for a nonexistent key.  What gives?")}isEmpty(){return this.root_.isEmpty()}count(){return this.root_.count()}minKey(){return this.root_.minKey()}maxKey(){return this.root_.maxKey()}inorderTraversal(e){return this.root_.inorderTraversal(e)}reverseTraversal(e){return this.root_.reverseTraversal(e)}getIterator(e){return new p1(this.root_,null,this.comparator_,!1,e)}getIteratorFrom(e,t){return new p1(this.root_,e,this.comparator_,!1,t)}getReverseIteratorFrom(e,t){return new p1(this.root_,e,this.comparator_,!0,t)}getReverseIterator(e){return new p1(this.root_,null,this.comparator_,!0,e)}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function p4(e,t){return f9(e.name,t.name)}function p6(e,t){return f9(e,t)}p3.EMPTY_NODE=new class{copy(e,t,n,r,i){return this}insert(e,t,n){return new p2(e,t,null)}remove(e,t){return this}count(){return 0}isEmpty(){return!0}inorderTraversal(e){return!1}reverseTraversal(e){return!1}minKey(){return null}maxKey(){return null}check_(){return 0}isRed_(){return!1}};let p5=function(e){return"number"==typeof e?"number:"+pi(e):"string:"+e},p8=function(e){if(e.isLeafNode()){let t=e.val();(0,S.hu)("string"==typeof t||"number"==typeof t||"object"==typeof t&&(0,S.r3)(t,".sv"),"Priority must be a string or number.")}else(0,S.hu)(e===i||e.isEmpty(),"priority of unexpected type.");(0,S.hu)(e===i||e.getPriority().isEmpty(),"Priority nodes can't have a priority of their own.")};class p9{constructor(e,t=p9.__childrenNodeConstructor.EMPTY_NODE){this.value_=e,this.priorityNode_=t,this.lazyHash_=null,(0,S.hu)(void 0!==this.value_&&null!==this.value_,"LeafNode shouldn't be created with null/undefined value."),p8(this.priorityNode_)}static set __childrenNodeConstructor(e){s=e}static get __childrenNodeConstructor(){return s}isLeafNode(){return!0}getPriority(){return this.priorityNode_}updatePriority(e){return new p9(this.value_,e)}getImmediateChild(e){return".priority"===e?this.priorityNode_:p9.__childrenNodeConstructor.EMPTY_NODE}getChild(e){return pB(e)?this:".priority"===pL(e)?this.priorityNode_:p9.__childrenNodeConstructor.EMPTY_NODE}hasChild(){return!1}getPredecessorChildName(e,t){return null}updateImmediateChild(e,t){return".priority"===e?this.updatePriority(t):t.isEmpty()&&".priority"!==e?this:p9.__childrenNodeConstructor.EMPTY_NODE.updateImmediateChild(e,t).updatePriority(this.priorityNode_)}updateChild(e,t){let n=pL(e);return null===n?t:t.isEmpty()&&".priority"!==n?this:((0,S.hu)(".priority"!==n||1===pM(e),".priority must be the last token in a path"),this.updateImmediateChild(n,p9.__childrenNodeConstructor.EMPTY_NODE.updateChild(pj(e),t)))}isEmpty(){return!1}numChildren(){return 0}forEachChild(e,t){return!1}val(e){return e&&!this.getPriority().isEmpty()?{".value":this.getValue(),".priority":this.getPriority().val()}:this.getValue()}hash(){if(null===this.lazyHash_){let e="";this.priorityNode_.isEmpty()||(e+="priority:"+p5(this.priorityNode_.val())+":");let t=typeof this.value_;e+=t+":","number"===t?e+=pi(this.value_):e+=this.value_,this.lazyHash_=fH(e)}return this.lazyHash_}getValue(){return this.value_}compareTo(e){return e===p9.__childrenNodeConstructor.EMPTY_NODE?1:e instanceof p9.__childrenNodeConstructor?-1:((0,S.hu)(e.isLeafNode(),"Unknown node type"),this.compareToLeafNode_(e))}compareToLeafNode_(e){let t=typeof e.value_,n=typeof this.value_,r=p9.VALUE_TYPE_ORDER.indexOf(t),i=p9.VALUE_TYPE_ORDER.indexOf(n);return((0,S.hu)(r>=0,"Unknown leaf type: "+t),(0,S.hu)(i>=0,"Unknown leaf type: "+n),r!==i)?i-r:"object"===n?0:this.value_<e.value_?-1:this.value_===e.value_?0:1}withIndex(){return this}isIndexed(){return!0}equals(e){return e===this||!!e.isLeafNode()&&this.value_===e.value_&&this.priorityNode_.equals(e.priorityNode_)}}p9.VALUE_TYPE_ORDER=["object","boolean","number","string"];let p7=new class extends pJ{compare(e,t){let n=e.node.getPriority(),r=t.node.getPriority(),i=n.compareTo(r);return 0===i?f9(e.name,t.name):i}isDefinedOn(e){return!e.getPriority().isEmpty()}indexedValueChanged(e,t){return!e.getPriority().equals(t.getPriority())}minPost(){return pX.MIN}maxPost(){return new pX(f8,new p9("[PRIORITY-POST]",a))}makePost(e,t){let n=o(e);return new pX(t,new p9("[PRIORITY-POST]",n))}toString(){return".priority"}},me=Math.log(2);class mt{constructor(e){this.count=parseInt(Math.log(e+1)/me,10),this.current_=this.count-1;let t=parseInt(Array(this.count+1).join("1"),2);this.bits_=e+1&t}nextBitIsOne(){let e=!(this.bits_&1<<this.current_);return this.current_--,e}}let mn=function(e,t,n,r){e.sort(t);let i=function(t,r){let s,o;let a=r-t;if(0===a)return null;if(1===a)return s=e[t],o=n?n(s):s,new p2(o,s.node,p2.BLACK,null,null);{let l=parseInt(a/2,10)+t,u=i(t,l),c=i(l+1,r);return s=e[l],o=n?n(s):s,new p2(o,s.node,p2.BLACK,u,c)}},s=new mt(e.length),o=function(t){let r=null,s=null,o=e.length,a=function(t,r){let s=o-t,a=o;o-=t;let u=i(s+1,a),c=e[s],h=n?n(c):c;l(new p2(h,c.node,r,null,u))},l=function(e){r?(r.left=e,r=e):(s=e,r=e)};for(let u=0;u<t.count;++u){let c=t.nextBitIsOne(),h=Math.pow(2,t.count-(u+1));c?a(h,p2.BLACK):(a(h,p2.BLACK),a(h,p2.RED))}return s}(s);return new p3(r||t,o)},mr={};class mi{constructor(e,t){this.indexes_=e,this.indexSet_=t}static get Default(){return(0,S.hu)(mr&&p7,"ChildrenNode.ts has not been loaded"),l=l||new mi({".priority":mr},{".priority":p7})}get(e){let t=(0,S.DV)(this.indexes_,e);if(!t)throw Error("No index defined for "+e);return t instanceof p3?t:null}hasIndex(e){return(0,S.r3)(this.indexSet_,e.toString())}addIndex(e,t){let n;(0,S.hu)(e!==p0,"KeyIndex always exists and isn't meant to be added to the IndexMap.");let r=[],i=!1,s=t.getIterator(pX.Wrap),o=s.getNext();for(;o;)i=i||e.isDefinedOn(o.node),r.push(o),o=s.getNext();n=i?mn(r,e.getCompare()):mr;let a=e.toString(),l=Object.assign({},this.indexSet_);l[a]=e;let u=Object.assign({},this.indexes_);return u[a]=n,new mi(u,l)}addToIndexes(e,t){let n=(0,S.UI)(this.indexes_,(n,r)=>{let i=(0,S.DV)(this.indexSet_,r);if((0,S.hu)(i,"Missing index implementation for "+r),n===mr){if(!i.isDefinedOn(e.node))return mr;{let s=[],o=t.getIterator(pX.Wrap),a=o.getNext();for(;a;)a.name!==e.name&&s.push(a),a=o.getNext();return s.push(e),mn(s,i.getCompare())}}{let l=t.get(e.name),u=n;return l&&(u=u.remove(new pX(e.name,l))),u.insert(e,e.node)}});return new mi(n,this.indexSet_)}removeFromIndexes(e,t){let n=(0,S.UI)(this.indexes_,n=>{if(n===mr)return n;{let r=t.get(e.name);return r?n.remove(new pX(e.name,r)):n}});return new mi(n,this.indexSet_)}}class ms{constructor(e,t,n){this.children_=e,this.priorityNode_=t,this.indexMap_=n,this.lazyHash_=null,this.priorityNode_&&p8(this.priorityNode_),this.children_.isEmpty()&&(0,S.hu)(!this.priorityNode_||this.priorityNode_.isEmpty(),"An empty node cannot have a priority")}static get EMPTY_NODE(){return u||(u=new ms(new p3(p6),null,mi.Default))}isLeafNode(){return!1}getPriority(){return this.priorityNode_||u}updatePriority(e){return this.children_.isEmpty()?this:new ms(this.children_,e,this.indexMap_)}getImmediateChild(e){if(".priority"===e)return this.getPriority();{let t=this.children_.get(e);return null===t?u:t}}getChild(e){let t=pL(e);return null===t?this:this.getImmediateChild(t).getChild(pj(e))}hasChild(e){return null!==this.children_.get(e)}updateImmediateChild(e,t){if((0,S.hu)(t,"We should always be passing snapshot nodes"),".priority"===e)return this.updatePriority(t);{let n,r;let i=new pX(e,t);t.isEmpty()?(n=this.children_.remove(e),r=this.indexMap_.removeFromIndexes(i,this.children_)):(n=this.children_.insert(e,t),r=this.indexMap_.addToIndexes(i,this.children_));let s=n.isEmpty()?u:this.priorityNode_;return new ms(n,s,r)}}updateChild(e,t){let n=pL(e);if(null===n)return t;{(0,S.hu)(".priority"!==pL(e)||1===pM(e),".priority must be the last token in a path");let r=this.getImmediateChild(n).updateChild(pj(e),t);return this.updateImmediateChild(n,r)}}isEmpty(){return this.children_.isEmpty()}numChildren(){return this.children_.count()}val(e){if(this.isEmpty())return null;let t={},n=0,r=0,i=!0;if(this.forEachChild(p7,(s,o)=>{t[s]=o.val(e),n++,i&&ms.INTEGER_REGEXP_.test(s)?r=Math.max(r,Number(s)):i=!1}),e||!i||!(r<2*n))return e&&!this.getPriority().isEmpty()&&(t[".priority"]=this.getPriority().val()),t;{let s=[];for(let o in t)s[o]=t[o];return s}}hash(){if(null===this.lazyHash_){let e="";this.getPriority().isEmpty()||(e+="priority:"+p5(this.getPriority().val())+":"),this.forEachChild(p7,(t,n)=>{let r=n.hash();""!==r&&(e+=":"+t+":"+r)}),this.lazyHash_=""===e?"":fH(e)}return this.lazyHash_}getPredecessorChildName(e,t,n){let r=this.resolveIndex_(n);if(!r)return this.children_.getPredecessorKey(e);{let i=r.getPredecessorKey(new pX(e,t));return i?i.name:null}}getFirstChildName(e){let t=this.resolveIndex_(e);if(!t)return this.children_.minKey();{let n=t.minKey();return n&&n.name}}getFirstChild(e){let t=this.getFirstChildName(e);return t?new pX(t,this.children_.get(t)):null}getLastChildName(e){let t=this.resolveIndex_(e);if(!t)return this.children_.maxKey();{let n=t.maxKey();return n&&n.name}}getLastChild(e){let t=this.getLastChildName(e);return t?new pX(t,this.children_.get(t)):null}forEachChild(e,t){let n=this.resolveIndex_(e);return n?n.inorderTraversal(e=>t(e.name,e.node)):this.children_.inorderTraversal(t)}getIterator(e){return this.getIteratorFrom(e.minPost(),e)}getIteratorFrom(e,t){let n=this.resolveIndex_(t);if(n)return n.getIteratorFrom(e,e=>e);{let r=this.children_.getIteratorFrom(e.name,pX.Wrap),i=r.peek();for(;null!=i&&0>t.compare(i,e);)r.getNext(),i=r.peek();return r}}getReverseIterator(e){return this.getReverseIteratorFrom(e.maxPost(),e)}getReverseIteratorFrom(e,t){let n=this.resolveIndex_(t);if(n)return n.getReverseIteratorFrom(e,e=>e);{let r=this.children_.getReverseIteratorFrom(e.name,pX.Wrap),i=r.peek();for(;null!=i&&t.compare(i,e)>0;)r.getNext(),i=r.peek();return r}}compareTo(e){return this.isEmpty()?e.isEmpty()?0:-1:e.isLeafNode()||e.isEmpty()?1:e===mo?-1:0}withIndex(e){if(e===p0||this.indexMap_.hasIndex(e))return this;{let t=this.indexMap_.addIndex(e,this.children_);return new ms(this.children_,this.priorityNode_,t)}}isIndexed(e){return e===p0||this.indexMap_.hasIndex(e)}equals(e){if(e===this)return!0;if(e.isLeafNode()||!this.getPriority().equals(e.getPriority())||this.children_.count()!==e.children_.count())return!1;{let t=this.getIterator(p7),n=e.getIterator(p7),r=t.getNext(),i=n.getNext();for(;r&&i;){if(r.name!==i.name||!r.node.equals(i.node))return!1;r=t.getNext(),i=n.getNext()}return null===r&&null===i}}resolveIndex_(e){return e===p0?null:this.indexMap_.get(e.toString())}}ms.INTEGER_REGEXP_=/^(0|[1-9]\d*)$/;let mo=new class extends ms{constructor(){super(new p3(p6),ms.EMPTY_NODE,mi.Default)}compareTo(e){return e===this?0:1}equals(e){return e===this}getPriority(){return this}getImmediateChild(e){return ms.EMPTY_NODE}isEmpty(){return!1}};function ma(e,t=null){if(null===e)return ms.EMPTY_NODE;if("object"==typeof e&&".priority"in e&&(t=e[".priority"]),(0,S.hu)(null===t||"string"==typeof t||"number"==typeof t||"object"==typeof t&&".sv"in t,"Invalid priority type found: "+typeof t),"object"==typeof e&&".value"in e&&null!==e[".value"]&&(e=e[".value"]),"object"!=typeof e||".sv"in e){let n=e;return new p9(n,ma(t))}if(e instanceof Array){let r=ms.EMPTY_NODE;return pr(e,(t,n)=>{if((0,S.r3)(e,t)&&"."!==t.substring(0,1)){let i=ma(n);(i.isLeafNode()||!i.isEmpty())&&(r=r.updateImmediateChild(t,i))}}),r.updatePriority(ma(t))}{let i=[],s=!1,o=e;if(pr(o,(e,t)=>{if("."!==e.substring(0,1)){let n=ma(t);n.isEmpty()||(s=s||!n.getPriority().isEmpty(),i.push(new pX(e,n)))}}),0===i.length)return ms.EMPTY_NODE;let a=mn(i,p4,e=>e.name,p6);if(!s)return new ms(a,ma(t),mi.Default);{let l=mn(i,p7.getCompare());return new ms(a,ma(t),new mi({".priority":l},{".priority":p7}))}}}Object.defineProperties(pX,{MIN:{value:new pX(f5,ms.EMPTY_NODE)},MAX:{value:new pX(f8,mo)}}),pZ.__EMPTY_NODE=ms.EMPTY_NODE,p9.__childrenNodeConstructor=ms,i=mo,a=mo,o=ma;/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class ml extends pJ{constructor(e){super(),this.indexPath_=e,(0,S.hu)(!pB(e)&&".priority"!==pL(e),"Can't create PathIndex with empty path or .priority key")}extractChild(e){return e.getChild(this.indexPath_)}isDefinedOn(e){return!e.getChild(this.indexPath_).isEmpty()}compare(e,t){let n=this.extractChild(e.node),r=this.extractChild(t.node),i=n.compareTo(r);return 0===i?f9(e.name,t.name):i}makePost(e,t){let n=ma(e),r=ms.EMPTY_NODE.updateChild(this.indexPath_,n);return new pX(t,r)}maxPost(){let e=ms.EMPTY_NODE.updateChild(this.indexPath_,mo);return new pX(f8,e)}toString(){return pU(this.indexPath_,0).join("/")}}let mu=new /**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class extends pJ{compare(e,t){let n=e.node.compareTo(t.node);return 0===n?f9(e.name,t.name):n}isDefinedOn(e){return!0}indexedValueChanged(e,t){return!e.equals(t)}minPost(){return pX.MIN}maxPost(){return pX.MAX}makePost(e,t){let n=ma(e);return new pX(t,n)}toString(){return".value"}};function mc(e,t,n){return{type:"child_changed",snapshotNode:t,childName:e,oldSnap:n}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class mh{constructor(){this.limitSet_=!1,this.startSet_=!1,this.startNameSet_=!1,this.startAfterSet_=!1,this.endSet_=!1,this.endNameSet_=!1,this.endBeforeSet_=!1,this.limit_=0,this.viewFrom_="",this.indexStartValue_=null,this.indexStartName_="",this.indexEndValue_=null,this.indexEndName_="",this.index_=p7}hasStart(){return this.startSet_}hasStartAfter(){return this.startAfterSet_}hasEndBefore(){return this.endBeforeSet_}isViewFromLeft(){return""===this.viewFrom_?this.startSet_:"l"===this.viewFrom_}getIndexStartValue(){return(0,S.hu)(this.startSet_,"Only valid if start has been set"),this.indexStartValue_}getIndexStartName(){return((0,S.hu)(this.startSet_,"Only valid if start has been set"),this.startNameSet_)?this.indexStartName_:f5}hasEnd(){return this.endSet_}getIndexEndValue(){return(0,S.hu)(this.endSet_,"Only valid if end has been set"),this.indexEndValue_}getIndexEndName(){return((0,S.hu)(this.endSet_,"Only valid if end has been set"),this.endNameSet_)?this.indexEndName_:f8}hasLimit(){return this.limitSet_}hasAnchoredLimit(){return this.limitSet_&&""!==this.viewFrom_}getLimit(){return(0,S.hu)(this.limitSet_,"Only valid if limit has been set"),this.limit_}getIndex(){return this.index_}loadsAllData(){return!(this.startSet_||this.endSet_||this.limitSet_)}isDefault(){return this.loadsAllData()&&this.index_===p7}copy(){let e=new mh;return e.limitSet_=this.limitSet_,e.limit_=this.limit_,e.startSet_=this.startSet_,e.indexStartValue_=this.indexStartValue_,e.startNameSet_=this.startNameSet_,e.indexStartName_=this.indexStartName_,e.endSet_=this.endSet_,e.indexEndValue_=this.indexEndValue_,e.endNameSet_=this.endNameSet_,e.indexEndName_=this.indexEndName_,e.index_=this.index_,e.viewFrom_=this.viewFrom_,e}}function md(e){let t;let n={};return e.isDefault()||(e.index_===p7?t="$priority":e.index_===mu?t="$value":e.index_===p0?t="$key":((0,S.hu)(e.index_ instanceof ml,"Unrecognized index type!"),t=e.index_.toString()),n.orderBy=(0,S.Wl)(t),e.startSet_&&(n.startAt=(0,S.Wl)(e.indexStartValue_),e.startNameSet_&&(n.startAt+=","+(0,S.Wl)(e.indexStartName_))),e.endSet_&&(n.endAt=(0,S.Wl)(e.indexEndValue_),e.endNameSet_&&(n.endAt+=","+(0,S.Wl)(e.indexEndName_))),e.limitSet_&&(e.isViewFromLeft()?n.limitToFirst=e.limit_:n.limitToLast=e.limit_)),n}function mf(e){let t={};if(e.startSet_&&(t.sp=e.indexStartValue_,e.startNameSet_&&(t.sn=e.indexStartName_)),e.endSet_&&(t.ep=e.indexEndValue_,e.endNameSet_&&(t.en=e.indexEndName_)),e.limitSet_){t.l=e.limit_;let n=e.viewFrom_;""===n&&(n=e.isViewFromLeft()?"l":"r"),t.vf=n}return e.index_!==p7&&(t.i=e.index_.toString()),t}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class mp extends pA{constructor(e,t,n,r){super(),this.repoInfo_=e,this.onDataUpdate_=t,this.authTokenProvider_=n,this.appCheckTokenProvider_=r,this.log_=fZ("p:rest:"),this.listens_={}}reportStats(e){throw Error("Method not implemented.")}static getListenId_(e,t){return void 0!==t?"tag$"+t:((0,S.hu)(e._queryParams.isDefault(),"should have a tag if it's not a default query."),e._path.toString())}listen(e,t,n,r){let i=e._path.toString();this.log_("Listen called for "+i+" "+e._queryIdentifier);let s=mp.getListenId_(e,n),o={};this.listens_[s]=o;let a=md(e._queryParams);this.restRequest_(i+".json",a,(e,t)=>{let a=t;404===e&&(a=null,e=null),null===e&&this.onDataUpdate_(i,a,!1,n),(0,S.DV)(this.listens_,s)===o&&r(e?401===e?"permission_denied":"rest_error:"+e:"ok",null)})}unlisten(e,t){let n=mp.getListenId_(e,t);delete this.listens_[n]}get(e){let t=md(e._queryParams),n=e._path.toString(),r=new S.BH;return this.restRequest_(n+".json",t,(e,t)=>{let i=t;404===e&&(i=null,e=null),null===e?(this.onDataUpdate_(n,i,!1,null),r.resolve(i)):r.reject(Error(i))}),r.promise}refreshAuthToken(e){}restRequest_(e,t={},n){return t.format="export",Promise.all([this.authTokenProvider_.getToken(!1),this.appCheckTokenProvider_.getToken(!1)]).then(([r,i])=>{r&&r.accessToken&&(t.auth=r.accessToken),i&&i.token&&(t.ac=i.token);let s=(this.repoInfo_.secure?"https://":"http://")+this.repoInfo_.host+e+"?ns="+this.repoInfo_.namespace+(0,S.xO)(t);this.log_("Sending REST request for "+s);let o=new XMLHttpRequest;o.onreadystatechange=()=>{if(n&&4===o.readyState){this.log_("REST Response for "+s+" received. status:",o.status,"response:",o.responseText);let e=null;if(o.status>=200&&o.status<300){try{e=(0,S.cI)(o.responseText)}catch(t){f2("Failed to parse JSON response for "+s+": "+o.responseText)}n(null,e)}else 401!==o.status&&404!==o.status&&f2("Got unsuccessful REST response for "+s+" Status: "+o.status),n(o.status);n=null}},o.open("GET",s,!0),o.send()})}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class mm{constructor(){this.rootNode_=ms.EMPTY_NODE}getNode(e){return this.rootNode_.getChild(e)}updateSnapshot(e,t){this.rootNode_=this.rootNode_.updateChild(e,t)}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function mg(){return{value:null,children:new Map}}function my(e,t,n){null!==e.value?n(t,e.value):function(e,t){e.children.forEach((e,n)=>{t(n,e)})}(e,(e,r)=>{let i=new pO(t.toString()+"/"+e);my(r,i,n)})}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class mv{constructor(e){this.collection_=e,this.last_=null}get(){let e=this.collection_.get(),t=Object.assign({},e);return this.last_&&pr(this.last_,(e,n)=>{t[e]=t[e]-n}),this.last_=e,t}}class m_{constructor(e,t){this.server_=t,this.statsToReport_={},this.statsListener_=new mv(e),pu(this.reportStats_.bind(this),Math.floor(1e4+2e4*Math.random()))}reportStats_(){let e=this.statsListener_.get(),t={},n=!1;pr(e,(e,r)=>{r>0&&(0,S.r3)(this.statsToReport_,e)&&(t[e]=r,n=!0)}),n&&this.server_.reportStats(t),pu(this.reportStats_.bind(this),Math.floor(2*Math.random()*3e5))}}function mw(){return{fromUser:!0,fromServer:!1,queryId:null,tagged:!1}}function mb(){return{fromUser:!1,fromServer:!0,queryId:null,tagged:!1}}function mI(e){return{fromUser:!1,fromServer:!0,queryId:e,tagged:!0}}(g=E||(E={}))[g.OVERWRITE=0]="OVERWRITE",g[g.MERGE=1]="MERGE",g[g.ACK_USER_WRITE=2]="ACK_USER_WRITE",g[g.LISTEN_COMPLETE=3]="LISTEN_COMPLETE";/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class mT{constructor(e,t,n){this.path=e,this.affectedTree=t,this.revert=n,this.type=E.ACK_USER_WRITE,this.source=mw()}operationForChild(e){if(!pB(this.path))return(0,S.hu)(pL(this.path)===e,"operationForChild called for unrelated child."),new mT(pj(this.path),this.affectedTree,this.revert);if(null!=this.affectedTree.value)return(0,S.hu)(this.affectedTree.children.isEmpty(),"affectedTree should not have overlapping affected paths."),this;{let t=this.affectedTree.subtree(new pO(e));return new mT(pP(),t,this.revert)}}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class mE{constructor(e,t,n){this.source=e,this.path=t,this.snap=n,this.type=E.OVERWRITE}operationForChild(e){return pB(this.path)?new mE(this.source,pP(),this.snap.getImmediateChild(e)):new mE(this.source,pj(this.path),this.snap)}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class mS{constructor(e,t,n){this.source=e,this.path=t,this.children=n,this.type=E.MERGE}operationForChild(e){if(!pB(this.path))return(0,S.hu)(pL(this.path)===e,"Can't get a merge for a child not on the path of the operation"),new mS(this.source,pj(this.path),this.children);{let t=this.children.subtree(new pO(e));return t.isEmpty()?null:t.value?new mE(this.source,pP(),t.value):new mS(this.source,pP(),t)}}toString(){return"Operation("+this.path+": "+this.source.toString()+" merge: "+this.children.toString()+")"}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class mk{constructor(e,t,n){this.node_=e,this.fullyInitialized_=t,this.filtered_=n}isFullyInitialized(){return this.fullyInitialized_}isFiltered(){return this.filtered_}isCompleteForPath(e){if(pB(e))return this.isFullyInitialized()&&!this.filtered_;let t=pL(e);return this.isCompleteForChild(t)}isCompleteForChild(e){return this.isFullyInitialized()&&!this.filtered_||this.node_.hasChild(e)}getNode(){return this.node_}}function mx(e,t,n,r,i,s){let o=r.filter(e=>e.type===n);o.sort((t,n)=>(function(e,t,n){if(null==t.childName||null==n.childName)throw(0,S.g5)("Should only compare child_ events.");let r=new pX(t.childName,t.snapshotNode),i=new pX(n.childName,n.snapshotNode);return e.index_.compare(r,i)})(e,t,n)),o.forEach(n=>{var r;let o=("value"===(r=n).type||"child_removed"===r.type||(r.prevName=s.getPredecessorChildName(r.childName,r.snapshotNode,e.index_)),r);i.forEach(r=>{r.respondsTo(n.type)&&t.push(r.createEvent(o,e.query_))})})}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function mC(e,t){return{eventCache:e,serverCache:t}}function mN(e,t,n,r){return mC(new mk(t,n,r),e.serverCache)}function mA(e,t,n,r){return mC(e.eventCache,new mk(t,n,r))}function mR(e){return e.eventCache.isFullyInitialized()?e.eventCache.getNode():null}function mD(e){return e.serverCache.isFullyInitialized()?e.serverCache.getNode():null}let mO=()=>(c||(c=new p3(f7)),c);class mP{constructor(e,t=mO()){this.value=e,this.children=t}static fromObject(e){let t=new mP(null);return pr(e,(e,n)=>{t=t.set(new pO(e),n)}),t}isEmpty(){return null===this.value&&this.children.isEmpty()}findRootMostMatchingPathAndValue(e,t){if(null!=this.value&&t(this.value))return{path:pP(),value:this.value};if(pB(e))return null;{let n=pL(e),r=this.children.get(n);if(null===r)return null;{let i=r.findRootMostMatchingPathAndValue(pj(e),t);if(null==i)return null;{let s=pq(new pO(n),i.path);return{path:s,value:i.value}}}}}findRootMostValueAndPath(e){return this.findRootMostMatchingPathAndValue(e,()=>!0)}subtree(e){if(pB(e))return this;{let t=pL(e),n=this.children.get(t);return null!==n?n.subtree(pj(e)):new mP(null)}}set(e,t){if(pB(e))return new mP(t,this.children);{let n=pL(e),r=this.children.get(n)||new mP(null),i=r.set(pj(e),t),s=this.children.insert(n,i);return new mP(this.value,s)}}remove(e){if(pB(e))return this.children.isEmpty()?new mP(null):new mP(null,this.children);{let t=pL(e),n=this.children.get(t);if(!n)return this;{let r;let i=n.remove(pj(e));return(r=i.isEmpty()?this.children.remove(t):this.children.insert(t,i),null===this.value&&r.isEmpty())?new mP(null):new mP(this.value,r)}}}get(e){if(pB(e))return this.value;{let t=pL(e),n=this.children.get(t);return n?n.get(pj(e)):null}}setTree(e,t){if(pB(e))return t;{let n;let r=pL(e),i=this.children.get(r)||new mP(null),s=i.setTree(pj(e),t);return n=s.isEmpty()?this.children.remove(r):this.children.insert(r,s),new mP(this.value,n)}}fold(e){return this.fold_(pP(),e)}fold_(e,t){let n={};return this.children.inorderTraversal((r,i)=>{n[r]=i.fold_(pq(e,r),t)}),t(e,this.value,n)}findOnPath(e,t){return this.findOnPath_(e,pP(),t)}findOnPath_(e,t,n){let r=!!this.value&&n(t,this.value);if(r)return r;if(pB(e))return null;{let i=pL(e),s=this.children.get(i);return s?s.findOnPath_(pj(e),pq(t,i),n):null}}foreachOnPath(e,t){return this.foreachOnPath_(e,pP(),t)}foreachOnPath_(e,t,n){if(pB(e))return this;{this.value&&n(t,this.value);let r=pL(e),i=this.children.get(r);return i?i.foreachOnPath_(pj(e),pq(t,r),n):new mP(null)}}foreach(e){this.foreach_(pP(),e)}foreach_(e,t){this.children.inorderTraversal((n,r)=>{r.foreach_(pq(e,n),t)}),this.value&&t(e,this.value)}foreachChild(e){this.children.inorderTraversal((t,n)=>{n.value&&e(t,n.value)})}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class mL{constructor(e){this.writeTree_=e}static empty(){return new mL(new mP(null))}}function mM(e,t,n){if(pB(t))return new mL(new mP(n));{let r=e.writeTree_.findRootMostValueAndPath(t);if(null!=r){let i=r.path,s=r.value,o=p$(i,t);return s=s.updateChild(o,n),new mL(e.writeTree_.set(i,s))}{let a=new mP(n),l=e.writeTree_.setTree(t,a);return new mL(l)}}}function mj(e,t,n){let r=e;return pr(n,(e,n)=>{r=mM(r,pq(t,e),n)}),r}function mF(e,t){if(pB(t))return mL.empty();{let n=e.writeTree_.setTree(t,new mP(null));return new mL(n)}}function mU(e,t){return null!=mV(e,t)}function mV(e,t){let n=e.writeTree_.findRootMostValueAndPath(t);return null!=n?e.writeTree_.get(n.path).getChild(p$(n.path,t)):null}function mq(e){let t=[],n=e.writeTree_.value;return null!=n?n.isLeafNode()||n.forEachChild(p7,(e,n)=>{t.push(new pX(e,n))}):e.writeTree_.children.inorderTraversal((e,n)=>{null!=n.value&&t.push(new pX(e,n.value))}),t}function mB(e,t){if(pB(t))return e;{let n=mV(e,t);return new mL(null!=n?new mP(n):e.writeTree_.subtree(t))}}function m$(e){return e.writeTree_.isEmpty()}function mz(e,t){return function e(t,n,r){if(null!=n.value)return r.updateChild(t,n.value);{let i=null;return n.children.inorderTraversal((n,s)=>{".priority"===n?((0,S.hu)(null!==s.value,"Priority writes must always be leaf nodes"),i=s.value):r=e(pq(t,n),s,r)}),r.getChild(t).isEmpty()||null===i||(r=r.updateChild(pq(t,".priority"),i)),r}}(pP(),e.writeTree_,t)}function mG(e){return e.visible}function mW(e,t,n){let r=mL.empty();for(let i=0;i<e.length;++i){let s=e[i];if(t(s)){let o;let a=s.path;if(s.snap)pG(n,a)?r=mM(r,o=p$(n,a),s.snap):pG(a,n)&&(o=p$(a,n),r=mM(r,pP(),s.snap.getChild(o)));else if(s.children){if(pG(n,a))r=mj(r,o=p$(n,a),s.children);else if(pG(a,n)){if(pB(o=p$(a,n)))r=mj(r,pP(),s.children);else{let l=(0,S.DV)(s.children,pL(o));if(l){let u=l.getChild(pj(o));r=mM(r,pP(),u)}}}}else throw(0,S.g5)("WriteRecord should have .snap or .children")}}return r}function mH(e,t,n,r,i){if(r||i){let s=mB(e.visibleWrites,t);if(!i&&m$(s))return n;if(!i&&null==n&&!mU(s,pP()))return null;{let o=mW(e.allWrites,function(e){return(e.visible||i)&&(!r||!~r.indexOf(e.writeId))&&(pG(e.path,t)||pG(t,e.path))},t),a=n||ms.EMPTY_NODE;return mz(o,a)}}{let l=mV(e.visibleWrites,t);if(null!=l)return l;{let u=mB(e.visibleWrites,t);if(m$(u))return n;if(null==n&&!mU(u,pP()))return null;{let c=n||ms.EMPTY_NODE;return mz(u,c)}}}}function mK(e,t,n,r){return mH(e.writeTree,e.treePath,t,n,r)}function mQ(e,t){return function(e,t,n){let r=ms.EMPTY_NODE,i=mV(e.visibleWrites,t);if(i)return i.isLeafNode()||i.forEachChild(p7,(e,t)=>{r=r.updateImmediateChild(e,t)}),r;if(n){let s=mB(e.visibleWrites,t);return n.forEachChild(p7,(e,t)=>{let n=mz(mB(s,new pO(e)),t);r=r.updateImmediateChild(e,n)}),mq(s).forEach(e=>{r=r.updateImmediateChild(e.name,e.node)}),r}{let o=mB(e.visibleWrites,t);return mq(o).forEach(e=>{r=r.updateImmediateChild(e.name,e.node)}),r}}(e.writeTree,e.treePath,t)}function mY(e,t,n,r){return function(e,t,n,r,i){(0,S.hu)(r||i,"Either existingEventSnap or existingServerSnap must exist");let s=pq(t,n);if(mU(e.visibleWrites,s))return null;{let o=mB(e.visibleWrites,s);return m$(o)?i.getChild(n):mz(o,i.getChild(n))}}(e.writeTree,e.treePath,t,n,r)}function mX(e,t){var n,r;return n=e.writeTree,r=pq(e.treePath,t),mV(n.visibleWrites,r)}function mJ(e,t,n){return function(e,t,n,r){let i=pq(t,n),s=mV(e.visibleWrites,i);if(null!=s)return s;if(!r.isCompleteForChild(n))return null;{let o=mB(e.visibleWrites,i);return mz(o,r.getNode().getImmediateChild(n))}}(e.writeTree,e.treePath,t,n)}function mZ(e,t){return m0(pq(e.treePath,t),e.writeTree)}function m0(e,t){return{treePath:e,writeTree:t}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class m1{constructor(){this.changeMap=new Map}trackChildChange(e){let t=e.type,n=e.childName;(0,S.hu)("child_added"===t||"child_changed"===t||"child_removed"===t,"Only child changes supported for tracking"),(0,S.hu)(".priority"!==n,"Only non-priority child changes can be tracked.");let r=this.changeMap.get(n);if(r){var i,s;let o=r.type;if("child_added"===t&&"child_removed"===o)this.changeMap.set(n,mc(n,e.snapshotNode,r.snapshotNode));else if("child_removed"===t&&"child_added"===o)this.changeMap.delete(n);else if("child_removed"===t&&"child_changed"===o)this.changeMap.set(n,(i=r.oldSnap,{type:"child_removed",snapshotNode:i,childName:n}));else if("child_changed"===t&&"child_added"===o)this.changeMap.set(n,(s=e.snapshotNode,{type:"child_added",snapshotNode:s,childName:n}));else if("child_changed"===t&&"child_changed"===o)this.changeMap.set(n,mc(n,e.snapshotNode,r.oldSnap));else throw(0,S.g5)("Illegal combination of changes: "+e+" occurred after "+r)}else this.changeMap.set(n,e)}getChanges(){return Array.from(this.changeMap.values())}}let m2=new /**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class{getCompleteChild(e){return null}getChildAfterChild(e,t,n){return null}};class m3{constructor(e,t,n=null){this.writes_=e,this.viewCache_=t,this.optCompleteServerCache_=n}getCompleteChild(e){let t=this.viewCache_.eventCache;if(t.isCompleteForChild(e))return t.getNode().getImmediateChild(e);{let n=null!=this.optCompleteServerCache_?new mk(this.optCompleteServerCache_,!0,!1):this.viewCache_.serverCache;return mJ(this.writes_,e,n)}}getChildAfterChild(e,t,n){var r;let i=null!=this.optCompleteServerCache_?this.optCompleteServerCache_:mD(this.viewCache_),s=function(e,t,n,r,i,s,o){let a;let l=mB(e.visibleWrites,t),u=mV(l,pP());if(null!=u)a=u;else{if(null==n)return[];a=mz(l,n)}if((a=a.withIndex(o)).isEmpty()||a.isLeafNode())return[];{let c=[],h=o.getCompare(),d=s?a.getReverseIteratorFrom(r,o):a.getIteratorFrom(r,o),f=d.getNext();for(;f&&c.length<1;)0!==h(f,r)&&c.push(f),f=d.getNext();return c}}((r=this.writes_).writeTree,r.treePath,i,t,0,n,e);return 0===s.length?null:s[0]}}function m4(e,t,n,r,i,s){let o=t.eventCache;if(null!=mX(r,n))return t;{let a,l;if(pB(n)){if((0,S.hu)(t.serverCache.isFullyInitialized(),"If change path is empty, we must have complete server data"),t.serverCache.isFiltered()){let u=mD(t),c=u instanceof ms?u:ms.EMPTY_NODE,h=mQ(r,c);a=e.filter.updateFullNode(t.eventCache.getNode(),h,s)}else{let d=mK(r,mD(t));a=e.filter.updateFullNode(t.eventCache.getNode(),d,s)}}else{let f=pL(n);if(".priority"===f){(0,S.hu)(1===pM(n),"Can't have a priority with additional path components");let p=o.getNode();l=t.serverCache.getNode();let m=mY(r,n,p,l);a=null!=m?e.filter.updatePriority(p,m):o.getNode()}else{let g;let y=pj(n);if(o.isCompleteForChild(f)){l=t.serverCache.getNode();let v=mY(r,n,o.getNode(),l);g=null!=v?o.getNode().getImmediateChild(f).updateChild(y,v):o.getNode().getImmediateChild(f)}else g=mJ(r,f,t.serverCache);a=null!=g?e.filter.updateChild(o.getNode(),f,g,y,i,s):o.getNode()}}return mN(t,a,o.isFullyInitialized()||pB(n),e.filter.filtersNodes())}}function m6(e,t,n,r,i,s,o,a){let l;let u=t.serverCache,c=o?e.filter:e.filter.getIndexedFilter();if(pB(n))l=c.updateFullNode(u.getNode(),r,null);else if(c.filtersNodes()&&!u.isFiltered()){let h=u.getNode().updateChild(n,r);l=c.updateFullNode(u.getNode(),h,null)}else{let d=pL(n);if(!u.isCompleteForPath(n)&&pM(n)>1)return t;let f=pj(n),p=u.getNode().getImmediateChild(d),m=p.updateChild(f,r);l=".priority"===d?c.updatePriority(u.getNode(),m):c.updateChild(u.getNode(),d,m,f,m2,null)}let g=mA(t,l,u.isFullyInitialized()||pB(n),c.filtersNodes()),y=new m3(i,g,s);return m4(e,g,n,i,y,a)}function m5(e,t,n,r,i,s,o){let a,l;let u=t.eventCache,c=new m3(i,t,s);if(pB(n))l=e.filter.updateFullNode(t.eventCache.getNode(),r,o),a=mN(t,l,!0,e.filter.filtersNodes());else{let h=pL(n);if(".priority"===h)l=e.filter.updatePriority(t.eventCache.getNode(),r),a=mN(t,l,u.isFullyInitialized(),u.isFiltered());else{let d;let f=pj(n),p=u.getNode().getImmediateChild(h);if(pB(f))d=r;else{let m=c.getCompleteChild(h);d=null!=m?".priority"===pF(f)&&m.getChild(pV(f)).isEmpty()?m:m.updateChild(f,r):ms.EMPTY_NODE}if(p.equals(d))a=t;else{let g=e.filter.updateChild(u.getNode(),h,d,f,c,o);a=mN(t,g,u.isFullyInitialized(),e.filter.filtersNodes())}}}return a}function m8(e,t){return e.eventCache.isCompleteForChild(t)}function m9(e,t,n){return n.foreach((e,n)=>{t=t.updateChild(e,n)}),t}function m7(e,t,n,r,i,s,o,a){let l;if(t.serverCache.getNode().isEmpty()&&!t.serverCache.isFullyInitialized())return t;let u=t;l=pB(n)?r:new mP(null).setTree(n,r);let c=t.serverCache.getNode();return l.children.inorderTraversal((n,r)=>{if(c.hasChild(n)){let l=t.serverCache.getNode().getImmediateChild(n),h=m9(e,l,r);u=m6(e,u,new pO(n),h,i,s,o,a)}}),l.children.inorderTraversal((n,r)=>{let l=!t.serverCache.isCompleteForChild(n)&&null===r.value;if(!c.hasChild(n)&&!l){let h=t.serverCache.getNode().getImmediateChild(n),d=m9(e,h,r);u=m6(e,u,new pO(n),d,i,s,o,a)}}),u}function ge(e,t,n,r){var i,s;t.type===E.MERGE&&null!==t.source.queryId&&((0,S.hu)(mD(e.viewCache_),"We should always have a full cache before handling merges"),(0,S.hu)(mR(e.viewCache_),"Missing event cache, even though we have a server cache"));let o=e.viewCache_,a=function(e,t,n,r,i){let s,o;let a=new m1;if(n.type===E.OVERWRITE)n.source.fromUser?s=m5(e,t,n.path,n.snap,r,i,a):((0,S.hu)(n.source.fromServer,"Unknown source."),o=n.source.tagged||t.serverCache.isFiltered()&&!pB(n.path),s=m6(e,t,n.path,n.snap,r,i,o,a));else if(n.type===E.MERGE){var l,u;let c;n.source.fromUser?(l=n.path,u=n.children,c=t,u.foreach((n,s)=>{let o=pq(l,n);m8(t,pL(o))&&(c=m5(e,c,o,s,r,i,a))}),u.foreach((n,s)=>{let o=pq(l,n);m8(t,pL(o))||(c=m5(e,c,o,s,r,i,a))}),s=c):((0,S.hu)(n.source.fromServer,"Unknown source."),o=n.source.tagged||t.serverCache.isFiltered(),s=m7(e,t,n.path,n.children,r,i,o,a))}else if(n.type===E.ACK_USER_WRITE)s=n.revert?function(e,t,n,r,i,s){let o;if(null!=mX(r,n))return t;{let a;let l=new m3(r,t,i),u=t.eventCache.getNode();if(pB(n)||".priority"===pL(n)){let c;if(t.serverCache.isFullyInitialized())c=mK(r,mD(t));else{let h=t.serverCache.getNode();(0,S.hu)(h instanceof ms,"serverChildren would be complete if leaf node"),c=mQ(r,h)}a=e.filter.updateFullNode(u,c,s)}else{let d=pL(n),f=mJ(r,d,t.serverCache);null==f&&t.serverCache.isCompleteForChild(d)&&(f=u.getImmediateChild(d)),(a=null!=f?e.filter.updateChild(u,d,f,pj(n),l,s):t.eventCache.getNode().hasChild(d)?e.filter.updateChild(u,d,ms.EMPTY_NODE,pj(n),l,s):u).isEmpty()&&t.serverCache.isFullyInitialized()&&(o=mK(r,mD(t))).isLeafNode()&&(a=e.filter.updateFullNode(a,o,s))}return o=t.serverCache.isFullyInitialized()||null!=mX(r,pP()),mN(t,a,o,e.filter.filtersNodes())}}(e,t,n.path,r,i,a):function(e,t,n,r,i,s,o){if(null!=mX(i,n))return t;let a=t.serverCache.isFiltered(),l=t.serverCache;if(null!=r.value){if(pB(n)&&l.isFullyInitialized()||l.isCompleteForPath(n))return m6(e,t,n,l.getNode().getChild(n),i,s,a,o);if(!pB(n))return t;{let u=new mP(null);return l.getNode().forEachChild(p0,(e,t)=>{u=u.set(new pO(e),t)}),m7(e,t,n,u,i,s,a,o)}}{let c=new mP(null);return r.foreach((e,t)=>{let r=pq(n,e);l.isCompleteForPath(r)&&(c=c.set(e,l.getNode().getChild(r)))}),m7(e,t,n,c,i,s,a,o)}}(e,t,n.path,n.affectedTree,r,i,a);else if(n.type===E.LISTEN_COMPLETE)s=function(e,t,n,r,i){let s=t.serverCache,o=mA(t,s.getNode(),s.isFullyInitialized()||pB(n),s.isFiltered());return m4(e,o,n,r,m2,i)}(e,t,n.path,r,a);else throw(0,S.g5)("Unknown operation type: "+n.type);let h=a.getChanges();return function(e,t,n){let r=t.eventCache;if(r.isFullyInitialized()){let i=r.getNode().isLeafNode()||r.getNode().isEmpty(),s=mR(e);if(n.length>0||!e.eventCache.isFullyInitialized()||i&&!r.getNode().equals(s)||!r.getNode().getPriority().equals(s.getPriority())){var o;n.push((o=mR(t),{type:"value",snapshotNode:o}))}}}(t,s,h),{viewCache:s,changes:h}}(e.processor_,o,t,n,r);return i=e.processor_,s=a.viewCache,(0,S.hu)(s.eventCache.getNode().isIndexed(i.filter.getIndex()),"Event snap not indexed"),(0,S.hu)(s.serverCache.getNode().isIndexed(i.filter.getIndex()),"Server snap not indexed"),(0,S.hu)(a.viewCache.serverCache.isFullyInitialized()||!o.serverCache.isFullyInitialized(),"Once a server snap is complete, it should never go back"),e.viewCache_=a.viewCache,function(e,t,n,r){let i=r?[r]:e.eventRegistrations_;return function(e,t,n,r){let i=[],s=[];return t.forEach(t=>{if("child_changed"===t.type&&e.index_.indexedValueChanged(t.oldSnap,t.snapshotNode)){var n,r;s.push((n=t.childName,r=t.snapshotNode,{type:"child_moved",snapshotNode:r,childName:n}))}}),mx(e,i,"child_removed",t,r,n),mx(e,i,"child_added",t,r,n),mx(e,i,"child_moved",s,r,n),mx(e,i,"child_changed",t,r,n),mx(e,i,"value",t,r,n),i}(e.eventGenerator_,t,n,i)}(e,a.changes,a.viewCache.eventCache.getNode(),null)}function gt(e,t,n,r){let i=t.source.queryId;if(null!==i){let s=e.views.get(i);return(0,S.hu)(null!=s,"SyncTree gave us an op for an invalid query."),ge(s,t,n,r)}{let o=[];for(let a of e.views.values())o=o.concat(ge(a,t,n,r));return o}}function gn(e,t){let n=null;for(let r of e.views.values())n=n||function(e,t){let n=mD(e.viewCache_);return n&&(e.query._queryParams.loadsAllData()||!pB(t)&&!n.getImmediateChild(pL(t)).isEmpty())?n.getChild(t):null}(r,t);return n}class gr{constructor(e){this.listenProvider_=e,this.syncPointTree_=new mP(null),this.pendingWriteTree_={visibleWrites:mL.empty(),allWrites:[],lastWriteId:-1},this.tagToQueryMap=new Map,this.queryToTagMap=new Map}}function gi(e,t,n=!1){let r=function(e,t){for(let n=0;n<e.allWrites.length;n++){let r=e.allWrites[n];if(r.writeId===t)return r}return null}(e.pendingWriteTree_,t),i=function(e,t){let n=e.allWrites.findIndex(e=>e.writeId===t);(0,S.hu)(n>=0,"removeWrite called with nonexistent writeId.");let r=e.allWrites[n];e.allWrites.splice(n,1);let i=r.visible,s=!1,o=e.allWrites.length-1;for(;i&&o>=0;){let a=e.allWrites[o];a.visible&&(o>=n&&function(e,t){if(e.snap)return pG(e.path,t);for(let n in e.children)if(e.children.hasOwnProperty(n)&&pG(pq(e.path,n),t))return!0;return!1}(a,r.path)?i=!1:pG(r.path,a.path)&&(s=!0)),o--}if(!i)return!1;if(s){var l;return(l=e).visibleWrites=mW(l.allWrites,mG,pP()),l.allWrites.length>0?l.lastWriteId=l.allWrites[l.allWrites.length-1].writeId:l.lastWriteId=-1,!0}if(r.snap)e.visibleWrites=mF(e.visibleWrites,r.path);else{let u=r.children;pr(u,t=>{e.visibleWrites=mF(e.visibleWrites,pq(r.path,t))})}return!0}(e.pendingWriteTree_,t);if(!i)return[];{let s=new mP(null);return null!=r.snap?s=s.set(pP(),!0):pr(r.children,e=>{s=s.set(new pO(e),!0)}),ga(e,new mT(r.path,s,n))}}function gs(e,t,n){return ga(e,new mE(mb(),t,n))}function go(e,t,n){let r=e.pendingWriteTree_,i=e.syncPointTree_.findOnPath(t,(e,n)=>{let r=p$(e,t),i=gn(n,r);if(i)return i});return mH(r,t,i,n,!0)}function ga(e,t){var n;return function e(t,n,r,i){if(pB(t.path))return function e(t,n,r,i){let s=n.get(pP());null==r&&null!=s&&(r=gn(s,pP()));let o=[];return n.children.inorderTraversal((n,s)=>{let a=r?r.getImmediateChild(n):null,l=mZ(i,n),u=t.operationForChild(n);u&&(o=o.concat(e(u,s,a,l)))}),s&&(o=o.concat(gt(s,t,i,r))),o}(t,n,r,i);{let s=n.get(pP());null==r&&null!=s&&(r=gn(s,pP()));let o=[],a=pL(t.path),l=t.operationForChild(a),u=n.children.get(a);if(u&&l){let c=r?r.getImmediateChild(a):null,h=mZ(i,a);o=o.concat(e(l,u,c,h))}return s&&(o=o.concat(gt(s,t,i,r))),o}}(t,e.syncPointTree_,null,(n=e.pendingWriteTree_,m0(pP(),n)))}function gl(e,t){return e.tagToQueryMap.get(t)}function gu(e){let t=e.indexOf("$");return(0,S.hu)(-1!==t&&t<e.length-1,"Bad queryKey."),{queryId:e.substr(t+1),path:new pO(e.substr(0,t))}}function gc(e,t,n){let r=e.syncPointTree_.get(t);(0,S.hu)(r,"Missing sync point for query tag that we're tracking");let i=m0(t,e.pendingWriteTree_);return gt(r,n,i,null)}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class gh{constructor(e){this.node_=e}getImmediateChild(e){let t=this.node_.getImmediateChild(e);return new gh(t)}node(){return this.node_}}class gd{constructor(e,t){this.syncTree_=e,this.path_=t}getImmediateChild(e){let t=pq(this.path_,e);return new gd(this.syncTree_,t)}node(){return go(this.syncTree_,this.path_)}}let gf=function(e,t,n){return e&&"object"==typeof e?((0,S.hu)(".sv"in e,"Unexpected leaf node or priority contents"),"string"==typeof e[".sv"])?gp(e[".sv"],t,n):"object"==typeof e[".sv"]?gm(e[".sv"],t):void(0,S.hu)(!1,"Unexpected server value: "+JSON.stringify(e,null,2)):e},gp=function(e,t,n){if("timestamp"===e)return n.timestamp;(0,S.hu)(!1,"Unexpected server value: "+e)},gm=function(e,t,n){e.hasOwnProperty("increment")||(0,S.hu)(!1,"Unexpected server value: "+JSON.stringify(e,null,2));let r=e.increment;"number"!=typeof r&&(0,S.hu)(!1,"Unexpected increment value: "+r);let i=t.node();if((0,S.hu)(null!=i,"Expected ChildrenNode.EMPTY_NODE for nulls"),!i.isLeafNode())return r;let s=i.getValue();return"number"!=typeof s?r:s+r};function gg(e,t,n){let r;let i=e.getPriority().val(),s=gf(i,t.getImmediateChild(".priority"),n);if(!e.isLeafNode())return r=e,s!==e.getPriority().val()&&(r=r.updatePriority(new p9(s))),e.forEachChild(p7,(e,i)=>{let s=gg(i,t.getImmediateChild(e),n);s!==i&&(r=r.updateImmediateChild(e,s))}),r;{let o=gf(e.getValue(),t,n);return o!==e.getValue()||s!==e.getPriority().val()?new p9(o,ma(s)):e}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class gy{constructor(e="",t=null,n={children:{},childCount:0}){this.name=e,this.parent=t,this.node=n}}function gv(e,t){let n=t instanceof pO?t:new pO(t),r=e,i=pL(n);for(;null!==i;){let s=(0,S.DV)(r.node.children,i)||{children:{},childCount:0};r=new gy(i,r,s),i=pL(n=pj(n))}return r}function g_(e){return e.node.value}function gw(e,t){e.node.value=t,function e(t){null!==t.parent&&function(t,n,r){let i=void 0===g_(r)&&!gb(r),s=(0,S.r3)(t.node.children,n);i&&s?(delete t.node.children[n],t.node.childCount--,e(t)):i||s||(t.node.children[n]=r.node,t.node.childCount++,e(t))}(t.parent,t.name,t)}(e)}function gb(e){return e.node.childCount>0}function gI(e,t){pr(e.node.children,(n,r)=>{t(new gy(n,e,r))})}function gT(e){return new pO(null===e.parent?e.name:gT(e.parent)+"/"+e.name)}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let gE=/[\[\].#$\/\u0000-\u001F\u007F]/,gS=/[\[\].#$\u0000-\u001F\u007F]/,gk=function(e){return"string"==typeof e&&0!==e.length&&!gE.test(e)},gx=function(e){var t;return e&&(e=e.replace(/^\/*\.info(\/|$)/,"/")),"string"==typeof(t=e)&&0!==t.length&&!gS.test(t)},gC=function(e,t,n){let r=n instanceof pO?new pW(n,e):n;if(void 0===t)throw Error(e+"contains undefined "+pK(r));if("function"==typeof t)throw Error(e+"contains a function "+pK(r)+" with contents = "+t.toString());if(f4(t))throw Error(e+"contains "+t.toString()+" "+pK(r));if("string"==typeof t&&t.length>3495253.3333333335&&(0,S.ug)(t)>10485760)throw Error(e+"contains a string greater than 10485760 utf8 bytes "+pK(r)+" ('"+t.substring(0,50)+"...')");if(t&&"object"==typeof t){let i=!1,s=!1;if(pr(t,(t,n)=>{var o;if(".value"===t)i=!0;else if(".priority"!==t&&".sv"!==t&&(s=!0,!gk(t)))throw Error(e+" contains an invalid key ("+t+") "+pK(r)+'.  Keys must be non-empty strings and can\'t contain ".", "#", "$", "/", "[", or "]"');(o=r).parts_.length>0&&(o.byteLength_+=1),o.parts_.push(t),o.byteLength_+=(0,S.ug)(t),pH(o),gC(e,n,r),function(e){let t=e.parts_.pop();e.byteLength_-=(0,S.ug)(t),e.parts_.length>0&&(e.byteLength_-=1)}(r)}),i&&s)throw Error(e+' contains ".value" child '+pK(r)+" in addition to actual children.")}},gN=function(e,t){let n=t.path.toString();if("string"!=typeof t.repoInfo.host||0===t.repoInfo.host.length||!gk(t.repoInfo.namespace)&&"localhost"!==t.repoInfo.host.split(":")[0]||0!==n.length&&!gx(n))throw Error((0,S.gK)(e,"url")+'must be a valid firebase URL and the path can\'t contain ".", "#", "$", "[", or "]".')};/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class gA{constructor(){this.eventLists_=[],this.recursionDepth_=0}}function gR(e,t,n){!function(e,t){let n=null;for(let r=0;r<t.length;r++){let i=t[r],s=i.getPath();null===n||pz(s,n.path)||(e.eventLists_.push(n),n=null),null===n&&(n={events:[],path:s}),n.events.push(i)}n&&e.eventLists_.push(n)}(e,n),function(e,t){e.recursionDepth_++;let n=!0;for(let r=0;r<e.eventLists_.length;r++){let i=e.eventLists_[r];if(i){let s=i.path;t(s)?(function(e){for(let t=0;t<e.events.length;t++){let n=e.events[t];if(null!==n){e.events[t]=null;let r=n.getEventRunner();fQ&&fJ("event: "+n.toString()),pa(r)}}}(e.eventLists_[r]),e.eventLists_[r]=null):n=!1}}n&&(e.eventLists_=[]),e.recursionDepth_--}(e,e=>pG(e,t)||pG(t,e))}class gD{constructor(e,t,n,r){this.repoInfo_=e,this.forceRestClient_=t,this.authTokenProvider_=n,this.appCheckProvider_=r,this.dataUpdateCount=0,this.statsListener_=null,this.eventQueue_=new gA,this.nextWriteId_=1,this.interceptServerDataCallback_=null,this.onDisconnect_=mg(),this.transactionQueueTree_=new gy,this.persistentConnection_=null,this.key=this.repoInfo_.toURLString()}toString(){return(this.repoInfo_.secure?"https://":"http://")+this.repoInfo_.host}}function gO(e){var t;return(t=t={timestamp:function(e){let t=e.infoData_.getNode(new pO(".info/serverTimeOffset")),n=t.val()||0;return new Date().getTime()+n}(e)}).timestamp=t.timestamp||new Date().getTime(),t}function gP(e,t,n,r,i){e.dataUpdateCount++;let s=new pO(t);n=e.interceptServerDataCallback_?e.interceptServerDataCallback_(t,n):n;let o=[];if(i){if(r){let a=(0,S.UI)(n,e=>ma(e));o=function(e,t,n,r){let i=gl(e,r);if(!i)return[];{let s=gu(i),o=s.path,a=s.queryId,l=p$(o,t),u=mP.fromObject(n),c=new mS(mI(a),l,u);return gc(e,o,c)}}(e.serverSyncTree_,s,a,i)}else{let l=ma(n);o=function(e,t,n,r){let i=gl(e,r);if(null==i)return[];{let s=gu(i),o=s.path,a=s.queryId,l=p$(o,t),u=new mE(mI(a),l,n);return gc(e,o,u)}}(e.serverSyncTree_,s,l,i)}}else if(r){let u=(0,S.UI)(n,e=>ma(e));o=function(e,t,n){let r=mP.fromObject(n);return ga(e,new mS(mb(),t,r))}(e.serverSyncTree_,s,u)}else{let c=ma(n);o=gs(e.serverSyncTree_,s,c)}let h=s;o.length>0&&(h=gU(e,s)),gR(e.eventQueue_,h,o)}function gL(e,t){gM(e,"connected",t),!1===t&&function(e){gj(e,"onDisconnectEvents");let t=gO(e),n=mg();my(e.onDisconnect_,pP(),(r,i)=>{var s;let o=(s=e.serverSyncTree_,gg(i,new gd(s,r),t));!function e(t,n,r){if(pB(n))t.value=r,t.children.clear();else if(null!==t.value)t.value=t.value.updateChild(n,r);else{let i=pL(n);t.children.has(i)||t.children.set(i,mg());let s=t.children.get(i);e(s,n=pj(n),r)}}(n,r,o)});let r=[];my(n,pP(),(t,n)=>{r=r.concat(gs(e.serverSyncTree_,t,n));let i=function(e,t){let n=gT(gV(e,t)),r=gv(e.transactionQueueTree_,t);return function(e,t,n){let r=e.parent;for(;null!==r;){if(t(r))return!0;r=r.parent}}(r,t=>{g$(e,t)}),g$(e,r),function e(t,n,r,i){r&&!i&&n(t),gI(t,t=>{e(t,n,!0,i)}),r&&i&&n(t)}(r,t=>{g$(e,t)}),n}(e,t);gU(e,i)}),e.onDisconnect_=mg(),gR(e.eventQueue_,pP(),r)}(e)}function gM(e,t,n){let r=new pO("/.info/"+t),i=ma(n);e.infoData_.updateSnapshot(r,i);let s=gs(e.infoSyncTree_,r,i);gR(e.eventQueue_,r,s)}function gj(e,...t){let n="";e.persistentConnection_&&(n=e.persistentConnection_.id+":"),fJ(n,...t)}function gF(e,t,n){return go(e.serverSyncTree_,t,n)||ms.EMPTY_NODE}function gU(e,t){let n=gV(e,t),r=gT(n),i=gq(e,n);return function(e,t,n){if(0===t.length)return;let r=[],i=[],s=t.filter(e=>0===e.status),o=s.map(e=>e.currentWriteId);for(let a=0;a<t.length;a++){let l=t[a],u=p$(n,l.path),c=!1,h;if((0,S.hu)(null!==u,"rerunTransactionsUnderNode_: relativePath should not be null."),4===l.status)c=!0,h=l.abortReason,i=i.concat(gi(e.serverSyncTree_,l.currentWriteId,!0));else if(0===l.status){if(l.retryCount>=25)c=!0,h="maxretry",i=i.concat(gi(e.serverSyncTree_,l.currentWriteId,!0));else{let d=gF(e,l.path,o);l.currentInputSnapshot=d;let f=t[a].update(d.val());if(void 0!==f){gC("transaction failed: Data returned ",f,l.path);let p=ma(f),m="object"==typeof f&&null!=f&&(0,S.r3)(f,".priority");m||(p=p.updatePriority(d.getPriority()));let g=l.currentWriteId,y=gO(e),v=gg(p,new gh(d),y);l.currentOutputSnapshotRaw=p,l.currentOutputSnapshotResolved=v,l.currentWriteId=e.nextWriteId_++,o.splice(o.indexOf(g),1),i=(i=i.concat(function(e,t,n,r,i){var s,o;return(s=e.pendingWriteTree_,o=i,(0,S.hu)(r>s.lastWriteId,"Stacking an older write on top of newer ones"),void 0===o&&(o=!0),s.allWrites.push({path:t,snap:n,writeId:r,visible:o}),o&&(s.visibleWrites=mM(s.visibleWrites,t,n)),s.lastWriteId=r,i)?ga(e,new mE(mw(),t,n)):[]}(e.serverSyncTree_,l.path,v,l.currentWriteId,l.applyLocally))).concat(gi(e.serverSyncTree_,g,!0))}else c=!0,h="nodata",i=i.concat(gi(e.serverSyncTree_,l.currentWriteId,!0))}}gR(e.eventQueue_,n,i),i=[],c&&(t[a].status=2,setTimeout(t[a].unwatcher,Math.floor(0)),t[a].onComplete&&("nodata"===h?r.push(()=>t[a].onComplete(null,!1,t[a].currentInputSnapshot)):r.push(()=>t[a].onComplete(Error(h),!1,null))))}gB(e,e.transactionQueueTree_);for(let _=0;_<r.length;_++)pa(r[_]);(function e(t,n=t.transactionQueueTree_){if(n||gB(t,n),g_(n)){let r=gq(t,n);(0,S.hu)(r.length>0,"Sending zero length transaction queue");let i=r.every(e=>0===e.status);i&&function(t,n,r){let i=r.map(e=>e.currentWriteId),s=gF(t,n,i),o=s,a=s.hash();for(let l=0;l<r.length;l++){let u=r[l];(0,S.hu)(0===u.status,"tryToSendTransactionQueue_: items in queue should all be run."),u.status=1,u.retryCount++;let c=p$(n,u.path);o=o.updateChild(c,u.currentOutputSnapshotRaw)}let h=o.val(!0);t.server_.put(n.toString(),h,i=>{gj(t,"transaction put response",{path:n.toString(),status:i});let s=[];if("ok"===i){let o=[];for(let a=0;a<r.length;a++)r[a].status=2,s=s.concat(gi(t.serverSyncTree_,r[a].currentWriteId)),r[a].onComplete&&o.push(()=>r[a].onComplete(null,!0,r[a].currentOutputSnapshotResolved)),r[a].unwatcher();gB(t,gv(t.transactionQueueTree_,n)),e(t,t.transactionQueueTree_),gR(t.eventQueue_,n,s);for(let l=0;l<o.length;l++)pa(o[l])}else{if("datastale"===i)for(let u=0;u<r.length;u++)3===r[u].status?r[u].status=4:r[u].status=0;else{f2("transaction at "+n.toString()+" failed: "+i);for(let c=0;c<r.length;c++)r[c].status=4,r[c].abortReason=i}gU(t,n)}},a)}(t,gT(n),r)}else gb(n)&&gI(n,n=>{e(t,n)})})(e,e.transactionQueueTree_)}(e,i,r),r}function gV(e,t){let n;let r=e.transactionQueueTree_;for(n=pL(t);null!==n&&void 0===g_(r);)r=gv(r,n),n=pL(t=pj(t));return r}function gq(e,t){let n=[];return function e(t,n,r){let i=g_(n);if(i)for(let s=0;s<i.length;s++)r.push(i[s]);gI(n,n=>{e(t,n,r)})}(e,t,n),n.sort((e,t)=>e.order-t.order),n}function gB(e,t){let n=g_(t);if(n){let r=0;for(let i=0;i<n.length;i++)2!==n[i].status&&(n[r]=n[i],r++);n.length=r,gw(t,n.length>0?n:void 0)}gI(t,t=>{gB(e,t)})}function g$(e,t){let n=g_(t);if(n){let r=[],i=[],s=-1;for(let o=0;o<n.length;o++)3===n[o].status||(1===n[o].status?((0,S.hu)(s===o-1,"All SENT items should be at beginning of queue."),s=o,n[o].status=3,n[o].abortReason="set"):((0,S.hu)(0===n[o].status,"Unexpected transaction status in abort"),n[o].unwatcher(),i=i.concat(gi(e.serverSyncTree_,n[o].currentWriteId,!0)),n[o].onComplete&&r.push(n[o].onComplete.bind(null,Error("set"),!1,null))));-1===s?gw(t,void 0):n.length=s+1,gR(e.eventQueue_,gT(t),i);for(let a=0;a<r.length;a++)pa(r[a])}}let gz=function(e,t){let n=gG(e),r=n.namespace;"firebase.com"===n.domain&&f1(n.host+" is no longer supported. Please use <YOUR FIREBASE>.firebaseio.com instead"),r&&"undefined"!==r||"localhost"===n.domain||f1("Cannot parse Firebase url. Please use https://<YOUR FIREBASE>.firebaseio.com"),n.secure||f3();let i="ws"===n.scheme||"wss"===n.scheme;return{repoInfo:new pg(n.host,n.secure,r,i,t,"",r!==n.subdomain),path:new pO(n.pathString)}},gG=function(e){let t="",n="",r="",i="",s="",o=!0,a="https",l=443;if("string"==typeof e){let u=e.indexOf("//");u>=0&&(a=e.substring(0,u-1),e=e.substring(u+2));let c=e.indexOf("/");-1===c&&(c=e.length);let h=e.indexOf("?");-1===h&&(h=e.length),t=e.substring(0,Math.min(c,h)),c<h&&(i=/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function(e){let t="",n=e.split("/");for(let r=0;r<n.length;r++)if(n[r].length>0){let i=n[r];try{i=decodeURIComponent(i.replace(/\+/g," "))}catch(s){}t+="/"+i}return t}(e.substring(c,h)));let d=function(e){let t={};for(let n of("?"===e.charAt(0)&&(e=e.substring(1)),e.split("&"))){if(0===n.length)continue;let r=n.split("=");2===r.length?t[decodeURIComponent(r[0])]=decodeURIComponent(r[1]):f2(`Invalid query segment '${n}' in query '${e}'`)}return t}(e.substring(Math.min(e.length,h)));(u=t.indexOf(":"))>=0?(o="https"===a||"wss"===a,l=parseInt(t.substring(u+1),10)):u=t.length;let f=t.slice(0,u);if("localhost"===f.toLowerCase())n="localhost";else if(f.split(".").length<=2)n=f;else{let p=t.indexOf(".");r=t.substring(0,p).toLowerCase(),n=t.substring(p+1),s=r}"ns"in d&&(s=d.ns)}return{host:t,port:l,domain:n,subdomain:r,secure:o,scheme:a,pathString:i,namespace:s}};/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class gW{constructor(e,t,n,r){this._repo=e,this._path=t,this._queryParams=n,this._orderByCalled=r}get key(){return pB(this._path)?null:pF(this._path)}get ref(){return new gH(this._repo,this._path)}get _queryIdentifier(){let e=mf(this._queryParams),t=pt(e);return"{}"===t?"default":t}get _queryObject(){return mf(this._queryParams)}isEqual(e){if(!((e=(0,S.m9)(e))instanceof gW))return!1;let t=this._repo===e._repo,n=pz(this._path,e._path),r=this._queryIdentifier===e._queryIdentifier;return t&&n&&r}toJSON(){return this.toString()}toString(){return this._repo.toString()+function(e){let t="";for(let n=e.pieceNum_;n<e.pieces_.length;n++)""!==e.pieces_[n]&&(t+="/"+encodeURIComponent(String(e.pieces_[n])));return t||"/"}(this._path)}}class gH extends gW{constructor(e,t){super(e,t,new mh,!1)}get parent(){let e=pV(this._path);return null===e?null:new gH(this._repo,e)}get root(){let e=this;for(;null!==e.parent;)e=e.parent;return e}}(0,S.hu)(!h,"__referenceConstructor has already been defined"),h=gH,(0,S.hu)(!d,"__referenceConstructor has already been defined"),d=gH;let gK={};class gQ{constructor(e,t){this._repoInternal=e,this.app=t,this.type="database",this._instanceStarted=!1}get _repo(){return this._instanceStarted||(function(e,t,n){if(e.stats_=pb(e.repoInfo_),e.forceRestClient_||pl())e.server_=new mp(e.repoInfo_,(t,n,r,i)=>{gP(e,t,n,r,i)},e.authTokenProvider_,e.appCheckProvider_),setTimeout(()=>gL(e,!0),0);else{if(null!=n){if("object"!=typeof n)throw Error("Only objects are supported for option databaseAuthVariableOverride");try{(0,S.Wl)(n)}catch(r){throw Error("Invalid authOverride provided: "+r)}}e.persistentConnection_=new pY(e.repoInfo_,t,(t,n,r,i)=>{gP(e,t,n,r,i)},t=>{gL(e,t)},t=>{pr(t,(t,n)=>{gM(e,t,n)})},e.authTokenProvider_,e.appCheckProvider_,n),e.server_=e.persistentConnection_}e.authTokenProvider_.addTokenChangeListener(t=>{e.server_.refreshAuthToken(t)}),e.appCheckProvider_.addTokenChangeListener(t=>{e.server_.refreshAppCheckToken(t.token)}),e.statsReporter_=function(e,t){let n=e.toString();return pw[n]||(pw[n]=t()),pw[n]}(e.repoInfo_,()=>new m_(e.stats_,e.server_)),e.infoData_=new mm,e.infoSyncTree_=new gr({startListening:(t,n,r,i)=>{let s=[],o=e.infoData_.getNode(t._path);return o.isEmpty()||(s=gs(e.infoSyncTree_,t._path,o),setTimeout(()=>{i("ok")},0)),s},stopListening:()=>{}}),gM(e,"connected",!1),e.serverSyncTree_=new gr({startListening:(t,n,r,i)=>(e.server_.listen(t,r,n,(n,r)=>{let s=i(n,r);gR(e.eventQueue_,t._path,s)}),[]),stopListening:(t,n)=>{e.server_.unlisten(t,n)}})}(this._repoInternal,this.app.options.appId,this.app.options.databaseAuthVariableOverride),this._instanceStarted=!0),this._repoInternal}get _root(){return this._rootInternal||(this._rootInternal=new gH(this._repo,pP())),this._rootInternal}_delete(){return null!==this._rootInternal&&(function(e,t){let n=gK[t];n&&n[e.key]===e||f1(`Database ${t}(${e.repoInfo_}) has already been deleted.`),e.persistentConnection_&&e.persistentConnection_.interrupt("repo_interrupt"),delete n[e.key]}(this._repo,this.app.name),this._repoInternal=null,this._rootInternal=null),Promise.resolve()}_checkNotDeleted(e){null===this._rootInternal&&f1("Cannot call "+e+" on a deleted database.")}}pY.prototype.simpleListen=function(e,t){this.sendRequest("q",{p:e},t)},pY.prototype.echo=function(e,t){this.sendRequest("echo",{d:e},t)},fU=x.SDK_VERSION,(0,x._registerComponent)(new k.wA("database",(e,{instanceIdentifier:t})=>{let n=e.getProvider("app").getImmediate(),r=e.getProvider("auth-internal"),i=e.getProvider("app-check-internal");return function(e,t,n,r,i){var s,o,a;let l,u,c,h,d=r||e.options.databaseURL;void 0===d&&(e.options.projectId||f1("Can't determine Firebase Database URL. Be sure to include  a Project ID when calling firebase.initializeApp()."),fJ("Using default host for project ",e.options.projectId),d=`${e.options.projectId}-default-rtdb.firebaseio.com`);let f=gz(d,i),p=f.repoInfo;void 0!==fM&&fM.env&&(c=fM.env.FIREBASE_DATABASE_EMULATOR_HOST),c?(h=!0,p=(f=gz(d=`http://${c}?ns=${p.namespace}`,i)).repoInfo):h=!f.repoInfo.secure;let m=i&&h?new pd(pd.OWNER):new ph(e.name,e.options,t);gN("Invalid Firebase Database URL",f),pB(f.path)||f1("Database URL must point to the root of a Firebase Database (not including a child path).");let g=(s=p,o=e,a=new pc(e.name,n),(l=gK[o.name])||(l={},gK[o.name]=l),(u=l[s.toURLString()])&&f1("Database initialized multiple times. Please make sure the format of the database URL matches with each database() call."),u=new gD(s,!1,m,a),l[s.toURLString()]=u,u);return new gQ(g,e)}(n,r,i,t)},"PUBLIC").setMultipleInstances(!0)),(0,x.registerVersion)(fj,fF,void 0),(0,x.registerVersion)(fj,fF,"esm2017"),R.apps.length||R.initializeApp({apiKey:"AIzaSyCnqA63y5H9q8rv4DPkIshwg8awh3Xk1FQ",authDomain:"infiopp-c399a.firebaseapp.com",projectId:"infiopp-c399a",storageBucket:"infiopp-c399a.appspot.com",messagingSenderId:"955369058407",appId:"1:955369058407:web:8311adee2e681ee92de4c2",measurementId:"G-CZKDK3GXXD"});let gY=R.auth(),gX=new R.auth.GoogleAuthProvider,gJ=R.firestore();R.firestore.FieldValue.serverTimestamp,R.firestore.Timestamp.fromMillis,R.firestore.FieldValue.increment,R.firestore.doc,R.firestore.getDoc;let gZ=R.storage(),g0=R.storage.TaskEvent.STATE_CHANGED;!function(e=(0,x.getApp)(),t){let n=(0,x._getProvider)(e,"database").getImmediate({identifier:void 0}),r=(0,S.P0)("database");r&&function(e,t,n,r={}){var i,s;let o;(e=(0,S.m9)(e))._checkNotDeleted("useEmulator"),e._instanceStarted&&f1("Cannot call useEmulator() after instance has already been initialized.");let a=e._repoInternal;if(a.repoInfo_.nodeAdmin)r.mockUserToken&&f1('mockUserToken is not supported by the Admin SDK. For client access with mock users, please use the "firebase" package instead of "firebase-admin".'),o=new pd(pd.OWNER);else if(r.mockUserToken){let l="string"==typeof r.mockUserToken?r.mockUserToken:(0,S.Sg)(r.mockUserToken,e.app.options.projectId);o=new pd(l)}i=a,s=o,i.repoInfo_=new pg(`${t}:${n}`,!1,i.repoInfo_.namespace,i.repoInfo_.webSocketOnly,i.repoInfo_.nodeAdmin,i.repoInfo_.persistenceKey,i.repoInfo_.includeNamespaceInQueryParams),s&&(i.authTokenProvider_=s)}(n,...r)}()},227:function(e,t){"use strict";Object.defineProperty(t,"__esModule",{value:!0}),t.getDomainLocale=function(e,t,n,r){return!1},("function"==typeof t.default||"object"==typeof t.default&&null!==t.default)&&void 0===t.default.__esModule&&(Object.defineProperty(t.default,"__esModule",{value:!0}),Object.assign(t.default,t),e.exports=t.default)},1551:function(e,t,n){"use strict";Object.defineProperty(t,"__esModule",{value:!0}),t.default=void 0;var r=n(2648).Z,i=n(7273).Z,s=r(n(7294)),o=n(1003),a=n(7795),l=n(4465),u=n(2692),c=n(8245),h=n(9246),d=n(227),f=n(3468);let p=new Set;function m(e,t,n,r){if(o.isLocalURL(t)){if(!r.bypassPrefetchedCheck){let i=void 0!==r.locale?r.locale:"locale"in e?e.locale:void 0,s=t+"%"+n+"%"+i;if(p.has(s))return;p.add(s)}Promise.resolve(e.prefetch(t,n,r)).catch(e=>{})}}function g(e){return"string"==typeof e?e:a.formatUrl(e)}let y=s.default.forwardRef(function(e,t){let n,r;let{href:a,as:p,children:y,prefetch:v,passHref:_,replace:w,shallow:b,scroll:I,locale:T,onClick:E,onMouseEnter:S,onTouchStart:k,legacyBehavior:x=!1}=e,C=i(e,["href","as","children","prefetch","passHref","replace","shallow","scroll","locale","onClick","onMouseEnter","onTouchStart","legacyBehavior"]);n=y,x&&("string"==typeof n||"number"==typeof n)&&(n=s.default.createElement("a",null,n));let N=!1!==v,A=s.default.useContext(u.RouterContext),R=s.default.useContext(c.AppRouterContext),D=null!=A?A:R,O=!A,{href:P,as:L}=s.default.useMemo(()=>{if(!A){let e=g(a);return{href:e,as:p?g(p):e}}let[t,n]=o.resolveHref(A,a,!0);return{href:t,as:p?o.resolveHref(A,p):n||t}},[A,a,p]),M=s.default.useRef(P),j=s.default.useRef(L);x&&(r=s.default.Children.only(n));let F=x?r&&"object"==typeof r&&r.ref:t,[U,V,q]=h.useIntersection({rootMargin:"200px"}),B=s.default.useCallback(e=>{(j.current!==L||M.current!==P)&&(q(),j.current=L,M.current=P),U(e),F&&("function"==typeof F?F(e):"object"==typeof F&&(F.current=e))},[L,F,P,q,U]);s.default.useEffect(()=>{D&&V&&N&&m(D,P,L,{locale:T})},[L,P,V,T,N,null==A?void 0:A.locale,D]);let $={ref:B,onClick(e){x||"function"!=typeof E||E(e),x&&r.props&&"function"==typeof r.props.onClick&&r.props.onClick(e),D&&!e.defaultPrevented&&function(e,t,n,r,i,a,l,u,c,h){let{nodeName:d}=e.currentTarget,f="A"===d.toUpperCase();if(f&&(function(e){let{target:t}=e.currentTarget;return t&&"_self"!==t||e.metaKey||e.ctrlKey||e.shiftKey||e.altKey||e.nativeEvent&&2===e.nativeEvent.which}(e)||!o.isLocalURL(n)))return;e.preventDefault();let p=()=>{"beforePopState"in t?t[i?"replace":"push"](n,r,{shallow:a,locale:u,scroll:l}):t[i?"replace":"push"](r||n,{forceOptimisticNavigation:!h})};c?s.default.startTransition(p):p()}(e,D,P,L,w,b,I,T,O,N)},onMouseEnter(e){x||"function"!=typeof S||S(e),x&&r.props&&"function"==typeof r.props.onMouseEnter&&r.props.onMouseEnter(e),D&&(N||!O)&&m(D,P,L,{locale:T,priority:!0,bypassPrefetchedCheck:!0})},onTouchStart(e){x||"function"!=typeof k||k(e),x&&r.props&&"function"==typeof r.props.onTouchStart&&r.props.onTouchStart(e),D&&(N||!O)&&m(D,P,L,{locale:T,priority:!0,bypassPrefetchedCheck:!0})}};if(!x||_||"a"===r.type&&!("href"in r.props)){let z=void 0!==T?T:null==A?void 0:A.locale,G=(null==A?void 0:A.isLocaleDomain)&&d.getDomainLocale(L,z,null==A?void 0:A.locales,null==A?void 0:A.domainLocales);$.href=G||f.addBasePath(l.addLocale(L,z,null==A?void 0:A.defaultLocale))}return x?s.default.cloneElement(r,$):s.default.createElement("a",Object.assign({},C,$),n)});t.default=y,("function"==typeof t.default||"object"==typeof t.default&&null!==t.default)&&void 0===t.default.__esModule&&(Object.defineProperty(t.default,"__esModule",{value:!0}),Object.assign(t.default,t),e.exports=t.default)},9246:function(e,t,n){"use strict";Object.defineProperty(t,"__esModule",{value:!0}),t.useIntersection=function(e){let{rootRef:t,rootMargin:n,disabled:l}=e,u=l||!s,[c,h]=r.useState(!1),[d,f]=r.useState(null);r.useEffect(()=>{if(s){if(!u&&!c&&d&&d.tagName){let e=function(e,t,n){let{id:r,observer:i,elements:s}=function(e){let t;let n={root:e.root||null,margin:e.rootMargin||""},r=a.find(e=>e.root===n.root&&e.margin===n.margin);if(r&&(t=o.get(r)))return t;let i=new Map,s=new IntersectionObserver(e=>{e.forEach(e=>{let t=i.get(e.target),n=e.isIntersecting||e.intersectionRatio>0;t&&n&&t(n)})},e);return t={id:n,observer:s,elements:i},a.push(n),o.set(n,t),t}(n);return s.set(e,t),i.observe(e),function(){if(s.delete(e),i.unobserve(e),0===s.size){i.disconnect(),o.delete(r);let t=a.findIndex(e=>e.root===r.root&&e.margin===r.margin);t>-1&&a.splice(t,1)}}}(d,e=>e&&h(e),{root:null==t?void 0:t.current,rootMargin:n});return e}}else if(!c){let r=i.requestIdleCallback(()=>h(!0));return()=>i.cancelIdleCallback(r)}},[d,u,n,t,c]);let p=r.useCallback(()=>{h(!1)},[]);return[f,c,p]};var r=n(7294),i=n(4686);let s="function"==typeof IntersectionObserver,o=new Map,a=[];("function"==typeof t.default||"object"==typeof t.default&&null!==t.default)&&void 0===t.default.__esModule&&(Object.defineProperty(t.default,"__esModule",{value:!0}),Object.assign(t.default,t),e.exports=t.default)},1669:function(e,t,n){"use strict";n.r(t),n.d(t,{default:function(){return I}});var r=n(5893);n(7475);var i=n(8059),s=n(3963),o=n(7294),a=n(6660);n(4444),n(5816),n(3333),n(8463);/*! *****************************************************************************
Copyright (c) Microsoft Corporation.

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
***************************************************************************** */var l=function(){return(l=Object.assign||function(e){for(var t,n=1,r=arguments.length;n<r;n++)for(var i in t=arguments[n])Object.prototype.hasOwnProperty.call(t,i)&&(e[i]=t[i]);return e}).apply(this,arguments)},u=function(e){return{loading:null==e,value:e}},c=function(e){var t=e?e():void 0,n=(0,o.useReducer)(function(e,t){switch(t.type){case"error":return l(l({},e),{error:t.error,loading:!1,value:void 0});case"reset":return u(t.defaultValue);case"value":return l(l({},e),{error:void 0,loading:!1,value:t.value});default:return e}},u(t)),r=n[0],i=n[1],s=function(){i({type:"reset",defaultValue:e?e():void 0})},a=function(e){i({type:"error",error:e})},c=function(e){i({type:"value",value:e})};return(0,o.useMemo)(function(){return{error:r.error,loading:r.loading,reset:s,setError:a,setValue:c,value:r.value}},[r.error,r.loading,s,a,c,r.value])},h=function(e,t){var n=c(function(){return e.currentUser}),r=n.error,i=n.loading,s=n.setError,l=n.setValue,u=n.value;(0,o.useEffect)(function(){var n=(0,a.v)(e,function(e){var n,r,i,o;return n=void 0,r=void 0,i=void 0,o=function(){return function(e,t){var n,r,i,s,o={label:0,sent:function(){if(1&i[0])throw i[1];return i[1]},trys:[],ops:[]};return s={next:a(0),throw:a(1),return:a(2)},"function"==typeof Symbol&&(s[Symbol.iterator]=function(){return this}),s;function a(s){return function(a){return function(s){if(n)throw TypeError("Generator is already executing.");for(;o;)try{if(n=1,r&&(i=2&s[0]?r.return:s[0]?r.throw||((i=r.return)&&i.call(r),0):r.next)&&!(i=i.call(r,s[1])).done)return i;switch(r=0,i&&(s=[2&s[0],i.value]),s[0]){case 0:case 1:i=s;break;case 4:return o.label++,{value:s[1],done:!1};case 5:o.label++,r=s[1],s=[0];continue;case 7:s=o.ops.pop(),o.trys.pop();continue;default:if(!(i=(i=o.trys).length>0&&i[i.length-1])&&(6===s[0]||2===s[0])){o=0;continue}if(3===s[0]&&(!i||s[1]>i[0]&&s[1]<i[3])){o.label=s[1];break}if(6===s[0]&&o.label<i[1]){o.label=i[1],i=s;break}if(i&&o.label<i[2]){o.label=i[2],o.ops.push(s);break}i[2]&&o.ops.pop(),o.trys.pop();continue}s=t.call(e,o)}catch(a){s=[6,a],r=0}finally{n=i=0}if(5&s[0])throw s[1];return{value:s[0]?s[1]:void 0,done:!0}}([s,a])}}}(this,function(n){switch(n.label){case 0:if(!(null==t?void 0:t.onUserChanged))return[3,4];n.label=1;case 1:return n.trys.push([1,3,,4]),[4,t.onUserChanged(e)];case 2:return n.sent(),[3,4];case 3:return s(n.sent()),[3,4];case 4:return l(e),[2]}})},new(i||(i=Promise))(function(e,t){function s(e){try{l(o.next(e))}catch(n){t(n)}}function a(e){try{l(o.throw(e))}catch(n){t(n)}}function l(t){var n;t.done?e(t.value):((n=t.value)instanceof i?n:new i(function(e){e(n)})).then(s,a)}l((o=o.apply(n,r||[])).next())})},s);return function(){n()}},[e]);var h=[u,i,r];return(0,o.useMemo)(function(){return h},h)},d=n(1664),f=n.n(d),p=n(1163),m=n(4536);function g(){let{user:e,username:t}=(0,o.useContext)(i.S),n=(0,p.useRouter)(),a=()=>{s.I8.signOut(),n.reload()};return(0,r.jsx)("nav",{className:"navbar",children:(0,r.jsxs)("ul",{children:[(0,r.jsx)("li",{children:(0,r.jsx)(f(),{href:"/",children:(0,r.jsx)("button",{className:"btn-logo",children:"InfiOpp"})})}),t&&(0,r.jsxs)(r.Fragment,{children:[(0,r.jsx)("li",{className:"push-left",children:(0,r.jsx)("button",{onClick:a,children:"Sign Out"})}),(0,r.jsx)("li",{children:(0,r.jsx)(m.Z,{eventData:null})}),(0,r.jsx)("li",{children:(0,r.jsx)(f(),{href:"/".concat(t),children:(0,r.jsx)("img",{src:(null==e?void 0:e.photoURL)||"/hacker.png"})})})]}),!t&&(0,r.jsx)("li",{children:(0,r.jsx)(f(),{href:"/enter",children:(0,r.jsx)("button",{className:"btn-blue",children:"Log in"})})})]})})}function y(){return(0,r.jsxs)("footer",{children:[(0,r.jsx)("div",{children:(0,r.jsx)("a",{href:"https://twitter.com/InfiOppME",target:"_blank",children:(0,r.jsx)("img",{src:"/twitter.png",alt:"title",className:"footerLogo"})})}),(0,r.jsxs)("div",{children:["InfiOpp by ",(0,r.jsx)("a",{href:"https://twitter.com/RajGM_Hacks/",target:"_blank",children:"RajGM"})]}),(0,r.jsx)("div",{children:(0,r.jsx)("a",{href:"https://www.linkedin.com/company/infiopp/",target:"_blank",children:(0,r.jsx)("img",{src:"/linkedin.png",alt:"title",className:"footerLogo"})})})]})}var v=n(24),_=n(9008),w=n.n(_);function b(e){let{title:t="InfiOpp",description:n="Opportunities listed and verified by the community",image:i="logo.jpg"}=e;return(0,r.jsxs)(w(),{children:[(0,r.jsx)("title",{children:"InfiOpp"}),(0,r.jsx)("meta",{name:"twitter:card",content:"summary"}),(0,r.jsx)("meta",{name:"twitter:site",content:"@InfiOppME"}),(0,r.jsx)("meta",{name:"twitter:title",content:t}),(0,r.jsx)("meta",{name:"twitter:description",content:n}),(0,r.jsx)("meta",{name:"twitter:image",content:"/"+i}),(0,r.jsx)("meta",{property:"og:title",content:t}),(0,r.jsx)("meta",{property:"og:description",content:n}),(0,r.jsx)("meta",{property:"og:image",content:"/"+i})]})}var I=function(e){let{Component:t,pageProps:n}=e,a=function(){let[e]=h(s.I8),[t,n]=(0,o.useState)(null),[r,i]=(0,o.useState)(null);return(0,o.useEffect)(()=>{let t;if(e){let r=s.RZ.collection("users").doc(e.uid);t=r.onSnapshot(e=>{var t,r;n(null===(t=e.data())||void 0===t?void 0:t.username);let o=s.RZ.collection("usernames").doc(null===(r=e.data())||void 0===r?void 0:r.username);o.get().then(e=>{i(e.data())})})}else n(null);return t},[e]),{user:e,username:t,social:r}}();return console.log("userData FROM MAIN: ",a),(0,r.jsx)(i.S.Provider,{value:a,children:(0,r.jsxs)(v.zt,{children:[(0,r.jsx)(b,{title:"InfiOpp",description:"Sign up for InfiOpp!"}),(0,r.jsx)(g,{}),(0,r.jsx)(t,{...n}),(0,r.jsx)(y,{})]})})}},6762:function(){},7475:function(){},7663:function(e){!function(){var t={229:function(e){var t,n,r,i=e.exports={};function s(){throw Error("setTimeout has not been defined")}function o(){throw Error("clearTimeout has not been defined")}function a(e){if(t===setTimeout)return setTimeout(e,0);if((t===s||!t)&&setTimeout)return t=setTimeout,setTimeout(e,0);try{return t(e,0)}catch(r){try{return t.call(null,e,0)}catch(n){return t.call(this,e,0)}}}!function(){try{t="function"==typeof setTimeout?setTimeout:s}catch(e){t=s}try{n="function"==typeof clearTimeout?clearTimeout:o}catch(r){n=o}}();var l=[],u=!1,c=-1;function h(){u&&r&&(u=!1,r.length?l=r.concat(l):c=-1,l.length&&d())}function d(){if(!u){var e=a(h);u=!0;for(var t=l.length;t;){for(r=l,l=[];++c<t;)r&&r[c].run();c=-1,t=l.length}r=null,u=!1,function(e){if(n===clearTimeout)return clearTimeout(e);if((n===o||!n)&&clearTimeout)return n=clearTimeout,clearTimeout(e);try{n(e)}catch(r){try{return n.call(null,e)}catch(t){return n.call(this,e)}}}(e)}}function f(e,t){this.fun=e,this.array=t}function p(){}i.nextTick=function(e){var t=Array(arguments.length-1);if(arguments.length>1)for(var n=1;n<arguments.length;n++)t[n-1]=arguments[n];l.push(new f(e,t)),1!==l.length||u||a(d)},f.prototype.run=function(){this.fun.apply(null,this.array)},i.title="browser",i.browser=!0,i.env={},i.argv=[],i.version="",i.versions={},i.on=p,i.addListener=p,i.once=p,i.off=p,i.removeListener=p,i.removeAllListeners=p,i.emit=p,i.prependListener=p,i.prependOnceListener=p,i.listeners=function(e){return[]},i.binding=function(e){throw Error("process.binding is not supported")},i.cwd=function(){return"/"},i.chdir=function(e){throw Error("process.chdir is not supported")},i.umask=function(){return 0}}},n={};function r(e){var i=n[e];if(void 0!==i)return i.exports;var s=n[e]={exports:{}},o=!0;try{t[e](s,s.exports,r),o=!1}finally{o&&delete n[e]}return s.exports}r.ab="//";var i=r(229);e.exports=i}()},9008:function(e,t,n){e.exports=n(3121)},1664:function(e,t,n){e.exports=n(1551)},1163:function(e,t,n){e.exports=n(880)},5760:function(e){"use strict";function t(e){this._maxSize=e,this.clear()}t.prototype.clear=function(){this._size=0,this._values=Object.create(null)},t.prototype.get=function(e){return this._values[e]},t.prototype.set=function(e,t){return this._size>=this._maxSize&&this.clear(),!(e in this._values)&&this._size++,this._values[e]=t};var n=/[^.^\]^[]+|(?=\[\]|\.\.)/g,r=/^\d+$/,i=/^\d/,s=/[~`!#$%\^&*+=\-\[\]\\';,/{}|\\":<>\?]/g,o=/^\s*(['"]?)(.*?)(\1)\s*$/,a=new t(512),l=new t(512),u=new t(512);function c(e){return a.get(e)||a.set(e,h(e).map(function(e){return e.replace(o,"$2")}))}function h(e){return e.match(n)||[""]}function d(e){return"string"==typeof e&&e&&-1!==["'",'"'].indexOf(e.charAt(0))}e.exports={Cache:t,split:h,normalizePath:c,setter:function(e){var t=c(e);return l.get(e)||l.set(e,function(e,n){for(var r=0,i=t.length,s=e;r<i-1;){var o=t[r];if("__proto__"===o||"constructor"===o||"prototype"===o)return e;s=s[t[r++]]}s[t[r]]=n})},getter:function(e,t){var n=c(e);return u.get(e)||u.set(e,function(e){for(var r=0,i=n.length;r<i;){if(null==e&&t)return;e=e[n[r++]]}return e})},join:function(e){return e.reduce(function(e,t){return e+(d(t)||r.test(t)?"["+t+"]":(e?".":"")+t)},"")},forEach:function(e,t,n){!function(e,t,n){var o,a,l,u,c,h=e.length;for(l=0;l<h;l++){(a=e[l])&&(!d(o=a)&&(o.match(i)&&!o.match(r)||s.test(o))&&(a='"'+a+'"'),u=!(c=d(a))&&/^\d+$/.test(a),t.call(n,a,c,u,l,e))}}(Array.isArray(e)?e:h(e),t,n)}}},9590:function(e){"use strict";var t=Array.isArray,n=Object.keys,r=Object.prototype.hasOwnProperty,i="undefined"!=typeof Element;e.exports=function(e,s){try{return function e(s,o){if(s===o)return!0;if(s&&o&&"object"==typeof s&&"object"==typeof o){var a,l,u,c=t(s),h=t(o);if(c&&h){if((l=s.length)!=o.length)return!1;for(a=l;0!=a--;)if(!e(s[a],o[a]))return!1;return!0}if(c!=h)return!1;var d=s instanceof Date,f=o instanceof Date;if(d!=f)return!1;if(d&&f)return s.getTime()==o.getTime();var p=s instanceof RegExp,m=o instanceof RegExp;if(p!=m)return!1;if(p&&m)return s.toString()==o.toString();var g=n(s);if((l=g.length)!==n(o).length)return!1;for(a=l;0!=a--;)if(!r.call(o,g[a]))return!1;if(i&&s instanceof Element&&o instanceof Element)return s===o;for(a=l;0!=a--;)if(("_owner"!==(u=g[a])||!s.$$typeof)&&!e(s[u],o[u]))return!1;return!0}return s!=s&&o!=o}(e,s)}catch(o){if(o.message&&o.message.match(/stack|recursion/i)||-2146828260===o.number)return console.warn("Warning: react-fast-compare does not handle circular references.",o.name,o.message),!1;throw o}}},9921:function(e,t){"use strict";/** @license React v16.13.1
 * react-is.production.min.js
 *
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */var n="function"==typeof Symbol&&Symbol.for,r=n?Symbol.for("react.element"):60103,i=n?Symbol.for("react.portal"):60106,s=n?Symbol.for("react.fragment"):60107,o=n?Symbol.for("react.strict_mode"):60108,a=n?Symbol.for("react.profiler"):60114,l=n?Symbol.for("react.provider"):60109,u=n?Symbol.for("react.context"):60110,c=n?Symbol.for("react.async_mode"):60111,h=n?Symbol.for("react.concurrent_mode"):60111,d=n?Symbol.for("react.forward_ref"):60112,f=n?Symbol.for("react.suspense"):60113,p=n?Symbol.for("react.suspense_list"):60120,m=n?Symbol.for("react.memo"):60115,g=n?Symbol.for("react.lazy"):60116,y=n?Symbol.for("react.block"):60121,v=n?Symbol.for("react.fundamental"):60117,_=n?Symbol.for("react.responder"):60118,w=n?Symbol.for("react.scope"):60119;function b(e){if("object"==typeof e&&null!==e){var t=e.$$typeof;switch(t){case r:switch(e=e.type){case c:case h:case s:case a:case o:case f:return e;default:switch(e=e&&e.$$typeof){case u:case d:case g:case m:case l:return e;default:return t}}case i:return t}}}function I(e){return b(e)===h}t.AsyncMode=c,t.ConcurrentMode=h,t.ContextConsumer=u,t.ContextProvider=l,t.Element=r,t.ForwardRef=d,t.Fragment=s,t.Lazy=g,t.Memo=m,t.Portal=i,t.Profiler=a,t.StrictMode=o,t.Suspense=f,t.isAsyncMode=function(e){return I(e)||b(e)===c},t.isConcurrentMode=I,t.isContextConsumer=function(e){return b(e)===u},t.isContextProvider=function(e){return b(e)===l},t.isElement=function(e){return"object"==typeof e&&null!==e&&e.$$typeof===r},t.isForwardRef=function(e){return b(e)===d},t.isFragment=function(e){return b(e)===s},t.isLazy=function(e){return b(e)===g},t.isMemo=function(e){return b(e)===m},t.isPortal=function(e){return b(e)===i},t.isProfiler=function(e){return b(e)===a},t.isStrictMode=function(e){return b(e)===o},t.isSuspense=function(e){return b(e)===f},t.isValidElementType=function(e){return"string"==typeof e||"function"==typeof e||e===s||e===h||e===a||e===o||e===f||e===p||"object"==typeof e&&null!==e&&(e.$$typeof===g||e.$$typeof===m||e.$$typeof===l||e.$$typeof===u||e.$$typeof===d||e.$$typeof===v||e.$$typeof===_||e.$$typeof===w||e.$$typeof===y)},t.typeOf=b},9864:function(e,t,n){"use strict";e.exports=n(9921)},9885:function(e){let t=/[A-Z\xc0-\xd6\xd8-\xde]?[a-z\xdf-\xf6\xf8-\xff]+(?:['’](?:d|ll|m|re|s|t|ve))?(?=[\xac\xb1\xd7\xf7\x00-\x2f\x3a-\x40\x5b-\x60\x7b-\xbf\u2000-\u206f \t\x0b\f\xa0\ufeff\n\r\u2028\u2029\u1680\u180e\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u202f\u205f\u3000]|[A-Z\xc0-\xd6\xd8-\xde]|$)|(?:[A-Z\xc0-\xd6\xd8-\xde]|[^\ud800-\udfff\xac\xb1\xd7\xf7\x00-\x2f\x3a-\x40\x5b-\x60\x7b-\xbf\u2000-\u206f \t\x0b\f\xa0\ufeff\n\r\u2028\u2029\u1680\u180e\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u202f\u205f\u3000\d+\u2700-\u27bfa-z\xdf-\xf6\xf8-\xffA-Z\xc0-\xd6\xd8-\xde])+(?:['’](?:D|LL|M|RE|S|T|VE))?(?=[\xac\xb1\xd7\xf7\x00-\x2f\x3a-\x40\x5b-\x60\x7b-\xbf\u2000-\u206f \t\x0b\f\xa0\ufeff\n\r\u2028\u2029\u1680\u180e\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u202f\u205f\u3000]|[A-Z\xc0-\xd6\xd8-\xde](?:[a-z\xdf-\xf6\xf8-\xff]|[^\ud800-\udfff\xac\xb1\xd7\xf7\x00-\x2f\x3a-\x40\x5b-\x60\x7b-\xbf\u2000-\u206f \t\x0b\f\xa0\ufeff\n\r\u2028\u2029\u1680\u180e\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u202f\u205f\u3000\d+\u2700-\u27bfa-z\xdf-\xf6\xf8-\xffA-Z\xc0-\xd6\xd8-\xde])|$)|[A-Z\xc0-\xd6\xd8-\xde]?(?:[a-z\xdf-\xf6\xf8-\xff]|[^\ud800-\udfff\xac\xb1\xd7\xf7\x00-\x2f\x3a-\x40\x5b-\x60\x7b-\xbf\u2000-\u206f \t\x0b\f\xa0\ufeff\n\r\u2028\u2029\u1680\u180e\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u202f\u205f\u3000\d+\u2700-\u27bfa-z\xdf-\xf6\xf8-\xffA-Z\xc0-\xd6\xd8-\xde])+(?:['’](?:d|ll|m|re|s|t|ve))?|[A-Z\xc0-\xd6\xd8-\xde]+(?:['’](?:D|LL|M|RE|S|T|VE))?|\d*(?:1ST|2ND|3RD|(?![123])\dTH)(?=\b|[a-z_])|\d*(?:1st|2nd|3rd|(?![123])\dth)(?=\b|[A-Z_])|\d+|(?:[\u2700-\u27bf]|(?:\ud83c[\udde6-\uddff]){2}|[\ud800-\udbff][\udc00-\udfff])[\ufe0e\ufe0f]?(?:[\u0300-\u036f\ufe20-\ufe2f\u20d0-\u20ff]|\ud83c[\udffb-\udfff])?(?:\u200d(?:[^\ud800-\udfff]|(?:\ud83c[\udde6-\uddff]){2}|[\ud800-\udbff][\udc00-\udfff])[\ufe0e\ufe0f]?(?:[\u0300-\u036f\ufe20-\ufe2f\u20d0-\u20ff]|\ud83c[\udffb-\udfff])?)*/g,n=e=>e.match(t)||[],r=e=>e[0].toUpperCase()+e.slice(1),i=(e,t)=>n(e).join(t).toLowerCase(),s=e=>n(e).reduce((e,t)=>`${e}${e?t[0].toUpperCase()+t.slice(1).toLowerCase():t.toLowerCase()}`,""),o=e=>r(s(e)),a=e=>i(e,"_"),l=e=>i(e,"-"),u=e=>r(i(e," ")),c=e=>n(e).map(r).join(" ");e.exports={words:n,upperFirst:r,camelCase:s,pascalCase:o,snakeCase:a,kebabCase:l,sentenceCase:u,titleCase:c}},4633:function(e){function t(e,t){var n=e.length,r=Array(n),i={},s=n,o=function(e){for(var t=new Map,n=0,r=e.length;n<r;n++){var i=e[n];t.has(i[0])||t.set(i[0],new Set),t.has(i[1])||t.set(i[1],new Set),t.get(i[0]).add(i[1])}return t}(t),a=function(e){for(var t=new Map,n=0,r=e.length;n<r;n++)t.set(e[n],n);return t}(e);for(t.forEach(function(e){if(!a.has(e[0])||!a.has(e[1]))throw Error("Unknown node. There is an unknown node in the supplied edges.")});s--;)i[s]||function e(t,s,l){if(l.has(t)){var u;try{u=", node was:"+JSON.stringify(t)}catch(c){u=""}throw Error("Cyclic dependency"+u)}if(!a.has(t))throw Error("Found unknown node. Make sure to provided all involved nodes. Unknown node: "+JSON.stringify(t));if(!i[s]){i[s]=!0;var h=o.get(t)||new Set;if(s=(h=Array.from(h)).length){l.add(t);do{var d=h[--s];e(d,a.get(d),l)}while(s);l.delete(t)}r[--n]=t}}(e[s],s,new Set);return r}e.exports=function(e){return t(function(e){for(var t=new Set,n=0,r=e.length;n<r;n++){var i=e[n];t.add(i[0]),t.add(i[1])}return Array.from(t)}(e),e)},e.exports.array=t},6310:function(e,t,n){"use strict";var r,i=n(5760),s=(n(9885),n(4633));let o=Object.prototype.toString,a=Error.prototype.toString,l=RegExp.prototype.toString,u="undefined"!=typeof Symbol?Symbol.prototype.toString:()=>"",c=/^Symbol\((.*)\)(.*)$/;function h(e,t=!1){if(null==e||!0===e||!1===e)return""+e;let n=typeof e;if("number"===n)return e!=+e?"NaN":0===e&&1/e<0?"-0":""+e;if("string"===n)return t?`"${e}"`:e;if("function"===n)return"[Function "+(e.name||"anonymous")+"]";if("symbol"===n)return u.call(e).replace(c,"Symbol($1)");let r=o.call(e).slice(8,-1);return"Date"===r?isNaN(e.getTime())?""+e:e.toISOString(e):"Error"===r||e instanceof Error?"["+a.call(e)+"]":"RegExp"===r?l.call(e):null}function d(e,t){let n=h(e,t);return null!==n?n:JSON.stringify(e,function(e,n){let r=h(this[e],t);return null!==r?r:n},2)}function f(e){return null==e?[]:[].concat(e)}let p=/\$\{\s*(\w+)\s*\}/g;class m extends Error{static formatError(e,t){let n=t.label||t.path||"this";return(n!==t.path&&(t=Object.assign({},t,{path:n})),"string"==typeof e)?e.replace(p,(e,n)=>d(t[n])):"function"==typeof e?e(t):e}static isError(e){return e&&"ValidationError"===e.name}constructor(e,t,n,r){super(),this.value=void 0,this.path=void 0,this.type=void 0,this.errors=void 0,this.params=void 0,this.inner=void 0,this.name="ValidationError",this.value=t,this.path=n,this.type=r,this.errors=[],this.inner=[],f(e).forEach(e=>{m.isError(e)?(this.errors.push(...e.errors),this.inner=this.inner.concat(e.inner.length?e.inner:e)):this.errors.push(e)}),this.message=this.errors.length>1?`${this.errors.length} errors occurred`:this.errors[0],Error.captureStackTrace&&Error.captureStackTrace(this,m)}}let g={default:"${path} is invalid",required:"${path} is a required field",defined:"${path} must be defined",notNull:"${path} cannot be null",oneOf:"${path} must be one of the following values: ${values}",notOneOf:"${path} must not be one of the following values: ${values}",notType:({path:e,type:t,value:n,originalValue:r})=>{let i=null!=r&&r!==n?` (cast from the value \`${d(r,!0)}\`).`:".";return"mixed"!==t?`${e} must be a \`${t}\` type, but the final value was: \`${d(n,!0)}\``+i:`${e} must match the configured type. The validated value was: \`${d(n,!0)}\``+i}},y={min:"${path} field must be later than ${min}",max:"${path} field must be at earlier than ${max}"};Object.assign(Object.create(null),{mixed:g,string:{length:"${path} must be exactly ${length} characters",min:"${path} must be at least ${min} characters",max:"${path} must be at most ${max} characters",matches:'${path} must match the following: "${regex}"',email:"${path} must be a valid email",url:"${path} must be a valid URL",uuid:"${path} must be a valid UUID",trim:"${path} must be a trimmed string",lowercase:"${path} must be a lowercase string",uppercase:"${path} must be a upper case string"},number:{min:"${path} must be greater than or equal to ${min}",max:"${path} must be less than or equal to ${max}",lessThan:"${path} must be less than ${less}",moreThan:"${path} must be greater than ${more}",positive:"${path} must be a positive number",negative:"${path} must be a negative number",integer:"${path} must be an integer"},date:y,object:{noUnknown:"${path} field has unspecified keys: ${unknown}"},array:{min:"${path} field must have at least ${min} items",max:"${path} field must have less than or equal to ${max} items",length:"${path} must have ${length} items"},boolean:{isValue:"${path} field must be ${value}"}});let v=e=>e&&e.__isYupSchema__;class _{static fromOptions(e,t){if(!t.then&&!t.otherwise)throw TypeError("either `then:` or `otherwise:` is required for `when()` conditions");let{is:n,then:r,otherwise:i}=t,s="function"==typeof n?n:(...e)=>e.every(e=>e===n);return new _(e,(e,t)=>{var n;let o=s(...e)?r:i;return null!=(n=null==o?void 0:o(t))?n:t})}constructor(e,t){this.fn=void 0,this.refs=e,this.refs=e,this.fn=t}resolve(e,t){let n=this.refs.map(e=>e.getValue(null==t?void 0:t.value,null==t?void 0:t.parent,null==t?void 0:t.context)),r=this.fn(n,e,t);if(void 0===r||r===e)return e;if(!v(r))throw TypeError("conditions must return a schema object");return r.resolve(t)}}let w={context:"$",value:"."};class b{constructor(e,t={}){if(this.key=void 0,this.isContext=void 0,this.isValue=void 0,this.isSibling=void 0,this.path=void 0,this.getter=void 0,this.map=void 0,"string"!=typeof e)throw TypeError("ref must be a string, got: "+e);if(this.key=e.trim(),""===e)throw TypeError("ref must be a non-empty string");this.isContext=this.key[0]===w.context,this.isValue=this.key[0]===w.value,this.isSibling=!this.isContext&&!this.isValue;let n=this.isContext?w.context:this.isValue?w.value:"";this.path=this.key.slice(n.length),this.getter=this.path&&(0,i.getter)(this.path,!0),this.map=t.map}getValue(e,t,n){let r=this.isContext?n:this.isValue?e:t;return this.getter&&(r=this.getter(r||{})),this.map&&(r=this.map(r)),r}cast(e,t){return this.getValue(e,null==t?void 0:t.parent,null==t?void 0:t.context)}resolve(){return this}describe(){return{type:"ref",key:this.key}}toString(){return`Ref(${this.key})`}static isRef(e){return e&&e.__isYupRef}}b.prototype.__isYupRef=!0;let I=e=>null==e;function T(e){function t({value:t,path:n="",options:r,originalValue:i,schema:s},o,a){let l;let{name:u,test:c,params:h,message:d,skipAbsent:f}=e,{parent:p,context:g,abortEarly:y=s.spec.abortEarly}=r;function v(e){return b.isRef(e)?e.getValue(t,p,g):e}function _(e={}){let r=Object.assign({value:t,originalValue:i,label:s.spec.label,path:e.path||n,spec:s.spec},h,e.params);for(let o of Object.keys(r))r[o]=v(r[o]);let a=new m(m.formatError(e.message||d,r),t,r.path,e.type||u);return a.params=r,a}let w=y?o:a,T={path:n,parent:p,type:u,from:r.from,createError:_,resolve:v,options:r,originalValue:i,schema:s},E=e=>{m.isError(e)?w(e):e?a(null):w(_())},S=e=>{m.isError(e)?w(e):o(e)},k=f&&I(t);if(!r.sync){try{Promise.resolve(!!k||c.call(T,t,T)).then(E,S)}catch(x){S(x)}return}try{var C;if(l=!!k||c.call(T,t,T),"function"==typeof(null==(C=l)?void 0:C.then))throw Error(`Validation test of type: "${T.type}" returned a Promise during a synchronous validate. This test will finish after the validate call has returned`)}catch(N){S(N);return}E(l)}return t.OPTIONS=e,t}class E extends Set{describe(){let e=[];for(let t of this.values())e.push(b.isRef(t)?t.describe():t);return e}resolveAll(e){let t=[];for(let n of this.values())t.push(e(n));return t}clone(){return new E(this.values())}merge(e,t){let n=this.clone();return e.forEach(e=>n.add(e)),t.forEach(e=>n.delete(e)),n}}function S(e,t=new Map){let n;if(v(e)||!e||"object"!=typeof e)return e;if(t.has(e))return t.get(e);if(e instanceof Date)n=new Date(e.getTime()),t.set(e,n);else if(e instanceof RegExp)n=RegExp(e),t.set(e,n);else if(Array.isArray(e)){n=Array(e.length),t.set(e,n);for(let r=0;r<e.length;r++)n[r]=S(e[r],t)}else if(e instanceof Map)for(let[i,s]of(n=new Map,t.set(e,n),e.entries()))n.set(i,S(s,t));else if(e instanceof Set)for(let o of(n=new Set,t.set(e,n),e))n.add(S(o,t));else if(e instanceof Object)for(let[a,l]of(n={},t.set(e,n),Object.entries(e)))n[a]=S(l,t);else throw Error(`Unable to clone ${e}`);return n}class k{constructor(e){this.type=void 0,this.deps=[],this.tests=void 0,this.transforms=void 0,this.conditions=[],this._mutate=void 0,this.internalTests={},this._whitelist=new E,this._blacklist=new E,this.exclusiveTests=Object.create(null),this._typeCheck=void 0,this.spec=void 0,this.tests=[],this.transforms=[],this.withMutation(()=>{this.typeError(g.notType)}),this.type=e.type,this._typeCheck=e.check,this.spec=Object.assign({strip:!1,strict:!1,abortEarly:!0,recursive:!0,nullable:!1,optional:!0,coerce:!0},null==e?void 0:e.spec),this.withMutation(e=>{e.nonNullable()})}get _type(){return this.type}clone(e){if(this._mutate)return e&&Object.assign(this.spec,e),this;let t=Object.create(Object.getPrototypeOf(this));return t.type=this.type,t._typeCheck=this._typeCheck,t._whitelist=this._whitelist.clone(),t._blacklist=this._blacklist.clone(),t.internalTests=Object.assign({},this.internalTests),t.exclusiveTests=Object.assign({},this.exclusiveTests),t.deps=[...this.deps],t.conditions=[...this.conditions],t.tests=[...this.tests],t.transforms=[...this.transforms],t.spec=S(Object.assign({},this.spec,e)),t}label(e){let t=this.clone();return t.spec.label=e,t}meta(...e){if(0===e.length)return this.spec.meta;let t=this.clone();return t.spec.meta=Object.assign(t.spec.meta||{},e[0]),t}withMutation(e){let t=this._mutate;this._mutate=!0;let n=e(this);return this._mutate=t,n}concat(e){if(!e||e===this)return this;if(e.type!==this.type&&"mixed"!==this.type)throw TypeError(`You cannot \`concat()\` schema's of different types: ${this.type} and ${e.type}`);let t=e.clone(),n=Object.assign({},this.spec,t.spec);return t.spec=n,t.internalTests=Object.assign({},this.internalTests,t.internalTests),t._whitelist=this._whitelist.merge(e._whitelist,e._blacklist),t._blacklist=this._blacklist.merge(e._blacklist,e._whitelist),t.tests=this.tests,t.exclusiveTests=this.exclusiveTests,t.withMutation(t=>{e.tests.forEach(e=>{t.test(e.OPTIONS)})}),t.transforms=[...this.transforms,...t.transforms],t}isType(e){return null==e?!!this.spec.nullable&&null===e||!!this.spec.optional&&void 0===e:this._typeCheck(e)}resolve(e){let t=this;if(t.conditions.length){let n=t.conditions;(t=t.clone()).conditions=[],t=(t=n.reduce((t,n)=>n.resolve(t,e),t)).resolve(e)}return t}resolveOptions(e){var t,n,r;return Object.assign({},e,{from:e.from||[],strict:null!=(t=e.strict)?t:this.spec.strict,abortEarly:null!=(n=e.abortEarly)?n:this.spec.abortEarly,recursive:null!=(r=e.recursive)?r:this.spec.recursive})}cast(e,t={}){let n=this.resolve(Object.assign({value:e},t)),r="ignore-optionality"===t.assert,i=n._cast(e,t);if(!1!==t.assert&&!n.isType(i)){if(r&&I(i))return i;let s=d(e),o=d(i);throw TypeError(`The value of ${t.path||"field"} could not be cast to a value that satisfies the schema type: "${n.type}". 

attempted value: ${s} 
`+(o!==s?`result of cast: ${o}`:""))}return i}_cast(e,t){let n=void 0===e?e:this.transforms.reduce((t,n)=>n.call(this,t,e,this),e);return void 0===n&&(n=this.getDefault(t)),n}_validate(e,t={},n,r){let{path:i,originalValue:s=e,strict:o=this.spec.strict}=t,a=e;o||(a=this._cast(a,Object.assign({assert:!1},t)));let l=[];for(let u of Object.values(this.internalTests))u&&l.push(u);this.runTests({path:i,value:a,originalValue:s,options:t,tests:l},n,e=>{if(e.length)return r(e,a);this.runTests({path:i,value:a,originalValue:s,options:t,tests:this.tests},n,r)})}runTests(e,t,n){let r=!1,{tests:i,value:s,originalValue:o,path:a,options:l}=e,u=e=>{r||(r=!0,t(e,s))},c=e=>{r||(r=!0,n(e,s))},h=i.length,d=[];if(!h)return c([]);let f={value:s,originalValue:o,path:a,options:l,schema:this};for(let p=0;p<i.length;p++){let m=i[p];m(f,u,function(e){e&&(d=d.concat(e)),--h<=0&&c(d)})}}asNestedTest({key:e,index:t,parent:n,parentPath:r,originalParent:i,options:s}){let o=null!=e?e:t;if(null==o)throw TypeError("Must include `key` or `index` for nested validations");let a="number"==typeof o,l=n[o],u=Object.assign({},s,{strict:!0,parent:n,value:l,originalValue:i[o],key:void 0,[a?"index":"key"]:o,path:a||o.includes(".")?`${r||""}[${l?o:`"${o}"`}]`:(r?`${r}.`:"")+e});return(e,t,n)=>this.resolve(u)._validate(l,u,t,n)}validate(e,t){let n=this.resolve(Object.assign({},t,{value:e}));return new Promise((r,i)=>n._validate(e,t,(e,t)=>{m.isError(e)&&(e.value=t),i(e)},(e,t)=>{e.length?i(new m(e,t)):r(t)}))}validateSync(e,t){let n;return this.resolve(Object.assign({},t,{value:e}))._validate(e,Object.assign({},t,{sync:!0}),(e,t)=>{throw m.isError(e)&&(e.value=t),e},(t,r)=>{if(t.length)throw new m(t,e);n=r}),n}isValid(e,t){return this.validate(e,t).then(()=>!0,e=>{if(m.isError(e))return!1;throw e})}isValidSync(e,t){try{return this.validateSync(e,t),!0}catch(n){if(m.isError(n))return!1;throw n}}_getDefault(e){let t=this.spec.default;return null==t?t:"function"==typeof t?t.call(this):S(t)}getDefault(e){return this.resolve(e||{})._getDefault(e)}default(e){return 0==arguments.length?this._getDefault():this.clone({default:e})}strict(e=!0){return this.clone({strict:e})}nullability(e,t){let n=this.clone({nullable:e});return n.internalTests.nullable=T({message:t,name:"nullable",test(e){return null!==e||this.schema.spec.nullable}}),n}optionality(e,t){let n=this.clone({optional:e});return n.internalTests.optionality=T({message:t,name:"optionality",test(e){return void 0!==e||this.schema.spec.optional}}),n}optional(){return this.optionality(!0)}defined(e=g.defined){return this.optionality(!1,e)}nullable(){return this.nullability(!0)}nonNullable(e=g.notNull){return this.nullability(!1,e)}required(e=g.required){return this.clone().withMutation(t=>t.nonNullable(e).defined(e))}notRequired(){return this.clone().withMutation(e=>e.nullable().optional())}transform(e){let t=this.clone();return t.transforms.push(e),t}test(...e){let t;if(void 0===(t=1===e.length?"function"==typeof e[0]?{test:e[0]}:e[0]:2===e.length?{name:e[0],test:e[1]}:{name:e[0],message:e[1],test:e[2]}).message&&(t.message=g.default),"function"!=typeof t.test)throw TypeError("`test` is a required parameters");let n=this.clone(),r=T(t),i=t.exclusive||t.name&&!0===n.exclusiveTests[t.name];if(t.exclusive&&!t.name)throw TypeError("Exclusive tests must provide a unique `name` identifying the test");return t.name&&(n.exclusiveTests[t.name]=!!t.exclusive),n.tests=n.tests.filter(e=>e.OPTIONS.name!==t.name||!i&&e.OPTIONS.test!==r.OPTIONS.test),n.tests.push(r),n}when(e,t){Array.isArray(e)||"string"==typeof e||(t=e,e=".");let n=this.clone(),r=f(e).map(e=>new b(e));return r.forEach(e=>{e.isSibling&&n.deps.push(e.key)}),n.conditions.push("function"==typeof t?new _(r,t):_.fromOptions(r,t)),n}typeError(e){let t=this.clone();return t.internalTests.typeError=T({message:e,name:"typeError",skipAbsent:!0,test(e){return!!this.schema._typeCheck(e)||this.createError({params:{type:this.schema.type}})}}),t}oneOf(e,t=g.oneOf){let n=this.clone();return e.forEach(e=>{n._whitelist.add(e),n._blacklist.delete(e)}),n.internalTests.whiteList=T({message:t,name:"oneOf",skipAbsent:!0,test(e){let t=this.schema._whitelist,n=t.resolveAll(this.resolve);return!!n.includes(e)||this.createError({params:{values:Array.from(t).join(", "),resolved:n}})}}),n}notOneOf(e,t=g.notOneOf){let n=this.clone();return e.forEach(e=>{n._blacklist.add(e),n._whitelist.delete(e)}),n.internalTests.blacklist=T({message:t,name:"notOneOf",test(e){let t=this.schema._blacklist,n=t.resolveAll(this.resolve);return!n.includes(e)||this.createError({params:{values:Array.from(t).join(", "),resolved:n}})}}),n}strip(e=!0){let t=this.clone();return t.spec.strip=e,t}describe(e){let t=(e?this.resolve(e):this).clone(),{label:n,meta:r,optional:i,nullable:s}=t.spec,o={meta:r,label:n,optional:i,nullable:s,default:t.getDefault(e),type:t.type,oneOf:t._whitelist.describe(),notOneOf:t._blacklist.describe(),tests:t.tests.map(e=>({name:e.OPTIONS.name,params:e.OPTIONS.params})).filter((e,t,n)=>n.findIndex(t=>t.name===e.name)===t)};return o}}for(let x of(k.prototype.__isYupSchema__=!0,["validate","validateSync"]))k.prototype[`${x}At`]=function(e,t,n={}){let{parent:r,parentPath:s,schema:o}=function(e,t,n,r=n){let s,o,a;return t?((0,i.forEach)(t,(i,l,u)=>{let c=l?i.slice(1,i.length-1):i,h="tuple"===(e=e.resolve({context:r,parent:s,value:n})).type,d=u?parseInt(c,10):0;if(e.innerType||h){if(h&&!u)throw Error(`Yup.reach cannot implicitly index into a tuple type. the path part "${a}" must contain an index to the tuple element, e.g. "${a}[0]"`);if(n&&d>=n.length)throw Error(`Yup.reach cannot resolve an array item at index: ${i}, in the path: ${t}. because there is no value at that index. `);s=n,n=n&&n[d],e=h?e.spec.types[d]:e.innerType}if(!u){if(!e.fields||!e.fields[c])throw Error(`The schema does not contain the path: ${t}. (failed at: ${a} which is a type: "${e.type}")`);s=n,n=n&&n[c],e=e.fields[c]}o=c,a=l?"["+i+"]":"."+i}),{schema:e,parent:s,parentPath:o}):{parent:s,parentPath:t,schema:e}}(this,e,t,n.context);return o[x](r&&r[s],Object.assign({},n,{parent:r,path:e}))};for(let C of["equals","is"])k.prototype[C]=k.prototype.oneOf;for(let N of["not","nope"])k.prototype[N]=k.prototype.notOneOf;({}).toString();var A=/^(\d{4}|[+\-]\d{6})(?:-?(\d{2})(?:-?(\d{2}))?)?(?:[ T]?(\d{2}):?(\d{2})(?::?(\d{2})(?:[,\.](\d{1,}))?)?(?:(Z)|([+\-])(\d{2})(?::?(\d{2}))?)?)?$/;let R=new Date(""),D=e=>"[object Date]"===Object.prototype.toString.call(e);function O(){return new P}class P extends k{constructor(){super({type:"date",check:e=>D(e)&&!isNaN(e.getTime())}),this.withMutation(()=>{this.transform((e,t,n)=>!n.spec.coerce||n.isType(e)||null===e?e:isNaN(e=function(e){var t,n,r=[1,4,5,6,7,10,11],i=0;if(n=A.exec(e)){for(var s,o=0;s=r[o];++o)n[s]=+n[s]||0;n[2]=(+n[2]||1)-1,n[3]=+n[3]||1,n[7]=n[7]?String(n[7]).substr(0,3):0,(void 0===n[8]||""===n[8])&&(void 0===n[9]||""===n[9])?t=+new Date(n[1],n[2],n[3],n[4],n[5],n[6],n[7]):("Z"!==n[8]&&void 0!==n[9]&&(i=60*n[10]+n[11],"+"===n[9]&&(i=0-i)),t=Date.UTC(n[1],n[2],n[3],n[4],n[5]+i,n[6],n[7]))}else t=Date.parse?Date.parse(e):NaN;return t}(e))?P.INVALID_DATE:new Date(e))})}prepareParam(e,t){let n;if(b.isRef(e))n=e;else{let r=this.cast(e);if(!this._typeCheck(r))throw TypeError(`\`${t}\` must be a Date or a value that can be \`cast()\` to a Date`);n=r}return n}min(e,t=y.min){let n=this.prepareParam(e,"min");return this.test({message:t,name:"min",exclusive:!0,params:{min:e},skipAbsent:!0,test(e){return e>=this.resolve(n)}})}max(e,t=y.max){let n=this.prepareParam(e,"max");return this.test({message:t,name:"max",exclusive:!0,params:{max:e},skipAbsent:!0,test(e){return e<=this.resolve(n)}})}}function L(e,t){let n=1/0;return e.some((e,r)=>{var i;if(null!=(i=t.path)&&i.includes(e))return n=r,!0}),n}P.INVALID_DATE=R,O.prototype=P.prototype,O.INVALID_DATE=R;r=[],(e,t)=>L(r,e)-L(r,t)},5816:function(e,t,n){"use strict";let r,i;n.r(t),n.d(t,{FirebaseError:function(){return l.ZR},SDK_VERSION:function(){return F},_DEFAULT_ENTRY_NAME:function(){return k},_addComponent:function(){return A},_addOrOverwriteComponent:function(){return R},_apps:function(){return C},_clearComponents:function(){return L},_components:function(){return N},_getProvider:function(){return O},_registerComponent:function(){return D},_removeServiceInstance:function(){return P},deleteApp:function(){return B},getApp:function(){return V},getApps:function(){return q},initializeApp:function(){return U},onLog:function(){return z},registerVersion:function(){return $},setLogLevel:function(){return G}});var s,o=n(8463),a=n(3333),l=n(4444);let u=(e,t)=>t.some(t=>e instanceof t),c=new WeakMap,h=new WeakMap,d=new WeakMap,f=new WeakMap,p=new WeakMap,m={get(e,t,n){if(e instanceof IDBTransaction){if("done"===t)return h.get(e);if("objectStoreNames"===t)return e.objectStoreNames||d.get(e);if("store"===t)return n.objectStoreNames[1]?void 0:n.objectStore(n.objectStoreNames[0])}return g(e[t])},set:(e,t,n)=>(e[t]=n,!0),has:(e,t)=>e instanceof IDBTransaction&&("done"===t||"store"===t)||t in e};function g(e){var t;if(e instanceof IDBRequest)return function(e){let t=new Promise((t,n)=>{let r=()=>{e.removeEventListener("success",i),e.removeEventListener("error",s)},i=()=>{t(g(e.result)),r()},s=()=>{n(e.error),r()};e.addEventListener("success",i),e.addEventListener("error",s)});return t.then(t=>{t instanceof IDBCursor&&c.set(t,e)}).catch(()=>{}),p.set(t,e),t}(e);if(f.has(e))return f.get(e);let n="function"==typeof(t=e)?t!==IDBDatabase.prototype.transaction||"objectStoreNames"in IDBTransaction.prototype?(i||(i=[IDBCursor.prototype.advance,IDBCursor.prototype.continue,IDBCursor.prototype.continuePrimaryKey])).includes(t)?function(...e){return t.apply(y(this),e),g(c.get(this))}:function(...e){return g(t.apply(y(this),e))}:function(e,...n){let r=t.call(y(this),e,...n);return d.set(r,e.sort?e.sort():[e]),g(r)}:(t instanceof IDBTransaction&&function(e){if(h.has(e))return;let t=new Promise((t,n)=>{let r=()=>{e.removeEventListener("complete",i),e.removeEventListener("error",s),e.removeEventListener("abort",s)},i=()=>{t(),r()},s=()=>{n(e.error||new DOMException("AbortError","AbortError")),r()};e.addEventListener("complete",i),e.addEventListener("error",s),e.addEventListener("abort",s)});h.set(e,t)}(t),u(t,r||(r=[IDBDatabase,IDBObjectStore,IDBIndex,IDBCursor,IDBTransaction])))?new Proxy(t,m):t;return n!==e&&(f.set(e,n),p.set(n,e)),n}let y=e=>p.get(e),v=["get","getKey","getAll","getAllKeys","count"],_=["put","add","delete","clear"],w=new Map;function b(e,t){if(!(e instanceof IDBDatabase&&!(t in e)&&"string"==typeof t))return;if(w.get(t))return w.get(t);let n=t.replace(/FromIndex$/,""),r=t!==n,i=_.includes(n);if(!(n in(r?IDBIndex:IDBObjectStore).prototype)||!(i||v.includes(n)))return;let s=async function(e,...t){let s=this.transaction(e,i?"readwrite":"readonly"),o=s.store;return r&&(o=o.index(t.shift())),(await Promise.all([o[n](...t),i&&s.done]))[0]};return w.set(t,s),s}m={...s=m,get:(e,t,n)=>b(e,t)||s.get(e,t,n),has:(e,t)=>!!b(e,t)||s.has(e,t)};/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class I{constructor(e){this.container=e}getPlatformInfoString(){let e=this.container.getProviders();return e.map(e=>{if(!function(e){let t=e.getComponent();return(null==t?void 0:t.type)==="VERSION"}(e))return null;{let t=e.getImmediate();return`${t.library}/${t.version}`}}).filter(e=>e).join(" ")}}let T="@firebase/app",E="0.8.2",S=new a.Yd("@firebase/app"),k="[DEFAULT]",x={[T]:"fire-core","@firebase/app-compat":"fire-core-compat","@firebase/analytics":"fire-analytics","@firebase/analytics-compat":"fire-analytics-compat","@firebase/app-check":"fire-app-check","@firebase/app-check-compat":"fire-app-check-compat","@firebase/auth":"fire-auth","@firebase/auth-compat":"fire-auth-compat","@firebase/database":"fire-rtdb","@firebase/database-compat":"fire-rtdb-compat","@firebase/functions":"fire-fn","@firebase/functions-compat":"fire-fn-compat","@firebase/installations":"fire-iid","@firebase/installations-compat":"fire-iid-compat","@firebase/messaging":"fire-fcm","@firebase/messaging-compat":"fire-fcm-compat","@firebase/performance":"fire-perf","@firebase/performance-compat":"fire-perf-compat","@firebase/remote-config":"fire-rc","@firebase/remote-config-compat":"fire-rc-compat","@firebase/storage":"fire-gcs","@firebase/storage-compat":"fire-gcs-compat","@firebase/firestore":"fire-fst","@firebase/firestore-compat":"fire-fst-compat","fire-js":"fire-js",firebase:"fire-js-all"},C=new Map,N=new Map;function A(e,t){try{e.container.addComponent(t)}catch(n){S.debug(`Component ${t.name} failed to register with FirebaseApp ${e.name}`,n)}}function R(e,t){e.container.addOrOverwriteComponent(t)}function D(e){let t=e.name;if(N.has(t))return S.debug(`There were multiple attempts to register component ${t}.`),!1;for(let n of(N.set(t,e),C.values()))A(n,e);return!0}function O(e,t){let n=e.container.getProvider("heartbeat").getImmediate({optional:!0});return n&&n.triggerHeartbeat(),e.container.getProvider(t)}function P(e,t,n=k){O(e,t).clearInstance(n)}function L(){N.clear()}let M=new l.LL("app","Firebase",{"no-app":"No Firebase App '{$appName}' has been created - call Firebase App.initializeApp()","bad-app-name":"Illegal App name: '{$appName}","duplicate-app":"Firebase App named '{$appName}' already exists with different options or config","app-deleted":"Firebase App named '{$appName}' already deleted","no-options":"Need to provide options, when not being deployed to hosting via source.","invalid-app-argument":"firebase.{$appName}() takes either no argument or a Firebase App instance.","invalid-log-argument":"First argument to `onLog` must be null or a function.","idb-open":"Error thrown when opening IndexedDB. Original error: {$originalErrorMessage}.","idb-get":"Error thrown when reading from IndexedDB. Original error: {$originalErrorMessage}.","idb-set":"Error thrown when writing to IndexedDB. Original error: {$originalErrorMessage}.","idb-delete":"Error thrown when deleting from IndexedDB. Original error: {$originalErrorMessage}."});/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class j{constructor(e,t,n){this._isDeleted=!1,this._options=Object.assign({},e),this._config=Object.assign({},t),this._name=t.name,this._automaticDataCollectionEnabled=t.automaticDataCollectionEnabled,this._container=n,this.container.addComponent(new o.wA("app",()=>this,"PUBLIC"))}get automaticDataCollectionEnabled(){return this.checkDestroyed(),this._automaticDataCollectionEnabled}set automaticDataCollectionEnabled(e){this.checkDestroyed(),this._automaticDataCollectionEnabled=e}get name(){return this.checkDestroyed(),this._name}get options(){return this.checkDestroyed(),this._options}get config(){return this.checkDestroyed(),this._config}get container(){return this._container}get isDeleted(){return this._isDeleted}set isDeleted(e){this._isDeleted=e}checkDestroyed(){if(this.isDeleted)throw M.create("app-deleted",{appName:this._name})}}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let F="9.12.1";function U(e,t={}){let n=e;if("object"!=typeof t){let r=t;t={name:r}}let i=Object.assign({name:k,automaticDataCollectionEnabled:!1},t),s=i.name;if("string"!=typeof s||!s)throw M.create("bad-app-name",{appName:String(s)});if(n||(n=(0,l.aH)()),!n)throw M.create("no-options");let a=C.get(s);if(a){if((0,l.vZ)(n,a.options)&&(0,l.vZ)(i,a.config))return a;throw M.create("duplicate-app",{appName:s})}let u=new o.H0(s);for(let c of N.values())u.addComponent(c);let h=new j(n,i,u);return C.set(s,h),h}function V(e=k){let t=C.get(e);if(!t&&e===k)return U();if(!t)throw M.create("no-app",{appName:e});return t}function q(){return Array.from(C.values())}async function B(e){let t=e.name;C.has(t)&&(C.delete(t),await Promise.all(e.container.getProviders().map(e=>e.delete())),e.isDeleted=!0)}function $(e,t,n){var r;let i=null!==(r=x[e])&&void 0!==r?r:e;n&&(i+=`-${n}`);let s=i.match(/\s|\//),a=t.match(/\s|\//);if(s||a){let l=[`Unable to register library "${i}" with version "${t}":`];s&&l.push(`library name "${i}" contains illegal characters (whitespace or "/")`),s&&a&&l.push("and"),a&&l.push(`version name "${t}" contains illegal characters (whitespace or "/")`),S.warn(l.join(" "));return}D(new o.wA(`${i}-version`,()=>({library:i,version:t}),"VERSION"))}function z(e,t){if(null!==e&&"function"!=typeof e)throw M.create("invalid-log-argument");(0,a.Am)(e,t)}function G(e){(0,a.Ub)(e)}let W="firebase-heartbeat-store",H=null;function K(){return H||(H=(function(e,t,{blocked:n,upgrade:r,blocking:i,terminated:s}={}){let o=indexedDB.open(e,1),a=g(o);return r&&o.addEventListener("upgradeneeded",e=>{r(g(o.result),e.oldVersion,e.newVersion,g(o.transaction))}),n&&o.addEventListener("blocked",()=>n()),a.then(e=>{s&&e.addEventListener("close",()=>s()),i&&e.addEventListener("versionchange",()=>i())}).catch(()=>{}),a})("firebase-heartbeat-database",0,{upgrade:(e,t)=>{0===t&&e.createObjectStore(W)}}).catch(e=>{throw M.create("idb-open",{originalErrorMessage:e.message})})),H}async function Q(e){try{let t=await K();return t.transaction(W).objectStore(W).get(X(e))}catch(r){if(r instanceof l.ZR)S.warn(r.message);else{let n=M.create("idb-get",{originalErrorMessage:null==r?void 0:r.message});S.warn(n.message)}}}async function Y(e,t){try{let n=await K(),r=n.transaction(W,"readwrite"),i=r.objectStore(W);return await i.put(t,X(e)),r.done}catch(o){if(o instanceof l.ZR)S.warn(o.message);else{let s=M.create("idb-set",{originalErrorMessage:null==o?void 0:o.message});S.warn(s.message)}}}function X(e){return`${e.name}!${e.options.appId}`}class J{constructor(e){this.container=e,this._heartbeatsCache=null;let t=this.container.getProvider("app").getImmediate();this._storage=new ee(t),this._heartbeatsCachePromise=this._storage.read().then(e=>(this._heartbeatsCache=e,e))}async triggerHeartbeat(){let e=this.container.getProvider("platform-logger").getImmediate(),t=e.getPlatformInfoString(),n=Z();return(null===this._heartbeatsCache&&(this._heartbeatsCache=await this._heartbeatsCachePromise),this._heartbeatsCache.lastSentHeartbeatDate===n||this._heartbeatsCache.heartbeats.some(e=>e.date===n))?void 0:(this._heartbeatsCache.heartbeats.push({date:n,agent:t}),this._heartbeatsCache.heartbeats=this._heartbeatsCache.heartbeats.filter(e=>{let t=new Date(e.date).valueOf(),n=Date.now();return n-t<=2592e6}),this._storage.overwrite(this._heartbeatsCache))}async getHeartbeatsHeader(){if(null===this._heartbeatsCache&&await this._heartbeatsCachePromise,null===this._heartbeatsCache||0===this._heartbeatsCache.heartbeats.length)return"";let e=Z(),{heartbeatsToSend:t,unsentEntries:n}=function(e,t=1024){let n=[],r=e.slice();for(let i of e){let s=n.find(e=>e.agent===i.agent);if(s){if(s.dates.push(i.date),et(n)>t){s.dates.pop();break}}else if(n.push({agent:i.agent,dates:[i.date]}),et(n)>t){n.pop();break}r=r.slice(1)}return{heartbeatsToSend:n,unsentEntries:r}}(this._heartbeatsCache.heartbeats),r=(0,l.L)(JSON.stringify({version:2,heartbeats:t}));return this._heartbeatsCache.lastSentHeartbeatDate=e,n.length>0?(this._heartbeatsCache.heartbeats=n,await this._storage.overwrite(this._heartbeatsCache)):(this._heartbeatsCache.heartbeats=[],this._storage.overwrite(this._heartbeatsCache)),r}}function Z(){let e=new Date;return e.toISOString().substring(0,10)}class ee{constructor(e){this.app=e,this._canUseIndexedDBPromise=this.runIndexedDBEnvironmentCheck()}async runIndexedDBEnvironmentCheck(){return!!(0,l.hl)()&&(0,l.eu)().then(()=>!0).catch(()=>!1)}async read(){let e=await this._canUseIndexedDBPromise;if(!e)return{heartbeats:[]};{let t=await Q(this.app);return t||{heartbeats:[]}}}async overwrite(e){var t;let n=await this._canUseIndexedDBPromise;if(n){let r=await this.read();return Y(this.app,{lastSentHeartbeatDate:null!==(t=e.lastSentHeartbeatDate)&&void 0!==t?t:r.lastSentHeartbeatDate,heartbeats:e.heartbeats})}}async add(e){var t;let n=await this._canUseIndexedDBPromise;if(n){let r=await this.read();return Y(this.app,{lastSentHeartbeatDate:null!==(t=e.lastSentHeartbeatDate)&&void 0!==t?t:r.lastSentHeartbeatDate,heartbeats:[...r.heartbeats,...e.heartbeats]})}}}function et(e){return(0,l.L)(JSON.stringify({version:2,heartbeats:e})).length}D(new o.wA("platform-logger",e=>new I(e),"PRIVATE")),D(new o.wA("heartbeat",e=>new J(e),"PRIVATE")),$(T,E,""),$(T,E,"esm2017"),$("fire-js","")},8463:function(e,t,n){"use strict";n.d(t,{H0:function(){return a},wA:function(){return i}});var r=n(4444);class i{constructor(e,t,n){this.name=e,this.instanceFactory=t,this.type=n,this.multipleInstances=!1,this.serviceProps={},this.instantiationMode="LAZY",this.onInstanceCreated=null}setInstantiationMode(e){return this.instantiationMode=e,this}setMultipleInstances(e){return this.multipleInstances=e,this}setServiceProps(e){return this.serviceProps=e,this}setInstanceCreatedCallback(e){return this.onInstanceCreated=e,this}}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let s="[DEFAULT]";/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class o{constructor(e,t){this.name=e,this.container=t,this.component=null,this.instances=new Map,this.instancesDeferred=new Map,this.instancesOptions=new Map,this.onInitCallbacks=new Map}get(e){let t=this.normalizeInstanceIdentifier(e);if(!this.instancesDeferred.has(t)){let n=new r.BH;if(this.instancesDeferred.set(t,n),this.isInitialized(t)||this.shouldAutoInitialize())try{let i=this.getOrInitializeService({instanceIdentifier:t});i&&n.resolve(i)}catch(s){}}return this.instancesDeferred.get(t).promise}getImmediate(e){var t;let n=this.normalizeInstanceIdentifier(null==e?void 0:e.identifier),r=null!==(t=null==e?void 0:e.optional)&&void 0!==t&&t;if(this.isInitialized(n)||this.shouldAutoInitialize())try{return this.getOrInitializeService({instanceIdentifier:n})}catch(i){if(r)return null;throw i}else{if(r)return null;throw Error(`Service ${this.name} is not available`)}}getComponent(){return this.component}setComponent(e){if(e.name!==this.name)throw Error(`Mismatching Component ${e.name} for Provider ${this.name}.`);if(this.component)throw Error(`Component for ${this.name} has already been provided`);if(this.component=e,this.shouldAutoInitialize()){if("EAGER"===e.instantiationMode)try{this.getOrInitializeService({instanceIdentifier:s})}catch(t){}for(let[n,r]of this.instancesDeferred.entries()){let i=this.normalizeInstanceIdentifier(n);try{let o=this.getOrInitializeService({instanceIdentifier:i});r.resolve(o)}catch(a){}}}}clearInstance(e=s){this.instancesDeferred.delete(e),this.instancesOptions.delete(e),this.instances.delete(e)}async delete(){let e=Array.from(this.instances.values());await Promise.all([...e.filter(e=>"INTERNAL"in e).map(e=>e.INTERNAL.delete()),...e.filter(e=>"_delete"in e).map(e=>e._delete())])}isComponentSet(){return null!=this.component}isInitialized(e=s){return this.instances.has(e)}getOptions(e=s){return this.instancesOptions.get(e)||{}}initialize(e={}){let{options:t={}}=e,n=this.normalizeInstanceIdentifier(e.instanceIdentifier);if(this.isInitialized(n))throw Error(`${this.name}(${n}) has already been initialized`);if(!this.isComponentSet())throw Error(`Component ${this.name} has not been registered yet`);let r=this.getOrInitializeService({instanceIdentifier:n,options:t});for(let[i,s]of this.instancesDeferred.entries()){let o=this.normalizeInstanceIdentifier(i);n===o&&s.resolve(r)}return r}onInit(e,t){var n;let r=this.normalizeInstanceIdentifier(t),i=null!==(n=this.onInitCallbacks.get(r))&&void 0!==n?n:new Set;i.add(e),this.onInitCallbacks.set(r,i);let s=this.instances.get(r);return s&&e(s,r),()=>{i.delete(e)}}invokeOnInitCallbacks(e,t){let n=this.onInitCallbacks.get(t);if(n)for(let r of n)try{r(e,t)}catch(i){}}getOrInitializeService({instanceIdentifier:e,options:t={}}){let n=this.instances.get(e);if(!n&&this.component&&(n=this.component.instanceFactory(this.container,{instanceIdentifier:e===s?void 0:e,options:t}),this.instances.set(e,n),this.instancesOptions.set(e,t),this.invokeOnInitCallbacks(n,e),this.component.onInstanceCreated))try{this.component.onInstanceCreated(this.container,e,n)}catch(r){}return n||null}normalizeInstanceIdentifier(e=s){return this.component?this.component.multipleInstances?e:s:e}shouldAutoInitialize(){return!!this.component&&"EXPLICIT"!==this.component.instantiationMode}}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class a{constructor(e){this.name=e,this.providers=new Map}addComponent(e){let t=this.getProvider(e.name);if(t.isComponentSet())throw Error(`Component ${e.name} has already been registered with ${this.name}`);t.setComponent(e)}addOrOverwriteComponent(e){let t=this.getProvider(e.name);t.isComponentSet()&&this.providers.delete(e.name),this.addComponent(e)}getProvider(e){if(this.providers.has(e))return this.providers.get(e);let t=new o(e,this);return this.providers.set(e,t),t}getProviders(){return Array.from(this.providers.values())}}},3333:function(e,t,n){"use strict";var r,i;n.d(t,{Am:function(){return d},Ub:function(){return h},Yd:function(){return c},in:function(){return r}});/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let s=[];(i=r||(r={}))[i.DEBUG=0]="DEBUG",i[i.VERBOSE=1]="VERBOSE",i[i.INFO=2]="INFO",i[i.WARN=3]="WARN",i[i.ERROR=4]="ERROR",i[i.SILENT=5]="SILENT";let o={debug:r.DEBUG,verbose:r.VERBOSE,info:r.INFO,warn:r.WARN,error:r.ERROR,silent:r.SILENT},a=r.INFO,l={[r.DEBUG]:"log",[r.VERBOSE]:"log",[r.INFO]:"info",[r.WARN]:"warn",[r.ERROR]:"error"},u=(e,t,...n)=>{if(t<e.logLevel)return;let r=new Date().toISOString(),i=l[t];if(i)console[i](`[${r}]  ${e.name}:`,...n);else throw Error(`Attempted to log a message with an invalid logType (value: ${t})`)};class c{constructor(e){this.name=e,this._logLevel=a,this._logHandler=u,this._userLogHandler=null,s.push(this)}get logLevel(){return this._logLevel}set logLevel(e){if(!(e in r))throw TypeError(`Invalid value "${e}" assigned to \`logLevel\``);this._logLevel=e}setLogLevel(e){this._logLevel="string"==typeof e?o[e]:e}get logHandler(){return this._logHandler}set logHandler(e){if("function"!=typeof e)throw TypeError("Value assigned to `logHandler` must be a function");this._logHandler=e}get userLogHandler(){return this._userLogHandler}set userLogHandler(e){this._userLogHandler=e}debug(...e){this._userLogHandler&&this._userLogHandler(this,r.DEBUG,...e),this._logHandler(this,r.DEBUG,...e)}log(...e){this._userLogHandler&&this._userLogHandler(this,r.VERBOSE,...e),this._logHandler(this,r.VERBOSE,...e)}info(...e){this._userLogHandler&&this._userLogHandler(this,r.INFO,...e),this._logHandler(this,r.INFO,...e)}warn(...e){this._userLogHandler&&this._userLogHandler(this,r.WARN,...e),this._logHandler(this,r.WARN,...e)}error(...e){this._userLogHandler&&this._userLogHandler(this,r.ERROR,...e),this._logHandler(this,r.ERROR,...e)}}function h(e){s.forEach(t=>{t.setLogLevel(e)})}function d(e,t){for(let n of s){let i=null;t&&t.level&&(i=o[t.level]),null===e?n.userLogHandler=null:n.userLogHandler=(t,n,...s)=>{let o=s.map(e=>{if(null==e)return null;if("string"==typeof e)return e;if("number"==typeof e||"boolean"==typeof e)return e.toString();if(e instanceof Error)return e.message;try{return JSON.stringify(e)}catch(t){return null}}).filter(e=>e).join(" ");n>=(null!=i?i:t.logLevel)&&e({level:r[n].toLowerCase(),message:o,args:s,type:t.name})}}}},24:function(e,t,n){"use strict";n.d(t,{zt:function(){return v},cn:function(){return _},KO:function(){return w}});var r=n(7294);let i=0;new WeakMap;let s=Symbol(),o=e=>!!e[s],a=e=>!e[s].c,l=e=>{var t;let{b:n,c:r}=e[s];r&&(r(),null==(t=d.get(n))||t())},u=(e,t)=>{let n=e[s].o,r=t[s].o;return n===r||e===r||o(n)&&u(n,t)},c=(e,t)=>{let n={b:e,o:t,c:null},r=new Promise(e=>{n.c=()=>{n.c=null,e()},t.finally(n.c)});return r[s]=n,r},h=e=>c(e[s].b,e[s].o),d=new WeakMap,f=e=>"init"in e,p=e=>{let t,n;let r=new WeakMap,i=new WeakMap,s=new Map;if(t=new Set,n=new Set,e)for(let[d,p]of e){let m={v:p,r:0,y:!0,d:new Map};Object.freeze(m),f(d)||console.warn("Found initial value for derived atom which can cause unexpected behavior",d),r.set(d,m)}let g=new WeakMap,y=(e,t,n)=>{let r=g.get(t);r||(r=new Map,g.set(t,r)),n.then(()=>{r.get(e)!==n||(r.delete(e),r.size||g.delete(t))}),r.set(e,n)},v=e=>{let t=new Set,n=g.get(e);return n&&(g.delete(e),n.forEach((e,n)=>{l(e),t.add(n)})),t},_=new WeakMap,w=e=>{let t=_.get(e);return t||(t=new Map,_.set(e,t)),t},b=(e,t)=>{if(e){let n=w(e),i=n.get(t);return!i&&((i=b(e.p,t))&&"p"in i&&a(i.p)&&(i=void 0),i&&n.set(t,i)),i}return r.get(t)},I=(e,t,n)=>{if(Object.freeze(n),e){let i=w(e);i.set(t,n)}else{let o=r.get(t);r.set(t,n),s.has(t)||s.set(t,o)}},T=(e,t=new Map,n)=>{if(!n)return t;let r=new Map,i=!1;return(n.forEach(n=>{var s;let o=(null==(s=b(e,n))?void 0:s.r)||0;r.set(n,o),t.get(n)!==o&&(i=!0)}),t.size!==r.size||i)?r:t},E=(e,t,n,r,i)=>{let s=b(e,t);if(s){if(i&&(!("p"in s)||!u(s.p,i)))return s;"p"in s&&l(s.p)}let o={v:n,r:(null==s?void 0:s.r)||0,y:!0,d:T(e,null==s?void 0:s.d,r)},a=!(null==s?void 0:s.y);return(s&&"v"in s&&Object.is(s.v,n)?o.d===s.d||o.d.size===s.d.size&&Array.from(o.d.keys()).every(e=>s.d.has(e))||(a=!0,Promise.resolve().then(()=>{q(e)})):(a=!0,++o.r,o.d.has(t)&&(o.d=new Map(o.d).set(t,o.r))),s&&!a)?s:(I(e,t,o),o)},S=(e,t,n,r,i)=>{let s=b(e,t);if(s){if(i&&(!("p"in s)||!u(s.p,i)))return s;"p"in s&&l(s.p)}let o={e:n,r:((null==s?void 0:s.r)||0)+1,y:!0,d:T(e,null==s?void 0:s.d,r)};return I(e,t,o),o},k=(e,t,n,r)=>{let i=b(e,t);if(i&&"p"in i){if(u(i.p,n)&&!a(i.p))return i.y?i:{...i,y:!0};l(i.p)}y(e,t,n);let s={p:n,r:((null==i?void 0:i.r)||0)+1,y:!0,d:T(e,null==i?void 0:i.d,r)};return I(e,t,s),s},x=(e,t,n,r)=>{if(n instanceof Promise){let i=c(n,n.then(n=>{E(e,t,n,r,i)}).catch(n=>{if(n instanceof Promise)return o(n)?n.then(()=>{N(e,t,!0)}):n;S(e,t,n,r,i)}));return k(e,t,i,r)}return E(e,t,n,r)},C=(e,t)=>{let n=b(e,t);if(n){let r={...n,y:!1};I(e,t,r)}else console.warn("[Bug] could not invalidate non existing atom",t)},N=(e,t,n)=>{if(!n){let r=b(e,t);if(r){if(r.y&&"p"in r&&!a(r.p))return r;if(r.d.forEach((n,r)=>{if(r!==t){if(i.has(r)){let s=b(e,r);s&&!s.y&&N(e,r)}else N(e,r)}}),Array.from(r.d).every(([t,n])=>{let r=b(e,t);return r&&!("p"in r)&&r.r===n}))return r.y?r:{...r,y:!0}}}let s=new Set;try{let l=t.read(n=>{s.add(n);let r=n===t?b(e,n):N(e,n);if(r){if("e"in r)throw r.e;if("p"in r)throw r.p;return r.v}if(f(n))return n.init;throw Error("no atom init")});return x(e,t,l,s)}catch(d){if(d instanceof Promise){let u=o(d)&&a(d)?h(d):c(d,d);return k(e,t,u,s)}return S(e,t,d,s)}},A=(e,t)=>{let n=N(t,e);return n},R=(e,t)=>{let n=i.get(t);return n||(n=F(e,t)),n},D=(e,t)=>!t.l.size&&(!t.t.size||1===t.t.size&&t.t.has(e)),O=(e,t)=>{let n=i.get(t);n&&D(t,n)&&U(e,t)},P=(e,t)=>{let n=i.get(t);null==n||n.t.forEach(n=>{n!==t&&(C(e,n),P(e,n))})},L=(e,t,n)=>{let r=!0,i=(t,n)=>{let r=N(e,t);if("e"in r)throw r.e;if("p"in r){if(null==n?void 0:n.unstable_promise)return r.p.then(()=>{let s=b(e,t);return s&&"p"in s&&s.p===r.p?new Promise(e=>setTimeout(e)).then(()=>i(t,n)):i(t,n)});throw console.info("Reading pending atom state in write operation. We throw a promise for now.",t),r.p}if("v"in r)return r.v;throw console.warn("[Bug] no value found while reading atom in write operation. This is probably a bug.",t),Error("no value found")},s=(n,i)=>{let s;if(n===t){if(!f(n))throw Error("atom not writable");let o=v(n);o.forEach(t=>{t!==e&&x(t,n,i)});let a=b(e,n),l=x(e,n,i);a!==l&&P(e,n)}else s=L(e,n,i);return r||q(e),s},o=t.write(i,s,n);return r=!1,o},M=(e,t,n)=>{let r=L(n,e,t);return q(n),r},j=e=>!!e.write,F=(e,t,r)=>{let s={t:new Set(r&&[r]),l:new Set};i.set(t,s),n.add(t);let o=N(void 0,t);if(o.d.forEach((n,r)=>{let s=i.get(r);s?s.t.add(t):r!==t&&F(e,r,t)}),j(t)&&t.onMount){let a=n=>M(t,n,e),l=t.onMount(a);e=void 0,l&&(s.u=l)}return s},U=(e,t)=>{var r;let s=null==(r=i.get(t))?void 0:r.u;s&&s(),i.delete(t),n.delete(t);let o=b(e,t);o?("p"in o&&l(o.p),o.d.forEach((n,r)=>{if(r!==t){let s=i.get(r);s&&(s.t.delete(t),D(r,s)&&U(e,r))}})):console.warn("[Bug] could not find atom state to unmount",t)},V=(e,t,n,r)=>{let s=new Set(n.d.keys());null==r||r.forEach((n,r)=>{if(s.has(r)){s.delete(r);return}let o=i.get(r);o&&(o.t.delete(t),D(r,o)&&U(e,r))}),s.forEach(n=>{let r=i.get(n);r?r.t.add(t):i.has(t)&&F(e,n,t)})},q=e=>{if(e){let n=w(e);n.forEach((t,n)=>{let s=r.get(n);if(t!==s){let o=i.get(n);null==o||o.l.forEach(t=>t(e))}});return}for(;s.size;){let o=Array.from(s);s.clear(),o.forEach(([e,t])=>{let n=b(void 0,e);if(n&&n.d!==(null==t?void 0:t.d)&&V(void 0,e,n,null==t?void 0:t.d),t&&!t.y&&(null==n?void 0:n.y))return;let r=i.get(e);null==r||r.l.forEach(e=>e())})}t.forEach(e=>e())},B=e=>{let t=w(e);t.forEach((t,n)=>{let i=r.get(n);(!i||t.r>i.r||t.y!==i.y||t.r===i.r&&t.d!==i.d)&&(r.set(n,t),t.d!==(null==i?void 0:i.d)&&V(e,n,t,null==i?void 0:i.d))})},$=(e,t)=>{t&&B(t),q(void 0)},z=(e,t,n)=>{let r=R(n,e),i=r.l;return i.add(t),()=>{i.delete(t),O(n,e)}},G=(e,t)=>{for(let[n,r]of e)f(n)&&(x(t,n,r),P(t,n));q(t)};return{r:A,w:M,c:$,s:z,h:G,n:e=>(t.add(e),()=>{t.delete(e)}),l:()=>n.values(),a:e=>r.get(e),m:e=>i.get(e)}},m=(e,t)=>{let n=t?t(e).SECRET_INTERNAL_store:p(e);return{s:n}},g=new Map,y=e=>(g.has(e)||g.set(e,(0,r.createContext)(m())),g.get(e)),v=({children:e,initialValues:t,scope:n,unstable_createStore:i,unstable_enableVersionedWrite:s})=>{let[o,a]=(0,r.useState)({});(0,r.useEffect)(()=>{let e=l.current;e.w&&(e.s.c(null,o),delete o.p,e.v=o)},[o]);let l=(0,r.useRef)();if(!l.current){let u=m(t,i);if(s){let c=0;u.w=e=>{a(t=>{let n=c?t:{p:t};return e(n),n})},u.v=o,u.r=e=>{++c,e(),--c}}l.current=u}let h=y(n);return(0,r.createElement)(h.Provider,{value:l.current},e)};function _(e,t){return function(e,t){let n=`atom${++i}`,r={toString:()=>n};return"function"==typeof e?r.read=e:(r.init=e,r.read=e=>e(r),r.write=(e,t,n)=>t(r,"function"==typeof n?n(e(r)):n)),t&&(r.write=t),r}(e,t)}function w(e,t){return"scope"in e&&(console.warn("atom.scope is deprecated. Please do useAtom(atom, scope) instead."),t=e.scope),[function(e,t){let n=y(t),i=(0,r.useContext)(n),{s:s,v:o}=i,a=t=>{let n=s.r(e,t);if(!n.y)throw Error("should not be invalidated");if("e"in n)throw n.e;if("p"in n)throw n.p;if("v"in n)return n.v;throw Error("no atom value")},[[l,u,c],h]=(0,r.useReducer)((t,n)=>{let r=a(n);return Object.is(t[1],r)&&t[2]===e?t:[n,r,e]},o,t=>{let n=a(t);return[t,n,e]}),d=u;return c!==e&&(h(l),d=a(l)),(0,r.useEffect)(()=>{let{v:t}=i;t&&s.c(e,t);let n=s.s(e,h,t);return h(t),n},[s,e,i]),(0,r.useEffect)(()=>{s.c(e,l)}),(0,r.useDebugValue)(d),d}(e,t),function(e,t){let n=y(t),{s:i,w:s}=(0,r.useContext)(n),o=(0,r.useCallback)(t=>{if(!("write"in e))throw Error("not writable atom");let n=n=>i.w(e,t,n);return s?s(n):n()},[i,s,e]);return o}(e,t)]}},6501:function(e,t,n){"use strict";let r,i;n.d(t,{x7:function(){return ei},ZP:function(){return es}});var s,o=n(7294);let a={data:""},l=e=>"object"==typeof window?((e?e.querySelector("#_goober"):window._goober)||Object.assign((e||document.head).appendChild(document.createElement("style")),{innerHTML:" ",id:"_goober"})).firstChild:e||a,u=/(?:([\u0080-\uFFFF\w-%@]+) *:? *([^{;]+?);|([^;}{]*?) *{)|(}\s*)/g,c=/\/\*[^]*?\*\/|  +/g,h=/\n+/g,d=(e,t)=>{let n="",r="",i="";for(let s in e){let o=e[s];"@"==s[0]?"i"==s[1]?n=s+" "+o+";":r+="f"==s[1]?d(o,s):s+"{"+d(o,"k"==s[1]?"":t)+"}":"object"==typeof o?r+=d(o,t?t.replace(/([^,])+/g,e=>s.replace(/(^:.*)|([^,])+/g,t=>/&/.test(t)?t.replace(/&/g,e):e?e+" "+t:t)):s):null!=o&&(s=/^--/.test(s)?s:s.replace(/[A-Z]/g,"-$&").toLowerCase(),i+=d.p?d.p(s,o):s+":"+o+";")}return n+(t&&i?t+"{"+i+"}":i)+r},f={},p=e=>{if("object"==typeof e){let t="";for(let n in e)t+=n+p(e[n]);return t}return e},m=(e,t,n,r,i)=>{var s,o;let a=p(e),l=f[a]||(f[a]=(e=>{let t=0,n=11;for(;t<e.length;)n=101*n+e.charCodeAt(t++)>>>0;return"go"+n})(a));if(!f[l]){let m=a!==e?e:(e=>{let t,n,r=[{}];for(;t=u.exec(e.replace(c,""));)t[4]?r.shift():t[3]?(n=t[3].replace(h," ").trim(),r.unshift(r[0][n]=r[0][n]||{})):r[0][t[1]]=t[2].replace(h," ").trim();return r[0]})(e);f[l]=d(i?{["@keyframes "+l]:m}:m,n?"":"."+l)}let g=n&&f.g?f.g:null;return n&&(f.g=f[l]),s=f[l],o=t,g?o.data=o.data.replace(g,s):-1===o.data.indexOf(s)&&(o.data=r?s+o.data:o.data+s),l},g=(e,t,n)=>e.reduce((e,r,i)=>{let s=t[i];if(s&&s.call){let o=s(n),a=o&&o.props&&o.props.className||/^go/.test(o)&&o;s=a?"."+a:o&&"object"==typeof o?o.props?"":d(o,""):!1===o?"":o}return e+r+(null==s?"":s)},"");function y(e){let t=this||{},n=e.call?e(t.p):e;return m(n.unshift?n.raw?g(n,[].slice.call(arguments,1),t.p):n.reduce((e,n)=>Object.assign(e,n&&n.call?n(t.p):n),{}):n,l(t.target),t.g,t.o,t.k)}y.bind({g:1});let v,_,w,b=y.bind({k:1});function I(e,t){let n=this||{};return function(){let r=arguments;function i(s,o){let a=Object.assign({},s),l=a.className||i.className;n.p=Object.assign({theme:_&&_()},a),n.o=/ *go\d+/.test(l),a.className=y.apply(n,r)+(l?" "+l:""),t&&(a.ref=o);let u=e;return e[0]&&(u=a.as||e,delete a.as),w&&u[0]&&w(a),v(u,a)}return t?t(i):i}}var T=e=>"function"==typeof e,E=(e,t)=>T(e)?e(t):e,S=(r=0,()=>(++r).toString()),k=()=>{if(void 0===i&&"u">typeof window){let e=matchMedia("(prefers-reduced-motion: reduce)");i=!e||e.matches}return i},x=new Map,C=e=>{if(x.has(e))return;let t=setTimeout(()=>{x.delete(e),O({type:4,toastId:e})},1e3);x.set(e,t)},N=e=>{let t=x.get(e);t&&clearTimeout(t)},A=(e,t)=>{switch(t.type){case 0:return{...e,toasts:[t.toast,...e.toasts].slice(0,20)};case 1:return t.toast.id&&N(t.toast.id),{...e,toasts:e.toasts.map(e=>e.id===t.toast.id?{...e,...t.toast}:e)};case 2:let{toast:n}=t;return e.toasts.find(e=>e.id===n.id)?A(e,{type:1,toast:n}):A(e,{type:0,toast:n});case 3:let{toastId:r}=t;return r?C(r):e.toasts.forEach(e=>{C(e.id)}),{...e,toasts:e.toasts.map(e=>e.id===r||void 0===r?{...e,visible:!1}:e)};case 4:return void 0===t.toastId?{...e,toasts:[]}:{...e,toasts:e.toasts.filter(e=>e.id!==t.toastId)};case 5:return{...e,pausedAt:t.time};case 6:let i=t.time-(e.pausedAt||0);return{...e,pausedAt:void 0,toasts:e.toasts.map(e=>({...e,pauseDuration:e.pauseDuration+i}))}}},R=[],D={toasts:[],pausedAt:void 0},O=e=>{D=A(D,e),R.forEach(e=>{e(D)})},P={blank:4e3,error:4e3,success:2e3,loading:1/0,custom:4e3},L=(e={})=>{let[t,n]=(0,o.useState)(D);(0,o.useEffect)(()=>(R.push(n),()=>{let e=R.indexOf(n);e>-1&&R.splice(e,1)}),[t]);let r=t.toasts.map(t=>{var n,r;return{...e,...e[t.type],...t,duration:t.duration||(null==(n=e[t.type])?void 0:n.duration)||(null==e?void 0:e.duration)||P[t.type],style:{...e.style,...null==(r=e[t.type])?void 0:r.style,...t.style}}});return{...t,toasts:r}},M=(e,t="blank",n)=>({createdAt:Date.now(),visible:!0,type:t,ariaProps:{role:"status","aria-live":"polite"},message:e,pauseDuration:0,...n,id:(null==n?void 0:n.id)||S()}),j=e=>(t,n)=>{let r=M(t,e,n);return O({type:2,toast:r}),r.id},F=(e,t)=>j("blank")(e,t);F.error=j("error"),F.success=j("success"),F.loading=j("loading"),F.custom=j("custom"),F.dismiss=e=>{O({type:3,toastId:e})},F.remove=e=>O({type:4,toastId:e}),F.promise=(e,t,n)=>{let r=F.loading(t.loading,{...n,...null==n?void 0:n.loading});return e.then(e=>(F.success(E(t.success,e),{id:r,...n,...null==n?void 0:n.success}),e)).catch(e=>{F.error(E(t.error,e),{id:r,...n,...null==n?void 0:n.error})}),e};var U=(e,t)=>{O({type:1,toast:{id:e,height:t}})},V=()=>{O({type:5,time:Date.now()})},q=e=>{let{toasts:t,pausedAt:n}=L(e);(0,o.useEffect)(()=>{if(n)return;let e=Date.now(),r=t.map(t=>{if(t.duration===1/0)return;let n=(t.duration||0)+t.pauseDuration-(e-t.createdAt);if(n<0){t.visible&&F.dismiss(t.id);return}return setTimeout(()=>F.dismiss(t.id),n)});return()=>{r.forEach(e=>e&&clearTimeout(e))}},[t,n]);let r=(0,o.useCallback)(()=>{n&&O({type:6,time:Date.now()})},[n]),i=(0,o.useCallback)((e,n)=>{let{reverseOrder:r=!1,gutter:i=8,defaultPosition:s}=n||{},o=t.filter(t=>(t.position||s)===(e.position||s)&&t.height),a=o.findIndex(t=>t.id===e.id),l=o.filter((e,t)=>t<a&&e.visible).length;return o.filter(e=>e.visible).slice(...r?[l+1]:[0,l]).reduce((e,t)=>e+(t.height||0)+i,0)},[t]);return{toasts:t,handlers:{updateHeight:U,startPause:V,endPause:r,calculateOffset:i}}},B=I("div")`
  width: 20px;
  opacity: 0;
  height: 20px;
  border-radius: 10px;
  background: ${e=>e.primary||"#ff4b4b"};
  position: relative;
  transform: rotate(45deg);

  animation: ${b`
from {
  transform: scale(0) rotate(45deg);
	opacity: 0;
}
to {
 transform: scale(1) rotate(45deg);
  opacity: 1;
}`} 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275)
    forwards;
  animation-delay: 100ms;

  &:after,
  &:before {
    content: '';
    animation: ${b`
from {
  transform: scale(0);
  opacity: 0;
}
to {
  transform: scale(1);
  opacity: 1;
}`} 0.15s ease-out forwards;
    animation-delay: 150ms;
    position: absolute;
    border-radius: 3px;
    opacity: 0;
    background: ${e=>e.secondary||"#fff"};
    bottom: 9px;
    left: 4px;
    height: 2px;
    width: 12px;
  }

  &:before {
    animation: ${b`
from {
  transform: scale(0) rotate(90deg);
	opacity: 0;
}
to {
  transform: scale(1) rotate(90deg);
	opacity: 1;
}`} 0.15s ease-out forwards;
    animation-delay: 180ms;
    transform: rotate(90deg);
  }
`,$=I("div")`
  width: 12px;
  height: 12px;
  box-sizing: border-box;
  border: 2px solid;
  border-radius: 100%;
  border-color: ${e=>e.secondary||"#e0e0e0"};
  border-right-color: ${e=>e.primary||"#616161"};
  animation: ${b`
  from {
    transform: rotate(0deg);
  }
  to {
    transform: rotate(360deg);
  }
`} 1s linear infinite;
`,z=I("div")`
  width: 20px;
  opacity: 0;
  height: 20px;
  border-radius: 10px;
  background: ${e=>e.primary||"#61d345"};
  position: relative;
  transform: rotate(45deg);

  animation: ${b`
from {
  transform: scale(0) rotate(45deg);
	opacity: 0;
}
to {
  transform: scale(1) rotate(45deg);
	opacity: 1;
}`} 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275)
    forwards;
  animation-delay: 100ms;
  &:after {
    content: '';
    box-sizing: border-box;
    animation: ${b`
0% {
	height: 0;
	width: 0;
	opacity: 0;
}
40% {
  height: 0;
	width: 6px;
	opacity: 1;
}
100% {
  opacity: 1;
  height: 10px;
}`} 0.2s ease-out forwards;
    opacity: 0;
    animation-delay: 200ms;
    position: absolute;
    border-right: 2px solid;
    border-bottom: 2px solid;
    border-color: ${e=>e.secondary||"#fff"};
    bottom: 6px;
    left: 6px;
    height: 10px;
    width: 6px;
  }
`,G=I("div")`
  position: absolute;
`,W=I("div")`
  position: relative;
  display: flex;
  justify-content: center;
  align-items: center;
  min-width: 20px;
  min-height: 20px;
`,H=I("div")`
  position: relative;
  transform: scale(0.6);
  opacity: 0.4;
  min-width: 20px;
  animation: ${b`
from {
  transform: scale(0.6);
  opacity: 0.4;
}
to {
  transform: scale(1);
  opacity: 1;
}`} 0.3s 0.12s cubic-bezier(0.175, 0.885, 0.32, 1.275)
    forwards;
`,K=({toast:e})=>{let{icon:t,type:n,iconTheme:r}=e;return void 0!==t?"string"==typeof t?o.createElement(H,null,t):t:"blank"===n?null:o.createElement(W,null,o.createElement($,{...r}),"loading"!==n&&o.createElement(G,null,"error"===n?o.createElement(B,{...r}):o.createElement(z,{...r})))},Q=e=>`
0% {transform: translate3d(0,${-200*e}%,0) scale(.6); opacity:.5;}
100% {transform: translate3d(0,0,0) scale(1); opacity:1;}
`,Y=e=>`
0% {transform: translate3d(0,0,-1px) scale(1); opacity:1;}
100% {transform: translate3d(0,${-150*e}%,-1px) scale(.6); opacity:0;}
`,X=I("div")`
  display: flex;
  align-items: center;
  background: #fff;
  color: #363636;
  line-height: 1.3;
  will-change: transform;
  box-shadow: 0 3px 10px rgba(0, 0, 0, 0.1), 0 3px 3px rgba(0, 0, 0, 0.05);
  max-width: 350px;
  pointer-events: auto;
  padding: 8px 10px;
  border-radius: 8px;
`,J=I("div")`
  display: flex;
  justify-content: center;
  margin: 4px 10px;
  color: inherit;
  flex: 1 1 auto;
  white-space: pre-line;
`,Z=(e,t)=>{let n=e.includes("top")?1:-1,[r,i]=k()?["0%{opacity:0;} 100%{opacity:1;}","0%{opacity:1;} 100%{opacity:0;}"]:[Q(n),Y(n)];return{animation:t?`${b(r)} 0.35s cubic-bezier(.21,1.02,.73,1) forwards`:`${b(i)} 0.4s forwards cubic-bezier(.06,.71,.55,1)`}},ee=o.memo(({toast:e,position:t,style:n,children:r})=>{let i=e.height?Z(e.position||t||"top-center",e.visible):{opacity:0},s=o.createElement(K,{toast:e}),a=o.createElement(J,{...e.ariaProps},E(e.message,e));return o.createElement(X,{className:e.className,style:{...i,...n,...e.style}},"function"==typeof r?r({icon:s,message:a}):o.createElement(o.Fragment,null,s,a))});s=o.createElement,d.p=void 0,v=s,_=void 0,w=void 0;var et=({id:e,className:t,style:n,onHeightUpdate:r,children:i})=>{let s=o.useCallback(t=>{if(t){let n=()=>{r(e,t.getBoundingClientRect().height)};n(),new MutationObserver(n).observe(t,{subtree:!0,childList:!0,characterData:!0})}},[e,r]);return o.createElement("div",{ref:s,className:t,style:n},i)},en=(e,t)=>{let n=e.includes("top"),r=e.includes("center")?{justifyContent:"center"}:e.includes("right")?{justifyContent:"flex-end"}:{};return{left:0,right:0,display:"flex",position:"absolute",transition:k()?void 0:"all 230ms cubic-bezier(.21,1.02,.73,1)",transform:`translateY(${t*(n?1:-1)}px)`,...n?{top:0}:{bottom:0},...r}},er=y`
  z-index: 9999;
  > * {
    pointer-events: auto;
  }
`,ei=({reverseOrder:e,position:t="top-center",toastOptions:n,gutter:r,children:i,containerStyle:s,containerClassName:a})=>{let{toasts:l,handlers:u}=q(n);return o.createElement("div",{style:{position:"fixed",zIndex:9999,top:16,left:16,right:16,bottom:16,pointerEvents:"none",...s},className:a,onMouseEnter:u.startPause,onMouseLeave:u.endPause},l.map(n=>{let s=n.position||t,a=en(s,u.calculateOffset(n,{reverseOrder:e,gutter:r,defaultPosition:t}));return o.createElement(et,{id:n.id,key:n.id,onHeightUpdate:u.updateHeight,className:n.visible?er:"",style:a},"custom"===n.type?E(n.message,n):i?i(n):o.createElement(ee,{toast:n,position:s}))}))},es=F}},function(e){var t=function(t){return e(e.s=t)};e.O(0,[774,179],function(){return t(1118),t(880)}),_N_E=e.O()}]);