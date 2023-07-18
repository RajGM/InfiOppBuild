"use strict";
(() => {
var exports = {};
exports.id = 808;
exports.ids = [808];
exports.modules = {

/***/ 2509:
/***/ ((module) => {

module.exports = require("firebase-admin");

/***/ }),

/***/ 2132:
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "auth": () => (/* binding */ auth),
/* harmony export */   "db": () => (/* binding */ db)
/* harmony export */ });
/* harmony import */ var firebase_admin__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(2509);
/* harmony import */ var firebase_admin__WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(firebase_admin__WEBPACK_IMPORTED_MODULE_0__);

if (!(firebase_admin__WEBPACK_IMPORTED_MODULE_0___default().apps.length)) {
    firebase_admin__WEBPACK_IMPORTED_MODULE_0___default().initializeApp({
        credential: firebase_admin__WEBPACK_IMPORTED_MODULE_0___default().credential.cert(adminConfig)
    });
}
const db = firebase_admin__WEBPACK_IMPORTED_MODULE_0___default().firestore();
const auth = firebase_admin__WEBPACK_IMPORTED_MODULE_0___default().auth();


/***/ })

};
;

// load runtime
var __webpack_require__ = require("../../webpack-api-runtime.js");
__webpack_require__.C(exports);
var __webpack_exec__ = (moduleId) => (__webpack_require__(__webpack_require__.s = moduleId))
var __webpack_exports__ = (__webpack_exec__(2132));
module.exports = __webpack_exports__;

})();