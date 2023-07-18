"use strict";
exports.id = 124;
exports.ids = [124];
exports.modules = {

/***/ 62:
/***/ ((module, __webpack_exports__, __webpack_require__) => {

__webpack_require__.a(module, async (__webpack_handle_async_dependencies__, __webpack_async_result__) => { try {
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "RZ": () => (/* binding */ firestore),
/* harmony export */   "v8": () => (/* binding */ generateFirebaseID)
/* harmony export */ });
/* unused harmony exports auth, googleAuthProvider, serverTimestamp, fromMillis, increment, doc, getDoc, storage, STATE_CHANGED, getUserWithUsername, postToJSON */
/* harmony import */ var firebase_compat_app__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(3773);
/* harmony import */ var firebase_compat_auth__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(4826);
/* harmony import */ var firebase_compat_firestore__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(741);
/* harmony import */ var firebase_compat_storage__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(451);
/* harmony import */ var firebase_database__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(1208);
var __webpack_async_dependencies__ = __webpack_handle_async_dependencies__([firebase_compat_app__WEBPACK_IMPORTED_MODULE_0__, firebase_compat_auth__WEBPACK_IMPORTED_MODULE_1__, firebase_compat_firestore__WEBPACK_IMPORTED_MODULE_2__, firebase_compat_storage__WEBPACK_IMPORTED_MODULE_3__, firebase_database__WEBPACK_IMPORTED_MODULE_4__]);
([firebase_compat_app__WEBPACK_IMPORTED_MODULE_0__, firebase_compat_auth__WEBPACK_IMPORTED_MODULE_1__, firebase_compat_firestore__WEBPACK_IMPORTED_MODULE_2__, firebase_compat_storage__WEBPACK_IMPORTED_MODULE_3__, firebase_database__WEBPACK_IMPORTED_MODULE_4__] = __webpack_async_dependencies__.then ? (await __webpack_async_dependencies__)() : __webpack_async_dependencies__);





const firebaseConfig = {
    apiKey: "AIzaSyCnqA63y5H9q8rv4DPkIshwg8awh3Xk1FQ",
    authDomain: "infiopp-c399a.firebaseapp.com",
    projectId: "infiopp-c399a",
    storageBucket: "infiopp-c399a.appspot.com",
    messagingSenderId: "955369058407",
    appId: "1:955369058407:web:8311adee2e681ee92de4c2",
    measurementId: "G-CZKDK3GXXD"
};
if (!firebase_compat_app__WEBPACK_IMPORTED_MODULE_0__["default"].apps.length) {
    firebase_compat_app__WEBPACK_IMPORTED_MODULE_0__["default"].initializeApp(firebaseConfig);
}
// Auth exports
const auth = firebase_compat_app__WEBPACK_IMPORTED_MODULE_0__["default"].auth();
const googleAuthProvider = new firebase_compat_app__WEBPACK_IMPORTED_MODULE_0__["default"].auth.GoogleAuthProvider();
// Firestore exports
const firestore = firebase_compat_app__WEBPACK_IMPORTED_MODULE_0__["default"].firestore();
const serverTimestamp = firebase_compat_app__WEBPACK_IMPORTED_MODULE_0__["default"].firestore.FieldValue.serverTimestamp;
const fromMillis = firebase_compat_app__WEBPACK_IMPORTED_MODULE_0__["default"].firestore.Timestamp.fromMillis;
const increment = firebase_compat_app__WEBPACK_IMPORTED_MODULE_0__["default"].firestore.FieldValue.increment;
const doc = firebase_compat_app__WEBPACK_IMPORTED_MODULE_0__["default"].firestore.doc;
const getDoc = firebase_compat_app__WEBPACK_IMPORTED_MODULE_0__["default"].firestore.getDoc;
// Storage exports
const storage = firebase_compat_app__WEBPACK_IMPORTED_MODULE_0__["default"].storage();
const STATE_CHANGED = firebase_compat_app__WEBPACK_IMPORTED_MODULE_0__["default"].storage.TaskEvent.STATE_CHANGED;
/// Helper functions
const db = (0,firebase_database__WEBPACK_IMPORTED_MODULE_4__.getDatabase)();
async function generateFirebaseID(collection) {
    const newRef = (0,firebase_database__WEBPACK_IMPORTED_MODULE_4__.push)((0,firebase_database__WEBPACK_IMPORTED_MODULE_4__.ref)(db, collection));
    console.log("New ID generated:", newRef.key);
    return newRef.key;
}
/**`
 * Gets a users/{uid} document with username
 * @param  {string} username
 */ async function getUserWithUsername(username) {
    const usersRef = firestore.collection("users");
    const query = usersRef.where("username", "==", username).limit(1);
    const userDoc = (await query.get()).docs[0];
    return userDoc;
}
/**`
 * Converts a firestore document to JSON
 * @param  {DocumentSnapshot} doc
 */ function postToJSON(doc) {
    const data = doc.data();
    return {
        ...data,
        // Gotcha! firestore timestamp NOT serializable to JSON. Must convert to milliseconds
        createdAt: data?.createdAt.toMillis() || 0,
        updatedAt: data?.updatedAt.toMillis() || 0
    };
}

__webpack_async_result__();
} catch(e) { __webpack_async_result__(e); } });

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