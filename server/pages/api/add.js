"use strict";
(() => {
var exports = {};
exports.id = 41;
exports.ids = [41,373];
exports.modules = {

/***/ 2509:
/***/ ((module) => {

module.exports = require("firebase-admin");

/***/ }),

/***/ 9993:
/***/ ((module) => {

module.exports = require("googleapis");

/***/ }),

/***/ 3773:
/***/ ((module) => {

module.exports = import("firebase/compat/app");;

/***/ }),

/***/ 4826:
/***/ ((module) => {

module.exports = import("firebase/compat/auth");;

/***/ }),

/***/ 741:
/***/ ((module) => {

module.exports = import("firebase/compat/firestore");;

/***/ }),

/***/ 451:
/***/ ((module) => {

module.exports = import("firebase/compat/storage");;

/***/ }),

/***/ 1208:
/***/ ((module) => {

module.exports = import("firebase/database");;

/***/ }),

/***/ 3274:
/***/ ((module, __webpack_exports__, __webpack_require__) => {

__webpack_require__.a(module, async (__webpack_handle_async_dependencies__, __webpack_async_result__) => { try {
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (/* binding */ handler)
/* harmony export */ });
/* harmony import */ var _lib_firebase__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(62);
/* harmony import */ var _firebaseAdmin_index__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(2132);
/* harmony import */ var _calendar_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(5305);
/* harmony import */ var _serverSideAdmin_index__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(2708);
var __webpack_async_dependencies__ = __webpack_handle_async_dependencies__([_lib_firebase__WEBPACK_IMPORTED_MODULE_0__]);
_lib_firebase__WEBPACK_IMPORTED_MODULE_0__ = (__webpack_async_dependencies__.then ? (await __webpack_async_dependencies__)() : __webpack_async_dependencies__)[0];





async function handler(req, res) {
    await _firebaseAdmin_index__WEBPACK_IMPORTED_MODULE_1__.auth.verifyIdToken(req.headers.authorization).then(async (decodedToken)=>{
        const userSocial = await getSocial(req.body.postedBy);
        const values = req.body;
        const category = req.headers.category;
        let newCalID = undefined;
        let newDiscordMessageID = undefined;
        newCalID = (0,_calendar_js__WEBPACK_IMPORTED_MODULE_2__.addCalendarEvent)(values.eventN, values.link, values.appS, values.appE, category);
        if (userSocial.discordID) {
            newDiscordMessageID = (0,_serverSideAdmin_index__WEBPACK_IMPORTED_MODULE_3__.sendMessage)(values, userSocial.discordID, category);
        } else if (userSocial.discord) {
            const foundDiscordID = await (0,_serverSideAdmin_index__WEBPACK_IMPORTED_MODULE_3__.findMemberId)(userSocial.discord);
            if (foundDiscordID) {
                newDiscordMessageID = (0,_serverSideAdmin_index__WEBPACK_IMPORTED_MODULE_3__.sendMessage)(values, foundDiscordID, category);
            } else {
                newDiscordMessageID = (0,_serverSideAdmin_index__WEBPACK_IMPORTED_MODULE_3__.sendMessage)(values, undefined, category);
            }
        } else {
            newDiscordMessageID = (0,_serverSideAdmin_index__WEBPACK_IMPORTED_MODULE_3__.sendMessage)(values, userSocial.discordID, category);
        }
        const allId = await Promise.all([
            newCalID,
            newDiscordMessageID
        ]);
        values.calID = allId[0];
        values.discordMessageID = allId[1];
        console.log("values:", values);
        let id = await (0,_lib_firebase__WEBPACK_IMPORTED_MODULE_0__/* .generateFirebaseID */ .v8)(category);
        const ref = _lib_firebase__WEBPACK_IMPORTED_MODULE_0__/* .firestore.collection */ .RZ.collection(category).doc(id);
        await ref.set(values);
        res.status(200).send({
            success: `${values.eventN} ADDED`
        });
    }).catch((error)=>{
        res.status(200).send({
            error: "Authorization Failed"
        });
    });
}
async function getSocial(username) {
    let document = undefined;
    await _lib_firebase__WEBPACK_IMPORTED_MODULE_0__/* .firestore.collection */ .RZ.collection("usernames").doc(username).get().then((doc)=>{
        if (doc.exists) {
            document = doc.data();
        } else {
            // doc.data() will be undefined in this case
            console.log("No such document!");
            document = undefined;
        }
    }).catch((error)=>{
        console.log("Error getting document:", error);
        return undefined;
    });
    return document;
}

__webpack_async_result__();
} catch(e) { __webpack_async_result__(e); } });

/***/ })

};
;

// load runtime
var __webpack_require__ = require("../../webpack-api-runtime.js");
__webpack_require__.C(exports);
var __webpack_exec__ = (moduleId) => (__webpack_require__(__webpack_require__.s = moduleId))
var __webpack_exports__ = __webpack_require__.X(0, [708,305,124], () => (__webpack_exec__(3274)));
module.exports = __webpack_exports__;

})();