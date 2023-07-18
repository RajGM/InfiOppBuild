(() => {
var exports = {};
exports.id = 888;
exports.ids = [888];
exports.modules = {

/***/ 723:
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "Z": () => (/* binding */ Footer)
/* harmony export */ });
/* harmony import */ var react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(997);
/* harmony import */ var react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__);
// Bottom footer

function Footer() {
    return /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("footer", {
        children: [
            /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("div", {
                children: /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("a", {
                    href: "https://twitter.com/InfiOppME",
                    target: "_blank",
                    children: /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("img", {
                        src: "/twitter.png",
                        alt: "title",
                        className: "footerLogo"
                    })
                })
            }),
            /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("div", {
                children: [
                    "InfiOpp by ",
                    /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("a", {
                        href: "https://twitter.com/RajGM_Hacks/",
                        target: "_blank",
                        children: "RajGM"
                    })
                ]
            }),
            /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("div", {
                children: /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("a", {
                    href: "https://www.linkedin.com/company/infiopp/",
                    target: "_blank",
                    children: /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("img", {
                        src: "/linkedin.png",
                        alt: "title",
                        className: "footerLogo"
                    })
                })
            })
        ]
    });
}


/***/ }),

/***/ 6004:
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";

// EXPORTS
__webpack_require__.d(__webpack_exports__, {
  "Z": () => (/* binding */ Metatags)
});

// EXTERNAL MODULE: external "react/jsx-runtime"
var jsx_runtime_ = __webpack_require__(997);
;// CONCATENATED MODULE: external "next/head"
const head_namespaceObject = require("next/head");
var head_default = /*#__PURE__*/__webpack_require__.n(head_namespaceObject);
;// CONCATENATED MODULE: ./components/Metatags.js


function Metatags({ title ="InfiOpp" , description ="Opportunities listed and verified by the community" , image ="logo.jpg"  }) {
    return /*#__PURE__*/ (0,jsx_runtime_.jsxs)((head_default()), {
        children: [
            /*#__PURE__*/ jsx_runtime_.jsx("title", {
                children: "InfiOpp"
            }),
            /*#__PURE__*/ jsx_runtime_.jsx("meta", {
                name: "twitter:card",
                content: "summary"
            }),
            /*#__PURE__*/ jsx_runtime_.jsx("meta", {
                name: "twitter:site",
                content: "@InfiOppME"
            }),
            /*#__PURE__*/ jsx_runtime_.jsx("meta", {
                name: "twitter:title",
                content: title
            }),
            /*#__PURE__*/ jsx_runtime_.jsx("meta", {
                name: "twitter:description",
                content: description
            }),
            /*#__PURE__*/ jsx_runtime_.jsx("meta", {
                name: "twitter:image",
                content: "/" + image
            }),
            /*#__PURE__*/ jsx_runtime_.jsx("meta", {
                property: "og:title",
                content: title
            }),
            /*#__PURE__*/ jsx_runtime_.jsx("meta", {
                property: "og:description",
                content: description
            }),
            /*#__PURE__*/ jsx_runtime_.jsx("meta", {
                property: "og:image",
                content: "/" + image
            })
        ]
    });
}


/***/ }),

/***/ 2103:
/***/ ((module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.a(module, async (__webpack_handle_async_dependencies__, __webpack_async_result__) => { try {
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "Z": () => (/* binding */ Navbar)
/* harmony export */ });
/* harmony import */ var react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(997);
/* harmony import */ var react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__);
/* harmony import */ var next_link__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(1664);
/* harmony import */ var next_link__WEBPACK_IMPORTED_MODULE_1___default = /*#__PURE__*/__webpack_require__.n(next_link__WEBPACK_IMPORTED_MODULE_1__);
/* harmony import */ var next_router__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(1853);
/* harmony import */ var next_router__WEBPACK_IMPORTED_MODULE_2___default = /*#__PURE__*/__webpack_require__.n(next_router__WEBPACK_IMPORTED_MODULE_2__);
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(6689);
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_3___default = /*#__PURE__*/__webpack_require__.n(react__WEBPACK_IMPORTED_MODULE_3__);
/* harmony import */ var _lib_context__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(8059);
/* harmony import */ var _lib_firebase__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(2881);
/* harmony import */ var _Modal__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(7274);
var __webpack_async_dependencies__ = __webpack_handle_async_dependencies__([_lib_firebase__WEBPACK_IMPORTED_MODULE_5__, _Modal__WEBPACK_IMPORTED_MODULE_6__]);
([_lib_firebase__WEBPACK_IMPORTED_MODULE_5__, _Modal__WEBPACK_IMPORTED_MODULE_6__] = __webpack_async_dependencies__.then ? (await __webpack_async_dependencies__)() : __webpack_async_dependencies__);







// Top navbar
function Navbar() {
    const { user , username  } = (0,react__WEBPACK_IMPORTED_MODULE_3__.useContext)(_lib_context__WEBPACK_IMPORTED_MODULE_4__/* .UserContext */ .S);
    const router = (0,next_router__WEBPACK_IMPORTED_MODULE_2__.useRouter)();
    const signOut = ()=>{
        _lib_firebase__WEBPACK_IMPORTED_MODULE_5__/* .auth.signOut */ .I8.signOut();
        router.reload();
    };
    return /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("nav", {
        className: "navbar",
        children: /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("ul", {
            children: [
                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("li", {
                    children: /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx((next_link__WEBPACK_IMPORTED_MODULE_1___default()), {
                        href: "/",
                        children: /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("button", {
                            className: "btn-logo",
                            children: "InfiOpp"
                        })
                    })
                }),
                username && /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)(react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.Fragment, {
                    children: [
                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("li", {
                            className: "push-left",
                            children: /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("button", {
                                onClick: signOut,
                                children: "Sign Out"
                            })
                        }),
                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("li", {
                            children: /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(_Modal__WEBPACK_IMPORTED_MODULE_6__/* ["default"] */ .Z, {
                                eventData: null
                            })
                        }),
                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("li", {
                            children: /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx((next_link__WEBPACK_IMPORTED_MODULE_1___default()), {
                                href: `/${username}`,
                                children: /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("img", {
                                    src: user?.photoURL || "/hacker.png"
                                })
                            })
                        })
                    ]
                }),
                !username && /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("li", {
                    children: /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx((next_link__WEBPACK_IMPORTED_MODULE_1___default()), {
                        href: "/enter",
                        children: /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("button", {
                            className: "btn-blue",
                            children: "Log in"
                        })
                    })
                })
            ]
        })
    });
} /*
<Link href="/admin">
                <button className="btn-blue">Write Posts</button>
              </Link>
*/ 

__webpack_async_result__();
} catch(e) { __webpack_async_result__(e); } });

/***/ }),

/***/ 2406:
/***/ ((module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.a(module, async (__webpack_handle_async_dependencies__, __webpack_async_result__) => { try {
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "v": () => (/* binding */ useUserData)
/* harmony export */ });
/* harmony import */ var _lib_firebase__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(2881);
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(6689);
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_1___default = /*#__PURE__*/__webpack_require__.n(react__WEBPACK_IMPORTED_MODULE_1__);
/* harmony import */ var react_firebase_hooks_auth__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(830);
/* harmony import */ var react_firebase_hooks_auth__WEBPACK_IMPORTED_MODULE_2___default = /*#__PURE__*/__webpack_require__.n(react_firebase_hooks_auth__WEBPACK_IMPORTED_MODULE_2__);
/* harmony import */ var _lib_context__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(8059);
var __webpack_async_dependencies__ = __webpack_handle_async_dependencies__([_lib_firebase__WEBPACK_IMPORTED_MODULE_0__]);
_lib_firebase__WEBPACK_IMPORTED_MODULE_0__ = (__webpack_async_dependencies__.then ? (await __webpack_async_dependencies__)() : __webpack_async_dependencies__)[0];




// Custom hook to read  auth record and user profile doc
function useUserData() {
    const [user] = (0,react_firebase_hooks_auth__WEBPACK_IMPORTED_MODULE_2__.useAuthState)(_lib_firebase__WEBPACK_IMPORTED_MODULE_0__/* .auth */ .I8);
    const [username, setUsername] = (0,react__WEBPACK_IMPORTED_MODULE_1__.useState)(null);
    const [social, setSocial] = (0,react__WEBPACK_IMPORTED_MODULE_1__.useState)(null);
    (0,react__WEBPACK_IMPORTED_MODULE_1__.useEffect)(()=>{
        // turn off realtime subscription
        let unsubscribe;
        if (user) {
            const ref = _lib_firebase__WEBPACK_IMPORTED_MODULE_0__/* .firestore.collection */ .RZ.collection("users").doc(user.uid);
            unsubscribe = ref.onSnapshot((doc)=>{
                setUsername(doc.data()?.username);
                const ref2 = _lib_firebase__WEBPACK_IMPORTED_MODULE_0__/* .firestore.collection */ .RZ.collection("usernames").doc(doc.data()?.username);
                ref2.get().then((doc)=>{
                    setSocial(doc.data());
                });
            });
        } else {
            setUsername(null);
        }
        return unsubscribe;
    }, [
        user
    ]);
    return {
        user,
        username,
        social
    };
}

__webpack_async_result__();
} catch(e) { __webpack_async_result__(e); } });

/***/ }),

/***/ 8484:
/***/ ((module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.a(module, async (__webpack_handle_async_dependencies__, __webpack_async_result__) => { try {
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (__WEBPACK_DEFAULT_EXPORT__)
/* harmony export */ });
/* harmony import */ var react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(997);
/* harmony import */ var react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__);
/* harmony import */ var _styles_globals_css__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(6764);
/* harmony import */ var _styles_globals_css__WEBPACK_IMPORTED_MODULE_1___default = /*#__PURE__*/__webpack_require__.n(_styles_globals_css__WEBPACK_IMPORTED_MODULE_1__);
/* harmony import */ var _lib_context__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(8059);
/* harmony import */ var _lib_hooks__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(2406);
/* harmony import */ var _components_Navbar__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(2103);
/* harmony import */ var _components_Footer__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(723);
/* harmony import */ var jotai__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(2451);
/* harmony import */ var _components_Metatags__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(6004);
var __webpack_async_dependencies__ = __webpack_handle_async_dependencies__([_lib_hooks__WEBPACK_IMPORTED_MODULE_3__, _components_Navbar__WEBPACK_IMPORTED_MODULE_4__, jotai__WEBPACK_IMPORTED_MODULE_6__]);
([_lib_hooks__WEBPACK_IMPORTED_MODULE_3__, _components_Navbar__WEBPACK_IMPORTED_MODULE_4__, jotai__WEBPACK_IMPORTED_MODULE_6__] = __webpack_async_dependencies__.then ? (await __webpack_async_dependencies__)() : __webpack_async_dependencies__);








function MyApp({ Component , pageProps  }) {
    const userData = (0,_lib_hooks__WEBPACK_IMPORTED_MODULE_3__/* .useUserData */ .v)();
    console.log("userData FROM MAIN: ", userData);
    return /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(_lib_context__WEBPACK_IMPORTED_MODULE_2__/* .UserContext.Provider */ .S.Provider, {
        value: userData,
        children: /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)(jotai__WEBPACK_IMPORTED_MODULE_6__.Provider, {
            children: [
                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(_components_Metatags__WEBPACK_IMPORTED_MODULE_7__/* ["default"] */ .Z, {
                    title: "InfiOpp",
                    description: "Sign up for InfiOpp!"
                }),
                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(_components_Navbar__WEBPACK_IMPORTED_MODULE_4__/* ["default"] */ .Z, {}),
                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(Component, {
                    ...pageProps
                }),
                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(_components_Footer__WEBPACK_IMPORTED_MODULE_5__/* ["default"] */ .Z, {})
            ]
        })
    });
}
/* harmony default export */ const __WEBPACK_DEFAULT_EXPORT__ = (MyApp);

__webpack_async_result__();
} catch(e) { __webpack_async_result__(e); } });

/***/ }),

/***/ 6764:
/***/ (() => {



/***/ }),

/***/ 2296:
/***/ ((module) => {

"use strict";
module.exports = require("formik");

/***/ }),

/***/ 3280:
/***/ ((module) => {

"use strict";
module.exports = require("next/dist/shared/lib/app-router-context.js");

/***/ }),

/***/ 2796:
/***/ ((module) => {

"use strict";
module.exports = require("next/dist/shared/lib/head-manager-context.js");

/***/ }),

/***/ 4014:
/***/ ((module) => {

"use strict";
module.exports = require("next/dist/shared/lib/i18n/normalize-locale-path.js");

/***/ }),

/***/ 8524:
/***/ ((module) => {

"use strict";
module.exports = require("next/dist/shared/lib/is-plain-object.js");

/***/ }),

/***/ 8020:
/***/ ((module) => {

"use strict";
module.exports = require("next/dist/shared/lib/mitt.js");

/***/ }),

/***/ 4406:
/***/ ((module) => {

"use strict";
module.exports = require("next/dist/shared/lib/page-path/denormalize-page-path.js");

/***/ }),

/***/ 4964:
/***/ ((module) => {

"use strict";
module.exports = require("next/dist/shared/lib/router-context.js");

/***/ }),

/***/ 1751:
/***/ ((module) => {

"use strict";
module.exports = require("next/dist/shared/lib/router/utils/add-path-prefix.js");

/***/ }),

/***/ 6220:
/***/ ((module) => {

"use strict";
module.exports = require("next/dist/shared/lib/router/utils/compare-states.js");

/***/ }),

/***/ 299:
/***/ ((module) => {

"use strict";
module.exports = require("next/dist/shared/lib/router/utils/format-next-pathname-info.js");

/***/ }),

/***/ 3938:
/***/ ((module) => {

"use strict";
module.exports = require("next/dist/shared/lib/router/utils/format-url.js");

/***/ }),

/***/ 9565:
/***/ ((module) => {

"use strict";
module.exports = require("next/dist/shared/lib/router/utils/get-asset-path-from-route.js");

/***/ }),

/***/ 5789:
/***/ ((module) => {

"use strict";
module.exports = require("next/dist/shared/lib/router/utils/get-next-pathname-info.js");

/***/ }),

/***/ 1897:
/***/ ((module) => {

"use strict";
module.exports = require("next/dist/shared/lib/router/utils/is-bot.js");

/***/ }),

/***/ 1428:
/***/ ((module) => {

"use strict";
module.exports = require("next/dist/shared/lib/router/utils/is-dynamic.js");

/***/ }),

/***/ 8854:
/***/ ((module) => {

"use strict";
module.exports = require("next/dist/shared/lib/router/utils/parse-path.js");

/***/ }),

/***/ 1292:
/***/ ((module) => {

"use strict";
module.exports = require("next/dist/shared/lib/router/utils/parse-relative-url.js");

/***/ }),

/***/ 4567:
/***/ ((module) => {

"use strict";
module.exports = require("next/dist/shared/lib/router/utils/path-has-prefix.js");

/***/ }),

/***/ 979:
/***/ ((module) => {

"use strict";
module.exports = require("next/dist/shared/lib/router/utils/querystring.js");

/***/ }),

/***/ 3297:
/***/ ((module) => {

"use strict";
module.exports = require("next/dist/shared/lib/router/utils/remove-trailing-slash.js");

/***/ }),

/***/ 6052:
/***/ ((module) => {

"use strict";
module.exports = require("next/dist/shared/lib/router/utils/resolve-rewrites.js");

/***/ }),

/***/ 4226:
/***/ ((module) => {

"use strict";
module.exports = require("next/dist/shared/lib/router/utils/route-matcher.js");

/***/ }),

/***/ 5052:
/***/ ((module) => {

"use strict";
module.exports = require("next/dist/shared/lib/router/utils/route-regex.js");

/***/ }),

/***/ 9232:
/***/ ((module) => {

"use strict";
module.exports = require("next/dist/shared/lib/utils.js");

/***/ }),

/***/ 1853:
/***/ ((module) => {

"use strict";
module.exports = require("next/router");

/***/ }),

/***/ 6689:
/***/ ((module) => {

"use strict";
module.exports = require("react");

/***/ }),

/***/ 6405:
/***/ ((module) => {

"use strict";
module.exports = require("react-dom");

/***/ }),

/***/ 830:
/***/ ((module) => {

"use strict";
module.exports = require("react-firebase-hooks/auth");

/***/ }),

/***/ 3069:
/***/ ((module) => {

"use strict";
module.exports = require("react-responsive-modal");

/***/ }),

/***/ 997:
/***/ ((module) => {

"use strict";
module.exports = require("react/jsx-runtime");

/***/ }),

/***/ 5609:
/***/ ((module) => {

"use strict";
module.exports = require("yup");

/***/ }),

/***/ 3773:
/***/ ((module) => {

"use strict";
module.exports = import("firebase/compat/app");;

/***/ }),

/***/ 4826:
/***/ ((module) => {

"use strict";
module.exports = import("firebase/compat/auth");;

/***/ }),

/***/ 741:
/***/ ((module) => {

"use strict";
module.exports = import("firebase/compat/firestore");;

/***/ }),

/***/ 451:
/***/ ((module) => {

"use strict";
module.exports = import("firebase/compat/storage");;

/***/ }),

/***/ 1208:
/***/ ((module) => {

"use strict";
module.exports = import("firebase/database");;

/***/ }),

/***/ 2451:
/***/ ((module) => {

"use strict";
module.exports = import("jotai");;

/***/ }),

/***/ 6201:
/***/ ((module) => {

"use strict";
module.exports = import("react-hot-toast");;

/***/ })

};
;

// load runtime
var __webpack_require__ = require("../webpack-runtime.js");
__webpack_require__.C(exports);
var __webpack_exec__ = (moduleId) => (__webpack_require__(__webpack_require__.s = moduleId))
var __webpack_exports__ = __webpack_require__.X(0, [210,676,664,843,274], () => (__webpack_exec__(8484)));
module.exports = __webpack_exports__;

})();