exports.id = 274;
exports.ids = [274];
exports.modules = {

/***/ 7885:
/***/ ((module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.a(module, async (__webpack_handle_async_dependencies__, __webpack_async_result__) => { try {
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "G": () => (/* binding */ Customform),
/* harmony export */   "x": () => (/* binding */ MyFormComponent)
/* harmony export */ });
/* harmony import */ var react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(997);
/* harmony import */ var react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__);
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(6689);
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_1___default = /*#__PURE__*/__webpack_require__.n(react__WEBPACK_IMPORTED_MODULE_1__);
/* harmony import */ var react_responsive_modal_styles_css__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(4602);
/* harmony import */ var react_responsive_modal_styles_css__WEBPACK_IMPORTED_MODULE_2___default = /*#__PURE__*/__webpack_require__.n(react_responsive_modal_styles_css__WEBPACK_IMPORTED_MODULE_2__);
/* harmony import */ var formik__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(2296);
/* harmony import */ var formik__WEBPACK_IMPORTED_MODULE_3___default = /*#__PURE__*/__webpack_require__.n(formik__WEBPACK_IMPORTED_MODULE_3__);
/* harmony import */ var react_hot_toast__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(6201);
/* harmony import */ var _atoms__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(8104);
/* harmony import */ var jotai__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(2451);
/* harmony import */ var yup__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(5609);
/* harmony import */ var yup__WEBPACK_IMPORTED_MODULE_7___default = /*#__PURE__*/__webpack_require__.n(yup__WEBPACK_IMPORTED_MODULE_7__);
/* harmony import */ var _lib_context__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(8059);
var __webpack_async_dependencies__ = __webpack_handle_async_dependencies__([react_hot_toast__WEBPACK_IMPORTED_MODULE_4__, _atoms__WEBPACK_IMPORTED_MODULE_5__, jotai__WEBPACK_IMPORTED_MODULE_6__]);
([react_hot_toast__WEBPACK_IMPORTED_MODULE_4__, _atoms__WEBPACK_IMPORTED_MODULE_5__, jotai__WEBPACK_IMPORTED_MODULE_6__] = __webpack_async_dependencies__.then ? (await __webpack_async_dependencies__)() : __webpack_async_dependencies__);










function Customform({ eventData , categoryTest  }) {
    if (categoryTest === "hackathon") {
        return /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(Hackathon, {
            eventData: eventData
        });
    } else if (categoryTest == "internship") {
        return /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(Internship, {
            eventData: eventData
        });
    } else if (categoryTest == "grants") {
        return /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(Grants, {
            eventData: eventData
        });
    } else if (categoryTest == "conferences") {
        return /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(Conferences, {
            eventData: eventData
        });
    }
}
;
const MyFormComponent = ({ eventData  })=>{
    return /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Formik, {
        initialValues: {
            category: "Hackathon"
        },
        onSubmit: (resetForm)=>{
            false, resetForm();
        },
        children: (formik)=>/*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("div", {
                children: [
                    /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("div", {
                        className: "multiOption",
                        children: [
                            /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("div", {
                                id: "my-radio-group",
                                children: "Category"
                            }),
                            /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("div", {
                                role: "group",
                                "aria-labelledby": "my-radio-group",
                                className: "optionDiv",
                                children: [
                                    /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("label", {
                                        children: [
                                            /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                                                type: "radio",
                                                name: "category",
                                                value: "Hackathon"
                                            }),
                                            "Hackathon"
                                        ]
                                    }),
                                    /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("label", {
                                        children: [
                                            /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                                                type: "radio",
                                                name: "category",
                                                value: "Internship"
                                            }),
                                            "Internship"
                                        ]
                                    }),
                                    /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("label", {
                                        children: [
                                            /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                                                type: "radio",
                                                name: "category",
                                                value: "Grants"
                                            }),
                                            "Grants"
                                        ]
                                    }),
                                    /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("label", {
                                        children: [
                                            /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                                                type: "radio",
                                                name: "category",
                                                value: "Conferences"
                                            }),
                                            "Conferences"
                                        ]
                                    })
                                ]
                            })
                        ]
                    }),
                    formik.values.category == "Hackathon" && /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(Hackathon, {
                        eventData: null
                    }),
                    formik.values.category == "Internship" && /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(Internship, {
                        eventData: null
                    }),
                    formik.values.category == "Grants" && /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(Grants, {
                        eventData: null
                    }),
                    formik.values.category == "Conferences" && /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(Conferences, {
                        eventData: null
                    })
                ]
            })
    });
};
function Hackathon({ eventData  }) {
    const { user , username  } = (0,react__WEBPACK_IMPORTED_MODULE_1__.useContext)(_lib_context__WEBPACK_IMPORTED_MODULE_8__/* .UserContext */ .S);
    if (eventData == null) {
        return /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Formik, {
            initialValues: {
                eventN: "",
                link: "",
                appS: "",
                appE: "",
                eventS: "",
                eventE: "",
                postedBy: "",
                filters: ""
            },
            onSubmit: async (values)=>{
                values.postedBy = username;
                react_hot_toast__WEBPACK_IMPORTED_MODULE_4__["default"].loading(`Adding ${values.eventN} for the community`);
                await post("add", "Hackathon", values, user);
            },
            children: ({ isSubmitting  })=>/*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)(formik__WEBPACK_IMPORTED_MODULE_3__.Form, {
                    children: [
                        /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("div", {
                            children: [
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("label", {
                                    htmlFor: "eventN",
                                    children: "Hackathon"
                                }),
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                                    name: "eventN",
                                    placeholder: "Hackathon",
                                    validate: (value)=>{
                                        if (!value) {
                                            return "Title is required";
                                        }
                                    }
                                }),
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.ErrorMessage, {
                                    name: "eventN"
                                })
                            ]
                        }),
                        /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("div", {
                            children: [
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("label", {
                                    htmlFor: "link",
                                    children: "Link"
                                }),
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                                    name: "link",
                                    placeholder: "HackthonURL",
                                    validate: (value)=>{
                                        if (!value) {
                                            return "Link is required";
                                        }
                                    }
                                }),
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.ErrorMessage, {
                                    name: "link"
                                })
                            ]
                        }),
                        /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("div", {
                            className: "multiOption",
                            children: [
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("div", {
                                    id: "my-radio-group",
                                    children: "Filters"
                                }),
                                /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("div", {
                                    role: "group",
                                    "aria-labelledby": "my-radio-group",
                                    className: "optionDiv",
                                    children: [
                                        /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("label", {
                                            children: [
                                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                                                    type: "radio",
                                                    name: "filters",
                                                    value: "onsite"
                                                }),
                                                "Onsite"
                                            ]
                                        }),
                                        /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("label", {
                                            children: [
                                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                                                    type: "radio",
                                                    name: "filters",
                                                    value: "remote"
                                                }),
                                                "Remote"
                                            ]
                                        }),
                                        /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("label", {
                                            children: [
                                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                                                    type: "radio",
                                                    name: "filters",
                                                    value: "hybrid"
                                                }),
                                                "Hybrid"
                                            ]
                                        })
                                    ]
                                })
                            ]
                        }),
                        /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("div", {
                            children: [
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("label", {
                                    htmlFor: "appS",
                                    children: "Application Starts"
                                }),
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                                    name: "appS",
                                    type: "date",
                                    validate: (value)=>{
                                        if (!value) {
                                            return "Application Start Date is required";
                                        }
                                    }
                                }),
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.ErrorMessage, {
                                    name: "appS"
                                })
                            ]
                        }),
                        /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("div", {
                            children: [
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("label", {
                                    htmlFor: "appE",
                                    children: "Application Ends"
                                }),
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                                    name: "appE",
                                    type: "date",
                                    validate: (value)=>{
                                        if (!value) {
                                            return "Application End Date is required";
                                        }
                                    }
                                }),
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.ErrorMessage, {
                                    name: "appE"
                                })
                            ]
                        }),
                        /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("div", {
                            children: [
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("label", {
                                    htmlFor: "eventS",
                                    children: "Hackathon Beings"
                                }),
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                                    name: "eventS",
                                    type: "date"
                                }),
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.ErrorMessage, {
                                    name: "eventS"
                                })
                            ]
                        }),
                        /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("div", {
                            children: [
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("label", {
                                    htmlFor: "eventE",
                                    children: "Hackathon Ends"
                                }),
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                                    name: "eventE",
                                    type: "date"
                                })
                            ]
                        }),
                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("button", {
                            type: "submit",
                            disabled: isSubmitting,
                            children: "Submit"
                        }),
                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(react_hot_toast__WEBPACK_IMPORTED_MODULE_4__.Toaster, {})
                    ]
                })
        });
    } else {
        return /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Formik, {
            initialValues: {
                eventN: eventData.eventN,
                link: eventData.link,
                appS: eventData.appS,
                appE: eventData.appE,
                eventS: eventData.eventS,
                eventE: eventData.eventE,
                filters: eventData.filters,
                postedBy: eventData.postedBy
            },
            onSubmit: async (values)=>{
                react_hot_toast__WEBPACK_IMPORTED_MODULE_4__["default"].loading(`Updating ${values.eventN} for the community`);
                values.calID = eventData.calID ? eventData.calID : "";
                values.discordMessageID = eventData.discordMessageID ? eventData.discordMessageID : "";
                await post("edit", "Hackathon", values, user, eventData.id);
            },
            children: ({ isSubmitting  })=>/*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)(formik__WEBPACK_IMPORTED_MODULE_3__.Form, {
                    children: [
                        /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("div", {
                            children: [
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("label", {
                                    htmlFor: "eventN",
                                    children: "Hackathon"
                                }),
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                                    name: "eventN",
                                    placeholder: "Title",
                                    validate: (value)=>{
                                        if (!value) {
                                            return "Hackathon Title is required";
                                        }
                                    }
                                }),
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.ErrorMessage, {
                                    name: "eventN"
                                })
                            ]
                        }),
                        /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("div", {
                            children: [
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("label", {
                                    htmlFor: "link",
                                    children: "Link"
                                }),
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                                    name: "link",
                                    placeholder: "Hackathon URL",
                                    validate: (value)=>{
                                        if (!value) {
                                            return "Hackathon URL is required";
                                        }
                                    }
                                }),
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.ErrorMessage, {
                                    name: "link"
                                })
                            ]
                        }),
                        /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("div", {
                            className: "multiOption",
                            children: [
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("div", {
                                    id: "my-radio-group",
                                    children: "Filters"
                                }),
                                /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("div", {
                                    role: "group",
                                    "aria-labelledby": "my-radio-group",
                                    className: "optionDiv",
                                    children: [
                                        /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("label", {
                                            children: [
                                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                                                    type: "radio",
                                                    name: "filters",
                                                    value: "onsite"
                                                }),
                                                "Onsite"
                                            ]
                                        }),
                                        /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("label", {
                                            children: [
                                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                                                    type: "radio",
                                                    name: "filters",
                                                    value: "remote"
                                                }),
                                                "Remote"
                                            ]
                                        }),
                                        /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("label", {
                                            children: [
                                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                                                    type: "radio",
                                                    name: "filters",
                                                    value: "hybrid"
                                                }),
                                                "Hybrid"
                                            ]
                                        })
                                    ]
                                })
                            ]
                        }),
                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("label", {
                            htmlFor: "appS",
                            children: "Registration Begins"
                        }),
                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                            name: "appS",
                            type: "date",
                            validate: (value)=>{
                                if (!value) {
                                    return "Application Start date is required";
                                }
                            }
                        }),
                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("label", {
                            htmlFor: "appE",
                            children: "Registration Ends"
                        }),
                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                            name: "appE",
                            type: "date",
                            validate: (value)=>{
                                if (!value) {
                                    return "Application End date is required";
                                }
                            }
                        }),
                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("label", {
                            htmlFor: "eventS",
                            children: "Conference Beings"
                        }),
                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                            name: "eventS",
                            type: "date"
                        }),
                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("label", {
                            htmlFor: "eventE",
                            children: "Conference Ends"
                        }),
                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                            name: "eventE",
                            type: "date"
                        }),
                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("button", {
                            type: "submit",
                            disabled: isSubmitting,
                            children: "Submit"
                        }),
                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(react_hot_toast__WEBPACK_IMPORTED_MODULE_4__.Toaster, {})
                    ]
                })
        });
    }
}
function Internship({ eventData  }) {
    const { user , username  } = (0,react__WEBPACK_IMPORTED_MODULE_1__.useContext)(_lib_context__WEBPACK_IMPORTED_MODULE_8__/* .UserContext */ .S);
    if (eventData == null) {
        return /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Formik, {
            initialValues: {
                eventN: "",
                link: "",
                appS: "",
                appE: "",
                eventS: "",
                eventE: "",
                filters: "",
                postedBy: ""
            },
            onSubmit: async (values)=>{
                values.postedBy = username;
                react_hot_toast__WEBPACK_IMPORTED_MODULE_4__["default"].loading(`Adding ${values.eventN} for the community`);
                await post("add", "Internship", values, user);
            },
            children: ({ isSubmitting  })=>/*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)(formik__WEBPACK_IMPORTED_MODULE_3__.Form, {
                    children: [
                        /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("div", {
                            children: [
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("label", {
                                    htmlFor: "eventN",
                                    children: "Company"
                                }),
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                                    name: "eventN",
                                    placeholder: "Internship",
                                    validate: (value)=>{
                                        if (!value) {
                                            return "Internship Title is required";
                                        }
                                    }
                                }),
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.ErrorMessage, {
                                    name: "eventN"
                                })
                            ]
                        }),
                        /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("div", {
                            children: [
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("label", {
                                    htmlFor: "link",
                                    children: "Link"
                                }),
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                                    name: "link",
                                    placeholder: "Link to application",
                                    validate: (value)=>{
                                        if (!value) {
                                            return "Internship URL is required";
                                        }
                                    }
                                }),
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.ErrorMessage, {
                                    name: "link"
                                })
                            ]
                        }),
                        /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("div", {
                            className: "multiOption",
                            children: [
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("div", {
                                    id: "my-radio-group",
                                    children: "Type"
                                }),
                                /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("div", {
                                    role: "group",
                                    "aria-labelledby": "my-radio-group",
                                    className: "optionDiv",
                                    children: [
                                        /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("label", {
                                            children: [
                                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                                                    type: "radio",
                                                    name: "filters",
                                                    value: "remote"
                                                }),
                                                "Onsite"
                                            ]
                                        }),
                                        /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("label", {
                                            children: [
                                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                                                    type: "radio",
                                                    name: "filters",
                                                    value: "remote"
                                                }),
                                                "Remote"
                                            ]
                                        }),
                                        /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("label", {
                                            children: [
                                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                                                    type: "radio",
                                                    name: "filters",
                                                    value: "hybrid"
                                                }),
                                                "Hybrid"
                                            ]
                                        })
                                    ]
                                })
                            ]
                        }),
                        /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("div", {
                            children: [
                                /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("div", {
                                    children: [
                                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("label", {
                                            htmlFor: "appS",
                                            children: "Application Starts"
                                        }),
                                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                                            name: "appS",
                                            type: "date",
                                            validate: (value)=>{
                                                if (!value) {
                                                    return "Application Start date is required";
                                                }
                                            }
                                        }),
                                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.ErrorMessage, {
                                            name: "appS"
                                        })
                                    ]
                                }),
                                /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("div", {
                                    children: [
                                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("label", {
                                            htmlFor: "appE",
                                            children: "Application Ends"
                                        }),
                                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                                            name: "appE",
                                            type: "date",
                                            validate: (value)=>{
                                                if (!value) {
                                                    return "Application End date is required";
                                                }
                                            }
                                        })
                                    ]
                                })
                            ]
                        }),
                        /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("div", {
                            children: [
                                /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("div", {
                                    children: [
                                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("label", {
                                            htmlFor: "eventS",
                                            children: "Internship Beings"
                                        }),
                                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                                            name: "eventS",
                                            type: "date"
                                        }),
                                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.ErrorMessage, {
                                            name: "eventS"
                                        })
                                    ]
                                }),
                                /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("div", {
                                    children: [
                                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("label", {
                                            htmlFor: "eventE",
                                            children: "Internship Ends"
                                        }),
                                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                                            name: "eventE",
                                            type: "date"
                                        })
                                    ]
                                })
                            ]
                        }),
                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("button", {
                            type: "submit",
                            disabled: isSubmitting,
                            children: "Submit"
                        }),
                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(react_hot_toast__WEBPACK_IMPORTED_MODULE_4__.Toaster, {})
                    ]
                })
        });
    } else {
        return /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Formik, {
            initialValues: {
                eventN: eventData.eventN,
                link: eventData.link,
                appS: eventData.appS,
                appE: eventData.appE,
                eventS: eventData.eventS,
                eventE: eventData.eventE,
                filters: eventData.filters,
                postedBy: eventData.postedBy
            },
            onSubmit: async (values)=>{
                values.postedBy = username;
                values.calID = eventData.calID ? eventData.calID : "";
                react_hot_toast__WEBPACK_IMPORTED_MODULE_4__["default"].loading(`Adding ${values.eventN} for the community`);
                await post("edit", "Grants", values, user);
            },
            children: ({ isSubmitting  })=>/*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)(formik__WEBPACK_IMPORTED_MODULE_3__.Form, {
                    children: [
                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("label", {
                            htmlFor: "eventN",
                            children: "Company"
                        }),
                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                            name: "eventN",
                            placeholder: "",
                            validate: (value)=>{
                                if (!value) {
                                    return "Company title is required";
                                }
                            }
                        }),
                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("label", {
                            htmlFor: "link",
                            children: "Link"
                        }),
                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                            name: "link",
                            placeholder: "hackHar.com",
                            validate: (value)=>{
                                if (!value) {
                                    return "Internship application URL is required";
                                }
                            }
                        }),
                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("div", {
                            id: "my-radio-group",
                            children: "Picked"
                        }),
                        /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("div", {
                            role: "group",
                            "aria-labelledby": "my-radio-group",
                            children: [
                                /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("label", {
                                    children: [
                                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                                            type: "radio",
                                            name: "filters",
                                            value: "onsite"
                                        }),
                                        "Onsite"
                                    ]
                                }),
                                /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("label", {
                                    children: [
                                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                                            type: "radio",
                                            name: "filters",
                                            value: "remote"
                                        }),
                                        "Remote"
                                    ]
                                }),
                                /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("label", {
                                    children: [
                                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                                            type: "radio",
                                            name: "filters",
                                            value: "hybrid"
                                        }),
                                        "Hybrid"
                                    ]
                                })
                            ]
                        }),
                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("label", {
                            htmlFor: "appS",
                            children: "Application Starts"
                        }),
                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                            name: "appS",
                            type: "date",
                            validate: (value)=>{
                                if (!value) {
                                    return "Application Start date is required";
                                }
                            }
                        }),
                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("label", {
                            htmlFor: "appE",
                            children: "Application Ends"
                        }),
                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                            name: "appE",
                            type: "date",
                            validate: (value)=>{
                                if (!value) {
                                    return "Application End date is required";
                                }
                            }
                        }),
                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("label", {
                            htmlFor: "eventS",
                            children: "Hackathon Beings"
                        }),
                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                            name: "eventS",
                            type: "date"
                        }),
                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("label", {
                            htmlFor: "eventE",
                            children: "Hackathon Ends"
                        }),
                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                            name: "eventE",
                            type: "date"
                        }),
                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("button", {
                            type: "submit",
                            disabled: isSubmitting,
                            children: "Submit"
                        }),
                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(react_hot_toast__WEBPACK_IMPORTED_MODULE_4__.Toaster, {})
                    ]
                })
        });
    }
}
function Grants({ eventData  }) {
    const { user , username  } = (0,react__WEBPACK_IMPORTED_MODULE_1__.useContext)(_lib_context__WEBPACK_IMPORTED_MODULE_8__/* .UserContext */ .S);
    if (eventData == null) {
        return /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Formik, {
            initialValues: {
                eventN: "",
                link: "",
                appS: "",
                appE: "",
                filters: "",
                postedBy: ""
            },
            //if edit then set initial values to eventData
            onSubmit: async (values)=>{
                values.postedBy = username;
                react_hot_toast__WEBPACK_IMPORTED_MODULE_4__["default"].loading(`Adding ${values.eventN} for the community`);
                await post("add", "Grants", values, user);
            },
            children: ({ isSubmitting  })=>/*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)(formik__WEBPACK_IMPORTED_MODULE_3__.Form, {
                    children: [
                        /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("div", {
                            children: [
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("label", {
                                    htmlFor: "eventN",
                                    children: "Company"
                                }),
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                                    name: "eventN",
                                    placeholder: "Grant Title",
                                    validate: (value)=>{
                                        if (!value) {
                                            return "Title is required";
                                        }
                                    }
                                }),
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.ErrorMessage, {
                                    name: "eventN"
                                })
                            ]
                        }),
                        /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("div", {
                            children: [
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("label", {
                                    htmlFor: "link",
                                    children: "Link"
                                }),
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                                    name: "link",
                                    placeholder: "Application link",
                                    validate: (value)=>{
                                        if (!value) {
                                            return "Link to application is required";
                                        }
                                    }
                                }),
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.ErrorMessage, {
                                    name: "link"
                                })
                            ]
                        }),
                        /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("div", {
                            className: "multiOption",
                            children: [
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("div", {
                                    id: "my-radio-group",
                                    children: "Type"
                                }),
                                /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("div", {
                                    role: "group",
                                    "aria-labelledby": "my-radio-group",
                                    className: "optionDiv",
                                    children: [
                                        /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("label", {
                                            children: [
                                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                                                    type: "radio",
                                                    name: "filters",
                                                    value: "travel"
                                                }),
                                                "Travel"
                                            ]
                                        }),
                                        /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("label", {
                                            children: [
                                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                                                    type: "radio",
                                                    name: "filters",
                                                    value: "course"
                                                }),
                                                "Course"
                                            ]
                                        }),
                                        /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("label", {
                                            children: [
                                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                                                    type: "radio",
                                                    name: "filters",
                                                    value: "conference"
                                                }),
                                                "Conference"
                                            ]
                                        })
                                    ]
                                })
                            ]
                        }),
                        /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("div", {
                            children: [
                                /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("div", {
                                    children: [
                                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("label", {
                                            htmlFor: "appS",
                                            children: "Application Starts"
                                        }),
                                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                                            name: "appS",
                                            type: "date",
                                            validate: (value)=>{
                                                if (!value) {
                                                    return "Application Start date is required";
                                                }
                                            }
                                        }),
                                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.ErrorMessage, {
                                            name: "appS"
                                        })
                                    ]
                                }),
                                /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("div", {
                                    children: [
                                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("label", {
                                            htmlFor: "appE",
                                            children: "Application Ends"
                                        }),
                                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                                            name: "appE",
                                            type: "date",
                                            validate: (value)=>{
                                                if (!value) {
                                                    return "Application End date is required";
                                                }
                                            }
                                        })
                                    ]
                                })
                            ]
                        }),
                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("button", {
                            type: "submit",
                            disabled: isSubmitting,
                            children: "Submit"
                        }),
                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(react_hot_toast__WEBPACK_IMPORTED_MODULE_4__.Toaster, {})
                    ]
                })
        });
    } else {
        return /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Formik, {
            initialValues: {
                eventN: eventData.eventN,
                link: eventData.link,
                appS: eventData.appS,
                appE: eventData.appE,
                filters: eventData.filters,
                postedBy: eventData.postedBy
            },
            onSubmit: async (values)=>{
                values.postedBy = username;
                values.calID = eventData.calID ? eventData.calID : "";
                react_hot_toast__WEBPACK_IMPORTED_MODULE_4__["default"].loading(`Adding ${values.eventN} for the community`);
                await post("edit", "Grants", values, user);
            },
            children: ({ isSubmitting  })=>/*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)(formik__WEBPACK_IMPORTED_MODULE_3__.Form, {
                    children: [
                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("label", {
                            htmlFor: "eventN",
                            children: "Grant"
                        }),
                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                            name: "eventN",
                            placeholder: "",
                            validate: (value)=>{
                                if (!value) {
                                    return "Grant title is required";
                                }
                            }
                        }),
                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("label", {
                            htmlFor: "link",
                            children: "Link"
                        }),
                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                            name: "link",
                            placeholder: "hackHar.com",
                            validate: (value)=>{
                                if (!value) {
                                    return "Grant application url is required";
                                }
                            }
                        }),
                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("div", {
                            id: "my-radio-group",
                            children: "Picked"
                        }),
                        /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("div", {
                            role: "group",
                            "aria-labelledby": "my-radio-group",
                            children: [
                                /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("label", {
                                    children: [
                                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                                            type: "radio",
                                            name: "filters",
                                            value: "travel"
                                        }),
                                        "Travel"
                                    ]
                                }),
                                /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("label", {
                                    children: [
                                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                                            type: "radio",
                                            name: "filters",
                                            value: "course"
                                        }),
                                        "Course"
                                    ]
                                }),
                                /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("label", {
                                    children: [
                                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                                            type: "radio",
                                            name: "filters",
                                            value: "conference"
                                        }),
                                        "Conference"
                                    ]
                                })
                            ]
                        }),
                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("label", {
                            htmlFor: "appS",
                            children: "Application Starts"
                        }),
                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                            name: "appS",
                            type: "date",
                            validate: (value)=>{
                                if (!value) {
                                    return "Application Start date is required";
                                }
                            }
                        }),
                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("label", {
                            htmlFor: "appE",
                            children: "Application Ends"
                        }),
                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                            name: "appE",
                            type: "date",
                            validate: (value)=>{
                                if (!value) {
                                    return "Application End date is required";
                                }
                            }
                        }),
                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("button", {
                            type: "submit",
                            disabled: isSubmitting,
                            children: "Submit"
                        }),
                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(react_hot_toast__WEBPACK_IMPORTED_MODULE_4__.Toaster, {})
                    ]
                })
        });
    }
}
function Conferences({ eventData  }) {
    const { user , username  } = (0,react__WEBPACK_IMPORTED_MODULE_1__.useContext)(_lib_context__WEBPACK_IMPORTED_MODULE_8__/* .UserContext */ .S);
    if (eventData == null) {
        return /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Formik, {
            initialValues: {
                eventN: "",
                link: "",
                appS: "",
                appE: "",
                eventS: "",
                eventE: "",
                filters: "",
                postedBy: ""
            },
            onSubmit: async (values)=>{
                values.postedBy = username;
                react_hot_toast__WEBPACK_IMPORTED_MODULE_4__["default"].loading(`Adding ${values.eventN} for the community`);
                await post("add", "Conferences", values, user);
            },
            children: ({ isSubmitting  })=>/*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)(formik__WEBPACK_IMPORTED_MODULE_3__.Form, {
                    children: [
                        /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("div", {
                            children: [
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("label", {
                                    htmlFor: "eventN",
                                    children: "Conference Title"
                                }),
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                                    name: "eventN",
                                    placeholder: "Title",
                                    validate: (value)=>{
                                        if (!value) {
                                            return "Conference Title is required";
                                        }
                                    }
                                }),
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.ErrorMessage, {
                                    name: "eventN"
                                })
                            ]
                        }),
                        /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("div", {
                            children: [
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("label", {
                                    htmlFor: "link",
                                    children: "Link"
                                }),
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                                    name: "link",
                                    placeholder: "Conference URL",
                                    validate: (value)=>{
                                        if (!value) {
                                            return "Conference url is required";
                                        }
                                    }
                                }),
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.ErrorMessage, {
                                    name: "link"
                                })
                            ]
                        }),
                        /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("div", {
                            className: "multiOption",
                            children: [
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("div", {
                                    id: "my-radio-group",
                                    children: "Picked "
                                }),
                                /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("div", {
                                    role: "group",
                                    "aria-labelledby": "my-radio-group",
                                    className: "optionDiv",
                                    children: [
                                        /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("label", {
                                            children: [
                                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                                                    type: "radio",
                                                    name: "filters",
                                                    value: "design"
                                                }),
                                                "Design"
                                            ]
                                        }),
                                        /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("label", {
                                            children: [
                                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                                                    type: "radio",
                                                    name: "filters",
                                                    value: "launch event"
                                                }),
                                                "Launch Event"
                                            ]
                                        })
                                    ]
                                })
                            ]
                        }),
                        /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("div", {
                            children: [
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("label", {
                                    htmlFor: "appS",
                                    children: "Registration Starts"
                                }),
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                                    name: "appS",
                                    type: "date",
                                    validate: (value)=>{
                                        if (!value) {
                                            return "Registration Start date is required";
                                        }
                                    }
                                }),
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.ErrorMessage, {
                                    name: "appS"
                                })
                            ]
                        }),
                        /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("div", {
                            children: [
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("label", {
                                    htmlFor: "appE",
                                    children: "Registration Ends"
                                }),
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                                    name: "appE",
                                    type: "date",
                                    validate: (value)=>{
                                        if (!value) {
                                            return "Registration End date is required";
                                        }
                                    }
                                })
                            ]
                        }),
                        /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("div", {
                            children: [
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("label", {
                                    htmlFor: "eventS",
                                    children: "Conference Beings"
                                }),
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                                    name: "eventS",
                                    type: "date"
                                }),
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.ErrorMessage, {
                                    name: "eventS"
                                })
                            ]
                        }),
                        /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("div", {
                            children: [
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("label", {
                                    htmlFor: "eventE",
                                    children: "Conference Ends"
                                }),
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                                    name: "eventE",
                                    type: "date"
                                })
                            ]
                        }),
                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("button", {
                            type: "submit",
                            disabled: isSubmitting,
                            children: "Submit"
                        }),
                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(react_hot_toast__WEBPACK_IMPORTED_MODULE_4__.Toaster, {})
                    ]
                })
        });
    } else {
        return /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Formik, {
            initialValues: {
                eventN: eventData.eventN,
                link: eventData.link,
                appS: eventData.appS,
                appE: eventData.appE,
                eventS: eventData.eventS,
                eventE: eventData.eventE,
                filters: eventData.filters,
                postedBy: eventData.postedBy
            },
            onSubmit: async (values)=>{
                values.postedBy = username;
                values.calID = eventData.calID ? eventData.calID : "";
                react_hot_toast__WEBPACK_IMPORTED_MODULE_4__["default"].loading(`Adding ${values.eventN} for the community`);
                await post("edit", "Conferences", values, user);
            },
            children: ({ isSubmitting  })=>/*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)(formik__WEBPACK_IMPORTED_MODULE_3__.Form, {
                    children: [
                        /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("div", {
                            children: [
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("label", {
                                    htmlFor: "eventN",
                                    children: "Conference Title"
                                }),
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                                    name: "eventN",
                                    placeholder: "Title",
                                    validate: (value)=>{
                                        if (!value) {
                                            return "Conference Title is required";
                                        }
                                    }
                                }),
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.ErrorMessage, {
                                    name: "eventN"
                                })
                            ]
                        }),
                        /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("div", {
                            children: [
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("label", {
                                    htmlFor: "link",
                                    children: "Link"
                                }),
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                                    name: "link",
                                    placeholder: "Conference URL",
                                    validate: (value)=>{
                                        if (!value) {
                                            return "Conference URL is required";
                                        }
                                    }
                                }),
                                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.ErrorMessage, {
                                    name: "link"
                                })
                            ]
                        }),
                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("div", {
                            id: "my-radio-group",
                            children: "Picked"
                        }),
                        /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("div", {
                            role: "group",
                            "aria-labelledby": "my-radio-group",
                            children: [
                                /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("label", {
                                    children: [
                                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                                            type: "radio",
                                            name: "filters",
                                            value: "design"
                                        }),
                                        "Design"
                                    ]
                                }),
                                /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("label", {
                                    children: [
                                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                                            type: "radio",
                                            name: "filters",
                                            value: "launch event"
                                        }),
                                        "Launch Event"
                                    ]
                                })
                            ]
                        }),
                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("label", {
                            htmlFor: "appS",
                            children: "Registration Begins"
                        }),
                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                            name: "appS",
                            type: "date",
                            validate: (value)=>{
                                if (!value) {
                                    return "Application Start date is required";
                                }
                            }
                        }),
                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("label", {
                            htmlFor: "appE",
                            children: "Registration Ends"
                        }),
                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                            name: "appE",
                            type: "date",
                            validate: (value)=>{
                                if (!value) {
                                    return "Application End date is required";
                                }
                            }
                        }),
                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("label", {
                            htmlFor: "eventS",
                            children: "Conference Beings"
                        }),
                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                            name: "eventS",
                            type: "date"
                        }),
                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("label", {
                            htmlFor: "eventE",
                            children: "Conference Ends"
                        }),
                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(formik__WEBPACK_IMPORTED_MODULE_3__.Field, {
                            name: "eventE",
                            type: "date"
                        }),
                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("button", {
                            type: "submit",
                            disabled: isSubmitting,
                            children: "Submit"
                        }),
                        /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(react_hot_toast__WEBPACK_IMPORTED_MODULE_4__.Toaster, {})
                    ]
                })
        });
    }
}
async function post(type, category, values, user, firestoreid) {
    react_hot_toast__WEBPACK_IMPORTED_MODULE_4__["default"].promise(fetch(`/api/${type}/`, {
        method: "POST",
        headers: {
            Authorization: `${user.accessToken}`,
            category: category,
            firestoreid: firestoreid ? firestoreid : "",
            "Content-Type": "application/json"
        },
        body: JSON.stringify(values)
    }).then((response)=>{
        if (response.ok) {
            react_hot_toast__WEBPACK_IMPORTED_MODULE_4__["default"].dismiss();
            react_hot_toast__WEBPACK_IMPORTED_MODULE_4__["default"].success(`${values.eventN} Added`);
            react_hot_toast__WEBPACK_IMPORTED_MODULE_4__["default"].success(`Thanks for your contribution ${values.postedBy}`);
        } else {
            if (response.status == 401) {
                react_hot_toast__WEBPACK_IMPORTED_MODULE_4__["default"].dismiss();
                react_hot_toast__WEBPACK_IMPORTED_MODULE_4__["default"].success(`${values.eventN} Updated`);
            } else {
                react_hot_toast__WEBPACK_IMPORTED_MODULE_4__["default"].dismiss();
                react_hot_toast__WEBPACK_IMPORTED_MODULE_4__["default"].error(`Error occurred while adding ${values.eventN}`);
            }
        }
    }));
} //Event DS
 /*
    eventN: '',
    link: '',
    appS: '',
    appE: '',
    eventS: '',
    eventE: '',
    filters: '',
    postedBy: '',
*/  //validation schema
 /*
const hackathonValidationSchema = Yup.object({
    eventN: Yup.string().min(4, 'Too short').max(30, 'Hackathon Name only').required('Event name is required'),
    link: Yup.string().min(3, 'Shorten URLs not allowed').max(60, 'Hackathon HomePage Link only').url('Please only homepage link'),
    appS: Yup.date().required('Application start date is required'),
    appE: Yup.date(),
    eventS: Yup.date(),
    eventE: Yup.date(),
    filters: Yup.string(),
    postedBy: Yup.string().required('Posted by is required')
});
*/ 

__webpack_async_result__();
} catch(e) { __webpack_async_result__(e); } });

/***/ }),

/***/ 7274:
/***/ ((module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.a(module, async (__webpack_handle_async_dependencies__, __webpack_async_result__) => { try {
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "Z": () => (/* binding */ ModalButton)
/* harmony export */ });
/* harmony import */ var react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(997);
/* harmony import */ var react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__);
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(6689);
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_1___default = /*#__PURE__*/__webpack_require__.n(react__WEBPACK_IMPORTED_MODULE_1__);
/* harmony import */ var react_responsive_modal_styles_css__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(4602);
/* harmony import */ var react_responsive_modal_styles_css__WEBPACK_IMPORTED_MODULE_2___default = /*#__PURE__*/__webpack_require__.n(react_responsive_modal_styles_css__WEBPACK_IMPORTED_MODULE_2__);
/* harmony import */ var react_responsive_modal__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(3069);
/* harmony import */ var react_responsive_modal__WEBPACK_IMPORTED_MODULE_3___default = /*#__PURE__*/__webpack_require__.n(react_responsive_modal__WEBPACK_IMPORTED_MODULE_3__);
/* harmony import */ var _Form__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(7885);
/* harmony import */ var _atoms__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(8104);
/* harmony import */ var jotai__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(2451);
/* harmony import */ var next_router__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(1853);
/* harmony import */ var next_router__WEBPACK_IMPORTED_MODULE_7___default = /*#__PURE__*/__webpack_require__.n(next_router__WEBPACK_IMPORTED_MODULE_7__);
/* harmony import */ var _lib_context__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(8059);
var __webpack_async_dependencies__ = __webpack_handle_async_dependencies__([_Form__WEBPACK_IMPORTED_MODULE_4__, _atoms__WEBPACK_IMPORTED_MODULE_5__, jotai__WEBPACK_IMPORTED_MODULE_6__]);
([_Form__WEBPACK_IMPORTED_MODULE_4__, _atoms__WEBPACK_IMPORTED_MODULE_5__, jotai__WEBPACK_IMPORTED_MODULE_6__] = __webpack_async_dependencies__.then ? (await __webpack_async_dependencies__)() : __webpack_async_dependencies__);










function ModalButton({ eventData  }) {
    const { user , username  } = (0,react__WEBPACK_IMPORTED_MODULE_1__.useContext)(_lib_context__WEBPACK_IMPORTED_MODULE_8__/* .UserContext */ .S);
    const router = (0,next_router__WEBPACK_IMPORTED_MODULE_7__.useRouter)();
    const [open, setOpen] = (0,react__WEBPACK_IMPORTED_MODULE_1__.useState)(false);
    const onOpenModal = ()=>{
        if (!username) {
            router.push("/enter");
            return;
        } else {
            setOpen(true);
        }
        ;
    };
    const onCloseModal = ()=>setOpen(false);
    const [category] = (0,jotai__WEBPACK_IMPORTED_MODULE_6__.useAtom)(_atoms__WEBPACK_IMPORTED_MODULE_5__/* .categoriesAtom */ .m9);
    if (eventData != null) {
        return /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("div", {
            children: [
                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("button", {
                    onClick: onOpenModal,
                    children: "Update " + eventData.eventN
                }),
                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(react_responsive_modal__WEBPACK_IMPORTED_MODULE_3__.Modal, {
                    open: open,
                    onClose: onCloseModal,
                    center: true,
                    children: /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(_Form__WEBPACK_IMPORTED_MODULE_4__/* .Customform */ .G, {
                        eventData: eventData,
                        categoryTest: category
                    })
                })
            ]
        });
    } else {
        return /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("div", {
            children: [
                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("button", {
                    onClick: onOpenModal,
                    children: "Add Opp"
                }),
                /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(react_responsive_modal__WEBPACK_IMPORTED_MODULE_3__.Modal, {
                    open: open,
                    onClose: onCloseModal,
                    center: true,
                    children: /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(_Form__WEBPACK_IMPORTED_MODULE_4__/* .MyFormComponent */ .x, {
                        eventData: eventData
                    })
                })
            ]
        });
    }
}
;

__webpack_async_result__();
} catch(e) { __webpack_async_result__(e); } });

/***/ }),

/***/ 8104:
/***/ ((module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.a(module, async (__webpack_handle_async_dependencies__, __webpack_async_result__) => { try {
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "Tq": () => (/* binding */ filterAtom),
/* harmony export */   "m9": () => (/* binding */ categoriesAtom)
/* harmony export */ });
/* unused harmony exports textAtom, incrementAtom, updateCategoryAtom, updateFilterAtom */
/* harmony import */ var jotai__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(2451);
var __webpack_async_dependencies__ = __webpack_handle_async_dependencies__([jotai__WEBPACK_IMPORTED_MODULE_0__]);
jotai__WEBPACK_IMPORTED_MODULE_0__ = (__webpack_async_dependencies__.then ? (await __webpack_async_dependencies__)() : __webpack_async_dependencies__)[0];

const textAtom = (0,jotai__WEBPACK_IMPORTED_MODULE_0__.atom)("hello");
const incrementAtom = (0,jotai__WEBPACK_IMPORTED_MODULE_0__.atom)((get)=>get(textAtom), (get, set, arg)=>set(textAtom, arg));
const categoriesAtom = (0,jotai__WEBPACK_IMPORTED_MODULE_0__.atom)("hackathon");
const updateCategoryAtom = (0,jotai__WEBPACK_IMPORTED_MODULE_0__.atom)((get)=>get(textAtom), (get, set, arg)=>set(textAtom, arg));
const filterAtom = (0,jotai__WEBPACK_IMPORTED_MODULE_0__.atom)("all");
const updateFilterAtom = (0,jotai__WEBPACK_IMPORTED_MODULE_0__.atom)((get)=>get(textAtom), (get, set, arg)=>set(textAtom, arg));

__webpack_async_result__();
} catch(e) { __webpack_async_result__(e); } });

/***/ }),

/***/ 4602:
/***/ (() => {



/***/ })

};
;