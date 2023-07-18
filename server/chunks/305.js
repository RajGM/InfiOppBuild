"use strict";
exports.id = 305;
exports.ids = [305];
exports.modules = {

/***/ 5305:
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "addCalendarEvent": () => (/* binding */ addCalendarEvent),
/* harmony export */   "editCalendarEvent": () => (/* binding */ editCalendarEvent)
/* harmony export */ });
const { google  } = __webpack_require__(9993);
const nameToCalID = {
    "Hackathon": "759d718fecf97c35ed0e8962a893d7a35af08c700458908baa458c87c80ca2c5@group.calendar.google.com",
    "Grants": "60b02992409cbd6122c3d7d129b0c963b5214e26cb36ef9faf3d522305645b4c@group.calendar.google.com",
    "Conferences": "7d6a6c2b83c91541e36590cb712f54c087cc15a29c42e9e10db07397e4e9069f@group.calendar.google.com",
    "Internship": "6588c33175b4ef8668d114b267979a361be4cd69816361b730312e3d3f416965@group.calendar.google.com"
};
const auth = new google.auth.GoogleAuth({
    credentials: data,
    scopes: [
        "https://www.googleapis.com/auth/calendar"
    ]
});
const calendar = google.calendar({
    version: "v3",
    auth: auth
});
async function addCalendarEvent(title, url, applicationStarts, applicationEnds, category) {
    const calIDbyName = nameToCalID[category];
    const calID = await calendar.events.insert({
        calendarId: calIDbyName,
        resource: {
            summary: title,
            "location": url,
            "description": "Hackathon",
            start: {
                dateTime: `${applicationStarts}T00:00:00-00:00`,
                timeZone: "Asia/Kolkata"
            },
            end: {
                dateTime: `${applicationEnds}T00:00:00-00:00`,
                timeZone: "Asia/Kolkata"
            }
        }
    }).then((res)=>{
        return res.data.id;
    }).catch((err)=>{
        return err;
    });
    return calID;
}
async function editCalendarEvent(id, title, url, applicationStarts, applicationEnds, category) {
    const calIDbyName = nameToCalID[category];
    const response = await calendar.events.update({
        calendarId: calIDbyName,
        eventId: id,
        resource: {
            summary: title,
            "location": url,
            "description": "Hackathon",
            start: {
                dateTime: `${applicationStarts}T00:00:00-00:00`,
                timeZone: "Asia/Kolkata"
            },
            end: {
                dateTime: `${applicationEnds}T00:00:00-00:00`,
                timeZone: "Asia/Kolkata"
            }
        }
    }).then((res)=>{
        return res.data;
    }).catch((err)=>{
        return err;
    });
    return response.id;
}


/***/ })

};
;