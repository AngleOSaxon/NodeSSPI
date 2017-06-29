var addon = require('../native');
var http = require('http');


// exports.makeRequest = () => {
//     let context = addon.initializeSecurityContext("Negotiate", "HTTP/win-5knflpj2ucf");
    
//     let options = {
//         host: "win-5knflpj2ucf",
//         port: "8080",
//         headers: {
//             "Authorization": `Negotiate ${context.token}`
//         }
//     };

//     http.get(options, () => {
//         console.log("Request successful?");
//         addon.cleanup(context);
//     });
// }

exports.getToken = (authType, spn) => {
    return addon.initializeSecurityContext(authType, spn);
}

exports.cleanup = (token) => {
    addon.cleanup(token);
}