var NamecoinModule = "namecoin_module"
var logname = "NCTLS:"

function notify(message) {
    browser.notifications.create("NamecoinTLS", {
        "type": "basic",
	"iconUrl": browser.extension.getURL("icons/namecoin-coin_100px.png"),
        "title": "Namecoin TLS",
        "message": message,
    })
    console.log(logname, message);
}

browser.runtime.onMessage.addListener(notify)

// based on https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/pkcs11/installModule

function onInstalled() {
	  return browser.pkcs11.getModuleSlots(NamecoinModule);
}

function onGotSlots(slots) {
    for (slot of slots) {
        console.log(logname, `Slot: ${slot.name}`);
	if (slot.token) {
		  console.log(logname, `Module Contains token: ${slot.token.name}`);
	} else {
		 console.log(logname, 'Module is empty');
	}
    }
}

function notifysuccess(){
	notify("Successfully loaded")
	return 0;
}

// install the module
//
// this doesnt work i think?
browser.pkcs11.installModule(NamecoinModule)
.then(onInstalled)
//.then(onGotSlots)
.then(notifysuccess);
notify("NamecoinTLS PKCS#11 module active");

// on click icon
browserAction.onClicked.addListener(notifysuccess);
