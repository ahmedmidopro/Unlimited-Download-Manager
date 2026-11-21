# Browser integration (no store)

UDM prepares the extension locally and guides the user: **Browser Integration** (main item in the left sidebar).
The page shows, per browser: browser detected, extension Installed / Not Installed, connection Connected / Disconnected, and native host status.

| Browser | What UDM can do | What the browser forces the user to do |
|---|---|---|
| Chrome / Brave / Edge | Writes the extension to `%USERPROFILE%\.udm\extensions\<browser>`, registers the Native Messaging host, opens the extensions page and the folder, verifies the link | Turn on Developer mode and click "Load unpacked" once (Chrome 137+ removed `--load-extension`; there is no silent install outside the stores) |
| Firefox (Release/Beta) | Same, plus a signed .xpi if the build has one | Unsigned add-ons are temporary only. Permanent = signed .xpi (optional CI step, needs AMO API keys in repository secrets AMO_JWT_ISSUER / AMO_JWT_SECRET) |
| Firefox Developer Edition / Nightly / ESR | Same | Set `xpinstall.signatures.required=false`, then install udm-firefox.xpi |

Native Messaging: `udm-host.exe` is registered under HKCU by the installer (`UDM.exe --register-native`) and again at every start of UDM.
The extension tries Native Messaging first and falls back to the local HTTP port.
