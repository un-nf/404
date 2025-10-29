# 404 v.01
Privacy tool.
**We are not a VPN. We do *not* log, track, collect, or *touch* any of your data. We do not route your traffic anywhere. We host no network infrastructure. Your machine does all the work. We do not hide your data. We do not offer Onion routing. We are not affiliated with the Tor Project.**

## Quick consent & warning
By running this software you accept and understand that:
- The proxy decrypts HTTPS for rewriting/testing. It can see ***passwords*** and ***session tokens***.
- You will not use your primary accounts.
- You will not share your CA certificate with anyone.
- This is research software - no warranty, no guarantees, minimal support, 
- If you find a security issue report it to 404mesh@proton.me

## How do I install and run this on my machine?

As of now, the only requirement is `mitmproxy` (and thus, a compatible `Python` version).

#### 1. Install venv

venv installation (WINDOWS):
In 404 directory:

```cmd
> python -m venv <venv_name>
> .\venv\Scripts\activate
> pip install mitmproxy
```

venv installation (MacOS):
In 404 directory:

```bash
$ python3 -m venv <venv_name>
$ source <venv_name>/bin/activate
$ pip install mitmproxy
```

*Configure your browser (or machine) to use localhost:8080 (127.0.0.1:8080) as an HTTP/S proxy.*
***Important:*** **This tool is a TLS-terminating proxy (man-in-the-middle) and has access to your plaintext HTTPS data (usernames, passwords, certain message protocols, etc.) do NOT share your CA cert with *anyone* for *anything, ever*.**

#### 2. Install mitmproxy CA cert

On CLIENT (Windows Command Prompt/MacOS Terminal):
Choose mitmproxy method:
- `mitmproxy` # interactive CLI
- `mitmdump`  # headless
- `mitmweb`   # web UI

1. 
```bash
$ mitmproxy
```
2. In browser, navigate to https://mitm.it - Follow instructions to install CA cert
3. Close original mitmproxy instance and run

```bash
$ mitmproxy -s header_profile.py <args>

# All mitmproxy CLI rules apply.
# Documentation @ https://docs.mitmproxy.org/stable/
```

**Note: FireFox works much better.**
*During preliminary tests, certain login flows in Chrome/Chromium browsers broke. This breakage is not due to mismatching headers (that I can tell), as login flows still do not work when spoofing a Chrome profile.*

*Login flows on FireFox are much more stable for reasons that are not clear to me. Would love some insight.*

## Why should I install and run this on my machine?

*lol*

Genuinely, it's hard for me to give you a reason in this state. 

One reason: it's interesting. This proxy allows you to experiment with browser-visible fingerprint mutation. Client identification is getting scary precise and the public does not have the tools to remain private with implementations of policies like Chat Control. 

A small win, I am getting consistent values from the following fingerprinting websites: 
1. https://amiunique.org/
2. https://browserleaks.com/
3. https://coveryourtracks.eff.org/
4. https://whatismybrowser.com/

## Why *shouldn't* I install and run this on my machine?

If you do not understand JavaScript, or if you don't take the time to look through the code, there is almost no point in you downloading this proxy. The point of this is not to be a privacy proxy. **Not yet.** This repository, in its current state, is experimental and intended only for educational, research, and development purposes. 

### Things will break

Routing your traffic through this proxy now means your browser *will* break. Chrome most certainly does not like it when you route traffic through this proxy. As mentioned earlier, FireFox is much more forgiving.

Your web page will look... strange. Most sites *will* be readable, but if the server thinks it's talking to FireFox, your Chrome page will not load 100% properly. Again, breakage is much less frequent in FireFox. Experimenting witn the JavaScript for canvas/webGL may improve functionality.

I do not know the long term effects on account usage. I have been logging-in via this proxy using my personal Google, Microsoft, and Apple accounts and have experienced no retaliation (bans and whatnot). That is *not* to say you will have the same experience. **I *strongly* recommend that you use alternate/disposable accounts if you're going to be testing OAuth or other login flows.**

I am not a cybersecurity engineer. I hammered this together and may have missed something important. Feel free to reach out with security vulnerabilities @ 404mesh@proton.me

## The dream