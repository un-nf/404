---
name: Bug Report
about: Report a reproducible issue with 404
title: '[BUG] '
labels: bug
---

## 404 Version

```
PUT YOUR COMMIT HASH OR VERSION TAG HERE
```

## Environment

**Host OS**: 
<!-- e.g., Windows 11, macOS 14.2, Ubuntu 22.04 -->

**Python version**: 
<!-- e.g., 3.11.5 -->

**mitmproxy version**: 
<!-- e.g., 10.1.1 -->

**Browser**: 
<!-- e.g., Firefox 120, Chrome 119 -->

**Profile used**: 
<!-- e.g., windows_chrome, macos_safari, or path to custom profile -->

**VM/eBPF in use?**
<!-- yes/no. If yes: VM OS and kernel version -->

## Expected Behavior

<!-- What were you trying to do? What should have happened? -->

## Actual Behavior

<!-- What went wrong? -->

## Steps to Reproduce

1. **Proxy command**: 
   <!-- e.g., mitmproxy -s header_profile.py --set profile=windows_chrome -->

2. **Target site**: 
   <!-- e.g., accounts.google.com, twitter.com -->

3. **Action taken**: 
   <!-- e.g., attempted login, clicked button, loaded page -->

4. **Result**: 
   <!-- error message, crash, incorrect behavior -->

## How often does this happen?

- [ ] Always

- [ ] Sometimes

- [ ] Only on specific sites
  <!-- List which sites -->

## When did it start?

- [ ] After upgrading
  <!-- Which version/commit did you upgrade from? -->

- [ ] After changing config
  <!-- What did you change? -->

- [ ] First time trying 404

## Logs

**mitmproxy output** (sanitize sensitive data):
```
PASTE RELEVANT MITMPROXY LOGS HERE
```

**Browser console errors** (F12 → Console):
```
PASTE BROWSER CONSOLE OUTPUT HERE
```

**Python traceback** (if applicable):
```
PASTE TRACEBACK HERE
```

## Traffic Sample

<!-- If relevant, attach a sanitized .har file or pcap. REMOVE COOKIES, TOKENS, PASSWORDS. -->

## Additional Context

- Does this happen with all profiles or just one?
- Does it work without the proxy?
- Any custom mitmproxy scripts or modifications?
- Multiple browser windows/tabs open?
