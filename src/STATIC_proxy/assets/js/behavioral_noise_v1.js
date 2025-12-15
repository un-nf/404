/* STATIC Proxy Behavioral Noise Layer v1 (AGPL-3.0) */
;(function () {
  if (window.__STATIC_BEHAVIOR_ENGINE__) {
    return;
  }

  if (window.__STATIC_BEHAVIOR_ENABLED !== true) {
    window.__STATIC_BEHAVIOR_ENGINE__ = false;
    return;
  }

  const NOISE_NAMESPACE = "__static_behavioral";
  const BUFFER = [];
  const CHANNELS = Object.freeze({ fetch: "fetch", xhr: "xhr", beacon: "beacon", ws: "websocket" });

  function now() {
    return typeof performance !== "undefined" ? performance.now() : Date.now();
  }

  function pushSynthetic(event) {
    BUFFER.push({
      ...event,
      ts: event.ts || now(),
      source: "behavioral-noise",
    });
  }

  function drainNoise(maxItems) {
    if (!BUFFER.length) {
      return [];
    }
    if (!maxItems || maxItems >= BUFFER.length) {
      return BUFFER.splice(0, BUFFER.length);
    }
    return BUFFER.splice(0, maxItems);
  }

  function looksJson(text) {
    if (typeof text !== "string") {
      return false;
    }
    const trimmed = text.trim();
    if (!trimmed.length) {
      return false;
    }
    const first = trimmed[0];
    return first === "{" || first === "[";
  }

  function serializePayload(payload) {
    if (payload == null) {
      return null;
    }

    if (typeof payload === "string" || payload instanceof String) {
      return payload.toString();
    }

    if (
      typeof ArrayBuffer !== "undefined" &&
      (payload instanceof ArrayBuffer || (typeof ArrayBuffer.isView === "function" && ArrayBuffer.isView(payload)))
    ) {
      return null;
    }

    if (typeof Blob !== "undefined" && payload instanceof Blob) {
      return null;
    }

    if (typeof FormData !== "undefined" && payload instanceof FormData) {
      return null;
    }

    if (typeof URLSearchParams !== "undefined" && payload instanceof URLSearchParams) {
      return null;
    }

    if (payload && typeof payload === "object") {
      try {
        return JSON.stringify(payload);
      } catch (err) {
        console.warn("behavioral payload serialization failed", err);
        return null;
      }
    }

    return null;
  }

  function wrapPayload(channel, originalPayload) {
    const serialized = serializePayload(originalPayload);
    if (!serialized || !looksJson(serialized)) {
      return originalPayload;
    }

    return JSON.stringify({
      [NOISE_NAMESPACE]: true,
      channel,
      issued_at: now(),
      original: serialized,
      noise: drainNoise(32),
    });
  }

  function markInit() {
    if (!window.__STATIC_BEHAVIOR) {
      window.__STATIC_BEHAVIOR = {
        queue: BUFFER,
        channels: CHANNELS,
        pushSynthetic,
        wrapPayload,
      };
    }
  }

  function patchFetch() {
    if (typeof window.fetch !== "function") {
      return;
    }
    const original = window.fetch.bind(window);
    window.fetch = function patchedFetch(input, init = {}) {
      try {
        if (init && init.body && shouldAnnotate(input)) {
          init.body = wrapPayload(CHANNELS.fetch, init.body);
        }
      } catch (err) {
        console.warn("behavioral fetch wrap failed", err);
      }
      return original(input, init);
    };
  }

  function patchBeacon() {
    if (typeof navigator === "undefined" || typeof navigator.sendBeacon !== "function") {
      return;
    }
    const original = navigator.sendBeacon.bind(navigator);
    navigator.sendBeacon = function patchedBeacon(url, data) {
      let payload = data;
      try {
        if (data && shouldAnnotate(url)) {
          payload = wrapPayload(CHANNELS.beacon, data);
        }
      } catch (err) {
        console.warn("behavioral beacon wrap failed", err);
      }
      return original(url, payload);
    };
  }

  function patchXHR() {
    if (typeof window.XMLHttpRequest !== "function") {
      return;
    }
    const send = window.XMLHttpRequest.prototype.send;
    window.XMLHttpRequest.prototype.send = function patchedSend(body) {
      let payload = body;
      try {
        if (body && shouldAnnotate(this.responseURL || this.__url)) {
          payload = wrapPayload(CHANNELS.xhr, body);
        }
      } catch (err) {
        console.warn("behavioral xhr wrap failed", err);
      }
      return send.call(this, payload);
    };
    const open = window.XMLHttpRequest.prototype.open;
    window.XMLHttpRequest.prototype.open = function patchedOpen(method, url) {
      this.__url = url;
      return open.apply(this, arguments);
    };
  }

  function patchWebSocket() {
    if (typeof window.WebSocket !== "function") {
      return;
    }
    const OriginalWS = window.WebSocket;
    function WrappedWS(url, protocols) {
      const ws = new OriginalWS(url, protocols);
      const originalSend = ws.send.bind(ws);
      ws.send = function patchedSend(data) {
        let payload = data;
        try {
          if (typeof data === "string" && shouldAnnotate(url)) {
            payload = wrapPayload(CHANNELS.ws, data);
          }
        } catch (err) {
          console.warn("behavioral ws wrap failed", err);
        }
        return originalSend(payload);
      };
      return ws;
    }
    WrappedWS.prototype = OriginalWS.prototype;
    window.WebSocket = WrappedWS;
  }

  function shouldAnnotate(target) {
    if (!target) {
      return false;
    }
    try {
      const url = typeof target === "string" ? new URL(target, window.location.href) : new URL(target.url || target.href);
      return /analytics|telemetry|events|collect|pixel/i.test(url.pathname);
    } catch (_) {
      return false;
    }
  }

  function seedIdleNoise() {
    const seeds = 5 + Math.floor(Math.random() * 4);
    for (let i = 0; i < seeds; i += 1) {
      pushSynthetic({
        type: "idle",
        duration: 300 + Math.random() * 900,
        fidelity: Math.random(),
      });
    }
  }

  function boot() {
    markInit();
    patchFetch();
    patchBeacon();
    patchXHR();
    patchWebSocket();
    seedIdleNoise();
  }

  try {
    boot();
    window.__STATIC_BEHAVIOR_ENGINE__ = true;
  } catch (err) {
    console.error("behavioral engine failed to bootstrap", err);
  }
})();
