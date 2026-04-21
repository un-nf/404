import { getRuntime } from './guard.js'

export function captureNativeRefs() {
  const runtime = getRuntime()
  const canvasPrototype = window.HTMLCanvasElement?.prototype || null
  const canvas2dPrototype = window.CanvasRenderingContext2D?.prototype || null
  const offscreenPrototype = window.OffscreenCanvas?.prototype || null
  const peerPrototype = window.RTCPeerConnection?.prototype || window.webkitRTCPeerConnection?.prototype || null
  const offlineAudioPrototype = window.OfflineAudioContext?.prototype || window.webkitOfflineAudioContext?.prototype || null
  const baseAudioPrototype = window.BaseAudioContext?.prototype || window.AudioContext?.prototype || window.webkitAudioContext?.prototype || null
  const audioDestinationPrototype = window.AudioDestinationNode?.prototype || null
  const analyserPrototype = window.AnalyserNode?.prototype || null
  const audioWorkletPrototype = window.AudioWorkletNode?.prototype || null
  const xhrPrototype = window.XMLHttpRequest?.prototype || null
  const eventPrototype = window.Event?.prototype || null
  const mediaDevicesPrototype = navigator.mediaDevices ? Object.getPrototypeOf(navigator.mediaDevices) : null
  const mediaStreamPrototype = window.MediaStream?.prototype || null
  const mediaStreamTrackPrototype = window.MediaStreamTrack?.prototype || null
  const speechSynthesisPrototype = window.speechSynthesis ? Object.getPrototypeOf(window.speechSynthesis) : null
  const htmlElementPrototype = window.HTMLElement?.prototype || null
  runtime.nativeRefs = {
    defineProperty: Object.defineProperty.bind(Object),
    getOwnPropertyDescriptor: Object.getOwnPropertyDescriptor.bind(Object),
    getOwnPropertyNames: Object.getOwnPropertyNames.bind(Object),
    getPrototypeOf: Object.getPrototypeOf.bind(Object),
    setPrototypeOf: Object.setPrototypeOf.bind(Object),
    functionToString: Function.prototype.toString,
    navigator: window.navigator,
    NavigatorPrototype: Object.getPrototypeOf(window.navigator),
    screen: window.screen,
    ScreenPrototype: Object.getPrototypeOf(window.screen),
    performance: window.performance,
    performanceNow: window.performance.now.bind(window.performance),
    dateGetTimezoneOffset: Date.prototype.getTimezoneOffset,
    intlDateTimeFormat: Intl.DateTimeFormat,
    documentHasFocus: Document.prototype.hasFocus,
    HTMLElementPrototype: htmlElementPrototype,
    fetch: typeof window.fetch === 'function' ? window.fetch.bind(window) : null,
    sendBeacon: typeof navigator.sendBeacon === 'function' ? navigator.sendBeacon.bind(navigator) : null,
    mediaDevices: navigator.mediaDevices || null,
    mediaDevicesPrototype,
    enumerateDevices: typeof navigator.mediaDevices?.enumerateDevices === 'function'
      ? navigator.mediaDevices.enumerateDevices.bind(navigator.mediaDevices)
      : null,
    getUserMedia: typeof navigator.mediaDevices?.getUserMedia === 'function'
      ? navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices)
      : null,
    MediaStream: window.MediaStream || null,
    mediaStreamPrototype,
    mediaStreamGetTracks: typeof mediaStreamPrototype?.getTracks === 'function'
      ? mediaStreamPrototype.getTracks
      : null,
    mediaStreamGetAudioTracks: typeof mediaStreamPrototype?.getAudioTracks === 'function'
      ? mediaStreamPrototype.getAudioTracks
      : null,
    mediaStreamGetVideoTracks: typeof mediaStreamPrototype?.getVideoTracks === 'function'
      ? mediaStreamPrototype.getVideoTracks
      : null,
    MediaStreamTrack: window.MediaStreamTrack || null,
    mediaStreamTrackPrototype,
    mediaStreamTrackLabelDescriptor: mediaStreamTrackPrototype
      ? Object.getOwnPropertyDescriptor(mediaStreamTrackPrototype, 'label')
      : null,
    speechSynthesisGetVoices: typeof window.speechSynthesis?.getVoices === 'function'
      ? window.speechSynthesis.getVoices.bind(window.speechSynthesis)
      : null,
    speechSynthesisPrototype,
    getGamepads: typeof navigator.getGamepads === 'function' ? navigator.getGamepads.bind(navigator) : null,
    mutationObserver: window.MutationObserver,
    response: window.Response,
    request: window.Request,
    canvasPrototype,
    canvasGetContext: typeof canvasPrototype?.getContext === 'function' ? canvasPrototype.getContext : null,
    canvasToDataURL: typeof canvasPrototype?.toDataURL === 'function' ? canvasPrototype.toDataURL : null,
    canvasToBlob: typeof canvasPrototype?.toBlob === 'function' ? canvasPrototype.toBlob : null,
    canvas2dPrototype,
    canvasGetImageData: typeof canvas2dPrototype?.getImageData === 'function' ? canvas2dPrototype.getImageData : null,
    canvasPutImageData: typeof canvas2dPrototype?.putImageData === 'function' ? canvas2dPrototype.putImageData : null,
    offscreenCanvas: window.OffscreenCanvas || null,
    offscreenPrototype,
    offscreenGetContext: typeof offscreenPrototype?.getContext === 'function' ? offscreenPrototype.getContext : null,
    offscreenConvertToBlob: typeof offscreenPrototype?.convertToBlob === 'function' ? offscreenPrototype.convertToBlob : null,
    offscreenTransferToImageBitmap: typeof offscreenPrototype?.transferToImageBitmap === 'function' ? offscreenPrototype.transferToImageBitmap : null,
    createImageBitmap: typeof window.createImageBitmap === 'function' ? window.createImageBitmap.bind(window) : null,
    WebGLRenderingContext: window.WebGLRenderingContext || null,
    WebGL2RenderingContext: window.WebGL2RenderingContext || null,
    RTCPeerConnection: window.RTCPeerConnection || window.webkitRTCPeerConnection || null,
    RTCIceCandidate: window.RTCIceCandidate || null,
    RTCSessionDescription: window.RTCSessionDescription || null,
    peerPrototype,
    peerAddEventListener: typeof peerPrototype?.addEventListener === 'function' ? peerPrototype.addEventListener : null,
    peerRemoveEventListener: typeof peerPrototype?.removeEventListener === 'function' ? peerPrototype.removeEventListener : null,
    peerSetLocalDescription: typeof peerPrototype?.setLocalDescription === 'function' ? peerPrototype.setLocalDescription : null,
    peerCreateOffer: typeof peerPrototype?.createOffer === 'function' ? peerPrototype.createOffer : null,
    peerCreateAnswer: typeof peerPrototype?.createAnswer === 'function' ? peerPrototype.createAnswer : null,
    OfflineAudioContext: window.OfflineAudioContext || window.webkitOfflineAudioContext || null,
    offlineAudioPrototype,
    offlineStartRendering: typeof offlineAudioPrototype?.startRendering === 'function' ? offlineAudioPrototype.startRendering : null,
    BaseAudioContext: window.BaseAudioContext || window.AudioContext || window.webkitAudioContext || null,
    baseAudioPrototype,
    audioDestinationPrototype,
    baseCreateOscillator: typeof baseAudioPrototype?.createOscillator === 'function' ? baseAudioPrototype.createOscillator : null,
    AnalyserNode: window.AnalyserNode || null,
    analyserPrototype,
    analyserGetFloatFrequencyData: typeof analyserPrototype?.getFloatFrequencyData === 'function' ? analyserPrototype.getFloatFrequencyData : null,
    AudioWorkletNode: window.AudioWorkletNode || null,
    audioWorkletPrototype,
    speechSynthesis: window.speechSynthesis || null,
    XMLHttpRequest: window.XMLHttpRequest || null,
    xhrPrototype,
    xhrOpen: typeof xhrPrototype?.open === 'function' ? xhrPrototype.open : null,
    xhrSend: typeof xhrPrototype?.send === 'function' ? xhrPrototype.send : null,
    WebSocket: window.WebSocket || null,
    Event: window.Event || null,
    eventPrototype,
    eventTimeStampDescriptor: eventPrototype ? Object.getOwnPropertyDescriptor(eventPrototype, 'timeStamp') : null,
  }
}