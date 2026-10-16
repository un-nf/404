import { arraySome, arrayMap, stringSplit, stringStartsWith, stringLower, stringTrim, includes, regexpTest, iterate, NumberIntrinsic as Number } from './primordials.js'

export function validateSemantics(fp) {
    if(fp.webrtc_observation_policy==='preserve-relay-routing'&&fp.webrtc_transport_policy!=='relay-only')throw new TypeError('STATIC relay routing observations require relay-only transport');
  if (!arraySome(['browser_variant', 'profile_variant', 'browser_type'], key => typeof fp[key] === 'string' && fp[key]))
    throw new TypeError('STATIC browser variant required')
  const ua = fp.user_agent || '', platform = fp.platform || ''
  validateIdentity(fp)
  if (includes(ua, 'Windows') && !stringStartsWith(platform, 'Win') || includes(ua, 'Mac OS X') && platform !== 'MacIntel')
    throw new TypeError('STATIC UA/platform contradiction')
  const [width, height] = arrayMap(stringSplit(fp.screen_resolution || '1920x1080', 'x'), Number)
  if ((fp.screen_avail_width ?? width) > width || (fp.screen_avail_height ?? height) > height)
    throw new TypeError('STATIC available screen exceeds screen dimensions')
  const audio = fp.audio_context
  if (audio && (audio.channel_count ?? 0) > (audio.max_channel_count ?? 32))
    throw new TypeError('STATIC audio channels exceed destination maximum')
  for(const axis of iterate(['width','height']))if(fp.enable_viewport_spoof&&fp['window_inner_'+axis]!==undefined&&fp['window_outer_'+axis]!==undefined&&fp['window_inner_'+axis]>fp['window_outer_'+axis])throw new TypeError('STATIC inner window exceeds outer dimensions')
}
function versionMajor(value){if(typeof value!=='string'||!regexpTest(/^\d+(?:\.\d+){0,3}$/,value))throw new TypeError('STATIC invalid version');const parts=stringSplit(value,'.');if(arraySome(parts,part=>!Number.isSafeInteger(Number(part))||Number(part)>4294967295))throw new TypeError('STATIC invalid version component');return Number(parts[0]);}
function tokenMajor(ua,token){const parts=stringSplit(ua,token);if(parts.length<2)return undefined;return versionMajor(stringSplit(parts[1],' ')[0]);}
function validateIdentity(fp){
  const variant=stringLower(stringTrim(fp.browser_variant||fp.profile_variant||fp.browser_type)),ua=fp.user_agent||'';
  const engine=tokenMajor(ua,'Chrome/'),firefox=tokenMajor(ua,'Firefox/'),edge=tokenMajor(ua,'Edg/');
  const product=variant==='edge'?edge:includes(['firefox','librewolf','waterfox'],variant)?firefox:engine;
  if(includes(['chrome','chromium','edge','firefox','librewolf','waterfox'],variant)&&product===undefined)throw new TypeError('STATIC UA does not identify the selected browser variant');
  if(fp.browser_version!==undefined&&includes(['chrome','chromium','edge','firefox'],variant)&&versionMajor(fp.browser_version)!==product)throw new TypeError('STATIC browser version contradicts UA');
  const data=fp.ua_data;if(!data)return;
  if(data.platform&&includes(ua,'Windows')&&data.platform!=='Windows'||data.platform&&includes(ua,'Mac OS X')&&data.platform!=='macOS')throw new TypeError('STATIC UA/client-hint platform contradiction');
  if(data.wow64&&(data.platform&&data.platform!=='Windows'||data.bitness&&data.bitness!=='64'))throw new TypeError('STATIC WoW64 requires a 64-bit Windows platform');
  if(data.ua_full_version&&includes(['chrome','chromium','edge'],variant)&&versionMajor(data.ua_full_version)!==product)throw new TypeError('STATIC full version contradicts UA');
  for(const list of iterate([data.brands||[],data.full_version_list||[]]))for(const brand of iterate(list)){
    const major=versionMajor(brand.version),expected=includes(['Chromium','Google Chrome'],brand.brand)?engine:brand.brand==='Microsoft Edge'?edge:undefined;
    if(expected!==undefined&&major!==expected)throw new TypeError('STATIC brand version contradicts UA');
  }
}
