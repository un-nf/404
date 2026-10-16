import { iterate, SymbolIntrinsic as Symbol } from '../core/primordials.js';
import { ReflectIntrinsic as Reflect, ObjectIntrinsic as Object, arrayMap, arrayFilter, arrayFind, stringPadStart, regexpTest, NumberIntrinsic as Number, MathIntrinsic as Math } from '../core/primordials.js';
const NativeDate = Date, now = Date.now, utc = Date.UTC, parse = Date.parse;
const time = Date.prototype.getTime;
const setTime = Date.prototype.setTime;
export const dateTime=time,NativeDateConstructor=NativeDate;
const date = NativeDate.prototype;
const timeLimit = 8640000000000000;
function daysFromCivil(year, month, day) { year -= month <= 2 ? 1 : 0; const era = Math.floor(year / 400), y = year - era * 400, m = month + (month > 2 ? -3 : 9); return era * 146097 + y * 365 + Math.floor(y / 4) - Math.floor(y / 100) + Math.floor((153 * m + 2) / 5) + day - 1 - 719468; }
function civilFromDays(days) { let z = days + 719468; const era = Math.floor(z / 146097), doe = z - era * 146097, yoe = Math.floor((doe - Math.floor(doe / 1460) + Math.floor(doe / 36524) - Math.floor(doe / 146096)) / 365); let year = yoe + era * 400; const doy = doe - (365 * yoe + Math.floor(yoe / 4) - Math.floor(yoe / 100)), mp = Math.floor((5 * doy + 2) / 153), day = doy - Math.floor((153 * mp + 2) / 5) + 1, month = mp + (mp < 10 ? 3 : -9); year += month <= 2 ? 1 : 0; return { FullYear: year, Month: month - 1, Date: day }; }
const utcGetters = Object.create(null), utcSetters = Object.create(null);
for (const suffix of iterate(['FullYear', 'Month', 'Date', 'Day', 'Hours', 'Minutes', 'Seconds', 'Milliseconds']))
    utcGetters[suffix] = date['getUTC' + suffix];
for (const suffix of iterate(['FullYear', 'Month', 'Date', 'Hours', 'Minutes', 'Seconds', 'Milliseconds']))
    utcSetters[suffix] = date['setUTC' + suffix];
export function createDateModel(zone, NativeIntl, legacyPolicy='normalize') {
    const formatter = new NativeIntl('en-US', { timeZone: zone, calendar: 'iso8601', numberingSystem: 'latn',
        year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23', era: 'short' });
    const parts = NativeIntl.prototype.formatToParts;
    const labelFormatter = new NativeIntl('en-US', { timeZone: zone, timeZoneName: 'long' });
    function offset(instant) {
        if (!Number.isFinite(instant))
            return NaN;
        const fields = Object.fromEntries(arrayMap(Reflect.apply(parts, formatter, [instant]), p => [p.type, p.value]));
        const year = fields.era === 'BC' ? 1 - Number(fields.year) : Number(fields.year);
        const value = daysFromCivil(year, Number(fields.month), Number(fields.day)) * 86400000 + (Number(fields.hour) * 3600 + Number(fields.minute) * 60 + Number(fields.second)) * 1000;
        return Math.floor(instant / 1000) * 1000 - value;
    }
    function wall(instant) { return new NativeDate(instant - offset(instant)); }
    function fromWall(value) {
        if (!Number.isFinite(value))
            return NaN;
        // Compatible disambiguation: earlier overlap instant; advance across gaps.
        const candidates = arrayMap([value - 172800000, value, value + 172800000], t => value + offset(Math.max(-timeLimit, Math.min(timeLimit, t))));
        const matches = arrayFilter(candidates, t => Math.abs(t) <= timeLimit && t - offset(t) === value);
        return matches.length ? Math.min(...iterate(matches)) : Math.max(...iterate(candidates));
    }
    function localParse(input) {
        const value = `${input}`;
        // ECMAScript standard date-time forms without an offset use profile time.
        // Nonstandard legacy parsing is explicitly not a portable engine contract.
        if (regexpTest(/^[+-]?\d{4,6}-\d\d-\d\dT\d\d:\d\d(?::\d\d(?:\.\d{1,3})?)?$/i,value))
            return fromWall(Reflect.apply(parse, NativeDate, [value + 'Z']));
        const native=Reflect.apply(parse,NativeDate,[value]);
        if(!Number.isFinite(native)||regexpTest(/^(?:\d{4}|[+-]\d{6})(?:-\d{2}(?:-\d{2})?)?$/,value)||regexpTest(/(?:\b(?:GMT|UTC|UT|EST|EDT|CST|CDT|MST|MDT|PST|PDT)\b|[zZ]\s*$|[+-]\d{2}:?\d{2}(?:\s*\([^)]*\))?\s*$)/,value)||legacyPolicy==='native')return native;
        if(legacyPolicy==='normalize'){
            const wallValue=Reflect.apply(parse,NativeDate,[value+' GMT']);
            if(Number.isFinite(wallValue))return fromWall(wallValue);
        }
        throw new DOMException('Legacy local-date syntax cannot be normalized under the selected timezone','NotSupportedError');
    }
    function localGet(receiver, suffix) {
        const instant = Reflect.apply(time, receiver, []);
        if (!Number.isFinite(instant))
            return NaN;
        const value = instant - offset(instant), days = Math.floor(value / 86400000), within = value - days * 86400000, fields = civilFromDays(days);
        fields.Day = ((days + 4) % 7 + 7) % 7;
        fields.Hours = Math.floor(within / 3600000);
        fields.Minutes = Math.floor(within / 60000) % 60;
        fields.Seconds = Math.floor(within / 1000) % 60;
        fields.Milliseconds = within % 1000;
        return fields[suffix];
    }
    function localSet(receiver, suffix, args) {
        const instant = Reflect.apply(time, receiver, []), working = wall(instant);
        const value = Reflect.apply(utcSetters[suffix], working, args);
        const resolved = fromWall(value);
        return Reflect.apply(setTime, receiver, [resolved]);
    }
    const weekday = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'], month = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    const get = (value, suffix) => Reflect.apply(utcGetters[suffix], value, []);
    const pad = (value, size = 2) => stringPadStart(`${value}`, size, '0');
    function strings(receiver) {
        const instant = Reflect.apply(time, receiver, []);
        if (!Number.isFinite(instant))
            return { date: 'Invalid Date', time: 'Invalid Date' };
        const minutes = offset(instant) / 60000, absolute = Math.abs(minutes);
        const get = suffix => localGet(receiver, suffix), year = get('FullYear'), yearText = year < 0 ? '-' + pad(-year, 4) : pad(year, 4);
        return { date: `${weekday[get('Day')]} ${month[get('Month')]} ${pad(get('Date'))} ${yearText}`,
            time: `${pad(get('Hours'))}:${pad(get('Minutes'))}:${pad(get('Seconds'))} GMT${minutes <= 0 ? '+' : '-'}${pad(Math.floor(absolute / 60))}${pad(Math.floor(absolute % 60))} (${arrayFind(Reflect.apply(parts, labelFormatter, [instant]), part => part.type === 'timeZoneName')?.value || zone})` };
    }
    return { offset, localGet, localSet, strings, localParse, construct(args, newTarget) {
            if (args.length >= 2)
                return Reflect.construct(NativeDate, [fromWall(Reflect.apply(utc, NativeDate, args))], newTarget);
            if (args.length === 1) {
                let value = args[0];
                if (value !== null && (typeof value === 'object' || typeof value === 'function')) {
                    try {
                        return Reflect.construct(NativeDate, [Reflect.apply(time, value, [])], newTarget);
                    }
                    catch { }
                    const exotic = Reflect.get(value, Symbol.toPrimitive, value);
                    if (exotic != null) {
                        if (typeof exotic !== 'function')
                            throw new TypeError('Invalid primitive conversion');
                        value = Reflect.apply(exotic, value, ['default']);
                        if (value !== null && (typeof value === 'object' || typeof value === 'function'))
                            throw new TypeError('Primitive conversion returned object');
                    }
                    else {
                        const original = value;
                        let converted = false;
                        for (const key of iterate(['valueOf', 'toString'])) {
                            const method = Reflect.get(original, key, original);
                            if (typeof method === 'function') {
                                const result = Reflect.apply(method, original, []);
                                if (result === null || typeof result !== 'object' && typeof result !== 'function') {
                                    value = result;
                                    converted = true;
                                    break;
                                }
                            }
                        }
                        if (!converted)
                            throw new TypeError('Cannot convert date input');
                    }
                }
                return Reflect.construct(NativeDate, [typeof value === 'string' ? localParse(value) : value], newTarget);
            }
            return Reflect.construct(NativeDate, args, newTarget);
        }, functionValue: () => { const s = strings(new NativeDate(Reflect.apply(now, NativeDate, []))); return s.date + ' ' + s.time; } };
}
