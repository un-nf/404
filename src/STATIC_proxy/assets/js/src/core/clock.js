import { MathIntrinsic as Math, NumberIntrinsic as Number } from './primordials.js';
export function coarsenTime(value) {
    if (!Number.isFinite(value))
        return value;
    const scaled = value * 10;
    // Keep an already-coarsened decimal on its bucket despite binary rounding.
    return Math.floor(scaled + Math.max(1, Math.abs(scaled)) * Number.EPSILON) / 10;
}
