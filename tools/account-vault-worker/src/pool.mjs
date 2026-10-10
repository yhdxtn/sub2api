import { delay } from './errors.mjs';

// Capacity is also enforced transactionally by the backend, across processes.
// A task returning false stops new claims; already running tasks finish safely.
export async function runPool({ concurrency, claim, run, signal, once = false, idleMs = 5000 }) {
  if (!Number.isInteger(concurrency) || concurrency < 1 || concurrency > 4) throw new RangeError('Invalid concurrency');
  let accepting = true;
  let failure;
  const lane = async index => {
    try {
      while (accepting && !signal.aborted) {
        const job = await claim(index, signal);
        if (!job) {
          if (once) break;
          await delay(idleMs, signal);
          continue;
        }
        // A claim in flight when another task becomes uncertain still owns a
        // lease. Run it to a durable outcome instead of abandoning the lease.
        const canContinue = await run(job, index);
        if (!canContinue) accepting = false;
        if (once) break;
      }
    } catch (error) {
      accepting = false;
      if (!signal.aborted) failure ??= error;
    }
  };
  await Promise.all(Array.from({ length: concurrency }, (_, index) => lane(index)));
  if (failure) throw failure;
}
