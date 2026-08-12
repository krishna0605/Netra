import "@testing-library/jest-dom/vitest";

// The console reads these at module load and throws without them, which is the
// behaviour we want in a browser and not in a test runner.
import.meta.env.VITE_SUPABASE_URL ||= "https://test.supabase.co";
import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY ||= "sb_publishable_test";
import.meta.env.VITE_DEPLOYMENT_PROFILE ||= "local";

// jsdom has no crypto.getRandomValues in some versions, and no randomUUID.
if (!globalThis.crypto?.getRandomValues) {
  Object.defineProperty(globalThis, "crypto", {
    value: {
      getRandomValues: (array: Uint32Array) => {
        for (let index = 0; index < array.length; index += 1) array[index] = Math.floor(Math.random() * 0xffffffff);
        return array;
      },
      randomUUID: () => "00000000-0000-4000-8000-000000000000",
    },
  });
}
