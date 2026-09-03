import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";
import "@testing-library/jest-dom/vitest";

// Vitest runs without globals, so RTL's automatic cleanup is not
// registered implicitly — do it explicitly to isolate tests.
afterEach(() => {
  cleanup();
});

// jsdom does not implement scrollIntoView; the chat panel's auto-scroll
// effect calls it whenever messages render.
Element.prototype.scrollIntoView = () => {};
