/**
 * Regression tests for the ConversationPanel conversation resolution
 * (final-release audit requirement).
 *
 * Previously the panel created a NEW conversation on every mount, so
 * closing/reopening "Ask SentinelGPT" orphaned the finding's thread and
 * split its history across conversations. The fixed contract:
 *
 * 1. on mount, reuse the user's existing conversation anchored to
 *    (scanId, findingId) and show its history — do NOT create;
 * 2. create only when no anchored conversation exists;
 * 3. concurrent resolution (mount reconnect + first send) results in
 *    exactly ONE createConversation call.
 */

import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ConversationPanel } from "./ConversationPanel";
import {
  createConversation,
  getConversation,
  listConversations,
  sendMessage,
} from "../api/conversationsApi";
import type { ConversationDetailDto, ConversationDto } from "../api/conversationsApi";

vi.mock("../api/conversationsApi", () => ({
  listConversations: vi.fn(),
  createConversation: vi.fn(),
  getConversation: vi.fn(),
  sendMessage: vi.fn(),
}));

const SCAN_ID = "scan-1";
const FINDING_ID = "finding-1";

const mocked = {
  list: vi.mocked(listConversations),
  create: vi.mocked(createConversation),
  get: vi.mocked(getConversation),
  send: vi.mocked(sendMessage),
};

function conversation(overrides: Partial<ConversationDto> = {}): ConversationDto {
  return {
    id: "conv-1",
    title: "Existing thread",
    userId: "user-1",
    scanId: SCAN_ID,
    findingId: FINDING_ID,
    messageCount: 2,
    createdAt: "2026-09-03T10:00:00Z",
    updatedAt: "2026-09-03T10:05:00Z",
    ...overrides,
  };
}

function detail(conv: ConversationDto, messages: ConversationDetailDto["messages"]): ConversationDetailDto {
  return { ...conv, messages };
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("ConversationPanel conversation resolution", () => {
  it("reconnects to the finding's existing conversation and shows its history without creating", async () => {
    mocked.list.mockResolvedValue([
      conversation({ findingId: "other-finding" }), // noise: different finding
      conversation(),
    ]);
    mocked.get.mockResolvedValue(
      detail(conversation(), [
        { id: "m1", role: "user", content: "earlier question", sequence: 1, createdAt: "2026-09-03T10:00:00Z" },
        { id: "m2", role: "assistant", content: "earlier answer", sequence: 2, createdAt: "2026-09-03T10:05:00Z" },
      ]),
    );

    render(<ConversationPanel scanId={SCAN_ID} findingId={FINDING_ID} />);

    await waitFor(() => expect(mocked.get).toHaveBeenCalledWith("conv-1"));
    expect(await screen.findByText("earlier question")).toBeInTheDocument();
    expect(await screen.findByText("earlier answer")).toBeInTheDocument();
    // Only the matching (scanId, findingId) conversation was requested.
    expect(mocked.get).toHaveBeenCalledTimes(1);
    // The reconnect must not create a new conversation.
    expect(mocked.create).not.toHaveBeenCalled();
  });

  it("creates a conversation only when no anchored one exists", async () => {
    mocked.list.mockResolvedValue([]);
    mocked.create.mockResolvedValue(conversation({ id: "conv-new" }));
    // The mount flow reconnect-loads after resolving, including after a create.
    mocked.get.mockResolvedValue(detail(conversation({ id: "conv-new" }), []));
    mocked.send.mockResolvedValue({
      userMessage: { id: "u1", role: "user", content: "first question", sequence: 1, createdAt: "2026-09-03T11:00:00Z" },
      assistantMessage: { id: "a1", role: "assistant", content: "first answer", sequence: 2, createdAt: "2026-09-03T11:00:01Z" },
    });

    render(<ConversationPanel scanId={SCAN_ID} findingId={FINDING_ID} />);
    await waitFor(() => expect(mocked.list).toHaveBeenCalled());

    await userEvent.type(screen.getByRole("textbox"), "first question");
    // Mount-time resolution completed, so the submit button reads "Send".
    await userEvent.click(await screen.findByRole("button", { name: "Send" }));

    await waitFor(() => expect(mocked.send).toHaveBeenCalledWith("conv-new", "first question"));
    expect(mocked.create).toHaveBeenCalledTimes(1);
    expect(mocked.create).toHaveBeenCalledWith({ scanId: SCAN_ID, findingId: FINDING_ID });
    expect(await screen.findByText("first answer")).toBeInTheDocument();
  });

  it("resolves concurrently with a single flight: two sends cause exactly one creation", async () => {
    // Block resolution so the second submit is guaranteed to land while
    // the first is still in flight (sending=true disables the button).
    let releaseList!: (value: ConversationDto[]) => void;
    mocked.list.mockImplementation(
      () => new Promise<ConversationDto[]>((resolve) => (releaseList = resolve)),
    );
    mocked.create.mockResolvedValue(conversation({ id: "conv-single" }));
    mocked.send.mockImplementation(async (_id: string, content: string) => ({
      userMessage: { id: `u-${content}`, role: "user", content, sequence: 1, createdAt: "2026-09-03T11:00:00Z" },
      assistantMessage: { id: `a-${content}`, role: "assistant", content: "reply", sequence: 2, createdAt: "2026-09-03T11:00:01Z" },
    }));

    render(<ConversationPanel scanId={SCAN_ID} findingId={FINDING_ID} />);
    const input = screen.getByRole("textbox");
    // Resolution is blocked in this test, so the label is still the initial one.
    const button = screen.getByRole("button", { name: /start conversation/i });

    await userEvent.type(input, "question one");
    await userEvent.click(button); // starts resolution + first submit

    await userEvent.type(input, "question two");
    await userEvent.click(button); // ignored: submit is in flight

    expect(mocked.create).not.toHaveBeenCalled();
    releaseList([]);

    await waitFor(() => expect(mocked.send).toHaveBeenCalledTimes(1));
    expect(mocked.send).toHaveBeenCalledWith("conv-single", "question one");
    // The blocked resolution window produced exactly one creation.
    await waitFor(() => expect(mocked.create).toHaveBeenCalledTimes(1));
  });
});
