import { fireEvent, screen } from "@testing-library/react";
import { MEMORY_TABS, memoryTabGroupOf, type MemoryTab } from "../lib/memoryWorkspaceState";

/**
 * Click a Memory tab the way an analyst does: views inside a group (Graph,
 * Raw Observations, Handles...) are only on screen once their group is open,
 * so open the group first when the tab is not already shown.
 */
export async function openMemoryTab(tab: MemoryTab): Promise<HTMLElement> {
  const testId = MEMORY_TABS.find((item) => item.key === tab)?.testId ?? `memory-tab-${tab}`;
  if (!screen.queryByTestId(testId)) {
    const group = memoryTabGroupOf(tab);
    if (group && group.tabs.length > 1) {
      fireEvent.click(await screen.findByTestId(`memory-tab-group-${group.key}`));
    }
  }
  const button = await screen.findByTestId(testId);
  fireEvent.click(button);
  return button;
}
