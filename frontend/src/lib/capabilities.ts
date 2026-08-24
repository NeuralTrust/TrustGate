export const PROVIDER_CAPABILITIES = [
  { key: "chat", label: "Chat" },
  { key: "embeddings", label: "Embeddings" },
  { key: "rerank", label: "Rerank" },
  { key: "files", label: "Files" },
  { key: "images", label: "Images" },
  { key: "audio_speech", label: "Speech" },
  { key: "audio_transcription", label: "Transcription" },
] as const;

export type ProviderCapability = (typeof PROVIDER_CAPABILITIES)[number]["key"];

export function providerSupportsCapability(
  capabilities: Record<string, boolean> | undefined,
  key: string,
): boolean {
  return capabilities?.[key] === true;
}

export function visibleProviderCapabilities(
  capabilities: Record<string, boolean> | undefined,
): readonly (typeof PROVIDER_CAPABILITIES)[number][] {
  return PROVIDER_CAPABILITIES.filter((capability) =>
    providerSupportsCapability(capabilities, capability.key),
  );
}
