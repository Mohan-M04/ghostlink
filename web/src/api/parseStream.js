export async function* parseStream(stream, signal) {
  const reader = stream.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  const parseLine = (line) => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith(":")) return null;
    const payload = trimmed.startsWith("data:") ? trimmed.slice(5).trim() : trimmed;
    if (!payload || payload === "[DONE]") return null;
    return JSON.parse(payload);
  };

  try {
    while (true) {
      if (signal?.aborted) throw new DOMException("The operation was aborted.", "AbortError");
      const { value, done } = await reader.read();
      buffer += decoder.decode(value, { stream: !done });
      const lines = buffer.split(/\r?\n/);
      buffer = lines.pop() ?? "";
      for (const line of lines) {
        const event = parseLine(line);
        if (event !== null) yield event;
      }
      if (done) break;
    }
    if (buffer.trim()) {
      const event = parseLine(buffer);
      if (event !== null) yield event;
    }
  } finally {
    reader.releaseLock();
  }
}
