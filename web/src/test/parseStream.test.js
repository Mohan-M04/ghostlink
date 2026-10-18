import { parseStream } from "../api/parseStream.js";

function streamOf(chunks) {
  let index = 0;
  return new ReadableStream({ pull(controller) { if (index === chunks.length) controller.close(); else controller.enqueue(new TextEncoder().encode(chunks[index++])); } });
}

describe("parseStream", () => {
  it("parses split chunks and buffered partial lines", async () => {
    const values = [];
    for await (const event of parseStream(streamOf(['{"type":"step",', '"seq":1}\n{"type":"done"', ', "seq":2}\n']))) values.push(event);
    expect(values).toEqual([{ type: "step", seq: 1 }, { type: "done", seq: 2 }]);
  });
  it("accepts SSE data prefixes", async () => {
    const values = [];
    for await (const event of parseStream(streamOf(['data: {"type":"done"}\n\n']))) values.push(event);
    expect(values).toEqual([{ type: "done" }]);
  });
  it("surfaces malformed JSON", async () => {
    const consume = async () => { for await (const _ of parseStream(streamOf(["{bad}\n"]))) void _; };
    await expect(consume()).rejects.toThrow();
  });
});
