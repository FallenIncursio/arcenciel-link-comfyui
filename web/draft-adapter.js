import { app } from "../../scripts/app.js";
import "./draft-inbox.js";
function requireManualQueue() {
  const mode = app.extensionManager?.queueSettings?.mode;
  if ((mode && mode !== "disabled") || app.ui?.autoQueueEnabled === true)
    throw new Error(
      "Disable Auto Queue in ComfyUI before importing or restoring a Link draft. Your workflow has not been changed.",
    );
}
function widgets(graph = app.graph) {
  const nodes = graph?._nodes || [];
  const samplers = nodes.filter((n) => n.type === "KSampler");
  if (samplers.length !== 1)
    throw new Error(
      "Open a basic txt2img workflow with one KSampler before importing these settings. Advanced graphs need a dedicated mapping.",
    );
  const sampler = samplers[0];
  const linked = (name) => {
    const slot = sampler.inputs.find((i) => i.name === name);
    const link = graph.links[slot?.link];
    return graph.getNodeById(link?.origin_id);
  };
  const positive = linked("positive"),
    negative = linked("negative"),
    latent = linked("latent_image");
  if (
    positive?.type !== "CLIPTextEncode" ||
    negative?.type !== "CLIPTextEncode" ||
    positive.id === negative.id ||
    latent?.type !== "EmptyLatentImage"
  )
    throw new Error(
      "This graph has advanced conditioning or an image input. Open a basic txt2img workflow to avoid changing the wrong nodes.",
    );
  const widget = (node, name) => node.widgets.find((w) => w.name === name);
  const result = {
    prompt: widget(positive, "text"),
    negativePrompt: widget(negative, "text"),
    width: widget(latent, "width"),
    height: widget(latent, "height"),
  };
  for (const [key, name] of Object.entries({
    seed: "seed",
    steps: "steps",
    cfg: "cfg",
    sampler: "sampler_name",
    scheduler: "scheduler",
  }))
    result[key] = widget(sampler, name);
  return result;
}
function basicGraph() {
  const graph = new app.graph.constructor();
  const types = [
    "CheckpointLoaderSimple",
    "CLIPTextEncode",
    "CLIPTextEncode",
    "EmptyLatentImage",
    "KSampler",
    "VAEDecode",
    "SaveImage",
  ];
  const nodes = types.map((type, i) => {
    const n = LiteGraph.createNode(type);
    if (!n) throw new Error(`Missing required basic node: ${type}`);
    graph.add(n);
    n.pos = [
      [20, 60],
      [400, 30],
      [400, 270],
      [400, 530],
      [820, 60],
      [1220, 60],
      [1540, 60],
    ][i];
    return n;
  });
  const [loader, positive, negative, latent, sampler, decode, output] = nodes;
  loader.connect(0, sampler, 0);
  loader.connect(1, positive, 0);
  loader.connect(1, negative, 0);
  loader.connect(2, decode, 1);
  positive.connect(0, sampler, 1);
  negative.connect(0, sampler, 2);
  latent.connect(0, sampler, 3);
  sampler.connect(0, decode, 0);
  decode.connect(0, output, 0);
  const model = loader.widgets.find((w) => w.name === "ckpt_name");
  if (model) model.value = "";
  return graph;
}
export const draftAdapter = {
  canCreateBasic: true,
  async snapshot() {
    return structuredClone(app.graph.serialize());
  },
  async restore(snapshot) {
    requireManualQueue();
    await app.loadGraphData(structuredClone(snapshot));
  },
  async read(keys) {
    const all = widgets();
    return Object.fromEntries(
      keys.map((key) => {
        if (!all[key]) throw new Error(`Missing ${key} widget.`);
        return [key, key === "seed" ? String(all[key].value) : all[key].value];
      }),
    );
  },
  async check(fields, options = {}) {
    requireManualQueue();
    const all = widgets(options.newTemplate ? basicGraph() : app.graph),
      result = {};
    for (const [key, value] of Object.entries(fields)) {
      const w = all[key];
      let reason = !w ? "This node does not expose this field." : undefined;
      const options = w?.options || {};
      if (
        ["seed", "steps", "cfg", "width", "height"].includes(key) &&
        (Number(value) < (options.min ?? -Infinity) ||
          Number(value) > (options.max ?? Infinity))
      )
        reason = "Outside this node’s current numeric range.";
      const values =
        typeof options.values === "function"
          ? options.values()
          : options.values;
      if (Array.isArray(values) && !values.includes(value))
        reason = "This node does not offer the source option.";
      result[key] = { before: w?.value, reason };
    }
    return result;
  },
  async apply(fields, options = {}) {
    requireManualQueue();
    if (options.newTemplate) await app.loadGraphData(basicGraph().serialize());
    const all = widgets();
    for (const [key, value] of Object.entries(fields)) {
      if (!all[key]) throw new Error(`The ${key} widget changed.`);
      all[key].value = key === "seed" ? Number(value) : value;
      // Setting a widget changes the saved workflow; it never queues /prompt.
    }
    app.graph.setDirtyCanvas(true, true);
  },
};
