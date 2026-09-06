import { app } from "../../scripts/app.js";
import "./draft-inbox.js";
function requireManualQueue() {
  const mode = app.extensionManager?.queueSettings?.mode;
  if ((mode && mode !== "disabled") || app.ui?.autoQueueEnabled === true)
    throw new Error(
      "Disable Auto Queue in ComfyUI before importing or restoring a Link draft. Your workflow has not been changed.",
    );
}
function modelChain(graph) {
  const samplers = graph._nodes.filter((n) => n.type === "KSampler");
  if (samplers.length !== 1)
    throw new Error("Choose a workflow with one base sampler.");
  const sampler = samplers[0];
  const linked = (node, name) =>
    graph.getNodeById(
      graph.links[node.inputs.find((i) => i.name === name)?.link]?.origin_id,
    );
  let model = linked(sampler, "model");
  const loras = [],
    visited = new Set();
  while (model?.type === "LoraLoader" && !visited.has(model.id)) {
    visited.add(model.id);
    loras.unshift(model);
    model = linked(model, "model");
  }
  if (model?.type !== "CheckpointLoaderSimple")
    throw new Error("This model architecture needs its own workflow mapping.");
  const positive = linked(sampler, "positive"),
    negative = linked(sampler, "negative");
  const last = loras.at(-1) || model;
  if (
    linked(positive, "clip")?.id !== last.id ||
    linked(negative, "clip")?.id !== last.id
  )
    throw new Error("Model and text conditioning use different paths.");
  return { loader: model, loras, sampler, positive, negative };
}
function loraValue(chain) {
  return JSON.stringify(
    chain.loras.map((node) => {
      const get = (name) => node.widgets.find((w) => w.name === name)?.value;
      const strength = get("strength_model"),
        clipStrength = get("strength_clip");
      return {
        name: get("lora_name"),
        strength,
        ...(clipStrength !== strength ? { clipStrength } : {}),
      };
    }),
  );
}
function setLoras(graph, raw) {
  const values = JSON.parse(raw),
    chain = modelChain(graph);
  const knownConsumers = new Set([
    chain.sampler.id,
    chain.positive.id,
    chain.negative.id,
    ...chain.loras.map((n) => n.id),
  ]);
  for (const node of chain.loras)
    for (const output of node.outputs)
      for (const id of output.links || []) {
        if (!knownConsumers.has(graph.links[id]?.target_id))
          throw new Error(
            "A LoRA is shared by another workflow branch. Review that branch before replacing it.",
          );
      }
  const newNodes = values.map((value) => {
    const node = LiteGraph.createNode("LoraLoader");
    if (!node) throw new Error("The native LoRA loader is unavailable.");
    const widget = (name) => node.widgets.find((w) => w.name === name);
    const choices = widget("lora_name").options.values;
    if (
      !(typeof choices === "function" ? choices() : choices).includes(
        value.name,
      )
    )
      throw new Error("A LoRA is no longer in the native catalog.");
    for (const [name, amount] of [
      ["strength_model", value.strength],
      ["strength_clip", value.clipStrength ?? value.strength],
    ]) {
      const options = widget(name).options || {};
      if (
        !Number.isFinite(amount) ||
        amount < (options.min ?? -Infinity) ||
        amount > (options.max ?? Infinity)
      )
        throw new Error(
          "A LoRA strength is outside this node's supported range.",
        );
    }
    widget("lora_name").value = value.name;
    widget("strength_model").value = value.strength;
    widget("strength_clip").value = value.clipStrength ?? value.strength;
    return node;
  });
  for (const node of chain.loras) graph.remove(node);
  let previous = chain.loader;
  for (const [index, node] of newNodes.entries()) {
    graph.add(node);
    node.pos = [chain.loader.pos[0] + 300, chain.loader.pos[1] + index * 200];
    previous.connect(0, node, 0);
    previous.connect(1, node, 1);
    previous = node;
  }
  previous.connect(0, chain.sampler, 0);
  previous.connect(1, chain.positive, 0);
  previous.connect(1, chain.negative, 0);
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
  try {
    const chain = modelChain(graph);
    result.checkpoint = widget(chain.loader, "ckpt_name");
    result.loras = { value: loraValue(chain) };
  } catch {
    /* Basic numeric fields remain available on an otherwise supported graph. */
  }
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
      if (key === "loras") {
        try {
          const scratch = new app.graph.constructor();
          scratch.configure(
            (options.newTemplate ? basicGraph() : app.graph).serialize(),
          );
          setLoras(scratch, value);
        } catch (error) {
          result[key] = { before: w?.value, reason: error.message };
          continue;
        }
      }
      let reason = !w ? "This node does not expose this field." : undefined;
      const widgetOptions = w?.options || {};
      if (
        ["seed", "steps", "cfg", "width", "height"].includes(key) &&
        (Number(value) < (widgetOptions.min ?? -Infinity) ||
          Number(value) > (widgetOptions.max ?? Infinity))
      )
        reason = "Outside this node’s current numeric range.";
      const values =
        typeof widgetOptions.values === "function"
          ? widgetOptions.values()
          : widgetOptions.values;
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
    if (fields.loras !== undefined) setLoras(app.graph, fields.loras);
    for (const [key, value] of Object.entries(fields)) {
      if (key === "loras") continue;
      if (!all[key]) throw new Error(`The ${key} widget changed.`);
      all[key].value = key === "seed" ? Number(value) : value;
      // Setting a widget changes the saved workflow; it never queues /prompt.
    }
    app.graph.setDirtyCanvas(true, true);
  },
};
