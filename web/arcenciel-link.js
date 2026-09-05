import { app } from "../../scripts/app.js";
import { api } from "../../scripts/api.js";
app.registerExtension({
  name: "ArcEnCiel.Link.DeviceStatus",
  async setup() {
    if (!app.extensionManager?.registerSidebarTab) return;
    app.extensionManager.registerSidebarTab({
      id: "arcenciel-link",
      icon: "pi pi-link",
      title: "Arc en Ciel Link",
      tooltip: "Arc en Ciel Link",
      type: "custom",
      render(el) {
        const panel = document.createElement("div");
        panel.style.padding = "16px";
        const title = document.createElement("h2");
        title.textContent = "Arc en Ciel Link";
        const status = document.createElement("p");
        status.setAttribute("role", "status");
        const button = document.createElement("button");
        button.textContent = "Refresh Link status";
        button.className = "comfy-btn";
        const link = document.createElement("a");
        link.href = "https://arcenciel.io/link";
        link.target = "_blank";
        link.rel = "noopener noreferrer";
        link.textContent = "Open device tools and your library";
        link.style.display = "block";
        link.style.marginTop = "16px";
        async function refresh() {
          button.disabled = true;
          try {
            const response = await api.fetchApi("/arcenciel-link/status");
            if (!response.ok) throw new Error("Status unavailable");
            const data = await response.json();
            status.textContent = `Link ${data.version} · ${data.connected ? "Connected" : "Disconnected"} · Downloads ${data.running ? "enabled" : "paused"}`;
            if (data.tool)
              status.textContent += ` · ${data.tool.action}: ${data.tool.state} · ${data.tool.processed}/${data.tool.total} · ${data.tool.warnings} warnings`;
          } catch {
            status.textContent =
              "Link status unavailable. Check the host logs or open the Link Hub.";
          } finally {
            button.disabled = false;
          }
        }
        button.addEventListener("click", refresh);
        panel.append(title, status, button, link);
        el.replaceChildren(panel);
        void refresh();
        return () => button.removeEventListener("click", refresh);
      },
    });
  },
});
