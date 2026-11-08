import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "@xyflow/react/dist/style.css";
import "./style.css";
import "./gradient.css";
import App from "./App";
import { startRealtime } from "./services/store";
import { initTheme } from "./lib/theme";

initTheme();
startRealtime();
createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
