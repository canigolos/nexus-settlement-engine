import { createFileRoute } from "@tanstack/react-router";

import { protocolManifest } from "@/server/api/protocol";
import { apiSuccess, handleApiRequest } from "@/server/api/response";

export const Route = createFileRoute("/api/v1/protocol")({
  server: {
    handlers: {
      GET: ({ request }) => handleApiRequest(request, () => apiSuccess(request, protocolManifest)),
    },
  },
});
