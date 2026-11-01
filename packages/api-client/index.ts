import createClient from "openapi-fetch";
import type { paths } from "./schema";
export const createApi = (baseUrl: string, token: string) =>
  createClient<paths>({
    baseUrl,
    headers: { Authorization: `Bearer ${token}` },
  });
