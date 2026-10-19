// proxy.ts in a Next.js 16 app: authenticate every request except public files.
import { createDaywalkerProxy } from "@shelbyb/daywalker-sdk/next";

export const proxy = createDaywalkerProxy({
  serviceSlug: process.env.DAYWALKER_SERVICE_SLUG,
  errorPath: "/service-error",
  validateServerActions: true,
});

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico|robots.txt).*)"],
};
