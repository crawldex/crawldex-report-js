import { createReporter, withPlaywright } from "crawldex-report";

const reporter = createReporter({
  reportUrl: process.env.CRAWLDEX_REPORT_URL,
  agentKey: process.env.CRAWLDEX_AGENT_KEY,
  dryRun: process.env.CRAWLDEX_DRY_RUN === "1"
});

export async function reportCheckoutAttempt(page: {
  goto: (url: string) => Promise<unknown>;
  getByRole: (role: string, options: { name: string | RegExp }) => { click: () => Promise<unknown> };
  getByText: (text: string | RegExp) => { isVisible: () => Promise<boolean> };
}) {
  return withPlaywright({
    reporter,
    page,
    site: "demo-shop.crawldex.com",
    task: "commerce.checkout",
    agentProfile: {
      stack: "playwright",
      browserRuntime: "chromium",
      version: "example"
    }
  }, async ({ page: playwrightPage, step, friction, evidence }) => {
    const p = playwrightPage as typeof page;
    await step("open cart", () => p.goto("https://demo-shop.crawldex.com/cart?session=local"));
    await step("start checkout", () => p.getByRole("button", { name: /checkout/i }).click());

    if (await p.getByText(/sign in/i).isVisible()) {
      friction("login_required");
      evidence("login_required_visible");
      return "success_with_handoff";
    }

    evidence("checkout_reached_without_login_gate");
    return "success";
  });
}
