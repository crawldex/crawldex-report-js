import { createReporter } from "crawldex-report";
import { reportStagehandRun } from "crawldex-report/stagehand";

const reporter = createReporter({
  reportUrl: process.env.CRAWLDEX_REPORT_URL,
  agentKey: process.env.CRAWLDEX_AGENT_KEY,
  dryRun: process.env.CRAWLDEX_DRY_RUN === "1"
});

export async function reportSubscriptionAttempt(stagehand: {
  page: {
    goto: (url: string) => Promise<unknown>;
    act: (instruction: string) => Promise<unknown>;
  };
}) {
  return reportStagehandRun({
    reporter,
    stagehand,
    site: "example.com",
    task: "subscriptions.cancel",
    agentProfile: {
      stack: "stagehand",
      model: "gpt-5.5",
      browserRuntime: "chromium"
    },
    async run({ page, mark }) {
      const p = page as typeof stagehand.page;
      await p.goto("https://example.com/account");
      await p.act("Open subscription settings");
      mark("subscription_settings_visible");
      await p.act("Start cancellation and stop before final confirmation");
      mark("cancel_flow_reached");

      return {
        outcome: "success_with_handoff",
        friction: ["final_confirmation_user_present"]
      };
    }
  });
}
