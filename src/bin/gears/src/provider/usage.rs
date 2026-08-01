//! Token and spend accounting, per agent.
//!
//! The numbers are the endpoint's own — reported usage, never a local
//! tokenizer's guess. Two things depend on them: `/status`, and the spend
//! budget that caps sub-agents. Cost is in USD where the endpoint reports it
//! (OpenRouter does) and token counts everywhere else, so a budget always has
//! *something* to measure even when it cannot be money.

use super::types::Usage;

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct UsageMeter {
    pub completions: u64,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    cost_usd: f64,
    /// How many completions reported a cost; without one, spend is unknown
    /// rather than zero.
    costed: u64,
}

impl UsageMeter {
    pub fn new() -> UsageMeter {
        UsageMeter::default()
    }

    pub fn add(&mut self, usage: &Usage) {
        self.completions += 1;
        self.prompt_tokens += usage.prompt_tokens;
        self.completion_tokens += usage.completion_tokens;
        if let Some(cost) = usage.cost {
            self.cost_usd += cost;
            self.costed += 1;
        }
    }

    pub fn total_tokens(&self) -> u64 {
        self.prompt_tokens + self.completion_tokens
    }

    /// USD spent so far, or `None` when the endpoint reports no cost at all.
    pub fn cost_usd(&self) -> Option<f64> {
        (self.costed > 0).then_some(self.cost_usd)
    }

    /// True when some completions were priced and others were not, which
    /// makes the total a floor rather than the whole bill.
    pub fn cost_is_partial(&self) -> bool {
        self.costed > 0 && self.costed < self.completions
    }

    pub fn merge(&mut self, other: &UsageMeter) {
        self.completions += other.completions;
        self.prompt_tokens += other.prompt_tokens;
        self.completion_tokens += other.completion_tokens;
        self.cost_usd += other.cost_usd;
        self.costed += other.costed;
    }

    /// One line for `/status`.
    pub fn summary(&self) -> String {
        let mut text = format!(
            "{} completions, {} + {} tokens",
            self.completions, self.prompt_tokens, self.completion_tokens
        );
        match self.cost_usd() {
            Some(cost) if self.cost_is_partial() => {
                text.push_str(&format!(", ${cost:.4} (partly unpriced)"))
            }
            Some(cost) => text.push_str(&format!(", ${cost:.4}")),
            None => text.push_str(", cost not reported"),
        }
        text
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usage(prompt: u64, completion: u64, cost: Option<f64>) -> Usage {
        Usage {
            prompt_tokens: prompt,
            completion_tokens: completion,
            total_tokens: prompt + completion,
            cost,
        }
    }

    #[test]
    fn accumulates_tokens_and_cost() {
        let mut meter = UsageMeter::new();
        meter.add(&usage(100, 20, Some(0.0012)));
        meter.add(&usage(300, 40, Some(0.0034)));

        assert_eq!(meter.completions, 2);
        assert_eq!(meter.prompt_tokens, 400);
        assert_eq!(meter.total_tokens(), 460);
        assert!((meter.cost_usd().unwrap() - 0.0046).abs() < 1e-9);
        assert!(!meter.cost_is_partial());
        assert_eq!(meter.summary(), "2 completions, 400 + 60 tokens, $0.0046");
    }

    #[test]
    fn an_endpoint_that_prices_nothing_reports_no_spend() {
        let mut meter = UsageMeter::new();
        meter.add(&usage(10, 5, None));
        // Not zero: unknown. A USD budget cannot be enforced against this,
        // and decision 10 says to fall back to token counts.
        assert_eq!(meter.cost_usd(), None);
        assert_eq!(meter.total_tokens(), 15);
        assert_eq!(
            meter.summary(),
            "1 completions, 10 + 5 tokens, cost not reported"
        );
    }

    #[test]
    fn a_partly_priced_run_says_so() {
        let mut meter = UsageMeter::new();
        meter.add(&usage(10, 5, Some(0.01)));
        meter.add(&usage(10, 5, None));
        assert!(meter.cost_is_partial());
        assert!(meter.summary().ends_with("$0.0100 (partly unpriced)"));
    }

    #[test]
    fn sub_agent_totals_merge_into_the_parent() {
        let mut child = UsageMeter::new();
        child.add(&usage(50, 10, Some(0.002)));
        let mut parent = UsageMeter::new();
        parent.add(&usage(100, 20, Some(0.001)));
        parent.merge(&child);

        assert_eq!(parent.completions, 2);
        assert_eq!(parent.total_tokens(), 180);
        assert!((parent.cost_usd().unwrap() - 0.003).abs() < 1e-9);
    }
}
