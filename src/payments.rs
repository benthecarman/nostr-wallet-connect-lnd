use std::collections::VecDeque;
use std::time::{Duration, Instant};

const CACHE_DURATION: Duration = Duration::from_secs(86_400); // 1 day

struct Payment {
    time: Instant,
    amount: u64,
}

pub struct PaymentTracker {
    payments: VecDeque<Payment>,
}

impl PaymentTracker {
    pub fn new() -> Self {
        PaymentTracker {
            payments: VecDeque::new(),
        }
    }

    pub fn add_payment(&mut self, amount: u64) {
        let now = Instant::now();
        let payment = Payment { time: now, amount };

        self.payments.push_back(payment);
    }

    fn clean_old_payments(&mut self) {
        let now = Instant::now();
        while let Some(payment) = self.payments.front() {
            if now.duration_since(payment.time) < CACHE_DURATION {
                break;
            }

            self.payments.pop_front();
        }
    }

    pub fn sum_payments(&mut self) -> u64 {
        self.clean_old_payments();
        self.payments.iter().map(|p| p.amount).sum()
    }
}
