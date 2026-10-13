//! Resize a semaphore without replacing active permits or its FIFO waiters.

use std::sync::{Arc, Mutex};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

struct Limit {
    target: usize,
    debt: usize,
    revision: u64,
}

pub(crate) struct Capacity {
    semaphore: Arc<Semaphore>,
    limit: Mutex<Limit>,
}

pub struct CapacityPermit {
    permit: Option<OwnedSemaphorePermit>,
    capacity: Arc<Capacity>,
}

impl Capacity {
    pub(crate) fn new(target: usize) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(target)),
            limit: Mutex::new(Limit {
                target,
                debt: 0,
                revision: 0,
            }),
        }
    }

    pub(crate) fn resize_at_revision(&self, target: usize, revision: u64) {
        let mut limit = self
            .limit
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // A request can retain an older snapshot while another thread has
        // already applied a new limit. It must not restore the old limit.
        if revision < limit.revision {
            return;
        }
        if target < limit.target {
            let decrease = limit.target - target;
            let removed = self.semaphore.forget_permits(decrease);
            // Existing requests keep their permits. Their next releases pay
            // this debt before the semaphore admits another request.
            limit.debt += decrease - removed;
        } else if target > limit.target {
            let increase = target - limit.target;
            let cancelled_debt = limit.debt.min(increase);
            limit.debt -= cancelled_debt;
            self.semaphore.add_permits(increase - cancelled_debt);
        }
        limit.target = target;
        limit.revision = revision;
    }

    pub(crate) fn try_acquire_owned(self: Arc<Self>) -> Result<CapacityPermit, ()> {
        let permit = self.semaphore.clone().try_acquire_owned().map_err(|_| ())?;
        Ok(CapacityPermit {
            permit: Some(permit),
            capacity: self,
        })
    }

    pub(crate) async fn acquire_owned(self: Arc<Self>) -> Result<CapacityPermit, ()> {
        let permit = self
            .semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| ())?;
        Ok(CapacityPermit {
            permit: Some(permit),
            capacity: self,
        })
    }
}

impl Drop for CapacityPermit {
    fn drop(&mut self) {
        let mut limit = self
            .capacity
            .limit
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(permit) = self.permit.take() {
            if limit.debt > 0 {
                limit.debt -= 1;
                permit.forget();
            } else {
                drop(permit);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shrink_keeps_active_requests_and_blocks_new_admission() -> Result<(), ()> {
        let capacity = Arc::new(Capacity::new(3));
        let first = capacity.clone().try_acquire_owned()?;
        let second = capacity.clone().try_acquire_owned()?;
        capacity.resize_at_revision(1, 1);
        capacity.resize_at_revision(3, 0);
        assert!(capacity.clone().try_acquire_owned().is_err());
        drop(first);
        assert!(capacity.clone().try_acquire_owned().is_err());
        drop(second);
        let final_request = capacity.clone().try_acquire_owned()?;
        assert!(capacity.clone().try_acquire_owned().is_err());
        drop(final_request);
        capacity.resize_at_revision(3, 2);
        let _one = capacity.clone().try_acquire_owned()?;
        let _two = capacity.clone().try_acquire_owned()?;
        let _three = capacity.clone().try_acquire_owned()?;
        assert!(capacity.try_acquire_owned().is_err());
        Ok(())
    }
    #[tokio::test]
    async fn grow_cancels_debt_and_wakes_existing_waiters() -> Result<(), ()> {
        let capacity = Arc::new(Capacity::new(2));
        let first = capacity.clone().try_acquire_owned()?;
        let second = capacity.clone().try_acquire_owned()?;
        capacity.resize_at_revision(1, 1);
        capacity.resize_at_revision(2, 2);
        drop(first);
        let third = capacity.clone().try_acquire_owned()?;
        let waiting = capacity.clone().acquire_owned();
        tokio::pin!(waiting);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), &mut waiting)
                .await
                .is_err()
        );
        capacity.resize_at_revision(3, 3);
        let _fourth = tokio::time::timeout(std::time::Duration::from_secs(1), waiting)
            .await
            .map_err(|_| ())??;
        drop(second);
        drop(third);
        Ok(())
    }
}
